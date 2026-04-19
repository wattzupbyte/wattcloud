/**
 * SFTP storage provider — thin WebSocket transport wrapper.
 *
 * All protocol logic (handshake, TOFU, verbs, v2 streaming) lives in
 * sdk-core via `SftpSessionWasm` (sdk-wasm WASM binding). This file
 * owns only:
 *   - relay cookie acquisition
 *   - WebSocket lifecycle (open / onmessage / onclose)
 *   - StorageProvider method delegation to the WASM session
 */

import type { StorageProvider, StorageEntry, ProviderConfig, UploadOptions, UploadResult } from '../types';
import { ConflictError, ProviderError } from '../errors';
import { acquireSftpRelayCookie, evictSftpRelayCookieCache } from '../relay/RelayAuth';

/** Chunk size mirrors UPLOAD_CHUNK_SIZE in sdk-core. */
const UPLOAD_CHUNK_SIZE = 4 * 1024 * 1024;
const SECURECLOUD_PATH = '/SecureCloud';

export class SftpProvider implements StorageProvider {
  readonly type = 'sftp' as const;
  readonly displayName = 'SFTP';

  private session: any = null; // SftpSessionWasm (loaded from WASM)
  private ws: WebSocket | null = null;
  private host = '';
  private port = 22;
  private _pendingRejecters = new Set<(e: Error) => void>();

  private _trackPromise<T>(p: Promise<T>): Promise<T> {
    let reject!: (e: Error) => void;
    const wrapped = new Promise<T>((res, rej) => {
      reject = rej;
      p.then(res, rej);
    });
    this._pendingRejecters.add(reject);
    wrapped.finally(() => this._pendingRejecters.delete(reject)).catch(() => {});
    return wrapped;
  }

  private _drainRejecters(err: Error): void {
    const rejecters = [...this._pendingRejecters];
    this._pendingRejecters.clear();
    for (const r of rejecters) r(err);
  }

  /** Set before init() when no stored fingerprint exists. */
  onFirstHostKey?: (fingerprint: string) => Promise<boolean>;

  /**
   * Opaque credential handle returned by `sftpStoreCredential`. The actual
   * password / private key lives inside the WASM heap and is consumed by
   * `session.auth_with_handle`. Must be set before `init()`.
   */
  credHandle?: number;
  /** SSH username associated with `credHandle`. */
  credUsername?: string;

  async init(savedConfig?: ProviderConfig): Promise<void> {
    if (!savedConfig?.sftpHost) throw new Error('SFTP requires host configuration');
    this.host = savedConfig.sftpHost;
    this.port = savedConfig.sftpPort || 22;

    // Acquire PoW-gated relay cookie (cached 9.5 min).
    await acquireSftpRelayCookie(this.host, this.port);

    // Load SftpSessionWasm from the WASM module (already initialised by the worker).
    const wasmModule = await import('secure-cloud-wasm') as any;
    const SftpSessionWasm = wasmModule.SftpSessionWasm;

    const wsUrl = `/relay/ws?mode=sftp&host=${encodeURIComponent(this.host)}&port=${encodeURIComponent(String(this.port))}`;

    await new Promise<void>((resolve, reject) => {
      this.ws = new WebSocket(wsUrl);
      this.ws.binaryType = 'arraybuffer';

      this.session = new SftpSessionWasm(
        (text: string) => this.ws?.send(text),
        (text: string, bin: Uint8Array) => { this.ws?.send(text); this.ws?.send(bin); },
        () => this.ws?.close(),
      );

      this.ws.onmessage = (e: MessageEvent) => {
        if (typeof e.data === 'string') this.session.on_recv_text(e.data);
        else this.session.on_recv_binary(new Uint8Array(e.data as ArrayBuffer));
      };

      this.ws.onclose = () => {
        this.session.on_close();
        this._drainRejecters(new ProviderError('NETWORK_ERROR', 'SFTP WebSocket closed during operation', 'sftp'));
      };

      this.ws.onerror = () => {
        evictSftpRelayCookieCache(this.host, this.port).catch(() => {});
        this._drainRejecters(new ProviderError('NETWORK_ERROR', 'SFTP WebSocket error during operation', 'sftp'));
        reject(new Error('SFTP relay WebSocket connection failed'));
      };

      this.ws.onopen = () => resolve();
    });

    // Handshake (TOFU + relay_version negotiation).
    const storedFp = savedConfig.sftpHostKeyFingerprint ?? null;
    // Inject stored fingerprint into session before handshake.
    if (storedFp) this.session.set_stored_fingerprint?.(storedFp);

    await this.session.handshake(this.onFirstHostKey
      ? (fp: string) => this.onFirstHostKey!(fp)
      : (_fp: string) => Promise.resolve(false),
    );

    // Authenticate by WASM credential handle — the plaintext never crosses
    // the JS boundary. Caller stores the credential with
    // `sftpStoreCredential` (which delegates to sdk-wasm) and hands us the
    // opaque handle.
    if (this.credHandle === undefined || !this.credUsername) {
      throw new Error('SftpProvider: credHandle + credUsername must be set before init()');
    }
    await this.session.auth_with_handle(this.credUsername, this.credHandle);

    await this.session.ensure_root_folders();
  }

  isReady(): boolean { return this.ws?.readyState === WebSocket.OPEN; }

  async disconnect(): Promise<void> {
    if (this.session) await this.session.disconnect().catch(() => {});
    this.ws?.close();
    this.ws = null;
  }

  getConfig(): ProviderConfig {
    return {
      type: 'sftp',
      sftpHost: this.host,
      sftpPort: this.port,
      // Persist the TOFU fingerprint so future init() skips the user prompt.
      sftpHostKeyFingerprint: this.session?.stored_fingerprint() || undefined,
    };
  }

  async refreshAuth(): Promise<void> {
    if (!this.isReady()) await this.init(this.getConfig());
  }

  // ── Blob I/O ────────────────────────────────────────────────────────────────

  async upload(ref: string | null, name: string, data: Uint8Array, options?: UploadOptions): Promise<UploadResult> {
    if (options?.expectedVersion) {
      const current = await this.getVersion(ref || `${SECURECLOUD_PATH}/data/${name}`).catch(() => null);
      if (current !== null && current !== options.expectedVersion) throw new ConflictError('sftp', current);
    }
    const streamId: string = await this.session.upload_open(name, data.length);
    if (streamId.startsWith('v2:')) {
      for (let pos = 0; pos < data.length; pos += UPLOAD_CHUNK_SIZE) {
        await this.session.upload_write_chunk(streamId, data.subarray(pos, pos + UPLOAD_CHUNK_SIZE));
      }
      return JSON.parse(await this.session.upload_close_v2(streamId));
    }
    return JSON.parse(await this.session.upload_close_v1(streamId, data));
  }

  async download(ref: string): Promise<{ data: Uint8Array; version: string }> {
    const data: Uint8Array = await this.session.read_file(ref);
    const version = await this.getVersion(ref);
    return { data, version };
  }

  async delete(ref: string): Promise<void> { await this.session.delete_file(ref); }

  async getVersion(ref: string): Promise<string> {
    const stat = JSON.parse(await this.session.stat(ref));
    return `${stat.mtime}:${stat.size}`;
  }

  // ── Streaming I/O ────────────────────────────────────────────────────────────

  async uploadStream(ref: string | null, name: string, totalSize: number, options?: UploadOptions): Promise<{ stream: WritableStream<Uint8Array>; result: Promise<UploadResult> }> {
    if (options?.expectedVersion) {
      const current = await this.getVersion(ref || `${SECURECLOUD_PATH}/data/${name}`).catch(() => null);
      if (current !== null && current !== options.expectedVersion) throw new ConflictError('sftp', current);
    }
    const streamId: string = await this.session.upload_open(name, totalSize);
    const isV2 = streamId.startsWith('v2:');
    const session = this.session;
    const provider = this;
    // v1 relay: buffer all chunks in memory and send at close (relay can't stream-receive).
    const v1Chunks: Uint8Array[] = [];
    let bytesWritten = 0;
    let resolveResult!: (r: UploadResult) => void;
    let rejectResult!: (e: Error) => void;
    const result = new Promise<UploadResult>((res, rej) => { resolveResult = res; rejectResult = rej; });
    // Register rejectResult so WS close/error drains it immediately.
    provider._pendingRejecters.add(rejectResult);
    result.finally(() => provider._pendingRejecters.delete(rejectResult)).catch(() => {});

    const stream = new WritableStream<Uint8Array>({
      async write(incoming) {
        if (isV2) {
          for (let pos = 0; pos < incoming.length; pos += UPLOAD_CHUNK_SIZE) {
            await session.upload_write_chunk(streamId, incoming.subarray(pos, pos + UPLOAD_CHUNK_SIZE));
          }
        } else {
          v1Chunks.push(incoming.slice());
        }
        bytesWritten += incoming.length;
        options?.onProgress?.(bytesWritten);
      },
      async close() {
        try {
          let r: UploadResult;
          if (isV2) {
            r = JSON.parse(await session.upload_close_v2(streamId));
          } else {
            const data = new Uint8Array(v1Chunks.reduce((s, c) => s + c.length, 0));
            let off = 0;
            for (const c of v1Chunks) { data.set(c, off); off += c.length; }
            r = JSON.parse(await session.upload_close_v1(streamId, data));
          }
          resolveResult(r);
        } catch (e) {
          rejectResult(e instanceof Error ? e : new Error(String(e)));
          throw e;
        }
      },
      async abort(reason) {
        if (isV2) await session.upload_abort_v2(streamId).catch(() => {});
        rejectResult(reason instanceof Error ? reason : new Error(String(reason)));
      },
    });
    return { stream, result };
  }

  async downloadStream(ref: string): Promise<ReadableStream<Uint8Array>> {
    const { data } = await this.download(ref);
    return new ReadableStream<Uint8Array>({ start(c) { c.enqueue(data); c.close(); } });
  }

  // ── Directory operations ──────────────────────────────────────────────────────

  async list(parentRef?: string): Promise<StorageEntry[]> {
    const entries: Array<{ ref: string; name: string; size: number; isFolder: boolean; modifiedAt?: number }> =
      JSON.parse(await this.session.list(parentRef || SECURECLOUD_PATH));
    // sdk-core serializes modifiedAt as Unix milliseconds (number); TS type expects ISO string.
    return entries.map(e => ({
      ...e,
      modifiedAt: e.modifiedAt ? new Date(e.modifiedAt).toISOString() : undefined,
    }));
  }

  async createFolder(name: string, parentRef?: string): Promise<{ ref: string }> {
    const path = parentRef ? `${parentRef}/${name}` : `${SECURECLOUD_PATH}/${name}`;
    await this.session.mkdir(path);
    return { ref: path };
  }

  async deleteFolder(ref: string): Promise<void> { await this.session.delete_file(ref); }
  // ── Share link (P10) ──────────────────────────────────────────────────

  async createPublicLink(_ref: string): Promise<string> {
    throw new ProviderError('PROVIDER_ERROR', 'Public links not supported by sftp', 'sftp');
  }

  async revokePublicLink(_ref: string): Promise<void> {
    // No-op.
  }

  async createPresignedUrl(_ref: string, _ttlSeconds: number): Promise<string> {
    throw new ProviderError('PROVIDER_ERROR', 'Presigned URLs not supported by sftp', 'sftp');
  }

  /** Read-and-reset relay bandwidth counters (bytes sent + received). */
  getBandwidthAndReset(): { sent: number; recv: number } {
    if (!this.session) return { sent: 0, recv: 0 };
    try {
      return this.session.relayBandwidthAndReset() as { sent: number; recv: number };
    } catch {
      return { sent: 0, recv: 0 };
    }
  }
}