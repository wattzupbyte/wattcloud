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
import { ConflictError, InsufficientSpaceError, ProviderError } from '../errors';
import { acquireSftpRelayCookie, evictSftpRelayCookieCache } from '../relay/RelayAuth';

/** Chunk size mirrors UPLOAD_CHUNK_SIZE in sdk-core. */
const UPLOAD_CHUNK_SIZE = 4 * 1024 * 1024;
/** Vault folder name on the SFTP server, relative to the optional per-session base path. */
const VAULT_ROOT_NAME = '/WattcloudVault';
/** Only preflight `statvfs@openssh.com` for uploads above this size —
 *  smaller ones are not worth the extra round trip and the relay will
 *  surface server errors mid-upload if space runs out. Mirrors the
 *  WebDAV RFC 4331 preflight threshold. */
const PREFLIGHT_QUOTA_MIN_BYTES = 100 * 1024 * 1024;

/**
 * Normalize a user-supplied SFTP base path:
 * empty → `""` (no prefix); trims whitespace; strips trailing slashes; prepends
 * a leading `/` if absent. Mirrors `normalize_base_path` in sdk-core so the
 * two layers agree on the canonical form.
 */
function normalizeBasePath(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  const withoutTrailing = trimmed.replace(/\/+$/, '');
  if (!withoutTrailing) return '';
  return withoutTrailing.startsWith('/') ? withoutTrailing : `/${withoutTrailing}`;
}

/**
 * Render a WS pre-open failure with whatever diagnostics the browser
 * gives us. Code 1006 is the "abnormal closure" the spec requires for
 * upgrade-time failures (the server didn't respond with 101); it's
 * frustratingly opaque because the browser hides the actual HTTP status
 * for security reasons. A close code != 1006 (or a non-empty reason)
 * usually means the upgrade succeeded but the server-side handler
 * rejected the session early — surface both so the operator can
 * triangulate.
 */
function formatWsFailure(host: string, port: number, code: number | null, reason: string): string {
  const parts: string[] = [`SFTP relay WebSocket connection failed (${host}:${port})`];
  if (code !== null) {
    parts.push(`close code ${code}`);
    if (code === 1006) {
      // 1006 specifically: upgrade refused before WS frames started.
      // Most common causes are the relay returning 401 (missing/invalid
      // relay_auth_sftp cookie), 403 (cookie purpose mismatch / consumed
      // jti / host or port not in allowlist / DNS-SSRF rejection /
      // Origin mismatch), or a network failure. DevTools → Network →
      // failed `/relay/ws?...` request will show the actual HTTP
      // status the server returned.
      parts.push('upgrade refused (HTTP status hidden by browser; check DevTools → Network)');
    }
  }
  if (reason) parts.push(`reason: ${reason}`);
  return parts.join(' — ');
}

export class SftpProvider implements StorageProvider {
  readonly type = 'sftp' as const;
  readonly displayName = 'SFTP';

  private session: any = null; // SftpSessionWasm (loaded from WASM)
  private ws: WebSocket | null = null;
  private host = '';
  private port = 22;
  /** Optional server-absolute prefix applied to the vault root. */
  private basePath = '';
  private _pendingRejecters = new Set<(e: Error) => void>();

  /**
   * Serializes every RPC-style call against the SFTP session.
   *
   * The relay transport in sdk-wasm (WasmRelayTransport) has a
   * single-consumer recv queue — two concurrent RPCs racing on `transport
   * .recv()` can pop each other's frames (non-matching id is skipped and
   * dropped, never re-queued), which deadlocks both. Until a proper
   * response-router mux lands in sdk-core, we keep only one in-flight
   * session call at a time per provider instance.
   */
  private _rpcChain: Promise<unknown> = Promise.resolve();
  private _rpc<T>(fn: () => Promise<T>): Promise<T> {
    const run = this._rpcChain.then(fn, fn);
    this._rpcChain = run.catch(() => {});
    return run;
  }

  /** Full vault root on the server, honoring the configured base path. */
  private vaultRoot(): string {
    return `${this.basePath}${VAULT_ROOT_NAME}`;
  }

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
    this.basePath = normalizeBasePath(savedConfig.sftpBasePath ?? '');

    // Acquire PoW-gated relay cookie (cached 9.5 min).
    await acquireSftpRelayCookie(this.host, this.port);

    // Load SftpSessionWasm from the WASM module. Main-thread WASM is a
    // separate instance from the worker's — see ../mainWasm.ts.
    const { ensureMainThreadWasm } = await import('../mainWasm');
    const wasmModule = await ensureMainThreadWasm<any>();
    const SftpSessionWasm = wasmModule.SftpSessionWasm;

    const wsUrl = `/relay/ws?mode=sftp&host=${encodeURIComponent(this.host)}&port=${encodeURIComponent(String(this.port))}`;

    // WebSocket upgrade can fail intermittently — transient relay
    // back-pressure, fleeting network blip, or a stale single-use cookie
    // racing with eviction. The browser API doesn't expose the upgrade
    // HTTP status, so the onerror handler can't distinguish "definitive
    // 4xx" from "retry-worthy". Try twice before giving up: re-acquire
    // a fresh cookie between attempts (the previous one may have been
    // consumed) and surface host:port in the final error so the user
    // can see which target failed instead of a generic "connection
    // failed". This is the path device-enrollment hits on the receiver
    // side when the just-handed-over SFTP config has its first connect
    // attempt swallowed by a transient.
    const MAX_ATTEMPTS = 2;
    let lastErr: Error | null = null;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        // Backoff + cookie refresh — the previous attempt's cookie may
        // already be consumed server-side and the cache eviction in
        // onerror only drops our local entry. Re-running acquire ensures
        // the next WS upgrade carries a fresh jti.
        await new Promise((r) => setTimeout(r, 500));
        await acquireSftpRelayCookie(this.host, this.port);
      }
      let opened = false;
      let closeCode: number | null = null;
      let closeReason = '';
      try {
        await new Promise<void>((resolve, reject) => {
          this.ws = new WebSocket(wsUrl);
          this.ws.binaryType = 'arraybuffer';

          this.session = new SftpSessionWasm(
            (text: string) => this.ws?.send(text),
            (text: string, bin: Uint8Array) => { this.ws?.send(text); this.ws?.send(bin); },
            () => this.ws?.close(),
            this.basePath || undefined,
          );

          this.ws.onmessage = (e: MessageEvent) => {
            if (typeof e.data === 'string') this.session.on_recv_text(e.data);
            else this.session.on_recv_binary(new Uint8Array(e.data as ArrayBuffer));
          };

          this.ws.onclose = (e: CloseEvent) => {
            // Capture the close code so a pre-open failure can include it
            // in the surfaced error — the WS API hides the upgrade HTTP
            // status from JS, but the close code at least narrows the
            // diagnosis (1006 abnormal vs application-defined codes).
            if (!opened) {
              closeCode = e.code;
              closeReason = e.reason ?? '';
            }
            this.session.on_close();
            this._drainRejecters(new ProviderError('NETWORK_ERROR', 'SFTP WebSocket closed during operation', 'sftp'));
            if (!opened) {
              reject(new Error(formatWsFailure(this.host, this.port, closeCode, closeReason)));
            }
          };

          this.ws.onerror = () => {
            evictSftpRelayCookieCache(this.host, this.port).catch(() => {});
            this._drainRejecters(new ProviderError('NETWORK_ERROR', 'SFTP WebSocket error during operation', 'sftp'));
            // Don't reject here — onclose fires right after with a close
            // code we can include in the error message. Rejecting twice
            // is harmless (the second is a no-op on a settled Promise)
            // but the code-augmented message is the better one to keep.
          };

          this.ws.onopen = () => {
            opened = true;
            // The server consumes the cookie's JTI on a successful upgrade
            // (single-use enforcement). Keeping the per-purpose cache entry would
            // re-offer the same consumed cookie on the next reconnect and earn a
            // 403 "jti already consumed (replay)". Drop it now so the next init()
            // runs a fresh PoW handshake.
            evictSftpRelayCookieCache(this.host, this.port).catch(() => {});
            resolve();
          };
        });
        lastErr = null;
        break;
      } catch (e) {
        lastErr = e instanceof Error ? e : new Error(String(e));
        // Tear down the half-open socket so the next attempt's onclose
        // handler doesn't fire against a stale session.
        try { this.ws?.close(); } catch { /* ignore */ }
        this.ws = null;
      }
    }
    if (lastErr) {
      throw new Error(
        `SFTP relay WebSocket connection failed (${this.host}:${this.port}) after ${MAX_ATTEMPTS} attempts: ${lastErr.message}`,
      );
    }

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
      sftpBasePath: this.basePath || undefined,
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
      const current = await this.getVersion(ref || `${this.vaultRoot()}/data/${name}`).catch(() => null);
      if (current !== null && current !== options.expectedVersion) throw new ConflictError('sftp', current);
    }
    return this._uploadWithDirRecover(name, data, async () => {
      const streamId: string = await this._rpc(() => this.session.upload_open(name, data.length));
      if (streamId.startsWith('v2:')) {
        for (let pos = 0; pos < data.length; pos += UPLOAD_CHUNK_SIZE) {
          await this._rpc(() => this.session.upload_write_chunk(streamId, data.subarray(pos, pos + UPLOAD_CHUNK_SIZE)));
        }
        return JSON.parse(await this._rpc(() => this.session.upload_close_v2(streamId)));
      }
      return JSON.parse(await this._rpc(() => this.session.upload_close_v1(streamId, data)));
    });
  }

  /** Wrap an upload attempt with one auto-retry after ensure_root_folders.
   *  init() already calls ensure_root_folders — but if a remote operator
   *  prunes the vault directory between sessions, or if a future code
   *  path skips the init mkdir for any reason, the first write hits a
   *  "No such file" from CREATE|WRITE|TRUNCATE on a missing parent dir.
   *  Re-running the mkdir-p chain and retrying once is cheap, idempotent,
   *  and avoids the "Debounced save failed: No such file" loop the user
   *  hit when adding a second SFTP provider. */
  private async _uploadWithDirRecover<T>(
    name: string,
    _data: Uint8Array,
    attempt: () => Promise<T>,
  ): Promise<T> {
    try {
      return await attempt();
    } catch (e: any) {
      const msg = String(e?.message ?? e ?? '');
      if (!/no such file|nosuchfile/i.test(msg)) throw e;
      // Best-effort dir reconciliation. ensure_root_folders is idempotent
      // (each step stat's first, only mkdir's on miss).
      try {
        await this._rpc(() => this.session.ensure_root_folders());
      } catch (mkdirErr) {
        console.warn(`[SftpProvider] ensure_root_folders during upload retry failed for ${name}`, mkdirErr);
        throw e; // Surface the original error rather than the mkdir error.
      }
      return await attempt();
    }
  }

  async download(ref: string): Promise<{ data: Uint8Array; version: string }> {
    const data: Uint8Array = await this._rpc(() => this.session.read_file(ref));
    const version = await this.getVersion(ref);
    return { data, version };
  }

  async delete(ref: string): Promise<void> { await this._rpc(() => this.session.delete_file(ref)); }

  async getVersion(ref: string): Promise<string> {
    const stat = JSON.parse(await this._rpc(() => this.session.stat(ref)));
    return `${stat.mtime}:${stat.size}`;
  }

  manifestRef(): string {
    return `${this.vaultRoot()}/data/vault_manifest.sc`;
  }

  bodyRef(providerId: string): string {
    return `${this.vaultRoot()}/data/vault_${providerId}.sc`;
  }

  journalRef(providerId: string): string {
    return `${this.vaultRoot()}/data/vault_journal_${providerId}.j`;
  }

  // ── Streaming I/O ────────────────────────────────────────────────────────────

  async uploadStream(ref: string | null, name: string, totalSize: number, options?: UploadOptions): Promise<{ stream: WritableStream<Uint8Array>; result: Promise<UploadResult> }> {
    if (options?.expectedVersion) {
      const current = await this.getVersion(ref || `${this.vaultRoot()}/data/${name}`).catch(() => null);
      if (current !== null && current !== options.expectedVersion) throw new ConflictError('sftp', current);
    }
    // statvfs@openssh.com preflight: OpenSSH-backed servers report free
    // bytes; everything else returns null and we skip silently. Small
    // uploads bypass the round trip — mid-upload server errors still
    // surface normally if the remote runs out of space.
    if (totalSize >= PREFLIGHT_QUOTA_MIN_BYTES) {
      const rawFree = await this._rpc<number | null>(() =>
        this.session.fs_info(this.vaultRoot()),
      ).catch(() => null);
      const free = typeof rawFree === 'number' ? rawFree : null;
      if (free !== null && totalSize > free) {
        throw new InsufficientSpaceError('sftp', totalSize, free);
      }
    }
    // Relay protocol ≥2 is required (v1 single-shot was retired at launch —
    // sdk-core.SftpClient::upload_open always produces a "v2:" stream_id
    // now and errors on older relays).
    const streamId: string = await this._rpc(() => this.session.upload_open(name, totalSize));
    const session = this.session;
    const provider = this;
    let bytesWritten = 0;
    let resolveResult!: (r: UploadResult) => void;
    let rejectResult!: (e: Error) => void;
    const result = new Promise<UploadResult>((res, rej) => { resolveResult = res; rejectResult = rej; });
    // Register rejectResult so WS close/error drains it immediately.
    provider._pendingRejecters.add(rejectResult);
    result.finally(() => provider._pendingRejecters.delete(rejectResult)).catch(() => {});

    const stream = new WritableStream<Uint8Array>({
      async write(incoming) {
        for (let pos = 0; pos < incoming.length; pos += UPLOAD_CHUNK_SIZE) {
          await provider._rpc(() =>
            session.upload_write_chunk(streamId, incoming.subarray(pos, pos + UPLOAD_CHUNK_SIZE)),
          );
        }
        bytesWritten += incoming.length;
        options?.onProgress?.(bytesWritten);
      },
      async close() {
        try {
          const r: UploadResult = JSON.parse(
            await provider._rpc(() => session.upload_close_v2(streamId)),
          );
          resolveResult(r);
        } catch (e) {
          rejectResult(e instanceof Error ? e : new Error(String(e)));
          throw e;
        }
      },
      async abort(reason) {
        await provider._rpc(() => session.upload_abort_v2(streamId)).catch(() => {});
        rejectResult(reason instanceof Error ? reason : new Error(String(reason)));
      },
    });
    return { stream, result };
  }

  async downloadStream(ref: string): Promise<ReadableStream<Uint8Array>> {
    // Relay protocol v3 adds read_open / read_chunk / read_close. On older
    // relays fall back to the single-shot buffered read.
    const relayVer: number = this.session?.relay_version?.() ?? 0;
    if (relayVer < 3) {
      const { data } = await this.download(ref);
      return new ReadableStream<Uint8Array>({ start(c) { c.enqueue(data); c.close(); } });
    }

    const handle: string = await this._rpc(() => this.session.read_open(ref));
    const session = this.session;
    const provider = this;
    let closed = false;
    const closeOnce = async () => {
      if (closed) return;
      closed = true;
      await provider._rpc(() => session.read_close(handle)).catch(() => {
        /* best-effort — relay drops sessions on disconnect */
      });
    };

    return new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const chunk: Uint8Array | null = await provider._rpc(() =>
            session.read_chunk(handle),
          );
          if (chunk === null) {
            await closeOnce();
            controller.close();
            return;
          }
          // A zero-length chunk is equivalent to EOF on this protocol; the
          // sdk-core client maps empty binary frames to `None` before we
          // see them, so this branch is a defensive guard only.
          if (chunk.byteLength === 0) {
            await closeOnce();
            controller.close();
            return;
          }
          controller.enqueue(chunk);
        } catch (e) {
          await closeOnce();
          controller.error(e);
        }
      },
      async cancel() {
        await closeOnce();
      },
    });
  }

  // ── Directory operations ──────────────────────────────────────────────────────

  async list(parentRef?: string): Promise<StorageEntry[]> {
    const entries: Array<{ ref: string; name: string; size: number; isFolder: boolean; modifiedAt?: number }> =
      JSON.parse(await this._rpc(() => this.session.list(parentRef || this.vaultRoot())));
    // sdk-core serializes modifiedAt as Unix milliseconds (number); TS type expects ISO string.
    return entries.map(e => ({
      ...e,
      modifiedAt: e.modifiedAt ? new Date(e.modifiedAt).toISOString() : undefined,
    }));
  }

  async createFolder(name: string, parentRef?: string): Promise<{ ref: string }> {
    const path = parentRef ? `${parentRef}/${name}` : `${this.vaultRoot()}/${name}`;
    await this._rpc(() => this.session.mkdir(path));
    return { ref: path };
  }

  async deleteFolder(ref: string): Promise<void> { await this._rpc(() => this.session.delete_file(ref)); }
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