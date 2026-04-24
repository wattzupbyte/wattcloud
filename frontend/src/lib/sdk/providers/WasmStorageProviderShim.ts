/**
 * WasmStorageProviderShim — generic TS shim for WASM-backed BYO storage providers.
 *
 * Replaces the per-provider HTTP TS classes (GDriveProvider, DropboxProvider, etc.)
 * introduced in P1-P6. All I/O is delegated to the Rust StorageProvider implementations
 * in sdk-core via the generic `byoProviderCall` worker dispatcher (P8).
 *
 * Binary data (upload payload, download result) is base64-encoded when crossing the
 * JSON worker boundary — acceptable overhead since messages already cross a thread
 * boundary with serialization cost.
 *
 * Security (R1.4): credentials are stored only in the worker's configRegistry. On init,
 * the full configJson is sent to the worker once; an opaque handle (UUID) is returned and
 * stored on the main thread instead. Every op passes the handle — the worker resolves it
 * and injects the config before calling WASM. Raw credentials never re-enter JS after init.
 *
 * OAuth token refresh: delegates to byoRefreshConfigByHandle — the worker refreshes
 * the token and updates the registry entry; the refreshed credentials never leave the worker.
 */

import type { StorageEntry, ProviderConfig, UploadOptions, UploadResult } from '../types';
import type { ProviderType, StorageProvider } from '../types';
import { ProviderError, ConflictError, UnauthorizedError, InsufficientSpaceError } from '../errors';
import {
  byoProviderCall,
  byoInitConfig,
  byoReleaseConfig,
  byoRefreshConfigByHandle,
} from '../worker/byoWorkerClient';

// ── Helpers ────────────────────────────────────────────────────────────────

function encodeBase64(bytes: Uint8Array): string {
  // btoa works in Worker context for binary strings.
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function decodeBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Map a WASM error string to a typed ProviderError subclass. */
function mapError(e: unknown, providerType: ProviderType): ProviderError {
  const msg = e instanceof Error ? e.message : String(e);
  // Rust-side `ProviderError::InsufficientSpace { needed, available }` renders
  // via thiserror as `insufficient space: need N bytes, M available`. Parse
  // the two numbers so the UI can show the specific shortfall.
  const insMatch = msg.match(/insufficient space: need (\d+) bytes, (\d+) available/);
  if (insMatch) {
    return new InsufficientSpaceError(
      providerType,
      Number(insMatch[1]),
      Number(insMatch[2]),
    );
  }
  if (msg.includes('Unauthorized') || msg.includes('HTTP 401'))
    return new UnauthorizedError(providerType);
  if (msg.includes('Conflict') || msg.includes('HTTP 409') || msg.includes('HTTP 412'))
    return new ConflictError(providerType, '');
  return new ProviderError('PROVIDER_ERROR', msg, providerType);
}

async function call<T>(
  providerType: ProviderType,
  op: string,
  argsWithoutConfig: Record<string, unknown>,
  configHandle: string,
): Promise<T> {
  try {
    return await byoProviderCall(providerType, op, configHandle, JSON.stringify(argsWithoutConfig)) as T;
  } catch (e) {
    throw mapError(e, providerType);
  }
}

/**
 * Normalise a user-supplied S3 in-bucket prefix to the canonical form used
 * when composing keys: trim whitespace, strip leading/trailing slashes, append
 * a trailing `/` when non-empty. Empty input → empty output (no prefixing).
 * Mirrors `normalize_s3_base_path` in sdk-core/src/byo/providers/s3.rs so the
 * two layers agree on what prefix ends up in S3.
 */
function normaliseS3BasePath(raw?: string): string {
  const trimmed = (raw ?? '').trim().replace(/^\/+|\/+$/g, '');
  return trimmed ? `${trimmed}/` : '';
}

// ── Provider display names ─────────────────────────────────────────────────

const DISPLAY_NAMES: Partial<Record<ProviderType, string>> = {
  gdrive: 'Google Drive',
  dropbox: 'Dropbox',
  onedrive: 'OneDrive',
  webdav: 'WebDAV',
  box: 'Box',
  pcloud: 'pCloud',
  s3: 'S3',
  sftp: 'SFTP',
};

// ── WasmStorageProviderShim ────────────────────────────────────────────────

export class WasmStorageProviderShim implements StorageProvider {
  readonly type: ProviderType;
  readonly displayName: string;

  // Opaque handle into the worker's configRegistry — credentials never stored here.
  private configHandle: string | null = null;
  private ready = false;

  /**
   * S3 only: normalised in-bucket prefix (empty or ends with `/`). Mirrors the
   * Rust-side `S3Config::base_path` so the TS refs passed to download/getVersion
   * match the keys the Rust side actually writes on upload. Non-S3 shims leave
   * this empty and it contributes nothing to the ref builders below.
   */
  private s3BasePath = '';

  constructor(type: ProviderType) {
    this.type = type;
    this.displayName = DISPLAY_NAMES[type] ?? type;
  }

  async init(savedConfig?: ProviderConfig): Promise<void> {
    if (!savedConfig) {
      throw new ProviderError(
        'PROVIDER_ERROR',
        `${this.displayName}: requires a saved config`,
        this.type,
      );
    }
    if (this.type === 's3') {
      this.s3BasePath = normaliseS3BasePath(savedConfig.s3BasePath);
    }
    // Send credentials to worker once; store only the returned opaque handle.
    this.configHandle = await byoInitConfig(JSON.stringify(savedConfig));
    this.ready = true;
  }

  isReady(): boolean { return this.ready; }

  /** Returns the worker-side config handle, or null if not yet initialised.
   *  Used by byoCrossProviderStreamCopy to avoid re-sending credentials. */
  getConfigHandle(): string | null { return this.configHandle; }

  async disconnect(): Promise<void> {
    if (this.configHandle) {
      await byoReleaseConfig(this.configHandle);
      this.configHandle = null;
    }
    this.ready = false;
  }

  /**
   * Returns a type-only stub. Raw credentials are not accessible from the main thread (R1.4).
   * Callers that need display metadata should use this; callers that need live config
   * should operate through the provider methods directly.
   */
  getConfig(): ProviderConfig {
    return { type: this.type };
  }

  async refreshAuth(): Promise<void> {
    const handle = this.requireHandle();
    // Worker refreshes the token and updates the registry entry in-place.
    await byoRefreshConfigByHandle(this.type, handle);
  }

  async upload(
    ref: string | null,
    name: string,
    data: Uint8Array,
    options?: UploadOptions,
  ): Promise<UploadResult> {
    const handle = this.requireHandle();
    const datab64 = encodeBase64(data);
    return call<UploadResult>(this.type, 'upload', {
      ref: ref ?? null,
      name,
      datab64,
      expectedVersion: options?.expectedVersion ?? null,
    }, handle);
  }

  async download(ref: string): Promise<{ data: Uint8Array; version: string }> {
    const handle = this.requireHandle();
    const result = await call<{ datab64: string }>(this.type, 'download', { ref }, handle);
    // Fetch version separately (HEAD request, cheap).
    const version = await call<string>(this.type, 'getVersion', { ref }, handle).catch(() => '');
    return { data: decodeBase64(result.datab64), version };
  }

  async delete(ref: string): Promise<void> {
    const handle = this.requireHandle();
    await call<null>(this.type, 'delete', { ref }, handle);
  }

  async getVersion(ref: string): Promise<string> {
    const handle = this.requireHandle();
    return call<string>(this.type, 'getVersion', { ref }, handle);
  }

  /**
   * Root-relative refs for the manifest, per-provider body and per-provider journal.
   *
   * For S3, the Rust side prepends `s3BasePath` to every key it writes, so the
   * TS-side ref (used by download/getVersion/delete) must include the same
   * prefix — otherwise the two sides disagree on where the object lives and
   * operations 404. Non-S3 providers ignore the field and keep the historical
   * `WattcloudVault/...` refs.
   */
  manifestRef(): string { return `${this.s3BasePath}WattcloudVault/vault_manifest.sc`; }
  bodyRef(providerId: string): string { return `${this.s3BasePath}WattcloudVault/vault_${providerId}.sc`; }
  journalRef(providerId: string): string { return `${this.s3BasePath}WattcloudVault/vault_journal_${providerId}.j`; }

  async uploadStream(
    ref: string | null,
    name: string,
    _totalSize: number,
    options?: UploadOptions,
  ): Promise<{ stream: WritableStream<Uint8Array>; result: Promise<UploadResult> }> {
    const handle = this.requireHandle();
    const chunks: Uint8Array[] = [];
    let resolveResult!: (r: UploadResult) => void;
    let rejectResult!: (e: unknown) => void;
    const resultPromise = new Promise<UploadResult>((res, rej) => {
      resolveResult = res;
      rejectResult = rej;
    });
    const type = this.type;
    const stream = new WritableStream<Uint8Array>({
      write(chunk) { chunks.push(chunk); },
      async close() {
        const totalLen = chunks.reduce((a, c) => a + c.length, 0);
        const merged = new Uint8Array(totalLen);
        let offset = 0;
        for (const c of chunks) { merged.set(c, offset); offset += c.length; }
        try {
          const datab64 = encodeBase64(merged);
          const r = await call<UploadResult>(type, 'upload', {
            ref: ref ?? null, name, datab64,
            expectedVersion: options?.expectedVersion ?? null,
          }, handle);
          resolveResult(r);
        } catch (e) { rejectResult(e); }
      },
      abort(reason) { rejectResult(reason); },
    });
    return { stream, result: resultPromise };
  }

  async downloadStream(ref: string): Promise<ReadableStream<Uint8Array>> {
    const { data } = await this.download(ref);
    return new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(data); controller.close(); },
    });
  }

  async list(parentRef?: string): Promise<StorageEntry[]> {
    const handle = this.requireHandle();
    return call<StorageEntry[]>(this.type, 'list', { parentRef: parentRef ?? null }, handle);
  }

  async createFolder(name: string, parentRef?: string): Promise<{ ref: string }> {
    const handle = this.requireHandle();
    return call<{ ref: string }>(this.type, 'createFolder', {
      name, parentRef: parentRef ?? null,
    }, handle);
  }

  async deleteFolder(ref: string): Promise<void> {
    const handle = this.requireHandle();
    await call<null>(this.type, 'deleteFolder', { ref }, handle);
  }

  async createPublicLink(ref: string): Promise<string> {
    const handle = this.requireHandle();
    return call<string>(this.type, 'createPublicLink', { ref }, handle);
  }

  async revokePublicLink(ref: string): Promise<void> {
    const handle = this.requireHandle();
    await call<null>(this.type, 'revokePublicLink', { ref }, handle);
  }

  async createPresignedUrl(ref: string, ttlSeconds: number): Promise<string> {
    const handle = this.requireHandle();
    return call<string>(this.type, 'createPresignedUrl', { ref, ttlSeconds }, handle);
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private requireHandle(): string {
    if (!this.configHandle) {
      throw new ProviderError('PROVIDER_ERROR', `${this.displayName}: not initialized`, this.type);
    }
    return this.configHandle;
  }
}
