/**
 * In-memory mock StorageProvider for BYO E2E testing.
 *
 * Exposed in the production bundle only when `__BYO_TEST_MODE__` is true
 * (set by vite.config.ts when `BYO_TEST_MODE=true`). Tree-shaking removes it
 * from production builds.
 *
 * Stores files in memory with version tracking and conflict detection.
 */

import type { StorageProvider, StorageEntry, ProviderConfig, UploadOptions, UploadResult } from '../types';
import { ProviderError, ConflictError } from '../errors';

export class MockProvider implements StorageProvider {
  readonly type = 'mock' as any;
  readonly displayName = 'Test Storage';

  private files = new Map<string, { data: Uint8Array; version: string; name: string; mimeType: string }>();
  private folders = new Map<string, Set<string>>();
  private versionCounter = 1;
  private ready = false;

  async init(_savedConfig?: ProviderConfig): Promise<void> {
    this.ready = true;
    this.folders.set('SecureCloud', new Set());
  }

  isReady(): boolean { return this.ready; }
  async disconnect(): Promise<void> { this.ready = false; }
  getConfig(): ProviderConfig { return { type: 'mock' as any }; }
  async refreshAuth(): Promise<void> { /* no-op */ }

  async upload(ref: string | null, name: string, data: Uint8Array, options?: UploadOptions): Promise<UploadResult> {
    if (ref && options?.expectedVersion) {
      const existing = this.files.get(ref);
      if (existing && existing.version !== options.expectedVersion) {
        throw new ConflictError('mock' as any, existing.version);
      }
    }
    const fileRef = ref ?? `SecureCloud/${name}`;
    const version = `v${this.versionCounter++}`;
    this.files.set(fileRef, { data: new Uint8Array(data), version, name, mimeType: options?.mimeType ?? '' });
    return { ref: fileRef, version };
  }

  async download(ref: string): Promise<{ data: Uint8Array; version: string }> {
    const file = this.files.get(ref);
    if (!file) throw new ProviderError('NOT_FOUND', 'File not found', 'mock' as any);
    return { data: new Uint8Array(file.data), version: file.version };
  }

  async delete(ref: string): Promise<void> {
    this.files.delete(ref);
  }

  async getVersion(ref: string): Promise<string> {
    const file = this.files.get(ref);
    if (!file) throw new ProviderError('NOT_FOUND', 'File not found', 'mock' as any);
    return file.version;
  }

  async uploadStream(
    ref: string | null,
    name: string,
    _totalSize: number,
    options?: UploadOptions,
  ): Promise<{ stream: WritableStream<Uint8Array>; result: Promise<UploadResult> }> {
    const chunks: Uint8Array[] = [];
    const self = this;
    let resolveResult!: (r: UploadResult) => void;
    let rejectResult!: (e: Error) => void;
    const result = new Promise<UploadResult>((res, rej) => { resolveResult = res; rejectResult = rej; });

    const stream = new WritableStream<Uint8Array>({
      write(chunk) { chunks.push(chunk); },
      async close() {
        const total = chunks.reduce((s, c) => s + c.length, 0);
        const data = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
        try {
          resolveResult(await self.upload(ref, name, data, options));
        } catch (e) {
          rejectResult(e instanceof Error ? e : new Error(String(e)));
          throw e;
        }
      },
      abort(reason) { rejectResult(reason instanceof Error ? reason : new Error(String(reason))); },
    });

    return { stream, result };
  }

  async downloadStream(ref: string): Promise<ReadableStream<Uint8Array>> {
    const file = this.files.get(ref);
    if (!file) throw new ProviderError('NOT_FOUND', 'File not found', 'mock' as any);
    const data = file.data;
    return new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(data)); controller.close(); },
    });
  }

  async list(_parentRef?: string): Promise<StorageEntry[]> {
    return [...this.files.entries()].map(([ref, file]) => ({
      ref,
      name: file.name,
      size: file.data.length,
      isFolder: false,
      mimeType: file.mimeType || undefined,
    }));
  }

  async createFolder(name: string, parentRef?: string): Promise<{ ref: string }> {
    const ref = parentRef ? `${parentRef}/${name}` : `SecureCloud/${name}`;
    this.folders.set(ref, new Set());
    return { ref };
  }

  async deleteFolder(ref: string): Promise<void> {
    this.folders.delete(ref);
  }

  hasFile(ref: string): boolean { return this.files.has(ref); }
  getFileData(ref: string): Uint8Array | undefined { return this.files.get(ref)?.data; }
  reset(): void { this.files.clear(); this.folders.clear(); this.versionCounter = 1; }

  async createPublicLink(ref: string): Promise<string> {
    return `mock://public/${ref}`;
  }
  async revokePublicLink(_ref: string): Promise<void> {}
  async createPresignedUrl(ref: string, ttlSeconds: number): Promise<string> {
    return `mock://presigned/${ref}?ttl=${ttlSeconds}`;
  }
}
