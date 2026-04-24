/**
 * In-memory mock StorageProvider for testing.
 *
 * Stores files in memory with version tracking, conflict detection,
 * and streaming support. Used by ByoDataProvider tests (Phase 5)
 * and unit tests for UploadStream/DownloadStream.
 */

import type { StorageProvider, StorageEntry, ProviderConfig, UploadOptions, UploadResult } from '../../../src/lib/sdk/types';
import { ProviderError, ConflictError } from '../../../src/lib/sdk/errors';

export class MockProvider implements StorageProvider {
  readonly type = 'mock' as any;
  readonly displayName = 'Mock Provider';

  private files = new Map<string, { data: Uint8Array; version: string; name: string; mimeType: string }>();
  private folders = new Map<string, Set<string>>();
  private versionCounter = 1;
  private ready = false;

  async init(savedConfig?: ProviderConfig): Promise<void> {
    this.ready = true;
    // Create root WattcloudVault directory
    this.folders.set('/WattcloudVault', new Set());
  }

  isReady(): boolean { return this.ready; }
  async disconnect(): Promise<void> { this.ready = false; }

  getConfig(): ProviderConfig { return { type: 'mock' as any }; }
  async refreshAuth(): Promise<void> { /* no-op for mock */ }

  async upload(ref: string | null, name: string, data: Uint8Array, options?: UploadOptions): Promise<UploadResult> {
    // Conflict detection
    if (ref && options?.expectedVersion) {
      const existing = this.files.get(ref);
      if (existing && existing.version !== options.expectedVersion) {
        throw new ConflictError('mock' as any, existing.version);
      }
    }

    const fileRef = ref || `file_${crypto.randomUUID()}`;
    const version = `v${this.versionCounter++}`;

    this.files.set(fileRef, { data: new Uint8Array(data), version, name, mimeType: options?.mimeType || '' });
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

  manifestRef(): string { return 'WattcloudVault/vault_manifest.sc'; }
  bodyRef(providerId: string): string { return `WattcloudVault/vault_${providerId}.sc`; }
  journalRef(providerId: string): string { return `WattcloudVault/vault_journal_${providerId}.j`; }

  async uploadStream(
    ref: string | null,
    name: string,
    totalSize: number,
    options?: UploadOptions,
  ): Promise<{ stream: WritableStream<Uint8Array>; result: Promise<UploadResult> }> {
    // Buffer all chunks then upload
    const chunks: Uint8Array[] = [];
    const self = this;

    let resolveResult!: (r: UploadResult) => void;
    let rejectResult!: (e: Error) => void;
    const result = new Promise<UploadResult>((res, rej) => {
      resolveResult = res;
      rejectResult = rej;
    });

    const stream = new WritableStream<Uint8Array>({
      write(chunk) {
        chunks.push(chunk);
        options?.onProgress?.(chunks.reduce((s, c) => s + c.length, 0));
      },
      async close() {
        const data = new Uint8Array(chunks.reduce((s, c) => s + c.length, 0));
        let offset = 0;
        for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
        try {
          const uploadResult = await self.upload(ref, name, data, options);
          resolveResult(uploadResult);
        } catch (e) {
          rejectResult(e instanceof Error ? e : new Error(String(e)));
          throw e;
        }
      },
      abort(reason) {
        rejectResult(reason instanceof Error ? reason : new Error(String(reason)));
      },
    });

    return { stream, result };
  }

  async downloadStream(ref: string): Promise<ReadableStream<Uint8Array>> {
    const file = this.files.get(ref);
    if (!file) throw new ProviderError('NOT_FOUND', 'File not found', 'mock' as any);
    const data = file.data;

    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(data));
        controller.close();
      },
    });
  }

  async list(parentRef?: string): Promise<StorageEntry[]> {
    const entries: StorageEntry[] = [];
    for (const [ref, file] of this.files) {
      entries.push({
        ref,
        name: file.name,
        size: file.data.length,
        isFolder: false,
        mimeType: file.mimeType || undefined,
      });
    }
    return entries;
  }

  async createFolder(name: string, parentRef?: string): Promise<{ ref: string }> {
    const ref = parentRef ? `${parentRef}/${name}` : `/WattcloudVault/${name}`;
    this.folders.set(ref, new Set());
    return { ref };
  }

  async deleteFolder(ref: string): Promise<void> {
    this.folders.delete(ref);
  }

  // ── Test helpers ──────────────────────────────────────────────────────

  /** Check if a file exists. */
  hasFile(ref: string): boolean { return this.files.has(ref); }

  /** Get file data for assertions. */
  getFileData(ref: string): Uint8Array | undefined { return this.files.get(ref)?.data; }

  /** Reset all stored data. */
  reset(): void {
    this.files.clear();
    this.folders.clear();
    this.versionCounter = 1;
  }
}