/**
 * BYO streaming upload adapter.
 *
 * When the provider is WASM-backed (has a configHandle), uses the Phase 3d
 * provider-integrated session: each push call encrypts and writes the cipher
 * frame directly to the provider inside WASM — ciphertext never crosses the
 * JS boundary.
 *
 * Falls back to the Phase 2 flow (ByoUploadFlow + provider.uploadStream) for
 * SFTP and any other non-WASM provider.
 *
 * Security: content_key, HMAC state, and file_iv never leave the WASM heap.
 * Memory: at most one plaintext chunk (V7_ENCRYPT_CHUNK_SIZE = 512 KiB) + one
 *   provider chunk in flight in WASM. No cipher frames in the JS heap.
 */

import type { StorageProvider, UploadOptions, UploadResult } from '../types';
import * as Worker from '../worker/byoWorkerClient';
import { recordEvent, classifyErr } from '../stats/StatsClient';

export class ByoUploadStream {
  static async upload(
    provider: StorageProvider,
    file: File,
    parentRef: string | null,
    publicKeysJson: string,
    options?: {
      onProgress?: (pct: number) => void;
      pauseSignal?: { isPaused(): boolean; wait(): Promise<void> };
    },
  ): Promise<UploadResult> {
    await Worker.initByoWorker();

    // Use Phase 3d (WASM-integrated) when the provider has a configHandle.
    const configHandle =
      (provider as { getConfigHandle?(): string | null }).getConfigHandle?.() ?? null;

    if (configHandle) {
      return ByoUploadStream.uploadWasm(
        provider, file, parentRef, publicKeysJson, configHandle, options);
    }
    return ByoUploadStream.uploadLegacy(
      provider, file, parentRef, publicKeysJson, options);
  }

  /**
   * Phase 3d: cipher frames written directly to provider inside WASM.
   * Peak JS heap: one 512 KiB plaintext chunk. No cipher bytes in JS.
   */
  private static async uploadWasm(
    provider: StorageProvider,
    file: File,
    parentRef: string | null,
    publicKeysJson: string,
    configHandle: string,
    options?: {
      onProgress?: (pct: number) => void;
      pauseSignal?: { isPaused(): boolean; wait(): Promise<void> };
    },
  ): Promise<UploadResult> {
    let sessionId: string | null = null;

    try {
      // ZK-6: pass an opaque UUID blob name — never the user's plaintext filename.
      // The encrypted filename is stored separately in the vault DB (encrypted_filename).
      const blobName = crypto.randomUUID();
      const { sessionId: sid, chunkSize } = await Worker.byoStreamUploadInit(
        publicKeysJson,
        provider.type,
        configHandle,
        blobName,
        parentRef,
        file.size,
      );
      sessionId = sid;

      const totalChunks = Math.ceil(file.size / chunkSize) || 0;
      for (let i = 0; i < totalChunks; i++) {
        if (options?.pauseSignal?.isPaused()) {
          await options.pauseSignal.wait();
        }

        const start = i * chunkSize;
        const end = Math.min(start + chunkSize, file.size);
        const isLast = end === file.size;
        const plaintext = await file.slice(start, end).arrayBuffer();

        // Transfer plaintext to WASM (zero-copy). Cipher frame stays inside WASM.
        await Worker.byoStreamUploadPush(sessionId, plaintext, isLast);

        options?.onProgress?.((end / file.size));
      }

      const result = await Worker.byoStreamUploadFinalize(sessionId);
      sessionId = null;
      recordEvent('upload', { provider_type: provider.type, bytes: file.size });
      return result;
    } catch (error) {
      if (sessionId) {
        await Worker.byoStreamUploadAbort(sessionId).catch(() => {});
      }
      recordEvent('error', { provider_type: provider.type, error_class: classifyErr(error) });
      throw error;
    }
  }

  /**
   * Legacy path (Phase 2): ByoUploadFlow + provider.uploadStream shim.
   * Used for SFTP and any non-WASM-backed providers.
   */
  private static async uploadLegacy(
    provider: StorageProvider,
    file: File,
    parentRef: string | null,
    publicKeysJson: string,
    options?: {
      onProgress?: (pct: number) => void;
      pauseSignal?: { isPaused(): boolean; wait(): Promise<void> };
    },
  ): Promise<UploadResult> {
    let sessionId: string | null = crypto.randomUUID();

    try {
      const { header, totalSize, chunkSize } = await Worker.byoUploadFlowInit(
        sessionId,
        publicKeysJson,
        file.size,
      );

      const uploadOptions: UploadOptions | undefined = parentRef
        ? { parentRef, onProgress: options?.onProgress }
        : options?.onProgress
          ? { onProgress: options.onProgress }
          : undefined;

      // ZK-6: use an opaque UUID blob name — never the user's plaintext filename.
      // The encrypted filename is stored separately in the vault DB (encrypted_filename).
      const blobName = crypto.randomUUID();
      const { stream: writable, result: uploadResult } = await provider.uploadStream(
        null,
        blobName,
        totalSize,
        uploadOptions,
      );
      const writer = writable.getWriter();

      try {
        await writer.write(new Uint8Array(header));

        const totalChunks = Math.ceil(file.size / chunkSize) || 0;
        for (let i = 0; i < totalChunks; i++) {
          if (options?.pauseSignal?.isPaused()) {
            await options.pauseSignal.wait();
          }

          const start = i * chunkSize;
          const end = Math.min(start + chunkSize, file.size);
          const isLast = end === file.size;
          const plaintext = await file.slice(start, end).arrayBuffer();
          const frame = await Worker.byoUploadFlowPush(sessionId!, plaintext, isLast);
          await writer.write(new Uint8Array(frame));
        }

        const footer = await Worker.byoUploadFlowFinalize(sessionId!);
        sessionId = null;
        await writer.write(new Uint8Array(footer));
        await writer.close();
      } catch (e) {
        if (sessionId) {
          await Worker.byoUploadFlowAbort(sessionId).catch(() => {});
          sessionId = null;
        }
        uploadResult.catch(() => {});
        await writer.abort(e);
        throw e;
      }

      const result = await uploadResult;
      recordEvent('upload', { provider_type: provider.type, bytes: totalSize });
      return result;
    } catch (error) {
      if (sessionId) {
        await Worker.byoUploadFlowAbort(sessionId).catch(() => {});
      }
      recordEvent('error', { provider_type: provider.type, error_class: classifyErr(error) });
      throw error;
    }
  }
}
