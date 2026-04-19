/**
 * BYO streaming download adapter.
 *
 * When the provider is WASM-backed (has a configHandle), uses the Phase 3d
 * provider-integrated session: ciphertext is read and decrypted inside WASM —
 * only plaintext crosses the JS boundary.
 *
 * Falls back to the Phase 2 flow (ByoDownloadFlow + provider.downloadStream)
 * for SFTP and other non-WASM providers.
 *
 * Security: content_key, HMAC state, and file_iv never leave the WASM heap.
 * SECURITY: callers MUST check that finalize/close completes without error before
 * trusting any yielded plaintext — the HMAC footer guards against truncation.
 */

import type { StorageProvider } from '../types';
import * as Worker from '../worker/byoWorkerClient';
import { recordEvent, classifyErr } from '../stats/StatsClient';

export class ByoDownloadStream {
  /**
   * Download ciphertext from the provider and stream-decrypt through V7.
   *
   * Yields plaintext chunks. After the generator completes normally, the HMAC
   * footer has been verified. If the generator throws, all yielded data is suspect.
   */
  static async *decrypt(
    provider: StorageProvider,
    ref: string,
    secKeysJson: string,
    signal?: AbortSignal,
    byoKeySessionId?: string,
  ): AsyncGenerator<Uint8Array, void, undefined> {
    await Worker.initByoWorker();

    const configHandle =
      (provider as { getConfigHandle?(): string | null }).getConfigHandle?.() ?? null;

    if (configHandle) {
      yield* ByoDownloadStream.decryptWasm(provider, ref, secKeysJson, configHandle, signal);
    } else {
      yield* ByoDownloadStream.decryptLegacy(provider, ref, secKeysJson, signal, byoKeySessionId);
    }
  }

  /**
   * Phase 3d: ciphertext read and decrypted inside WASM.
   * Only plaintext crosses the WASM/JS boundary.
   */
  private static async *decryptWasm(
    provider: StorageProvider,
    ref: string,
    secKeysJson: string,
    configHandle: string,
    signal?: AbortSignal,
  ): AsyncGenerator<Uint8Array, void, undefined> {
    let sessionId: string | null = null;

    try {
      sessionId = await Worker.byoStreamDownloadInit(
        secKeysJson,
        provider.type,
        configHandle,
        ref,
      );

      let ciphertextBytes = 0;
      while (true) {
        if (signal?.aborted) throw new DOMException('Download aborted', 'AbortError');

        const chunk = await Worker.byoStreamDownloadPull(sessionId);
        if (chunk === null) break;

        // chunk is a Uint8Array; may be empty during the 1709-byte header phase.
        if (chunk instanceof Uint8Array && chunk.length > 0) {
          ciphertextBytes += chunk.length;
          yield chunk;
        }
      }

      // Verify HMAC footer — throws on mismatch. Drops the decryptor (ZeroizeOnDrop).
      await Worker.byoStreamDownloadClose(sessionId);
      sessionId = null;
      recordEvent('download', { provider_type: provider.type, bytes: ciphertextBytes });
    } catch (error) {
      if (sessionId) {
        // Close on error path — best-effort, don't surface secondary failure.
        await Worker.byoStreamDownloadClose(sessionId).catch(() => {});
        sessionId = null;
      }
      recordEvent('error', { provider_type: provider.type, error_class: classifyErr(error) });
      throw error;
    }
  }

  /**
   * Legacy path (Phase 2): ByoDownloadFlow + provider.downloadStream shim.
   * Used for SFTP and other non-WASM-backed providers.
   *
   * Note: secKeysJson is accepted for API compatibility; keys are resolved
   * from the worker-side key registry via byoKeySessionId (or sessionId fallback).
   */
  private static async *decryptLegacy(
    provider: StorageProvider,
    ref: string,
    secKeysJson: string,
    signal?: AbortSignal,
    byoKeySessionId?: string,
  ): AsyncGenerator<Uint8Array, void, undefined> {
    const readable = await provider.downloadStream(ref);
    const reader = readable.getReader();

    const sessionId = crypto.randomUUID();
    let sessionOpen = false;
    let ciphertextBytes = 0;

    try {
      await Worker.byoDownloadFlowInit(sessionId, byoKeySessionId);
      sessionOpen = true;

      while (true) {
        if (signal?.aborted) throw new DOMException('Download aborted', 'AbortError');

        const { value, done } = await reader.read();
        if (done) break;

        // Cast to ArrayBuffer: provider.downloadStream() never yields SharedArrayBuffer-backed
        // Uint8Arrays; the cast is safe and resolves the TS2345 ArrayBufferLike mismatch.
        const tightBuf = (value.byteOffset === 0 && value.byteLength === value.buffer.byteLength
          ? value.buffer
          : value.slice().buffer) as ArrayBuffer;
        ciphertextBytes += value.byteLength;
        const ptBuf = await Worker.byoDownloadFlowPush(sessionId, tightBuf);
        const plaintext = new Uint8Array(ptBuf);
        if (plaintext.length > 0) yield plaintext;
      }

      await Worker.byoDownloadFlowFinalize(sessionId);
      sessionOpen = false;
      recordEvent('download', { provider_type: provider.type, bytes: ciphertextBytes });
    } catch (error) {
      if (sessionOpen) {
        await Worker.byoDownloadFlowAbort(sessionId).catch(() => {});
      }
      recordEvent('error', { provider_type: provider.type, error_class: classifyErr(error) });
      throw error;
    } finally {
      // If we didn't reach finalize (consumer stopped iterating, abort signal,
      // or exception), cancel the underlying fetch so RangedDownloadBuffer
      // stops issuing Range requests and the source connection is released.
      if (sessionOpen) {
        await reader.cancel().catch(() => {});
      }
      reader.releaseLock();
    }
  }

  /**
   * Convenience: download and decrypt a complete file to a Uint8Array.
   * Use for vault body downloads where streaming isn't needed.
   */
  static async downloadComplete(
    provider: StorageProvider,
    ref: string,
    secKeysJson: string,
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let totalLength = 0;

    for await (const chunk of ByoDownloadStream.decrypt(provider, ref, secKeysJson, signal)) {
      chunks.push(chunk);
      totalLength += chunk.length;
    }

    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }
}
