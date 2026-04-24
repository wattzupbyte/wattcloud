/**
 * DownloadStream tests (Phase 2 — ByoDownloadFlow API).
 *
 * Verifies the thin driver in ByoDownloadStream.decrypt():
 * - Initialises the flow with the correct key session.
 * - Feeds all raw ciphertext bytes through byoDownloadFlowPush.
 * - Yields all non-empty plaintext returned by push.
 * - Calls byoDownloadFlowFinalize after the stream ends.
 * - Calls byoDownloadFlowAbort on error (so the worker cleans up key state).
 *
 * Header buffering, footer trimming, and HMAC verification are all internal
 * to the ByoDownloadFlow WASM state machine and are tested by sdk-core unit
 * tests — this file only tests the TS driver logic.
 *
 * The byoWorkerClient is fully mocked — WASM cannot run in Node.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ByoDownloadStream } from '../../src/lib/sdk/streaming/DownloadStream';

// ── Worker mock ───────────────────────────────────────────────────────────────

const mockInit = vi.fn<[string, string | undefined], Promise<void>>();
const mockPush = vi.fn<[string, ArrayBuffer], Promise<ArrayBuffer>>();
const mockFinalize = vi.fn<[string], Promise<void>>();
const mockAbort = vi.fn<[string], Promise<void>>();

vi.mock('../../src/lib/sdk/worker/byoWorkerClient', () => ({
  initByoWorker: vi.fn(() => Promise.resolve()),
  byoDownloadFlowInit: (...args: [string, string | undefined]) => mockInit(...args),
  byoDownloadFlowPush: (...args: [string, ArrayBuffer]) => mockPush(...args),
  byoDownloadFlowFinalize: (...args: [string]) => mockFinalize(...args),
  byoDownloadFlowAbort: (...args: [string]) => mockAbort(...args),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build a provider that streams the given data split into chunks. */
function makeStreamProvider(data: Uint8Array, splits?: number[]): any {
  return {
    isReady: () => true,
    downloadStream: async () => {
      const chunks: Uint8Array[] = [];
      if (splits) {
        let offset = 0;
        for (const size of splits) {
          if (size > 0) chunks.push(data.slice(offset, offset + size));
          offset += size;
        }
        if (offset < data.length) chunks.push(data.slice(offset));
      } else {
        chunks.push(data);
      }

      let i = 0;
      return new ReadableStream<Uint8Array>({
        pull(controller) {
          if (i < chunks.length) controller.enqueue(chunks[i++]);
          else controller.close();
        },
      });
    },
  };
}

/** Collect all chunks yielded by the async generator. */
async function collectAll(gen: AsyncGenerator<Uint8Array>): Promise<Uint8Array[]> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of gen) chunks.push(chunk);
  return chunks;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('ByoDownloadStream.decrypt()', () => {
  beforeEach(() => {
    mockInit.mockClear().mockResolvedValue(undefined);
    // By default, push echoes the input back as plaintext (identity mock).
    mockPush.mockClear().mockImplementation((_sid, data) =>
      Promise.resolve(data),
    );
    mockFinalize.mockClear().mockResolvedValue(undefined);
    mockAbort.mockClear().mockResolvedValue(undefined);
  });

  describe('normal flow', () => {
    it('yields all plaintext returned by byoDownloadFlowPush', async () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const provider = makeStreamProvider(data);

      const chunks = await collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}'));

      // The mock echoes the input, so we should see the data back.
      const combined = new Uint8Array(chunks.reduce((s, c) => s + c.length, 0));
      let off = 0;
      for (const c of chunks) { combined.set(c, off); off += c.length; }
      expect(Array.from(combined)).toEqual(Array.from(data));
    });

    it('calls byoDownloadFlowFinalize after the stream ends', async () => {
      const data = new Uint8Array(100).fill(0xab);
      const provider = makeStreamProvider(data);

      await collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}'));

      expect(mockFinalize).toHaveBeenCalledOnce();
    });

    it('does not call abort on success', async () => {
      const data = new Uint8Array(50);
      const provider = makeStreamProvider(data);

      await collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}'));

      expect(mockAbort).not.toHaveBeenCalled();
    });

    it('skips empty push results (does not yield empty chunks)', async () => {
      // Make push return empty for some chunks.
      let call = 0;
      mockPush.mockImplementation((_sid, data) => {
        call++;
        if (call % 2 === 0) return Promise.resolve(new ArrayBuffer(0));
        return Promise.resolve(data);
      });

      const data = new Uint8Array([10, 20, 30, 40, 50]);
      const provider = makeStreamProvider(data, [2, 2, 1]);

      const chunks = await collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}'));

      // All yielded chunks must be non-empty.
      expect(chunks.every(c => c.length > 0)).toBe(true);
    });

    it('passes byoKeySessionId to byoDownloadFlowInit', async () => {
      const data = new Uint8Array(10);
      const provider = makeStreamProvider(data);

      await collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}', undefined, 'key-session-abc'));

      expect(mockInit).toHaveBeenCalledOnce();
      const [, keySessionId] = mockInit.mock.calls[0];
      expect(keySessionId).toBe('key-session-abc');
    });
  });

  describe('error handling', () => {
    it('throws and calls abort when byoDownloadFlowPush throws', async () => {
      mockPush.mockRejectedValueOnce(new Error('Worker push failed'));

      const data = new Uint8Array(50).fill(0xff);
      const provider = makeStreamProvider(data);

      await expect(
        collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}')),
      ).rejects.toThrow('Worker push failed');

      expect(mockAbort).toHaveBeenCalledOnce();
    });

    it('throws when byoDownloadFlowFinalize throws (HMAC failure)', async () => {
      mockFinalize.mockRejectedValueOnce(new Error('MAC verification failed'));

      const data = new Uint8Array(50).fill(0xab);
      const provider = makeStreamProvider(data);

      await expect(
        collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}')),
      ).rejects.toThrow('MAC verification failed');

      expect(mockAbort).toHaveBeenCalledOnce();
    });
  });

  describe('abort signal', () => {
    it('throws AbortError when signal is already aborted', async () => {
      // Provider that never closes — signal should fire first.
      const provider = {
        isReady: () => true,
        downloadStream: async () =>
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(new Uint8Array(10));
              // Deliberately never closes.
            },
          }),
      };

      const controller = new AbortController();
      controller.abort();

      await expect(
        collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}', controller.signal)),
      ).rejects.toThrow(/aborted/i);
    });
  });

  describe('regression guards', () => {
    it('C2: passes a tight buffer even when reader yields a sub-view (byteOffset > 0)', async () => {
      // Simulates a BYOB reader or provider shim that yields a Uint8Array view
      // whose byteOffset > 0 or byteLength < buffer.byteLength.  The driver must
      // pass only the valid slice bytes to the worker, not the entire underlying
      // ArrayBuffer.
      const underlying = new ArrayBuffer(20);
      // Fill underlying: bytes 0-4 are garbage; bytes 5-14 are the real ciphertext.
      const view = new Uint8Array(underlying, 5, 10);
      view.fill(0xaa);

      const capturedBuffers: ArrayBuffer[] = [];
      mockPush.mockImplementation((_sid, data) => {
        capturedBuffers.push(data);
        return Promise.resolve(new ArrayBuffer(0));
      });

      const provider: any = {
        isReady: () => true,
        downloadStream: async () => {
          let done = false;
          return new ReadableStream<Uint8Array>({
            pull(controller) {
              if (!done) {
                // Enqueue a sub-view: byteOffset=5, byteLength=10.
                controller.enqueue(view);
                done = true;
              } else {
                controller.close();
              }
            },
          });
        },
      };

      await collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}')).catch(() => {});

      expect(capturedBuffers.length).toBeGreaterThan(0);
      for (const buf of capturedBuffers) {
        // The driver must produce a tight buffer: byteLength must equal the
        // Uint8Array view length (10), not the underlying buffer size (20).
        expect(buf.byteLength).toBe(10);
      }
    });

    it('C1: byoDownloadFlowPush mock matches real worker protocol (returns ArrayBuffer)', async () => {
      // The real worker returns { plaintext: ArrayBuffer } and the client
      // unwraps it to ArrayBuffer. This test verifies the mock (direct ArrayBuffer)
      // is the value the driver receives — preventing mock/real shape drift.
      const data = new Uint8Array([0x07, 0x08]);
      const provider = makeStreamProvider(data);

      // Override push to return a wrapper (simulating the unwrap in byoWorkerClient).
      const pt = new Uint8Array([0x42]).buffer;
      mockPush.mockResolvedValueOnce(pt);

      const chunks = await collectAll(ByoDownloadStream.decrypt(provider, 'ref', '{}'));

      // Driver must have called new Uint8Array(ArrayBuffer), not new Uint8Array({plaintext: ...})
      // If the shape were wrong, chunks would be empty even though mock resolved.
      expect(chunks.length).toBeGreaterThan(0);
      expect(chunks[0][0]).toBe(0x42);
    });
  });
});
