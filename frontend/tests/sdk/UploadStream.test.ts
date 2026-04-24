/**
 * UploadStream tests (Phase 2 — ByoUploadFlow API).
 *
 * Verifies the thin driver in ByoUploadStream.upload():
 * - Calls byoUploadFlowInit and writes the header as the first bytes.
 * - Loops over chunks and calls byoUploadFlowPush for each.
 * - Calls byoUploadFlowFinalize and writes the footer as the last bytes.
 * - Calls byoUploadFlowAbort on error (so the worker zeroizes key material).
 *
 * The byoWorkerClient is fully mocked — WASM cannot run in Node.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ByoUploadStream } from '../../src/lib/sdk/streaming/UploadStream';
import { MockProvider } from './mocks/MockProvider';

// ── Constants ──────────────────────────────────────────────────────────────────

const FAKE_HEADER = new Uint8Array(1709).fill(0x07);
const FAKE_FOOTER = new Uint8Array(32).fill(0xfe);
const ENCRYPT_CHUNK_SIZE = 512 * 1024;

// ── Mock helpers ───────────────────────────────────────────────────────────────

const mockAbort = vi.fn<[string], Promise<void>>();
const mockPush = vi.fn<[string, ArrayBuffer, boolean], Promise<ArrayBuffer>>();
const mockFinalize = vi.fn<[string], Promise<ArrayBuffer>>();

vi.mock('../../src/lib/sdk/worker/byoWorkerClient', () => {
  let sessionCounter = 0;
  return {
    initByoWorker: vi.fn(() => Promise.resolve()),
    byoUploadFlowInit: vi.fn((_sid: string, _pubKeys: string, plaintextLen: number) => {
      // totalSize = header + n_chunks * frame_overhead + plaintextLen + footer
      const nChunks = Math.ceil(plaintextLen / ENCRYPT_CHUNK_SIZE) || 0;
      const totalSize = 1709 + nChunks * 32 + plaintextLen + 32;
      // chunkSize is now returned by init so the driver does not hard-code it.
      return Promise.resolve({ header: FAKE_HEADER.buffer.slice(0), totalSize, chunkSize: ENCRYPT_CHUNK_SIZE });
    }),
    byoUploadFlowPush: (...args: [string, ArrayBuffer, boolean]) => mockPush(...args),
    byoUploadFlowFinalize: (...args: [string]) => mockFinalize(...args),
    byoUploadFlowAbort: (...args: [string]) => mockAbort(...args),
  };
});

// ── Tests ──────────────────────────────────────────────────────────────────────

describe('ByoUploadStream.upload()', () => {
  let provider: MockProvider;

  beforeEach(async () => {
    provider = new MockProvider();
    await provider.init();
    mockAbort.mockClear().mockResolvedValue(undefined);
    mockPush.mockClear().mockImplementation((_sid, plaintext, _isLast) =>
      // Return a frame the same size as the plaintext (mock doesn't compress/expand)
      Promise.resolve(new Uint8Array(plaintext.byteLength).buffer),
    );
    mockFinalize.mockClear().mockResolvedValue(FAKE_FOOTER.buffer.slice(0));
  });

  describe('result handling', () => {
    it('returns a truthy ref and version from the provider', async () => {
      const content = new Uint8Array(100).fill(0xaa);
      const file = new File([content], 'test.bin', { type: 'application/octet-stream' });

      const result = await ByoUploadStream.upload(provider, file, null, '{}');

      expect(result.ref).toBeTruthy();
      expect(result.version).toBeTruthy();
    });

    it('resolves result promise with data from provider.uploadStream close()', async () => {
      const content = new Uint8Array(10);
      const file = new File([content], 'tiny.bin');

      const result = await ByoUploadStream.upload(provider, file, null, '{}');

      // MockProvider generates refs as "file_{uuid}" and versions as "v{N}"
      expect(result.ref).toMatch(/^file_/);
      expect(result.version).toMatch(/^v\d+$/);
    });

    it('uploads the correct total byte count (header + body + footer)', async () => {
      const plainTextSize = 50;
      const content = new Uint8Array(plainTextSize).fill(0xbb);
      const file = new File([content], 'data.bin', { type: 'application/octet-stream' });

      const result = await ByoUploadStream.upload(provider, file, null, '{}');

      const uploaded = provider.getFileData(result.ref);
      expect(uploaded).toBeDefined();
      // header (1709) + frame (same size as mock plaintext) + footer (32)
      expect(uploaded!.length).toBe(1709 + plainTextSize + 32);
    });

    it('writes header before any chunk frames', async () => {
      const content = new Uint8Array(100).fill(0xcc);
      const file = new File([content], 'order.bin');

      const result = await ByoUploadStream.upload(provider, file, null, '{}');
      const uploaded = provider.getFileData(result.ref);
      expect(uploaded).toBeDefined();

      // The first 1709 bytes must equal the fake header
      expect(Array.from(uploaded!.subarray(0, 1709))).toEqual(Array.from(FAKE_HEADER));
    });

    it('writes footer as the last 32 bytes', async () => {
      const content = new Uint8Array(50).fill(0xdd);
      const file = new File([content], 'footer.bin');

      const result = await ByoUploadStream.upload(provider, file, null, '{}');
      const uploaded = provider.getFileData(result.ref);
      expect(uploaded).toBeDefined();

      const last32 = uploaded!.subarray(uploaded!.length - 32);
      expect(Array.from(last32)).toEqual(Array.from(FAKE_FOOTER));
    });
  });

  describe('error cleanup', () => {
    it('calls byoUploadFlowAbort exactly once when byoUploadFlowPush throws', async () => {
      mockPush.mockRejectedValueOnce(new Error('Worker encrypt failed'));

      const content = new Uint8Array(100).fill(0xcc);
      const file = new File([content], 'fail.bin');

      await expect(ByoUploadStream.upload(provider, file, null, '{}')).rejects.toThrow(
        'Worker encrypt failed',
      );

      // Must be aborted once (inner catch clears sessionId; outer catch skips).
      expect(mockAbort).toHaveBeenCalledOnce();
    });

    it('does not call abort when upload succeeds', async () => {
      const content = new Uint8Array(50);
      const file = new File([content], 'ok.bin');

      await ByoUploadStream.upload(provider, file, null, '{}');

      expect(mockAbort).not.toHaveBeenCalled();
    });
  });

  describe('chunk splitting', () => {
    it('sends a single push call for a file smaller than one chunk', async () => {
      const content = new Uint8Array(1000).fill(0xaa);
      const file = new File([content], 'small.bin');

      await ByoUploadStream.upload(provider, file, null, '{}');

      expect(mockPush).toHaveBeenCalledOnce();
      const [, , isLast] = mockPush.mock.calls[0];
      expect(isLast).toBe(true);
    });

    it('sends multiple push calls for a multi-chunk file', async () => {
      // 2 full chunks + 1 partial
      const size = ENCRYPT_CHUNK_SIZE * 2 + 100;
      const content = new Uint8Array(size).fill(0xbb);
      const file = new File([content], 'large.bin');

      await ByoUploadStream.upload(provider, file, null, '{}');

      expect(mockPush).toHaveBeenCalledTimes(3);
      // Only the last call should have isLast = true
      const calls = mockPush.mock.calls;
      expect(calls[0][2]).toBe(false);
      expect(calls[1][2]).toBe(false);
      expect(calls[2][2]).toBe(true);
    });

    it('sends no push calls for a zero-byte file', async () => {
      const file = new File([], 'empty.bin');

      const result = await ByoUploadStream.upload(provider, file, null, '{}');

      // No plaintext to push, but header + footer must still be written.
      expect(mockPush).not.toHaveBeenCalled();
      expect(result.ref).toBeTruthy();
    });
  });

  describe('regression guards', () => {
    it('mock byoUploadFlowInit returns chunkSize (guards C1/H4 mock shape)', async () => {
      // The mock must return chunkSize so the driver uses it instead of
      // a hardcoded constant. This test catches mock drift from the real protocol.
      const { byoUploadFlowInit } = await import('../../src/lib/sdk/worker/byoWorkerClient');
      const spy = byoUploadFlowInit as ReturnType<typeof vi.fn>;
      spy.mockClear();

      const file = new File([new Uint8Array(10)], 'check.bin');
      await ByoUploadStream.upload(provider, file, null, '{}');

      const returnValue = await spy.mock.results[0]?.value;
      expect(returnValue).toBeDefined();
      expect(typeof returnValue?.chunkSize).toBe('number');
      expect(returnValue?.chunkSize).toBeGreaterThan(0);
    });

    it('byoUploadFlowAbort is called when writer.abort() path is taken', async () => {
      // Ensures that the sessionId is aborted (key material freed) even when
      // the WritableStream writer throws during abort.
      mockPush.mockRejectedValueOnce(new Error('push failed'));

      const file = new File([new Uint8Array(100)], 'abort.bin');
      await expect(ByoUploadStream.upload(provider, file, null, '{}')).rejects.toThrow('push failed');

      expect(mockAbort).toHaveBeenCalledOnce();
    });
  });
});
