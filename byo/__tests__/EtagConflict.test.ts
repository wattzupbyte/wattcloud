/**
 * ETag / conflict parity tests for WasmStorageProviderShim.
 *
 * Verifies that:
 * - upload() with a matching expectedVersion succeeds and returns version
 * - upload() with a stale expectedVersion throws ConflictError
 * - uploadStream() propagates ConflictError from close()
 * - getVersion() returns the string from byoProviderCall("getVersion")
 * - ConflictError is thrown for HTTP 409 and HTTP 412 responses
 *
 * byoWorkerClient is fully mocked — WASM cannot run in Node.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WasmStorageProviderShim } from '../src/providers/WasmStorageProviderShim';
import { ConflictError, UnauthorizedError } from '../src/errors';

// ── Worker mock ───────────────────────────────────────────────────────────────

const mockByoProviderCall = vi.fn<[string, string, string, string], Promise<unknown>>();
const mockByoInitConfig = vi.fn<[string], Promise<string>>();
const mockByoReleaseConfig = vi.fn<[string], Promise<void>>();

vi.mock('../src/worker/byoWorkerClient', () => ({
  byoProviderCall: (...args: [string, string, string, string]) => mockByoProviderCall(...args),
  byoInitConfig: (...args: [string]) => mockByoInitConfig(...args),
  byoReleaseConfig: (...args: [string]) => mockByoReleaseConfig(...args),
  byoRefreshConfigByHandle: vi.fn(),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build a shim that is already initialized (configHandle stored). */
async function makeShim(type = 'gdrive'): Promise<WasmStorageProviderShim> {
  mockByoInitConfig.mockResolvedValueOnce('handle-abc');
  const shim = new WasmStorageProviderShim(type as any);
  await shim.init({ type: type as any });
  return shim;
}

const SMALL_DATA = new Uint8Array([1, 2, 3, 4, 5]);

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('ETag / conflict — upload()', () => {
  beforeEach(() => {
    mockByoProviderCall.mockClear();
    mockByoInitConfig.mockClear();
    mockByoReleaseConfig.mockClear();
  });

  it('succeeds and returns version from provider when no expectedVersion', async () => {
    mockByoInitConfig.mockResolvedValueOnce('h1');
    const shim = new WasmStorageProviderShim('dropbox');
    await shim.init({ type: 'dropbox' });

    mockByoProviderCall.mockResolvedValueOnce({ ref: 'vault/f.bin', version: 'etag-v1' });
    const result = await shim.upload(null, 'f.bin', SMALL_DATA);

    expect(result.ref).toBe('vault/f.bin');
    expect(result.version).toBe('etag-v1');
  });

  it('passes expectedVersion to byoProviderCall', async () => {
    const shim = await makeShim('s3');
    mockByoProviderCall.mockResolvedValueOnce({ ref: 'obj/f.bin', version: 'etag-v2' });

    await shim.upload('obj/f.bin', 'f.bin', SMALL_DATA, { expectedVersion: 'etag-v1' });

    const [, op, , argsJson] = mockByoProviderCall.mock.calls[0];
    expect(op).toBe('upload');
    const args = JSON.parse(argsJson);
    expect(args.expectedVersion).toBe('etag-v1');
  });

  it('throws ConflictError when provider returns HTTP 409', async () => {
    const shim = await makeShim('gdrive');
    mockByoProviderCall.mockRejectedValueOnce(new Error('HTTP 409 Conflict'));

    await expect(
      shim.upload('file/ref', 'file.bin', SMALL_DATA, { expectedVersion: 'stale-etag' }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('throws ConflictError when provider returns HTTP 412', async () => {
    const shim = await makeShim('webdav');
    mockByoProviderCall.mockRejectedValueOnce(new Error('HTTP 412 Precondition Failed'));

    await expect(
      shim.upload('file/ref', 'file.bin', SMALL_DATA, { expectedVersion: 'stale-etag' }),
    ).rejects.toBeInstanceOf(ConflictError);
  });

  it('throws ConflictError when provider response contains "Conflict"', async () => {
    const shim = await makeShim('onedrive');
    mockByoProviderCall.mockRejectedValueOnce(new Error('Conflict: ETag mismatch'));

    await expect(shim.upload(null, 'f.bin', SMALL_DATA)).rejects.toBeInstanceOf(ConflictError);
  });

  it('throws UnauthorizedError on HTTP 401 during upload', async () => {
    const shim = await makeShim('box');
    mockByoProviderCall.mockRejectedValueOnce(new Error('HTTP 401 Unauthorized'));

    await expect(shim.upload(null, 'f.bin', SMALL_DATA)).rejects.toBeInstanceOf(UnauthorizedError);
  });
});

describe('ETag / conflict — getVersion()', () => {
  beforeEach(() => {
    mockByoProviderCall.mockClear();
    mockByoInitConfig.mockClear();
  });

  it('returns the etag string from byoProviderCall', async () => {
    const shim = await makeShim('s3');
    mockByoProviderCall.mockResolvedValueOnce('etag-deadbeef');

    const version = await shim.getVersion('SecureCloud/vault.sc');

    expect(version).toBe('etag-deadbeef');
    const [, op] = mockByoProviderCall.mock.calls[0];
    expect(op).toBe('getVersion');
  });
});

describe('ETag / conflict — uploadStream()', () => {
  beforeEach(() => {
    mockByoProviderCall.mockClear();
    mockByoInitConfig.mockClear();
  });

  it('resolves with version from provider on successful upload via stream', async () => {
    const shim = await makeShim('gdrive');
    mockByoProviderCall.mockResolvedValueOnce({ ref: 'SecureCloud/vault.sc', version: 'v-stream' });

    const { stream, result } = await shim.uploadStream(null, 'vault.sc', 1024);
    const writer = stream.getWriter();
    await writer.write(new Uint8Array([10, 20, 30]));
    await writer.close();

    const uploadResult = await result;
    expect(uploadResult.version).toBe('v-stream');
  });

  it('rejects result promise with ConflictError on HTTP 409 in stream close', async () => {
    const shim = await makeShim('dropbox');
    mockByoProviderCall.mockRejectedValueOnce(new Error('HTTP 409 Conflict'));

    const { stream, result } = await shim.uploadStream('old/ref', 'vault.sc', 1024, {
      expectedVersion: 'stale',
    });
    const writer = stream.getWriter();
    await writer.write(SMALL_DATA);
    // writer.close() will trigger byoProviderCall → ConflictError
    // The close itself returns void; the error propagates through result promise
    await writer.close().catch(() => {});

    await expect(result).rejects.toBeInstanceOf(ConflictError);
  });
});
