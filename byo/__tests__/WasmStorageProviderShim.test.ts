/**
 * WasmStorageProviderShim tests (P8 + R1.4).
 *
 * Verifies that the generic WASM shim creates providers with the correct
 * type and displayName for every provider type, and that ProviderFactory
 * returns shim instances for all non-SFTP providers.
 *
 * R1.4: byoInitConfig / byoReleaseConfig are mocked — the real implementations
 * require a running BYO worker. The shim's credential-isolation invariant is
 * tested separately: getConfig() must not expose credentials after init().
 */

import { describe, it, expect, afterEach, vi, beforeEach } from 'vitest';
import { WasmStorageProviderShim } from '../src/providers/WasmStorageProviderShim';
import { SftpProvider } from '../src/providers/SftpProvider';
import { createProvider, getDisplayName, clearAllProviders } from '../src/ProviderFactory';
import { ProviderError } from '../src/errors';
import type { ProviderType } from '../src/types';

// ── Mock worker client so init()/disconnect() work without a real worker ──────
let handleCounter = 0;
vi.mock('../src/worker/byoWorkerClient', () => ({
  byoInitConfig: vi.fn(async () => `mock-handle-${++handleCounter}`),
  byoReleaseConfig: vi.fn(async () => undefined),
  byoRefreshConfigByHandle: vi.fn(async () => undefined),
  byoProviderCall: vi.fn(async () => null),
  byoRefreshToken: vi.fn(async () => '{}'),
}));

const PROVIDER_META: Array<{ type: ProviderType; displayName: string }> = [
  { type: 'gdrive',   displayName: 'Google Drive' },
  { type: 'dropbox',  displayName: 'Dropbox' },
  { type: 'onedrive', displayName: 'OneDrive' },
  { type: 'webdav',   displayName: 'WebDAV' },
  { type: 'box',      displayName: 'Box' },
  { type: 'pcloud',   displayName: 'pCloud' },
  { type: 's3',       displayName: 'S3' },
];

afterEach(async () => clearAllProviders());
beforeEach(() => { handleCounter = 0; vi.clearAllMocks(); });

describe('WasmStorageProviderShim', () => {
  it.each(PROVIDER_META)('creates $type with displayName "$displayName"', ({ type, displayName }) => {
    const shim = new WasmStorageProviderShim(type);
    expect(shim.type).toBe(type);
    expect(shim.displayName).toBe(displayName);
    expect(shim.isReady()).toBe(false);
  });

  it('is not ready before init()', () => {
    const shim = new WasmStorageProviderShim('gdrive');
    expect(shim.isReady()).toBe(false);
  });

  it('getConfig() returns type-only stub (R1.4: credentials never exposed to main thread)', () => {
    const shim = new WasmStorageProviderShim('dropbox');
    const cfg = shim.getConfig();
    expect(cfg.type).toBe('dropbox');
    // Credentials must not be present — they stay in the worker configRegistry.
    expect((cfg as Record<string, unknown>).accessToken).toBeUndefined();
    expect((cfg as Record<string, unknown>).secret_access_key).toBeUndefined();
    expect((cfg as Record<string, unknown>).password).toBeUndefined();
  });

  it('init() with valid config marks ready and stores handle (not configJson)', async () => {
    const { byoInitConfig } = await import('../src/worker/byoWorkerClient');
    const shim = new WasmStorageProviderShim('gdrive');
    await shim.init({ type: 'gdrive', accessToken: 'fake' });
    expect(shim.isReady()).toBe(true);
    // byoInitConfig must have been called with the serialized config.
    expect(byoInitConfig).toHaveBeenCalledWith(JSON.stringify({ type: 'gdrive', accessToken: 'fake' }));
    // getConfig() returns stub only — no credentials.
    const cfg = shim.getConfig();
    expect(cfg.type).toBe('gdrive');
    expect((cfg as Record<string, unknown>).accessToken).toBeUndefined();
  });

  it('init() without config throws ProviderError', async () => {
    const shim = new WasmStorageProviderShim('gdrive');
    await expect(shim.init()).rejects.toBeInstanceOf(ProviderError);
  });

  it('disconnect() releases handle and clears ready state', async () => {
    const { byoReleaseConfig } = await import('../src/worker/byoWorkerClient');
    const shim = new WasmStorageProviderShim('gdrive');
    await shim.init({ type: 'gdrive', accessToken: 'tok' });
    await shim.disconnect();
    expect(shim.isReady()).toBe(false);
    expect(byoReleaseConfig).toHaveBeenCalledWith('mock-handle-1');
  });
});

describe('ProviderFactory (P8 — all non-SFTP providers use WasmStorageProviderShim)', () => {
  it.each(PROVIDER_META)('createProvider($type) returns WasmStorageProviderShim', ({ type }) => {
    const p = createProvider(type, `${type}-test`);
    expect(p).toBeInstanceOf(WasmStorageProviderShim);
    expect(p.type).toBe(type);
  });

  it('createProvider(sftp) returns SftpProvider (WebSocket transport — not a WASM shim)', () => {
    const p = createProvider('sftp', 'sftp-test');
    expect(p).toBeInstanceOf(SftpProvider);
    expect(p.type).toBe('sftp');
  });

  it.each(PROVIDER_META)('getDisplayName($type) returns "$displayName"', ({ type, displayName }) => {
    expect(getDisplayName(type)).toBe(displayName);
  });
});
