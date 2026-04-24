import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  initRuntimeConfig,
  getRuntimeConfig,
  validateRuntimeConfig,
  __resetRuntimeConfigForTests,
  type WattcloudRuntimeConfig,
} from '../../src/lib/sdk/runtimeConfig';

function validConfig(): unknown {
  return {
    baseUrl: 'https://example.com',
    clientIds: {
      gdrive: 'gdrive-client-id',
      dropbox: 'dropbox-client-id',
      onedrive: 'onedrive-client-id',
      box: 'box-client-id',
      pcloud: 'pcloud-client-id',
    },
  };
}

function mockFetchOk(body: unknown): typeof fetch {
  return (async () => ({
    ok: true,
    status: 200,
    json: async () => body,
  })) as unknown as typeof fetch;
}

function mockFetchStatus(status: number): typeof fetch {
  return (async () => ({ ok: false, status, json: async () => ({}) })) as unknown as typeof fetch;
}

beforeEach(() => {
  __resetRuntimeConfigForTests();
});

describe('validateRuntimeConfig', () => {
  it('accepts a well-formed config', () => {
    const result = validateRuntimeConfig(validConfig());
    expect(result.baseUrl).toBe('https://example.com');
    expect(result.clientIds.gdrive).toBe('gdrive-client-id');
    expect(result.clientIds.pcloud).toBe('pcloud-client-id');
  });

  it('rejects non-object input', () => {
    expect(() => validateRuntimeConfig(null)).toThrow(/expected a JSON object/);
    expect(() => validateRuntimeConfig('nope')).toThrow(/expected a JSON object/);
    expect(() => validateRuntimeConfig(42)).toThrow(/expected a JSON object/);
  });

  it('rejects missing baseUrl', () => {
    const cfg = validConfig() as Record<string, unknown>;
    delete cfg.baseUrl;
    expect(() => validateRuntimeConfig(cfg)).toThrow(/baseUrl missing/);
  });

  it('rejects empty baseUrl', () => {
    const cfg = validConfig() as Record<string, unknown>;
    cfg.baseUrl = '   ';
    expect(() => validateRuntimeConfig(cfg)).toThrow(/baseUrl missing/);
  });

  it('rejects non-https baseUrl in production-like env', () => {
    const cfg = validConfig() as Record<string, unknown>;
    cfg.baseUrl = 'http://example.com';
    expect(() => validateRuntimeConfig(cfg)).toThrow(/baseUrl must be https/);
  });

  it('accepts http://localhost only in dev', () => {
    const originalDev = (import.meta as any).env?.DEV;
    (import.meta as any).env = { ...(import.meta as any).env, DEV: true };
    const cfg = validConfig() as Record<string, unknown>;
    cfg.baseUrl = 'http://localhost:5173';
    expect(() => validateRuntimeConfig(cfg)).not.toThrow();
    cfg.baseUrl = 'http://127.0.0.1:5173';
    expect(() => validateRuntimeConfig(cfg)).not.toThrow();
    (import.meta as any).env.DEV = originalDev;
  });

  it('rejects missing clientIds object', () => {
    const cfg = validConfig() as Record<string, unknown>;
    delete cfg.clientIds;
    expect(() => validateRuntimeConfig(cfg)).toThrow(/clientIds missing/);
  });

  it('accepts empty individual client IDs (provider disabled per .env.example)', () => {
    for (const provider of ['gdrive', 'dropbox', 'onedrive', 'box', 'pcloud'] as const) {
      const cfg = validConfig() as Record<string, any>;
      cfg.clientIds[provider] = '';
      const result = validateRuntimeConfig(cfg);
      expect(result.clientIds[provider]).toBe('');
    }
  });

  it('rejects missing (undefined) individual client IDs', () => {
    const cfg = validConfig() as Record<string, any>;
    delete cfg.clientIds.box;
    expect(() => validateRuntimeConfig(cfg)).toThrow(/clientIds\.box must be a string/);
  });

  it('rejects non-string individual client IDs', () => {
    const cfg = validConfig() as Record<string, any>;
    cfg.clientIds.dropbox = 42;
    expect(() => validateRuntimeConfig(cfg)).toThrow(/clientIds\.dropbox must be a string/);
  });
});

describe('initRuntimeConfig', () => {
  it('fetches /config.json with no-store + no credentials', async () => {
    const fetchMock = vi.fn(mockFetchOk(validConfig()));
    const cfg = await initRuntimeConfig(fetchMock as unknown as typeof fetch);
    expect(cfg.baseUrl).toBe('https://example.com');
    expect(fetchMock).toHaveBeenCalledWith('/config.json', {
      credentials: 'omit',
      cache: 'no-store',
    });
  });

  it('throws on non-2xx', async () => {
    await expect(
      initRuntimeConfig(mockFetchStatus(404)),
    ).rejects.toThrow(/HTTP 404/);
  });

  it('caches after first successful load', async () => {
    const fetchMock = vi.fn(mockFetchOk(validConfig()));
    await initRuntimeConfig(fetchMock as unknown as typeof fetch);
    await initRuntimeConfig(fetchMock as unknown as typeof fetch);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('propagates validator errors without caching', async () => {
    const bad = { baseUrl: 'http://example.com', clientIds: {} };
    await expect(
      initRuntimeConfig(mockFetchOk(bad) as unknown as typeof fetch),
    ).rejects.toThrow();
    // A later valid load must succeed — prior bad load did not poison the cache.
    const cfg = await initRuntimeConfig(mockFetchOk(validConfig()) as unknown as typeof fetch);
    expect(cfg.baseUrl).toBe('https://example.com');
  });
});

describe('getRuntimeConfig', () => {
  it('throws before init', () => {
    expect(() => getRuntimeConfig()).toThrow(/not initialized/);
  });

  it('returns the loaded config after init', async () => {
    await initRuntimeConfig(mockFetchOk(validConfig()) as unknown as typeof fetch);
    const cfg = getRuntimeConfig();
    expect(cfg.clientIds.gdrive).toBe('gdrive-client-id');
  });
});
