/**
 * Runtime configuration for Wattcloud.
 *
 * At SPA boot, main.ts does `await initRuntimeConfig()` which fetches
 * `/config.json` from the same origin. The deploy-vps.sh script writes that
 * file from the operator's .env at provision time and serves it with
 * `Cache-Control: no-store`.
 *
 * This replaces the previous build-time `VITE_BYO_*` env vars so a single
 * container image can serve any operator's OAuth client IDs without rebuilding.
 *
 * Security: OAuth client IDs are public values (PKCE is the security boundary),
 * so fetching them at runtime is equivalent in security to baking them at
 * build time. Shape validation fails closed on any mismatch — without a valid
 * config the SPA refuses to run. HTTPS scheme is enforced on BASE_URL in
 * production (localhost http is allowed in dev).
 */

export interface WattcloudRuntimeConfig {
  /** Base URL for redirect URIs + relay WebSocket (e.g. `https://example.com`). */
  baseUrl: string;
  /** Public OAuth client IDs — one per supported provider. */
  clientIds: {
    gdrive: string;
    dropbox: string;
    onedrive: string;
    box: string;
    pcloud: string;
  };
}

let loaded: WattcloudRuntimeConfig | null = null;

const PROVIDER_KEYS = ['gdrive', 'dropbox', 'onedrive', 'box', 'pcloud'] as const;

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.trim().length > 0;
}

/**
 * Validate the fetched JSON matches WattcloudRuntimeConfig.
 *
 * In production the baseUrl must be https://; in dev an `http://localhost[:port]`
 * URL is accepted. Each of the five provider client IDs must be a non-empty
 * string. Throws on any violation — callers must let this bubble up.
 */
export function validateRuntimeConfig(raw: unknown): WattcloudRuntimeConfig {
  if (!raw || typeof raw !== 'object') {
    throw new Error('config.json: expected a JSON object');
  }
  const r = raw as Record<string, unknown>;
  if (!isNonEmptyString(r.baseUrl)) {
    throw new Error('config.json: baseUrl missing or empty');
  }
  const baseUrl = r.baseUrl.trim();
  const isDev = typeof import.meta !== 'undefined' && !!(import.meta as any).env?.DEV;
  const isLocalhost = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(baseUrl);
  if (!baseUrl.startsWith('https://') && !(isDev && isLocalhost)) {
    throw new Error(`config.json: baseUrl must be https:// (got ${baseUrl})`);
  }
  const ids = r.clientIds;
  if (!ids || typeof ids !== 'object') {
    throw new Error('config.json: clientIds missing');
  }
  const clientIds: Record<string, string> = {};
  for (const key of PROVIDER_KEYS) {
    const v = (ids as Record<string, unknown>)[key];
    if (!isNonEmptyString(v)) {
      throw new Error(`config.json: clientIds.${key} missing or empty`);
    }
    clientIds[key] = v.trim();
  }
  return {
    baseUrl,
    clientIds: clientIds as WattcloudRuntimeConfig['clientIds'],
  };
}

/**
 * Fetch and cache /config.json. Call once at app boot before importing modules
 * that read OAuth configuration. Subsequent calls return the cached config.
 */
export async function initRuntimeConfig(
  fetchImpl: typeof fetch = fetch,
): Promise<WattcloudRuntimeConfig> {
  if (loaded) return loaded;
  const res = await fetchImpl('/config.json', {
    credentials: 'omit',
    cache: 'no-store',
  });
  if (!res.ok) {
    throw new Error(`config.json: HTTP ${res.status}`);
  }
  const raw = await res.json();
  loaded = validateRuntimeConfig(raw);
  return loaded;
}

/**
 * Synchronous accessor — throws if `initRuntimeConfig` has not been awaited.
 * Intended for use inside OAuth flow helpers invoked after app boot.
 */
export function getRuntimeConfig(): WattcloudRuntimeConfig {
  if (!loaded) {
    throw new Error('runtime config not initialized — call initRuntimeConfig() at app boot');
  }
  return loaded;
}

/** Test-only: reset the cached config. Never called by production code. */
export function __resetRuntimeConfigForTests(): void {
  loaded = null;
}
