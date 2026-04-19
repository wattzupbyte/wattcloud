/**
 * BYO stats client — collects usage events and flushes them to /relay/stats.
 *
 * Privacy invariants:
 *   - Device UUID is generated once, stored in localStorage, never rotated.
 *   - All values must come from ciphertext contexts (bytes = ciphertext sizes).
 *   - No filenames, paths, user IDs, or plaintext sizes.
 *   - Errors are swallowed — stats failures must never break user flows.
 */

import * as Worker from '../worker/byoWorkerClient';
import { acquireRelayCookie } from '../relay/RelayAuth';

const UUID_KEY = 'byo:stats_device_id';
const FLUSH_INTERVAL_MS = 60_000;
const EARLY_FLUSH_THRESHOLD = 50;

/** Closed set of allowed payload fields — rejects filenames/paths at TS level. */
export interface StatsPayload {
  provider_type?: string;
  bytes?: number;
  error_class?: string;
  share_variant?: string;
  file_count_bucket?: number;
  vault_size_bucket?: number;
  ts?: number;
}

let _initialized = false;
let _flushTimer: ReturnType<typeof setInterval> | null = null;
let _flushInFlight = false;

// ── Share-relay bandwidth counter ─────────────────────────────────────────────
// Accumulated by ByoDataProvider on each B1/B2 relay request; read-and-reset
// by VaultLifecycle on lock to emit relay_bandwidth_share events.
let _shareRelayBandwidthBytes = 0;

/** Accumulate bytes transferred to/from the share relay (B1/B2 requests). */
export function addShareRelayBandwidth(bytes: number): void {
  _shareRelayBandwidthBytes += bytes;
}

/** Read and atomically reset the share-relay bandwidth counter. */
export function getShareRelayBandwidthAndReset(): number {
  const val = _shareRelayBandwidthBytes;
  _shareRelayBandwidthBytes = 0;
  return val;
}

// ── Device UUID ───────────────────────────────────────────────────────────────

function getOrCreateDeviceId(): string {
  try {
    let id = localStorage.getItem(UUID_KEY);
    if (!id || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) {
      id = crypto.randomUUID();
      localStorage.setItem(UUID_KEY, id);
    }
    return id;
  } catch {
    // localStorage unavailable (private mode, etc.) — generate ephemeral UUID.
    return crypto.randomUUID();
  }
}

// ── Flush ─────────────────────────────────────────────────────────────────────

async function doFlush(): Promise<void> {
  if (_flushInFlight) return;
  _flushInFlight = true;
  try {
    // Acquire a stats relay cookie — PoW handshake, same as share cookies.
    await acquireRelayCookie('stats');
    await Worker.statsFlush();
  } catch {
    // Best-effort — stats errors must not surface to the user.
  } finally {
    _flushInFlight = false;
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Initialise the stats client. Call once after the BYO worker is ready.
 * Idempotent — subsequent calls are no-ops.
 */
export async function initStatsClient(baseUrl?: string): Promise<void> {
  if (_initialized) return;
  _initialized = true;

  const deviceId = getOrCreateDeviceId();
  const origin = baseUrl ?? (typeof location !== 'undefined' ? location.origin : '');

  try {
    await Worker.initByoWorker();
    await Worker.statsInit(origin, deviceId);
  } catch {
    return;
  }

  // 60-second periodic flush.
  _flushTimer = setInterval(() => { doFlush().catch(() => {}); }, FLUSH_INTERVAL_MS);

  // Flush on tab hide.
  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') doFlush().catch(() => {});
    });
  }
}

/**
 * Record a usage event. Fire-and-forget — never throws.
 * Triggers an early flush if the queue depth exceeds EARLY_FLUSH_THRESHOLD.
 */
export function recordEvent(kind: string, payload?: StatsPayload): void {
  if (!_initialized) return;
  const event = { kind, ts: Math.floor(Date.now() / 1000), ...payload };
  Worker.statsRecord(JSON.stringify(event)).catch(() => {});

  // Early flush check (best-effort — queue depth race is fine).
  Worker.statsDrain().then((depth) => {
    if (depth >= EARLY_FLUSH_THRESHOLD) doFlush().catch(() => {});
  }).catch(() => {});
}

/**
 * Map an error to a stats ErrorClass string.
 * Returns one of: Unauthorized, RateLimited, Conflict, Network, Other.
 */
export function classifyErr(e: unknown): string {
  // User-initiated cancels (AbortController / fetch abort) are not errors.
  if (e instanceof Error && e.name === 'AbortError') return 'Aborted';
  if (e instanceof Response || (e && typeof (e as any).status === 'number')) {
    const status = (e as any).status as number;
    if (status === 401 || status === 403) return 'Unauthorized';
    if (status === 429) return 'RateLimited';
    if (status === 409) return 'Conflict';
    return 'Other';
  }
  const msg = e instanceof Error ? e.message : String(e);
  if (/network|fetch|failed to fetch|load failed/i.test(msg)) return 'Network';
  if (/401|403|unauthorized/i.test(msg)) return 'Unauthorized';
  if (/429|rate.?limit/i.test(msg)) return 'RateLimited';
  if (/409|conflict/i.test(msg)) return 'Conflict';
  return 'Other';
}

/**
 * Compute log2 bucket index for histogram fields (file_count_bucket / vault_size_bucket).
 * Mirrors `bucket_log2` in sdk-core: floor(log2(max(1, n))).
 */
export function bucketLog2(n: number): number {
  return Math.floor(Math.log2(Math.max(1, n)));
}
