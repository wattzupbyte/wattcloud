/**
 * BYO share-storage stats
 *
 * Two bundles of numbers:
 *   - `byoShareStats` — local aggregate over this vault's active (non-revoked,
 *     non-expired) share_tokens rows. Kept in-memory so the drawer can render
 *     without an async read on every paint.
 *   - `byoRelayHeadroom` — response from `GET /relay/share/headroom`. Cached
 *     so the drawer doesn't fetch on every open; a 60s TTL keeps it roughly
 *     fresh without hammering the endpoint.
 *
 * Both reset on vault lock.
 */

import { writable, type Readable } from 'svelte/store';
import type { DataProvider } from '../DataProvider';

// ── Local share totals ─────────────────────────────────────────────────────

export interface ShareStats {
  count: number;
  bytes: number;
}

const _stats = writable<ShareStats>({ count: 0, bytes: 0 });

export const byoShareStats: Readable<ShareStats> = { subscribe: _stats.subscribe };

/** Recompute share totals from the vault; call after mutations. */
export function refreshShareStats(dp: DataProvider): void {
  const now = Date.now();
  const active = dp.listShares().filter((s) =>
    !s.revoked && (s.presigned_expires_at === null || s.presigned_expires_at > now)
  );
  const bytes = active.reduce((sum, s) => sum + (s.total_bytes ?? 0), 0);
  _stats.set({ count: active.length, bytes });
}

export function resetShareStats(): void {
  _stats.set({ count: 0, bytes: 0 });
  _headroom.set(null);
  _lastFetchedAt = 0;
}

// ── Relay headroom ─────────────────────────────────────────────────────────

export interface RelayHeadroom {
  /** Bytes available on the share-storage filesystem. */
  freeBytes: number;
  /** Bytes the caller's IP can still upload today. */
  remainingTodayBytes: number;
  /** Configured daily cap per IP. */
  dailyBytesPerIp: number;
}

const _headroom = writable<RelayHeadroom | null>(null);

export const byoRelayHeadroom: Readable<RelayHeadroom | null> = {
  subscribe: _headroom.subscribe,
};

const HEADROOM_TTL_MS = 60_000;
let _lastFetchedAt = 0;
let _inflight: Promise<void> | null = null;

/**
 * Fetch `/relay/share/headroom`. No-ops if a fetch completed within the TTL,
 * or if a fetch is already in flight. Errors are swallowed — the store stays
 * at its previous value so the drawer keeps showing stale-but-usable info.
 */
export async function fetchRelayHeadroom(force = false): Promise<void> {
  const now = Date.now();
  if (!force && now - _lastFetchedAt < HEADROOM_TTL_MS) return;
  if (_inflight) return _inflight;

  _inflight = (async () => {
    try {
      const res = await fetch('/relay/share/headroom', {
        method: 'GET',
        credentials: 'same-origin',
      });
      if (!res.ok) return;
      const body = await res.json();
      _headroom.set({
        freeBytes: Number(body.free_bytes ?? 0),
        remainingTodayBytes: Number(body.your_remaining_bytes_today ?? 0),
        dailyBytesPerIp: Number(body.daily_bytes_per_ip ?? 0),
      });
      _lastFetchedAt = Date.now();
    } catch {
      // Best-effort — drawer falls back to "unknown" copy when store is null.
    } finally {
      _inflight = null;
    }
  })();
  return _inflight;
}
