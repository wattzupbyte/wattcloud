/**
 * BYO Offline Detector
 *
 * Monitors network and cloud provider reachability independently per provider.
 * Surfaces per-provider state via vaultStore.updateProviderStatus().
 * The global vaultStore.isOnline flag is true if ANY provider is reachable (M2).
 *
 * BEHAVIOR (R6.C):
 *   - Each provider is pinged independently on a staggered interval.
 *   - Base interval: 30 s. On repeated failure, backs off to a max of 5 min.
 *   - On transition offline→online or online→offline, calls vaultStore.updateProviderStatus.
 *   - The global isOnline flag reflects whether any provider is reachable (M2).
 *
 * DETECTION:
 *   1. window online/offline events (immediate for all providers)
 *   2. Periodic per-provider probe: uses provider.probe() if implemented (M1),
 *      otherwise falls back to getVersion(vault_manifest.sc).
 */

import type { StorageProvider } from '@wattcloud/sdk';
import { UnauthorizedError } from '@wattcloud/sdk';
import { vaultStore } from './stores/vaultStore';
import type { ProviderMeta } from './stores/vaultStore';

// ── Constants ──────────────────────────────────────────────────────────────

const PING_BASE_MS = 30_000;
const PING_MAX_MS = 300_000; // 5 min
const PING_TIMEOUT_MS = 8_000;
const PING_FILE = 'SecureCloud/vault_manifest.sc';

// ── Per-provider state ─────────────────────────────────────────────────────

interface ProviderPingState {
  provider: StorageProvider;
  status: ProviderMeta['status'];
  failCount: number;
  timer: ReturnType<typeof setTimeout> | null;
  // C9: generation counter — any in-flight ping whose generation doesn't match
  // the current value is treated as stale and its result dropped. Needed so
  // `onNetworkOnline` can restart pings without racing prior in-flight pings.
  generation: number;
}

// ── OfflineDetector ────────────────────────────────────────────────────────

export class OfflineDetector {
  private states: Map<string, ProviderPingState> = new Map();
  private stopped = false;
  private primaryProviderId = '';

  /**
   * Start monitoring providers.
   *
   * @param providers  Map of providerId → StorageProvider
   * @param primaryId  The primary provider ID (drives global isOnline flag)
   */
  start(providers: Map<string, StorageProvider>, primaryId: string): void {
    this.stopped = false;
    this.primaryProviderId = primaryId;

    window.addEventListener('online', this.onNetworkOnline);
    window.addEventListener('offline', this.onNetworkOffline);

    // Set initial global online state
    vaultStore.setOnline(navigator.onLine);

    // Stagger initial pings to spread load (200 ms apart)
    let stagger = 0;
    for (const [providerId, provider] of providers) {
      this.states.set(providerId, {
        provider,
        status: 'connected',
        failCount: 0,
        timer: null,
        generation: 0,
      });
      setTimeout(() => {
        if (!this.stopped) this.pingProvider(providerId);
      }, stagger);
      stagger += 200;
    }
  }

  /**
   * Update the provider set (e.g. after a provider is added or removed).
   * Existing providers keep their backoff state.
   */
  updateProviders(providers: Map<string, StorageProvider>, primaryId: string): void {
    this.primaryProviderId = primaryId;

    // Remove providers no longer present
    for (const [id, state] of this.states) {
      if (!providers.has(id)) {
        if (state.timer) clearTimeout(state.timer);
        this.states.delete(id);
      }
    }

    // Add new providers
    for (const [id, provider] of providers) {
      if (!this.states.has(id)) {
        this.states.set(id, { provider, status: 'connected', failCount: 0, timer: null, generation: 0 });
        if (!this.stopped) this.pingProvider(id);
      }
    }
  }

  stop(): void {
    this.stopped = true;
    for (const state of this.states.values()) {
      if (state.timer) clearTimeout(state.timer);
    }
    this.states.clear();
    window.removeEventListener('online', this.onNetworkOnline);
    window.removeEventListener('offline', this.onNetworkOffline);
  }

  // ── Network events ─────────────────────────────────────────────────────

  private onNetworkOnline = (): void => {
    // Don't optimistically set isOnline=true here; let pingProvider confirm
    // reachability and call updateGlobalOnline once we have real results (M2).
    // Re-ping all providers with staggered delays to avoid a thundering herd.
    //
    // C9: bump the per-provider generation counter so any ping currently
    // mid-flight (the one we're preempting) doesn't race the new ping and
    // write a stale status into vaultStore after the new ping finishes.
    const ids = [...this.states.keys()];
    ids.forEach((id, i) => {
      const state = this.states.get(id)!;
      if (state.timer) { clearTimeout(state.timer); state.timer = null; }
      state.generation += 1;
      setTimeout(() => this.pingProvider(id), i * 200 + Math.floor(Math.random() * 200));
    });
  };

  private onNetworkOffline = (): void => {
    // OS reports no network — tag as offline_os (distinct from provider-side failure)
    // so the UI can show a single "you're offline" banner instead of N provider chips.
    for (const [id, state] of this.states) {
      if (state.status !== 'offline_os') {
        state.status = 'offline_os';
        vaultStore.updateProviderStatus(id, 'offline_os', { lastPingTs: Date.now() });
      }
    }
    vaultStore.setOnline(false);
  };

  // ── Ping ───────────────────────────────────────────────────────────────

  private async pingProvider(providerId: string): Promise<void> {
    if (this.stopped) return;
    const state = this.states.get(providerId);
    if (!state) return;

    // C9: snapshot the generation at probe start so a `onNetworkOnline` that
    // fires mid-probe can invalidate this in-flight result.
    const startGeneration = state.generation;

    let reachable = false;
    let unauthorized = false;
    try {
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('ping timeout')), PING_TIMEOUT_MS),
      );
      // M1: prefer provider.probe() if implemented (cheap HEAD/stat);
      // fall back to getVersion which downloads metadata (counts against quota).
      const probeOp = state.provider.probe
        ? state.provider.probe()
        : state.provider.getVersion(PING_FILE);
      await Promise.race([probeOp, timeoutPromise]);
      reachable = true;
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        unauthorized = true;
      }
      // Any other error = unreachable
    }

    if (this.stopped) return;
    // C9: if a newer ping has been requested since we started, drop this
    // result rather than letting it race the newer probe into vaultStore.
    if (state.generation !== startGeneration) return;
    const prev = state.status;
    const now = Date.now();

    if (unauthorized) {
      state.status = 'unauthorized';
      vaultStore.updateProviderStatus(providerId, 'unauthorized', {
        failCount: state.failCount, lastPingTs: now,
      });
      if (prev !== 'unauthorized') this.updateGlobalOnline();
    } else if (reachable) {
      state.failCount = 0;
      state.status = 'connected';
      vaultStore.updateProviderStatus(providerId, 'connected', {
        failCount: 0, lastPingTs: now,
      });
      if (prev !== 'connected') this.updateGlobalOnline();
    } else {
      state.failCount++;
      state.status = 'offline';
      vaultStore.updateProviderStatus(providerId, 'offline', {
        failCount: state.failCount, lastPingTs: now,
      });
      if (prev === 'connected' || prev === 'syncing') this.updateGlobalOnline();
    }

    // Schedule next ping with exponential backoff on failure.
    // M10: formula is 1.5^failCount (capped at failCount=6 → 1.5^6 ≈ 11×);
    // PING_MAX_MS provides the hard ceiling.
    const backoffFactor = Math.min(state.failCount, 6);
    const interval = Math.min(PING_BASE_MS * Math.pow(1.5, backoffFactor), PING_MAX_MS);
    state.timer = setTimeout(() => this.pingProvider(providerId), interval);
  }

  /**
   * Derive global isOnline from per-provider states (M2).
   * True when at least one provider is connected/syncing/read_only.
   */
  private updateGlobalOnline(): void {
    const anyReachable = [...this.states.values()].some(
      (s) => s.status === 'connected' || s.status === 'syncing',
    );
    vaultStore.setOnline(anyReachable);
  }
}
