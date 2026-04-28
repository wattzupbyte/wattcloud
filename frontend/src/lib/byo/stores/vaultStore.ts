/**
 * BYO Vault State Store
 *
 * Svelte writable store exposing vault lifecycle state to UI components.
 * Follows the createAuthStore() factory pattern from stores/auth.ts.
 *
 * The store is the single source of truth for:
 *   - Vault lock/unlock status
 *   - Save/conflict state
 *   - Online/offline state
 *   - Prompt flags (rollback warning, backup prompt due)
 */

import { writable, derived, type Readable } from 'svelte/store';
import type { ProviderType } from '@wattcloud/sdk';

// ── Provider metadata ──────────────────────────────────────────────────────

export interface ProviderMeta {
  providerId: string;
  type: ProviderType;
  displayName: string;
  /** Whether this is the primary provider (manifest lives here). */
  isPrimary: boolean;
  /**
   * Connection status for the UI chip / offline banner (R6.C).
   *   connected    — reachable and writable
   *   syncing      — upload in progress
   *   offline      — unreachable (provider-side failure), cache-read-only
   *   offline_os   — OS reports no network (navigator.onLine = false)
   *   error        — unrecoverable error for this provider
   *   unauthorized — OAuth token expired; re-auth required
   */
  status: 'connected' | 'syncing' | 'offline' | 'offline_os' | 'error' | 'unauthorized';
  /** Number of consecutive probe failures (reset on success). */
  failCount: number;
  /** Unix timestamp (ms) of the most recent probe attempt. */
  lastPingTs: number;
}

// ── State shape ────────────────────────────────────────────────────────────

export type VaultStatus =
  | 'idle'           // No vault loaded
  | 'connecting'     // Initializing provider
  | 'downloading'    // Downloading vault_manifest.sc + per-provider bodies
  | 'unlocking'      // Running Argon2id / decrypting body
  | 'unlocked'       // Vault open, ready to operate
  | 'saving'         // Vault save in progress
  | 'conflict'       // Resolving ETag conflict
  | 'error'          // Unrecoverable error
  | 'locked';        // Explicitly locked (keys cleared)

export interface VaultState {
  status: VaultStatus;
  /** Primary provider type (kept for backward compat; use providers for multi-provider). */
  providerType: ProviderType | null;
  /** Hex-encoded vault_id of the currently open vault. */
  vaultId: string | null;
  /** Whether the in-memory SQLite has unsaved mutations. */
  dirty: boolean;
  /** Unix timestamp of the last successful save. */
  lastSavedAt: number | null;
  /** Human-readable error description. */
  error: string | null;
  /** Whether the cloud provider is reachable. */
  isOnline: boolean;
  /** Vault version rollback detected on unlock. */
  rollbackWarning: boolean;
  /** 60-day vault backup prompt is due. */
  backupPromptDue: boolean;
  /** Merge-based conflict resolution is in progress. */
  conflictInProgress: boolean;
  /**
   * Cross-tab vault ownership via navigator.locks.
   *   'this'  — this tab holds the exclusive vault lock
   *   'other' — another tab holds the lock; vault is read-only in this tab
   *   'none'  — no tab holds the lock (vault not unlocked)
   */
  tabOwnership: 'this' | 'other' | 'none';
  /**
   * True when one or more providers were unreachable at unlock time and their
   * data was loaded from IDB cache. Destructive operations (delete, move) should
   * be disabled for affected providers when partialView is true.
   */
  partialView: boolean;
  // ── Multi-provider (P9) ──────────────────────────────────────────────────
  /** All connected providers for this vault (P9). */
  providers: ProviderMeta[];
  /** ID of the provider whose tab is currently visible. Persisted to sessionStorage. */
  activeProviderId: string | null;
  /** ID of the primary provider (vault file lives here). */
  primaryProviderId: string | null;
}

// ── Initial state ──────────────────────────────────────────────────────────

const initialState: VaultState = {
  status: 'idle',
  providerType: null,
  vaultId: null,
  dirty: false,
  lastSavedAt: null,
  error: null,
  isOnline: typeof navigator !== 'undefined' ? navigator.onLine : true,
  rollbackWarning: false,
  backupPromptDue: false,
  conflictInProgress: false,
  tabOwnership: 'none',
  partialView: false,
  providers: [],
  activeProviderId: null,
  primaryProviderId: null,
};

// ── Store factory ──────────────────────────────────────────────────────────

function createVaultStore() {
  const { subscribe, set, update } = writable<VaultState>(initialState);

  return {
    subscribe,

    setStatus(status: VaultStatus) {
      update((s) => ({ ...s, status }));
    },

    setProvider(providerType: ProviderType | null) {
      update((s) => ({ ...s, providerType }));
    },

    setVaultId(vaultId: string | null) {
      update((s) => ({ ...s, vaultId }));
    },

    setDirty(dirty: boolean) {
      update((s) => ({ ...s, dirty }));
    },

    setSaved(at: number) {
      update((s) => ({ ...s, dirty: false, lastSavedAt: at }));
    },

    setError(error: string | null) {
      update((s) => ({ ...s, error, status: error ? 'error' : s.status }));
    },

    clearError() {
      update((s) => ({ ...s, error: null }));
    },

    setOnline(isOnline: boolean) {
      update((s) => ({ ...s, isOnline }));
    },

    setRollbackWarning(v: boolean) {
      update((s) => ({ ...s, rollbackWarning: v }));
    },

    setBackupPromptDue(v: boolean) {
      update((s) => ({ ...s, backupPromptDue: v }));
    },

    setConflictInProgress(v: boolean) {
      update((s) => ({ ...s, conflictInProgress: v }));
    },

    // ── Multi-provider (P9) ────────────────────────────────────────────────

    setProviders(providers: ProviderMeta[]) {
      update((s) => ({ ...s, providers }));
    },

    setActiveProviderId(activeProviderId: string | null) {
      if (activeProviderId) {
        try { sessionStorage.setItem('byo:activeProviderId', activeProviderId); } catch { /* ignore */ }
      }
      update((s) => ({ ...s, activeProviderId }));
    },

    setPrimaryProviderId(primaryProviderId: string | null) {
      update((s) => ({ ...s, primaryProviderId }));
    },

    setTabOwnership(tabOwnership: VaultState['tabOwnership']) {
      update((s) => ({ ...s, tabOwnership }));
    },

    setPartialView(partialView: boolean) {
      update((s) => ({ ...s, partialView }));
    },

    updateProviderStatus(
      providerId: string,
      status: ProviderMeta['status'],
      patch?: { failCount?: number; lastPingTs?: number },
    ) {
      update((s) => ({
        ...s,
        providers: s.providers.map((p) =>
          p.providerId === providerId
            ? { ...p, status, ...patch }
            : p,
        ),
      }));
    },

    reset() {
      set(initialState);
    },
  };
}

// ── Exported store instance ────────────────────────────────────────────────

export const vaultStore = createVaultStore();

// ── Derived stores ─────────────────────────────────────────────────────────

/** True when the vault is open and keys are loaded. */
export const isVaultUnlocked: Readable<boolean> = derived(
  vaultStore,
  ($s) => $s.status === 'unlocked' || $s.status === 'saving' || $s.status === 'conflict',
);

/** True when a vault save is in progress. */
export const isVaultSaving: Readable<boolean> = derived(
  vaultStore,
  ($s) => $s.status === 'saving',
);

/**
 * True when the vault is ready for user operations:
 *   - Unlocked
 *   - Online (required for any cloud I/O)
 *   - No save or conflict in progress
 */
export const canOperate: Readable<boolean> = derived(
  vaultStore,
  ($s) =>
    ($s.status === 'unlocked') &&
    $s.isOnline &&
    !$s.conflictInProgress,
);

/** True when vault has unsaved mutations. */
export const isVaultDirty: Readable<boolean> = derived(
  vaultStore,
  ($s) => $s.dirty,
);

/**
 * Providers ordered for UI surfaces: primary always first, secondaries
 * alphabetical by displayName. Manifest order isn't user-meaningful —
 * the Drawer switcher and Settings → Providers list both want a stable,
 * scannable layout regardless of when a given provider was added.
 */
export const sortedProviders: Readable<ProviderMeta[]> = derived(
  vaultStore,
  ($s) =>
    [...$s.providers].sort((a, b) => {
      if (a.isPrimary !== b.isPrimary) return a.isPrimary ? -1 : 1;
      return a.displayName.localeCompare(b.displayName);
    }),
);
