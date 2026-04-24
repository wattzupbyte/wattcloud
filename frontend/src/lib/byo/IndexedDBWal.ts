/**
 * BYO IndexedDB Write-Ahead Log
 *
 * Encrypted write-ahead log stored in IndexedDB. Each SQL mutation on the
 * vault SQLite is appended here before execution. On next startup with a
 * dirty flag set (crash recovery), the WAL is replayed against the latest
 * downloaded vault.
 *
 * SECURITY: Each WAL entry is AES-GCM encrypted with a WAL key derived from
 * vault_key via HKDF ("SecureCloud BYO WAL v1"). This satisfies invariant S4
 * (WAL entries in IndexedDB encrypted with vault_key).
 *
 * CRASH RECOVERY FLOW:
 * 1. beforeunload: setDirtyFlag(vaultId, true) — synchronous IDB dispatch
 *    Do NOT attempt async vault encryption/upload in beforeunload.
 * 2. On next startup: getDirtyFlag(vaultId) returns true
 * 3. Download latest vault from provider, decrypt
 * 4. getWalEntries(vaultId) → decrypt each → replay SQL onto SQLite
 * 5. Save vault, clearWalEntries(vaultId), setDirtyFlag(vaultId, false)
 *
 * See BYO_PLAN §4.1, §4.2.
 */

import {
  appendWalEntry,
  getWalEntries,
  clearWalEntries,
  type WalEntry,
} from './DeviceKeyStore';

// ── Domain-separation constant ────────────────────────────────────────────

const WAL_KEY_INFO = new TextEncoder().encode('SecureCloud BYO WAL v1');

// ── Key derivation ─────────────────────────────────────────────────────────

/**
 * Derive a per-session AES-256-GCM WAL encryption key from pre-derived subkey bytes.
 *
 * The caller obtains `walKeyBytes` via `byoVaultDeriveSubkey(sessionId, WAL_KEY_INFO_STR)`
 * so vault_key never leaves WASM. The returned CryptoKey is non-extractable.
 *
 * @param walKeyBytes - 32-byte HKDF output (derived from vault_key by the WASM session)
 */
export async function deriveWalKey(walKeyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    walKeyBytes as Uint8Array<ArrayBuffer>,
    { name: 'AES-GCM' },
    false, // non-extractable
    ['encrypt', 'decrypt'],
  );
}

/** The HKDF info string for WAL key derivation — must match the WASM call. */
export const WAL_KEY_PURPOSE = 'SecureCloud BYO WAL v1';

// ── Entry types ───────────────────────────────────────────────────────────

/** A SQL mutation WAL entry (type field absent for backward compat). */
export interface WalSqlEntry {
  type?: 'sql';
  sql: string;
  params: unknown[];
}

/** A blob-delete WAL entry produced by cross-provider move orchestration. */
export interface WalBlobDeleteEntry {
  type: 'blob_delete';
  /** Provider that owns the blob to delete. */
  provider_id: string;
  /** Opaque provider-specific blob reference. */
  provider_ref: string;
  /** file_id the move was for (used to look up dst row on replay). */
  file_id: number;
  /** Raw MoveStep bytes as base64 (for WASM decode_replay dispatch). */
  step_b64: string;
}

export type WalAnyEntry = WalSqlEntry | WalBlobDeleteEntry;

// ── Helpers ───────────────────────────────────────────────────────────────

async function encryptPayload(walKey: CryptoKey, payload: WalAnyEntry): Promise<WalEntry> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, walKey, plaintext);
  return {
    vault_id: '', // set by caller
    timestamp: Date.now(),
    encrypted_payload: ciphertext,
    iv: iv.buffer,
  };
}

// ── Append ────────────────────────────────────────────────────────────────

/**
 * Encrypt and append a SQL mutation to the WAL.
 *
 * Call this BEFORE executing the SQL on the in-memory SQLite — the WAL
 * is the crash recovery mechanism.
 */
export async function appendWal(
  vaultId: string,
  walKey: CryptoKey,
  sql: string,
  params: unknown[],
): Promise<void> {
  const entry = await encryptPayload(walKey, { sql, params });
  await appendWalEntry({ ...entry, vault_id: vaultId });
}

/**
 * Encrypt and append a blob-delete WAL entry for cross-provider move crash recovery.
 *
 * Call this BEFORE calling `srcProvider.delete(providerRef)`.
 * On the next vault unlock after a crash, the reconciler uses this entry to
 * retry the delete if the destination vault row already exists.
 */
export async function appendWalBlobDelete(
  vaultId: string,
  walKey: CryptoKey,
  providerId: string,
  providerRef: string,
  fileId: number,
  stepB64: string,
): Promise<void> {
  const payload: WalBlobDeleteEntry = {
    type: 'blob_delete',
    provider_id: providerId,
    provider_ref: providerRef,
    file_id: fileId,
    step_b64: stepB64,
  };
  const entry = await encryptPayload(walKey, payload);
  await appendWalEntry({ ...entry, vault_id: vaultId });
}

// ── Replay ────────────────────────────────────────────────────────────────

export interface WalMutation {
  sql: string;
  params: unknown[];
}

/**
 * Decrypt and return all WAL entries for a vault, ordered by insertion time.
 *
 * SQL entries (`type` absent or `"sql"`) are returned as `WalMutation[]` via
 * the `mutations` field for backward-compatible replay.  Blob-delete entries
 * are returned separately in `blobDeletes` for reconciler dispatch.
 */
export async function getWalMutations(
  vaultId: string,
  walKey: CryptoKey,
): Promise<WalMutation[]> {
  const { mutations } = await getWalEntryGroups(vaultId, walKey);
  return mutations;
}

export async function getWalEntryGroups(
  vaultId: string,
  walKey: CryptoKey,
): Promise<{ mutations: WalMutation[]; blobDeletes: WalBlobDeleteEntry[] }> {
  const entries = await getWalEntries(vaultId);
  const mutations: WalMutation[] = [];
  const blobDeletes: WalBlobDeleteEntry[] = [];

  for (const entry of entries) {
    try {
      const iv = new Uint8Array(entry.iv);
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        walKey,
        entry.encrypted_payload,
      );
      const decoded = JSON.parse(new TextDecoder().decode(plaintext)) as WalAnyEntry;
      if (decoded.type === 'blob_delete') {
        blobDeletes.push(decoded as WalBlobDeleteEntry);
      } else {
        mutations.push(decoded as WalMutation);
      }
    } catch {
      // Corrupted or tampered WAL entry — skip it.
      console.warn('[IndexedDBWal] Skipping corrupted WAL entry id:', entry.id);
    }
  }

  return { mutations, blobDeletes };
}

/**
 * Apply a list of WAL mutations to an sql.js Database instance.
 *
 * @param db - sql.js Database (already opened with decrypted vault body)
 * @param mutations - Decrypted mutations from getWalMutations()
 */
export function replayWal(db: import('sql.js').Database, mutations: WalMutation[]): void {
  for (const { sql, params } of mutations) {
    try {
      db.run(sql, params as import('sql.js').BindParams);
    } catch (err) {
      console.warn('[IndexedDBWal] Failed to replay WAL mutation:', sql, err);
    }
  }
}

// ── Cleanup ───────────────────────────────────────────────────────────────

/** Clear all WAL entries for a vault after successful save. */
export async function clearWal(vaultId: string): Promise<void> {
  await clearWalEntries(vaultId);
}

