/**
 * BYO Device Key Store
 *
 * Manages the `sc-byo` IndexedDB database. This is the local, per-device
 * persistent state for BYO mode — it stores:
 *   - Device record: vault_id, device_id, device_name, version tracking, backup prompt
 *   - Non-extractable CryptoKey for shard decryption
 *   - Encrypted WAL entries for crash recovery
 *   - Dirty flags for beforeunload crash detection
 *
 * SECURITY: The CryptoKey stored here is non-extractable. It is the device
 * "possession" factor. The shard (knowledge + cloud factor) is NOT stored
 * here — it exists only in the vault header device slots, encrypted by this key.
 *
 * See BYO_PLAN §1.6 and §2.2 for the full IndexedDB schema.
 */

// ── Database constants ─────────────────────────────────────────────────────

const DB_NAME = 'sc-byo';
// v2: adds `provider_configs` store for per-device provider config persistence.
// v3: adds `device_webauthn` store for the opt-in WebAuthn/PRF device-key
//     gate (SECURITY.md §12). Holds one row per vault recording the current
//     mode ('none' | 'presence' | 'prf') and the list of enrolled passkeys
//     along with their wrapped device-key copies (prf mode). Missing row =
//     mode 'none' and the existing `device_crypto_keys` entry is used
//     directly — fully backward compatible with pre-v3 vaults.
// v4: adds `thumbnails` store — per-vault, AES-GCM-wrapped photo-timeline
//     thumbnail cache. Wiped alongside the other per-vault state when a
//     vault is "forgotten" (see ThumbnailStore.deleteVaultThumbnails +
//     VaultContextSheet.doForget).
const DB_VERSION = 4;

const STORE_DEVICE_KEYS = 'device_keys';
const STORE_DEVICE_CRYPTO_KEYS = 'device_crypto_keys';
const STORE_WAL = 'wal';
const STORE_DIRTY_FLAGS = 'dirty_flags';
export const STORE_PROVIDER_CONFIGS = 'provider_configs';
const STORE_DEVICE_WEBAUTHN = 'device_webauthn';
export const STORE_THUMBNAILS = 'thumbnails';

// ── Types ──────────────────────────────────────────────────────────────────

export interface DeviceRecord {
  /** Hex-encoded 16-byte vault_id. Primary key for this store. */
  vault_id: string;
  /** Hex-encoded 16-byte device_id matching a slot in the vault header. */
  device_id: string;
  /** Human-readable device name (e.g. browser + OS). */
  device_name: string;
  /** Monotonically increasing vault version last seen by this device. Used for rollback detection. */
  last_seen_vault_version: number;
  /**
   * Monotonically increasing manifest_version last seen by this device.
   * Passed to byoManifestMerge as min_acceptable_version so a hostile provider
   * cannot roll back the manifest to an older version (C3 / C8 mitigations).
   */
  last_seen_manifest_version: number;
  /** ISO 8601 timestamp when vault backup prompt was last shown. null = never shown. */
  last_backup_prompt_at: string | null;
  /**
   * ISO 8601 timestamp when the user permanently dismissed the
   * credential-protection auto-offer ("Don't ask again"). Missing / null =
   * the offer may still be shown on the next unlock for this vault.
   */
  cred_protection_offer_dismissed_at?: string | null;
}

/**
 * One enrolled WebAuthn credential for the device-key gate.
 * `prf_salt` + `wrapped_device_key` are populated only when the enrolment
 * used the PRF extension; in `presence` mode they're undefined and the
 * existing `device_crypto_keys` row stays the source of truth (the gate
 * just enforces a user touch before any crypto.subtle call).
 */
export interface WebAuthnCredentialEntry {
  /** Raw credential ID (base64url-encoded string for stable serialization). */
  credential_id: string;
  /** 32-byte random salt used as the `first` eval input for PRF. base64. */
  prf_salt?: string;
  /** AES-GCM `nonce(12) || ct||tag` wrapping the 32-byte device key. base64. */
  wrapped_device_key?: string;
  /**
   * AES-GCM `nonce(12) || ct||tag` wrapping the 32-byte `vault_key`. Present
   * only when the opt-in "passkey replaces passphrase" toggle is ON for this
   * vault — and then exactly one copy exists per enrolled `prf`-mode
   * credential, each wrapped under its own PRF-derived wrapping key. Unset
   * means the user kept the default (passphrase still required on unlock).
   * See SECURITY.md §12 "Passkey replaces passphrase".
   */
  wrapped_vault_key?: string;
  /** User-editable label (e.g. "MacBook Touch ID", "YubiKey 5C"). */
  display_name: string;
  /** ISO 8601 timestamp when this credential was enrolled. */
  added_at: string;
  /**
   * Whether this specific credential's authenticator reported PRF support at
   * enrolment. In a vault with mixed authenticators (one supports PRF, one
   * doesn't), the vault-level `mode` defers to the weakest — but per-
   * credential `prf_supported` lets the UI flag the outlier so the user can
   * upgrade it later.
   */
  prf_supported: boolean;
}

/**
 * Per-vault WebAuthn gate state. Missing = mode 'none' = no gate; the
 * existing `device_crypto_keys` row is used directly. See SECURITY.md §12.
 */
export interface DeviceWebAuthnRecord {
  vault_id: string;
  mode: 'none' | 'presence' | 'prf';
  credentials: WebAuthnCredentialEntry[];
  /**
   * Opt-in flag: when true, the passkey alone unlocks the vault (the
   * `vault_key` is wrapped under the PRF and stored in each credential's
   * `wrapped_vault_key`). Default is undefined/false — passphrase is still
   * required on unlock and the passkey gates only the device shard.
   * Requires `mode === 'prf'`; presence mode is a behavioural speed-bump
   * and cannot cryptographically commit to a vault_key wrap.
   * See SECURITY.md §12 "Passkey replaces passphrase".
   */
  passkey_unlocks_vault?: boolean;
}

export interface WalEntry {
  /** Auto-increment primary key. */
  id?: number;
  /** Hex-encoded vault_id this WAL entry belongs to. */
  vault_id: string;
  /** Unix timestamp in ms when the entry was written. */
  timestamp: number;
  /** AES-GCM encrypted JSON payload ({ sql: string; params: unknown[] }). */
  encrypted_payload: ArrayBuffer;
  /** AES-GCM IV used for this entry. */
  iv: ArrayBuffer;
}

// ── Database open ──────────────────────────────────────────────────────────

export function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Device records keyed by vault_id
      if (!db.objectStoreNames.contains(STORE_DEVICE_KEYS)) {
        db.createObjectStore(STORE_DEVICE_KEYS, { keyPath: 'vault_id' });
      }

      // Non-extractable CryptoKeys keyed by vault_id (string)
      if (!db.objectStoreNames.contains(STORE_DEVICE_CRYPTO_KEYS)) {
        db.createObjectStore(STORE_DEVICE_CRYPTO_KEYS);
      }

      // WAL entries with auto-increment id, indexed by vault_id
      if (!db.objectStoreNames.contains(STORE_WAL)) {
        const walStore = db.createObjectStore(STORE_WAL, {
          keyPath: 'id',
          autoIncrement: true,
        });
        walStore.createIndex('by_vault_id', 'vault_id', { unique: false });
      }

      // Dirty flags keyed by vault_id (boolean value)
      if (!db.objectStoreNames.contains(STORE_DIRTY_FLAGS)) {
        db.createObjectStore(STORE_DIRTY_FLAGS);
      }

      // Provider configs keyed by provider_id (UUID from vault manifest),
      // indexed by vault_id so we can fetch "all providers for vault X" cheap.
      if (!db.objectStoreNames.contains(STORE_PROVIDER_CONFIGS)) {
        const pcStore = db.createObjectStore(STORE_PROVIDER_CONFIGS, {
          keyPath: 'provider_id',
        });
        pcStore.createIndex('by_vault_id', 'vault_id', { unique: false });
      }

      // Per-vault WebAuthn gate state keyed by vault_id. Row absent = no gate.
      if (!db.objectStoreNames.contains(STORE_DEVICE_WEBAUTHN)) {
        db.createObjectStore(STORE_DEVICE_WEBAUTHN, { keyPath: 'vault_id' });
      }

      // Encrypted thumbnail cache — key `${vault_id}:${file_id}`, indexed
      // on vault_id (for bulk delete on "forget vault") and last_access
      // (for LRU eviction once the global byte cap is hit).
      if (!db.objectStoreNames.contains(STORE_THUMBNAILS)) {
        const t = db.createObjectStore(STORE_THUMBNAILS, { keyPath: 'key' });
        t.createIndex('by_vault_id', 'vault_id', { unique: false });
        t.createIndex('by_last_access', 'last_access', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// ── Device record ──────────────────────────────────────────────────────────

/** Read the device record for a vault. Returns null if not enrolled on this device. */
export async function getDeviceRecord(vaultId: string): Promise<DeviceRecord | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_KEYS, 'readonly');
    const req = tx.objectStore(STORE_DEVICE_KEYS).get(vaultId);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

/** Write or update the device record for a vault. */
export async function setDeviceRecord(record: DeviceRecord): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_KEYS, 'readwrite');
    tx.objectStore(STORE_DEVICE_KEYS).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Delete the device record for a vault (e.g. on device revocation or vault reset). */
export async function deleteDeviceRecord(vaultId: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_KEYS, 'readwrite');
    tx.objectStore(STORE_DEVICE_KEYS).delete(vaultId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── Device CryptoKey ───────────────────────────────────────────────────────

/**
 * Generate a new non-extractable AES-256-GCM CryptoKey for shard wrapping and store it.
 *
 * SECURITY: extractable=false means the key bytes can never be read by JavaScript,
 * including XSS payloads. The key can only be used via crypto.subtle.encrypt/decrypt.
 * This is the device "possession" factor in the three-factor BYO security model.
 */
export async function generateDeviceCryptoKey(vaultId: string): Promise<CryptoKey> {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable
    ['encrypt', 'decrypt'],
  );
  await setDeviceCryptoKey(vaultId, key);
  return key;
}

/**
 * Read the raw device CryptoKey for a vault from IDB, without consulting the
 * WebAuthn gate. Returns null if no row exists. Use `getDeviceCryptoKey`
 * (the public API) from normal app flows — it transparently delegates to
 * the gate when one is configured.
 */
export async function readRawDeviceCryptoKey(
  vaultId: string,
): Promise<CryptoKey | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_CRYPTO_KEYS, 'readonly');
    const req = tx.objectStore(STORE_DEVICE_CRYPTO_KEYS).get(vaultId);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Resolve the device CryptoKey for a vault, routing through the WebAuthn
 * gate when one is configured (SECURITY.md §12):
 *   - mode 'none'  → return the plain stored CryptoKey as today.
 *   - mode 'prf'   → ignore the raw store and invoke
 *                    `WebAuthnGate.unlockDeviceKey`, which prompts the
 *                    user (if not already cached for this session) and
 *                    returns the CryptoKey derived from the PRF output.
 *   - mode 'presence' → WebAuthnGate prompts for a touch, then returns
 *                    the plain stored CryptoKey.
 *
 * Callers that invoke this from an async flow originating in a user-
 * gesture click will see the WebAuthn prompt at that click's transient
 * activation. Post-unlock reads hit the module-local session cache and
 * never prompt again for the tab lifetime.
 *
 * Returns null when no key is enrolled in either store.
 */
export async function getDeviceCryptoKey(vaultId: string): Promise<CryptoKey | null> {
  const gate = await getWebAuthnRecord(vaultId);
  if (gate && gate.mode !== 'none' && gate.credentials.length > 0) {
    // Dynamic import avoids a static circular dep with WebAuthnGate and
    // keeps its DOM-bound code out of the initial bundle for users who
    // never enable the gate.
    const { unlockDeviceKey } = await import('./WebAuthnGate');
    return unlockDeviceKey(vaultId);
  }
  return readRawDeviceCryptoKey(vaultId);
}

/** Store a device CryptoKey. Used during enrollment when importing an existing key. */
export async function setDeviceCryptoKey(vaultId: string, key: CryptoKey): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_CRYPTO_KEYS, 'readwrite');
    tx.objectStore(STORE_DEVICE_CRYPTO_KEYS).put(key, vaultId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Delete the device CryptoKey for a vault (e.g. on device revocation). */
export async function deleteDeviceCryptoKey(vaultId: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_CRYPTO_KEYS, 'readwrite');
    tx.objectStore(STORE_DEVICE_CRYPTO_KEYS).delete(vaultId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── Dirty flags ────────────────────────────────────────────────────────────

/**
 * Mark a vault as dirty (unsaved changes pending).
 *
 * Called synchronously from the beforeunload handler — IndexedDB writes are
 * synchronous in that the IDBRequest is dispatched, though the commit may
 * flush asynchronously. The vault must NOT be saved asynchronously in
 * beforeunload (BYO_PLAN §4.1); the WAL is the crash recovery mechanism.
 */
export async function setDirtyFlag(vaultId: string, dirty: boolean): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DIRTY_FLAGS, 'readwrite');
    if (dirty) {
      tx.objectStore(STORE_DIRTY_FLAGS).put(true, vaultId);
    } else {
      tx.objectStore(STORE_DIRTY_FLAGS).delete(vaultId);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Check if a vault has unrecovered dirty state (crash recovery needed). */
export async function getDirtyFlag(vaultId: string): Promise<boolean> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DIRTY_FLAGS, 'readonly');
    const req = tx.objectStore(STORE_DIRTY_FLAGS).get(vaultId);
    req.onsuccess = () => resolve(req.result === true);
    req.onerror = () => reject(req.error);
  });
}

// ── WAL entries ────────────────────────────────────────────────────────────

/** Append an encrypted WAL entry for crash recovery. */
export async function appendWalEntry(entry: WalEntry): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_WAL, 'readwrite');
    tx.objectStore(STORE_WAL).add(entry);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Read all WAL entries for a vault, ordered by id (insertion order). */
export async function getWalEntries(vaultId: string): Promise<WalEntry[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_WAL, 'readonly');
    const index = tx.objectStore(STORE_WAL).index('by_vault_id');
    const req = index.getAll(IDBKeyRange.only(vaultId));
    req.onsuccess = () => {
      const entries: WalEntry[] = req.result ?? [];
      // Sort by id ascending (insertion order) — should already be in order
      entries.sort((a, b) => (a.id ?? 0) - (b.id ?? 0));
      resolve(entries);
    };
    req.onerror = () => reject(req.error);
  });
}

// ── WebAuthn gate state ────────────────────────────────────────────────────

/**
 * Read the per-vault WebAuthn gate record. Returns null when no row exists
 * (equivalent to mode 'none' — the caller should fall back to the plain
 * `device_crypto_keys` path).
 */
export async function getWebAuthnRecord(
  vaultId: string,
): Promise<DeviceWebAuthnRecord | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_WEBAUTHN, 'readonly');
    const req = tx.objectStore(STORE_DEVICE_WEBAUTHN).get(vaultId);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

/** Write or replace the per-vault WebAuthn gate record. */
export async function setWebAuthnRecord(
  record: DeviceWebAuthnRecord,
): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_WEBAUTHN, 'readwrite');
    tx.objectStore(STORE_DEVICE_WEBAUTHN).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/**
 * Delete the per-vault WebAuthn gate record. Called when the user disables
 * the gate from Settings; after this call `getWebAuthnRecord` returns null
 * and the standard `device_crypto_keys` path takes over.
 */
export async function clearWebAuthnRecord(vaultId: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_WEBAUTHN, 'readwrite');
    tx.objectStore(STORE_DEVICE_WEBAUTHN).delete(vaultId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Delete all WAL entries for a vault (called after successful vault save). */
export async function clearWalEntries(vaultId: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_WAL, 'readwrite');
    const index = tx.objectStore(STORE_WAL).index('by_vault_id');
    const req = index.getAllKeys(IDBKeyRange.only(vaultId));
    req.onsuccess = () => {
      const keys = req.result ?? [];
      for (const key of keys) {
        tx.objectStore(STORE_WAL).delete(key);
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
