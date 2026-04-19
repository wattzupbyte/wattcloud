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
const DB_VERSION = 1;

const STORE_DEVICE_KEYS = 'device_keys';
const STORE_DEVICE_CRYPTO_KEYS = 'device_crypto_keys';
const STORE_WAL = 'wal';
const STORE_DIRTY_FLAGS = 'dirty_flags';

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

function openDB(): Promise<IDBDatabase> {
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

/** Read the device CryptoKey for a vault. Returns null if not enrolled. */
export async function getDeviceCryptoKey(vaultId: string): Promise<CryptoKey | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE_CRYPTO_KEYS, 'readonly');
    const req = tx.objectStore(STORE_DEVICE_CRYPTO_KEYS).get(vaultId);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
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
