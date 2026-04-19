/**
 * VaultBodyCache — IndexedDB cache for encrypted vault bodies.
 *
 * Stores the encrypted body blob for each provider's vault so that offline
 * access is possible. The blobs are AES-GCM ciphertext under the per-vault
 * key — safe to persist in IDB without additional wrapping.
 *
 * Also caches the encrypted manifest body so that on-reconnect merging can
 * read the last-known-good manifest version.
 *
 * Schema (IDB object stores):
 *   "vault_body_cache"   — keyed by `<vaultId>:<providerId>`
 *   "manifest_cache"     — keyed by `<vaultId>`
 *
 * SECURITY: Only ciphertext is stored. Plaintext SQLite bytes never touch IDB.
 */

const DB_NAME = 'sc_vault_body_cache';
const DB_VERSION = 1;
const BODY_STORE = 'vault_body_cache';
const MANIFEST_STORE = 'manifest_cache';

// ── Types ─────────────────────────────────────────────────────────────────

export interface CachedVaultBody {
  /** Compound key: `<vaultId>:<providerId>` */
  key: string;
  /** base64-encoded encrypted body blob `[iv(12) | ct+tag]` */
  blob_b64: string;
  /** ETag / version string from the cloud provider (for conflict detection). */
  version: string;
  /** Unix timestamp when this entry was cached. */
  stored_at: number;
}

export interface CachedManifest {
  /** Key: vaultId */
  vault_id: string;
  /** base64-encoded encrypted manifest body blob */
  blob_b64: string;
  /** ETag / version string from the provider this was downloaded from. */
  version: string;
  /** Monotonic manifest_version field (from the decrypted manifest). */
  manifest_version: number;
  /** Unix timestamp when this entry was cached. */
  stored_at: number;
  /**
   * base64-encoded vault header bytes (1227 B).
   * Stored to enable vault unlock when the primary provider is offline (H2).
   * The header only changes on passphrase change / re-key.
   */
  header_bytes_b64?: string;
}

// ── DB open ────────────────────────────────────────────────────────────────

let _db: IDBDatabase | null = null;

async function openDb(): Promise<IDBDatabase> {
  if (_db) return _db;

  return new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(BODY_STORE)) {
        db.createObjectStore(BODY_STORE, { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains(MANIFEST_STORE)) {
        db.createObjectStore(MANIFEST_STORE, { keyPath: 'vault_id' });
      }
    };

    req.onsuccess = (event) => {
      _db = (event.target as IDBOpenDBRequest).result;
      resolve(_db);
    };

    req.onerror = () => reject(req.error);
  });
}

// ── Vault body cache ────────────────────────────────────────────────────────

/** Store an encrypted vault body blob for a provider. */
export async function storeCachedBody(
  vaultId: string,
  providerId: string,
  blobB64: string,
  version: string,
): Promise<void> {
  const db = await openDb();
  const entry: CachedVaultBody = {
    key: `${vaultId}:${providerId}`,
    blob_b64: blobB64,
    version,
    stored_at: Date.now(),
  };
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(BODY_STORE, 'readwrite');
    const store = tx.objectStore(BODY_STORE);
    const req = store.put(entry);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

/** Load a cached encrypted vault body for a provider. Returns null if not cached. */
export async function loadCachedBody(
  vaultId: string,
  providerId: string,
): Promise<CachedVaultBody | null> {
  const db = await openDb();
  return new Promise<CachedVaultBody | null>((resolve, reject) => {
    const tx = db.transaction(BODY_STORE, 'readonly');
    const store = tx.objectStore(BODY_STORE);
    const req = store.get(`${vaultId}:${providerId}`);
    req.onsuccess = () => resolve((req.result as CachedVaultBody | undefined) ?? null);
    req.onerror = () => reject(req.error);
  });
}

// ── Manifest cache ─────────────────────────────────────────────────────────

/** Store the encrypted manifest body (from any provider). */
export async function storeCachedManifest(
  vaultId: string,
  blobB64: string,
  version: string,
  manifestVersion: number,
  headerBytesB64?: string,
): Promise<void> {
  const db = await openDb();
  const entry: CachedManifest = {
    vault_id: vaultId,
    blob_b64: blobB64,
    version,
    manifest_version: manifestVersion,
    stored_at: Date.now(),
    ...(headerBytesB64 !== undefined ? { header_bytes_b64: headerBytesB64 } : {}),
  };
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(MANIFEST_STORE, 'readwrite');
    const store = tx.objectStore(MANIFEST_STORE);
    const req = store.put(entry);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

/** Load the cached encrypted manifest. Returns null if not cached. */
export async function loadCachedManifest(vaultId: string): Promise<CachedManifest | null> {
  const db = await openDb();
  return new Promise<CachedManifest | null>((resolve, reject) => {
    const tx = db.transaction(MANIFEST_STORE, 'readonly');
    const store = tx.objectStore(MANIFEST_STORE);
    const req = store.get(vaultId);
    req.onsuccess = () => resolve((req.result as CachedManifest | undefined) ?? null);
    req.onerror = () => reject(req.error);
  });
}

// ── Cleanup ────────────────────────────────────────────────────────────────

/** Remove all cached entries for a vault (e.g. after vault deletion). */
export async function clearVaultCache(vaultId: string): Promise<void> {
  const db = await openDb();
  // Remove manifest
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(MANIFEST_STORE, 'readwrite');
    const req = tx.objectStore(MANIFEST_STORE).delete(vaultId);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
  // Remove all body entries for this vault (prefix scan)
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(BODY_STORE, 'readwrite');
    const store = tx.objectStore(BODY_STORE);
    const range = IDBKeyRange.bound(`${vaultId}:`, `${vaultId}:\uFFFF`);
    const req = store.openCursor(range);
    req.onsuccess = () => {
      const cursor = req.result as IDBCursorWithValue | null;
      if (cursor) {
        cursor.delete();
        cursor.continue();
      } else {
        resolve();
      }
    };
    req.onerror = () => reject(req.error);
  });
}
