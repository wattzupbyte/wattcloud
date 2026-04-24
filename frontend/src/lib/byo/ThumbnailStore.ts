/**
 * Persistent thumbnail cache — per-vault, size-capped, AES-GCM wrapped.
 *
 * Thumbnails survive reload / lock so subsequent visits to Photos feel
 * instant instead of paying the download → decrypt → resize tax for each
 * photo every time. Rows are encrypted at rest under the per-vault
 * non-extractable device `CryptoKey` (same material protecting
 * provider configs), so a disk-image attacker sees nothing useful.
 *
 * Lifecycle invariants:
 *   - deleteVaultThumbnails(vaultId) runs alongside the other IDB wipes
 *     when a vault is "forgotten" on the device (VaultContextSheet).
 *   - Global cap ≈ 128 MB across all vaults; per-vault insert enforces an
 *     LRU rollover (oldest `last_access` first) until under cap.
 *   - Missing `device_crypto_keys` row → silently disables caching
 *     (writes no-op, reads return null). Not having a device key means
 *     we'd be caching plaintext, which is worse than a slower reload.
 */

import { openDB } from './DeviceKeyStore';

// ── Constants ──────────────────────────────────────────────────────────────

/** Hard cap on total encrypted ciphertext bytes across all vaults. */
const CACHE_MAX_BYTES = 128 * 1024 * 1024;
/** Once the cap is hit, evict until we're below this watermark so eviction doesn't run on every insert. */
const CACHE_EVICT_TO_BYTES = Math.floor(CACHE_MAX_BYTES * 0.8);
const STORE_THUMBNAILS = 'thumbnails';
const IDX_VAULT_ID = 'by_vault_id';
const IDX_LAST_ACCESS = 'by_last_access';

// ── Types ──────────────────────────────────────────────────────────────────

interface ThumbRow {
  /** Primary key: `${vault_id}:${file_id}`. */
  key: string;
  vault_id: string;
  file_id: number;
  /** AES-GCM ciphertext of the thumbnail bytes. */
  ct: ArrayBuffer;
  /** 12-byte AES-GCM IV. */
  iv: ArrayBuffer;
  /** MIME of the plaintext thumbnail (usually "image/webp" — see resizeToThumbnail). */
  mime: string;
  /** Encrypted-size in bytes, used for cap accounting without reading the blob. */
  bytes: number;
  /** Unix-ms of the last read or write, used for LRU eviction. */
  last_access: number;
}

// ── DB helpers ─────────────────────────────────────────────────────────────

/** Alias to DeviceKeyStore's openDB — the v4 upgrade there creates the thumbnails store. */
const openThumbnailDB = openDB;

async function getDeviceKey(vaultId: string): Promise<CryptoKey | null> {
  const { getDeviceCryptoKey } = await import('./DeviceKeyStore');
  try { return await getDeviceCryptoKey(vaultId); } catch { return null; }
}

function rowKey(vaultId: string, fileId: number): string {
  return `${vaultId}:${fileId}`;
}

// ── Public API ─────────────────────────────────────────────────────────────

/** Read a cached thumbnail. Returns null on miss / decrypt failure / no device key. */
export async function readCachedThumbnail(
  vaultId: string,
  fileId: number,
): Promise<{ bytes: Uint8Array; mime: string } | null> {
  const key = await getDeviceKey(vaultId);
  if (!key) return null;

  let row: ThumbRow | undefined;
  try {
    const db = await openThumbnailDB();
    row = await new Promise<ThumbRow | undefined>((resolve, reject) => {
      const tx = db.transaction(STORE_THUMBNAILS, 'readonly');
      const req = tx.objectStore(STORE_THUMBNAILS).get(rowKey(vaultId, fileId));
      req.onsuccess = () => resolve(req.result as ThumbRow | undefined);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
  if (!row) return null;

  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: row.iv }, key, row.ct);
    // Best-effort `last_access` bump so LRU ranks reads honestly. A
    // failed write here shouldn't affect the caller — return the bytes.
    touchLastAccess(vaultId, fileId).catch(() => {});
    return { bytes: new Uint8Array(pt), mime: row.mime };
  } catch {
    return null;
  }
}

/** Write a thumbnail into the cache, enforcing the global byte cap. */
export async function writeCachedThumbnail(
  vaultId: string,
  fileId: number,
  bytes: Uint8Array,
  mime: string,
): Promise<void> {
  const key = await getDeviceKey(vaultId);
  if (!key) return;

  const iv = crypto.getRandomValues(new Uint8Array(12));
  let ct: ArrayBuffer;
  try {
    ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      // Slice to a fresh ArrayBuffer — subtle.encrypt rejects typed-array
      // views into shared buffers on some engines.
      bytes.slice().buffer,
    );
  } catch {
    return;
  }

  const row: ThumbRow = {
    key: rowKey(vaultId, fileId),
    vault_id: vaultId,
    file_id: fileId,
    ct,
    iv: iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength),
    mime,
    bytes: ct.byteLength + iv.byteLength,
    last_access: Date.now(),
  };

  try {
    const db = await openThumbnailDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_THUMBNAILS, 'readwrite');
      tx.objectStore(STORE_THUMBNAILS).put(row);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    return;
  }

  // Enforce the cap out-of-band — this read/delete cycle doesn't need
  // to block the caller on the happy path.
  enforceCap().catch(() => {});
}

/** Delete every thumbnail owned by a vault (used on forget / vault wipe). */
export async function deleteVaultThumbnails(vaultId: string): Promise<void> {
  let db: IDBDatabase;
  try { db = await openThumbnailDB(); } catch { return; }
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_THUMBNAILS, 'readwrite');
    const store = tx.objectStore(STORE_THUMBNAILS);
    const idx = store.index(IDX_VAULT_ID);
    const req = idx.openCursor(IDBKeyRange.only(vaultId));
    req.onsuccess = () => {
      const cursor = req.result;
      if (!cursor) return;
      cursor.delete();
      cursor.continue();
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── Internals ──────────────────────────────────────────────────────────────

async function touchLastAccess(vaultId: string, fileId: number): Promise<void> {
  const db = await openThumbnailDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_THUMBNAILS, 'readwrite');
    const store = tx.objectStore(STORE_THUMBNAILS);
    const getReq = store.get(rowKey(vaultId, fileId));
    getReq.onsuccess = () => {
      const r = getReq.result as ThumbRow | undefined;
      if (r) {
        r.last_access = Date.now();
        store.put(r);
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function enforceCap(): Promise<void> {
  const db = await openThumbnailDB();

  // Tally current total.
  const { total, entries } = await new Promise<{ total: number; entries: ThumbRow[] }>(
    (resolve, reject) => {
      const tx = db.transaction(STORE_THUMBNAILS, 'readonly');
      const req = tx.objectStore(STORE_THUMBNAILS).index(IDX_LAST_ACCESS).openCursor();
      let sum = 0;
      const rows: ThumbRow[] = [];
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor) return;
        const r = cursor.value as ThumbRow;
        sum += r.bytes;
        rows.push(r);
        cursor.continue();
      };
      tx.oncomplete = () => resolve({ total: sum, entries: rows });
      tx.onerror = () => reject(tx.error);
    },
  );

  if (total <= CACHE_MAX_BYTES) return;

  // Delete oldest first until we drop below the evict-to watermark.
  // `entries` is already sorted by last_access ascending (index order).
  let running = total;
  const toDelete: string[] = [];
  for (const r of entries) {
    if (running <= CACHE_EVICT_TO_BYTES) break;
    toDelete.push(r.key);
    running -= r.bytes;
  }
  if (toDelete.length === 0) return;

  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_THUMBNAILS, 'readwrite');
    const store = tx.objectStore(STORE_THUMBNAILS);
    for (const k of toDelete) store.delete(k);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
