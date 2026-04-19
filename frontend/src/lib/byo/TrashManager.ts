/**
 * BYO Trash Manager
 *
 * Manages the `trash` SQLite table. Supports:
 *   - Listing trash entries with optional blob availability check
 *   - Restoring files/folders to their original table
 *   - Permanent deletion (removes blob from provider)
 *   - Auto-purge of entries expired >30 days
 *
 * Blob lifecycle: provider blobs are NOT deleted on soft-delete (move to trash).
 * They are only removed on permanent delete or auto-purge.
 *
 * See BYO_PLAN §1.5 (trash table), §6.4 (ByoTrash component notes).
 */

import type { StorageProvider } from '@wattcloud/sdk';
import { ProviderError } from '@wattcloud/sdk';
import type { TrashEntry } from './DataProvider';
import { queryRows } from './ConflictResolver';

// ── TrashManager ──────────────────────────────────────────────────────────

export class TrashManager {
  private readonly db: import('sql.js').Database;
  private readonly provider: StorageProvider;
  private readonly onMutate: (sql: string, params: unknown[]) => Promise<void>;

  constructor(
    db: import('sql.js').Database,
    provider: StorageProvider,
    onMutate: (sql: string, params: unknown[]) => Promise<void>,
  ) {
    this.db = db;
    this.provider = provider;
    this.onMutate = onMutate;
  }

  // ── List ──────────────────────────────────────────────────────────────

  /** List all trash entries for the vault. */
  listTrash(): TrashEntry[] {
    const rows = queryRows(
      this.db,
      'SELECT id, item_type, original_id, data, deleted_at, expires_at FROM trash ORDER BY deleted_at DESC',
    );
    return rows.map((r) => ({
      id: r['id'] as number,
      item_type: r['item_type'] as 'file' | 'folder',
      original_id: r['original_id'] as number,
      data: r['data'] as string,
      deleted_at: r['deleted_at'] as string,
      expires_at: r['expires_at'] as string,
      blob_available: null,
    }));
  }

  // ── Blob availability check ───────────────────────────────────────────

  /**
   * Check if the provider blob for a trash entry still exists.
   * Returns true if available, false if NOT_FOUND.
   */
  async checkBlobAvailability(entry: TrashEntry): Promise<boolean> {
    if (entry.item_type !== 'file') return false;

    try {
      const rowData = JSON.parse(entry.data) as { storage_ref?: string };
      if (!rowData.storage_ref) return false;

      await this.provider.getVersion(rowData.storage_ref);
      return true;
    } catch (err) {
      if (err instanceof ProviderError && err.code === 'NOT_FOUND') return false;
      return false;
    }
  }

  // ── Restore ───────────────────────────────────────────────────────────

  /**
   * Restore a trash entry back to its original table.
   *
   * For files: verifies blob still exists on provider first.
   * Returns false if blob is unavailable (user should permanently delete).
   */
  async restoreItem(trashId: number): Promise<boolean> {
    const rows = queryRows(this.db, 'SELECT * FROM trash WHERE id = ?', [trashId]);
    if (rows.length === 0) throw new Error(`Trash entry ${trashId} not found`);

    const entry = rows[0];
    const itemType = entry['item_type'] as 'file' | 'folder';
    const rowData = JSON.parse(entry['data'] as string) as Record<string, unknown>;

    // For files, verify blob exists
    if (itemType === 'file') {
      const storageRef = rowData['storage_ref'] as string | undefined;
      if (storageRef) {
        try {
          await this.provider.getVersion(storageRef);
        } catch (err) {
          if (err instanceof ProviderError && err.code === 'NOT_FOUND') {
            return false; // Blob gone — caller shows "Data unavailable"
          }
        }
      }
    }

    // Re-insert into original table
    const table = itemType === 'file' ? 'files' : 'folders';
    const cols = Object.keys(rowData);
    const placeholders = cols.map(() => '?').join(', ');
    const values = cols.map((c) => rowData[c]);

    const insertSql = `INSERT OR REPLACE INTO ${table} (${cols.join(', ')}) VALUES (${placeholders})`;
    await this.onMutate(insertSql, values);
    this.db.run(insertSql, values as import('sql.js').BindParams);

    // Remove from trash
    const deleteSql = 'DELETE FROM trash WHERE id = ?';
    await this.onMutate(deleteSql, [trashId]);
    this.db.run(deleteSql, [trashId]);

    return true;
  }

  // ── Permanent delete ──────────────────────────────────────────────────

  /**
   * Permanently delete a trash entry and its provider blob.
   */
  async permanentDelete(trashId: number): Promise<void> {
    const rows = queryRows(this.db, 'SELECT * FROM trash WHERE id = ?', [trashId]);
    if (rows.length === 0) throw new Error(`Trash entry ${trashId} not found`);

    const entry = rows[0];
    const itemType = entry['item_type'] as 'file' | 'folder';
    const rowData = JSON.parse(entry['data'] as string) as Record<string, unknown>;

    // Delete provider blob (file only)
    if (itemType === 'file') {
      const storageRef = rowData['storage_ref'] as string | undefined;
      if (storageRef) {
        try {
          await this.provider.delete(storageRef);
        } catch (err) {
          if (!(err instanceof ProviderError && err.code === 'NOT_FOUND')) {
            throw err;
          }
          // Already gone — acceptable
        }
      }
    }

    // Remove from trash table
    const deleteSql = 'DELETE FROM trash WHERE id = ?';
    await this.onMutate(deleteSql, [trashId]);
    this.db.run(deleteSql, [trashId]);
  }

  /** Delete all trash entries permanently. */
  async emptyTrash(): Promise<void> {
    const entries = this.listTrash();
    for (const entry of entries) {
      try {
        await this.permanentDelete(entry.id);
      } catch (err) {
        console.warn('[TrashManager] Failed to delete trash entry:', entry.id, err);
      }
    }
  }

  // ── Auto-purge ────────────────────────────────────────────────────────

  /**
   * Remove all trash entries where expires_at < now.
   * Deletes provider blobs for expired file entries.
   * Called on vault open.
   */
  async autoPurge(): Promise<number> {
    const now = new Date().toISOString();
    const expiredRows = queryRows(
      this.db,
      "SELECT id FROM trash WHERE expires_at < ?",
      [now],
    );

    let purged = 0;
    for (const row of expiredRows) {
      try {
        await this.permanentDelete(row['id'] as number);
        purged++;
      } catch (err) {
        console.warn('[TrashManager] autoPurge failed for id:', row['id'], err);
      }
    }

    return purged;
  }
}
