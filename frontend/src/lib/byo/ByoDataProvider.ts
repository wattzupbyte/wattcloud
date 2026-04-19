/**
 * BYO Data Provider
 *
 * Implements the DataProvider interface. Orchestrates:
 *   - sql.js in-memory SQLite (decrypted vault body)
 *   - StorageProvider (cloud blob I/O)
 *   - BYO Web Worker via byoWorkerClient (all crypto)
 *   - IndexedDB WAL (crash recovery)
 *   - VaultJournal (cloud-side append-only mutation log)
 *
 * All mutating methods:
 *   1. Check online + vault unlocked
 *   2. Append WAL entry (crash recovery)
 *   3. Execute SQL mutation
 *   4. Append journal entry (cloud journal)
 *   5. markDirty() (schedules debounced save)
 *   6. Update search index / stores
 *
 * OAuth refresh token expiry: every provider call is wrapped in
 * withAuthRetry() which catches UnauthorizedError, calls refreshAuth(),
 * and retries. On second failure, error surfaces to UI.
 *
 * See BYO_PLAN §6.1, §3.2 (OAuth), §4.5 (offline).
 */

import type { StorageProvider } from '@secure-cloud/byo';
import { UnauthorizedError, ProviderError, acquireRelayCookie, recordEvent, addShareRelayBandwidth } from '@secure-cloud/byo';
import { ByoUploadStream } from '@secure-cloud/byo';
import { ByoDownloadStream } from '@secure-cloud/byo';
import * as byoWorker from '@secure-cloud/byo';
import type {
  DataProvider,
  FileEntry,
  FolderEntry,
  StorageUsage,
  TrashEntry,
  ShareEntry,
  ShareVariant,
} from './DataProvider';
import { markDirty, getProvider, getJournal, getWalKey, getWalKeyForProvider, getVaultId, getOrInitProvider } from './VaultLifecycle';
import { bytesToBase64 as _bytesToBase64 } from './base64';
import { appendWal, appendWalBlobDelete } from './IndexedDBWal';
import { queryRows } from './ConflictResolver';
import { SearchIndex } from './SearchIndex';
import { TrashManager } from './TrashManager';
import { byoFiles, byoFolders } from './stores/byoFileStore';

// ── Constants ──────────────────────────────────────────────────────────────

/** Max concurrent filename decryptions when populating file lists. */
const DECRYPT_CONCURRENCY = 20;

// ── ByoDataProvider ────────────────────────────────────────────────────────

export class ByoDataProvider implements DataProvider {
  private readonly db: import('sql.js').Database;
  /** Primary provider (backward compat + upload target for single-provider vaults). */
  private readonly provider: StorageProvider;
  private readonly sessionId: string;
  /** provider_id of the active tab — uploads go here. Mutable: changes on tab-switch. */
  activeProviderId: string;
  readonly searchIndex: SearchIndex;
  readonly trash: TrashManager;

  constructor(
    db: import('sql.js').Database,
    provider: StorageProvider,
    activeProviderId: string,
    sessionId: string,
  ) {
    this.db = db;
    this.provider = provider;
    this.activeProviderId = activeProviderId;
    this.sessionId = sessionId;
    this.searchIndex = new SearchIndex();
    this.trash = new TrashManager(db, provider, this.onMutate.bind(this));
  }

  /** Switch the active provider (called when user selects a different tab). */
  setActiveProviderId(providerId: string): void {
    this.activeProviderId = providerId;
  }

  /** Resolve the provider for a given provider_id. In R6 provider_id is always NOT NULL. */
  private async resolveProvider(providerId: string): Promise<StorageProvider> {
    const p = await getOrInitProvider(providerId);
    return p ?? this.provider;
  }

  // ── File operations ────────────────────────────────────────────────────

  async listFiles(folderId: number | null): Promise<FileEntry[]> {
    const pid = this.activeProviderId;
    const sql = folderId === null
      ? 'SELECT * FROM files WHERE folder_id IS NULL AND provider_id = ? ORDER BY name'
      : 'SELECT * FROM files WHERE folder_id = ? AND provider_id = ? ORDER BY name';
    const params = folderId === null ? [pid] : [folderId, pid];
    const rows = queryRows(this.db, sql, params as import('sql.js').BindParams);
    const entries = await this.decryptFileRows(rows);
    byoFiles.set(entries);
    return entries;
  }

  async uploadFile(
    folderId: number | null,
    file: File,
    onProgress?: (bytesWritten: number) => void,
    uploadOpts?: { pauseSignal?: { isPaused(): boolean; wait(): Promise<void> } },
  ): Promise<FileEntry> {
    this.checkOperational();

    const activeKeyVersionId = await this.getActiveKeyVersionId();
    const publicKeysJson = await this.getActivePublicKeysJson();

    // Encrypt filename
    const { encrypted_filename, encrypted_filename_key } =
      await byoWorker.Worker.encryptFilenameAtomic(file.name, publicKeysJson);

    // Stream-encrypt and upload to the active provider's SecureCloud/data folder.
    const activeProvider = await this.resolveProvider(this.activeProviderId);
    const uploadResult = await this.withAuthRetry(() =>
      ByoUploadStream.upload(activeProvider, file, 'SecureCloud/data', publicKeysJson, {
        onProgress: onProgress ? (pct) => onProgress(Math.round(pct * file.size)) : undefined,
        pauseSignal: uploadOpts?.pauseSignal,
      }),
    );
    const storageRef = uploadResult.ref;

    const now = new Date().toISOString();
    const insertSql = `
      INSERT INTO files (folder_id, name, filename_key, size, encrypted_size, storage_ref, mime_type, file_type, key_version_id, metadata, created_at, updated_at, provider_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const insertParams = [
      folderId ?? null,
      encrypted_filename,
      encrypted_filename_key,
      file.size,
      0, // encrypted size not tracked per blob
      storageRef,
      file.type || '',
      inferFileType(file.name),
      activeKeyVersionId,
      '',
      now,
      now,
      this.activeProviderId,
    ];

    await this.onMutate(insertSql, insertParams);
    this.db.run(insertSql, insertParams as import('sql.js').BindParams);

    const lastId = queryRows(this.db, 'SELECT last_insert_rowid() AS id')[0]['id'] as number;

    const entry: FileEntry = {
      id: lastId,
      folder_id: folderId,
      name: encrypted_filename,
      decrypted_name: file.name,
      size: file.size,
      encrypted_size: 0,
      storage_ref: storageRef,
      mime_type: file.type || '',
      file_type: inferFileType(file.name),
      key_version_id: activeKeyVersionId,
      metadata: '',
      created_at: now,
      updated_at: now,
      provider_id: this.activeProviderId,
    };

    this.searchIndex.upsert(lastId, file.name);
    markDirty();
    return entry;
  }

  async downloadFile(fileId: number): Promise<ReadableStream<Uint8Array>> {
    this.checkOperational();

    const rows = queryRows(this.db, 'SELECT * FROM files WHERE id = ?', [fileId]);
    if (rows.length === 0) throw new Error(`File ${fileId} not found`);

    const row = rows[0];
    const storageRef = row['storage_ref'] as string;
    // Route download to the provider that holds this file's blob. provider_id is NOT NULL in R6.
    const fileProviderId = row['provider_id'] as string;
    const provider = await this.resolveProvider(fileProviderId);
    const keySessionId = this.sessionId;

    // Convert the async generator from ByoDownloadStream.decrypt() to a ReadableStream.
    // byoKeySessionId tells the BYO worker to look up private keys by our session ID.
    return new ReadableStream<Uint8Array>({
      start(controller) {
        const gen = ByoDownloadStream.decrypt(provider, storageRef, '', undefined, keySessionId);
        async function pump() {
          try {
            for await (const chunk of gen) {
              controller.enqueue(chunk);
            }
            controller.close();
          } catch (err) {
            controller.error(err);
          }
        }
        pump();
      },
    });
  }

  async deleteFile(fileId: number): Promise<void> {
    this.checkOperational();

    const rows = queryRows(this.db, 'SELECT * FROM files WHERE id = ?', [fileId]);
    if (rows.length === 0) throw new Error(`File ${fileId} not found`);

    const row = rows[0];
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const rowJson = JSON.stringify(row);

    // Move to trash
    const insertTrashSql = `
      INSERT INTO trash (item_type, original_id, data, deleted_at, expires_at)
      VALUES ('file', ?, ?, ?, ?)
    `;
    const insertTrashParams = [fileId, rowJson, now, expiresAt];
    await this.onMutate(insertTrashSql, insertTrashParams);
    this.db.run(insertTrashSql, insertTrashParams as import('sql.js').BindParams);

    // Remove from files table
    const deleteSql = 'DELETE FROM files WHERE id = ?';
    await this.onMutate(deleteSql, [fileId]);
    this.db.run(deleteSql, [fileId]);

    this.searchIndex.remove(fileId);
    markDirty();
  }

  async moveFile(fileId: number, targetFolderId: number | null): Promise<void> {
    this.checkOperational();

    // Cross-provider move is not allowed via this path — use the cross-provider move flow.
    if (targetFolderId !== null) {
      const fileRows = queryRows(this.db, 'SELECT provider_id FROM files WHERE id = ?', [fileId]);
      const folderRows = queryRows(this.db, 'SELECT provider_id FROM folders WHERE id = ?', [targetFolderId]);
      if (fileRows.length > 0 && folderRows.length > 0) {
        const filePid = fileRows[0]['provider_id'] as string;
        const folderPid = folderRows[0]['provider_id'] as string;
        if (filePid !== folderPid) {
          throw new Error('Cross-provider move not allowed via moveFile — use the cross-provider move flow');
        }
      }
    }

    const now = new Date().toISOString();
    const sql = 'UPDATE files SET folder_id = ?, updated_at = ? WHERE id = ?';
    const params = [targetFolderId ?? null, now, fileId];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);
    markDirty();
  }

  async renameFile(fileId: number, newName: string): Promise<void> {
    this.checkOperational();

    const publicKeysJson = await this.getActivePublicKeysJson();
    const { encrypted_filename, encrypted_filename_key } =
      await byoWorker.Worker.encryptFilenameAtomic(newName, publicKeysJson);

    const now = new Date().toISOString();
    const sql = 'UPDATE files SET name = ?, filename_key = ?, updated_at = ? WHERE id = ?';
    const params = [encrypted_filename, encrypted_filename_key, now, fileId];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);

    this.searchIndex.upsert(fileId, newName);
    markDirty();
  }

  // ── Folder operations ──────────────────────────────────────────────────

  async listFolders(parentId: number | null): Promise<FolderEntry[]> {
    const pid = this.activeProviderId;
    const sql = parentId === null
      ? 'SELECT * FROM folders WHERE parent_id IS NULL AND provider_id = ? ORDER BY name'
      : 'SELECT * FROM folders WHERE parent_id = ? AND provider_id = ? ORDER BY name';
    const params = parentId === null ? [pid] : [parentId, pid];
    const rows = queryRows(this.db, sql, params as import('sql.js').BindParams);
    const entries = await this.decryptFolderRows(rows);
    byoFolders.set(entries);
    return entries;
  }

  async createFolder(parentId: number | null, name: string): Promise<FolderEntry> {
    this.checkOperational();

    const publicKeysJson = await this.getActivePublicKeysJson();
    const { encrypted_filename: encName, encrypted_filename_key: nameKey } =
      await byoWorker.Worker.encryptFilenameAtomic(name, publicKeysJson);

    const now = new Date().toISOString();
    const sql = `
      INSERT INTO folders (parent_id, name, name_key, created_at, updated_at, provider_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    const params = [parentId ?? null, encName, nameKey, now, now, this.activeProviderId];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);

    const lastId = queryRows(this.db, 'SELECT last_insert_rowid() AS id')[0]['id'] as number;

    const entry: FolderEntry = {
      id: lastId,
      parent_id: parentId,
      name: encName,
      decrypted_name: name,
      name_key: nameKey,
      created_at: now,
      updated_at: now,
    };

    markDirty();
    return entry;
  }

  async deleteFolder(folderId: number): Promise<void> {
    this.checkOperational();

    const rows = queryRows(this.db, 'SELECT * FROM folders WHERE id = ?', [folderId]);
    if (rows.length === 0) throw new Error(`Folder ${folderId} not found`);

    const row = rows[0];
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const rowJson = JSON.stringify(row);

    const insertTrashSql = `
      INSERT INTO trash (item_type, original_id, data, deleted_at, expires_at)
      VALUES ('folder', ?, ?, ?, ?)
    `;
    const insertTrashParams = [folderId, rowJson, now, expiresAt];
    await this.onMutate(insertTrashSql, insertTrashParams);
    this.db.run(insertTrashSql, insertTrashParams as import('sql.js').BindParams);

    const deleteSql = 'DELETE FROM folders WHERE id = ?';
    await this.onMutate(deleteSql, [folderId]);
    this.db.run(deleteSql, [folderId]);

    markDirty();
  }

  async renameFolder(folderId: number, newName: string): Promise<void> {
    this.checkOperational();

    const publicKeysJson = await this.getActivePublicKeysJson();
    const { encrypted_filename: encName, encrypted_filename_key: nameKey } =
      await byoWorker.Worker.encryptFilenameAtomic(newName, publicKeysJson);

    const now = new Date().toISOString();
    const sql = 'UPDATE folders SET name = ?, name_key = ?, updated_at = ? WHERE id = ?';
    const params = [encName, nameKey, now, folderId];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);

    markDirty();
  }

  async moveFolder(folderId: number, targetParentId: number | null): Promise<void> {
    this.checkOperational();

    // Cross-provider move is not allowed via this path — use the cross-provider move flow.
    if (targetParentId !== null) {
      const srcRows = queryRows(this.db, 'SELECT provider_id FROM folders WHERE id = ?', [folderId]);
      const dstRows = queryRows(this.db, 'SELECT provider_id FROM folders WHERE id = ?', [targetParentId]);
      if (srcRows.length > 0 && dstRows.length > 0) {
        const srcPid = srcRows[0]['provider_id'] as string;
        const dstPid = dstRows[0]['provider_id'] as string;
        if (srcPid !== dstPid) {
          throw new Error('Cross-provider move not allowed via moveFolder — use the cross-provider move flow');
        }
      }
    }

    const now = new Date().toISOString();
    const sql = 'UPDATE folders SET parent_id = ?, updated_at = ? WHERE id = ?';
    const params = [targetParentId ?? null, now, folderId];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);

    markDirty();
  }

  // ── Favorites ──────────────────────────────────────────────────────────

  async getFavorites(): Promise<{ files: FileEntry[]; folders: FolderEntry[] }> {
    const fileRows = queryRows(
      this.db,
      "SELECT f.* FROM files f JOIN favorites fav ON fav.item_id = f.id WHERE fav.item_type = 'file'",
    );
    const folderRows = queryRows(
      this.db,
      "SELECT f.* FROM folders f JOIN favorites fav ON fav.item_id = f.id WHERE fav.item_type = 'folder'",
    );
    const files = await this.decryptFileRows(fileRows);
    const folders = await this.decryptFolderRows(folderRows);
    return { files, folders };
  }

  async toggleFavorite(type: 'file' | 'folder', id: number): Promise<boolean> {
    this.checkOperational();

    const existing = queryRows(
      this.db,
      'SELECT id FROM favorites WHERE item_type = ? AND item_id = ?',
      [type, id],
    );

    if (existing.length > 0) {
      const sql = 'DELETE FROM favorites WHERE item_type = ? AND item_id = ?';
      const params = [type, id];
      await this.onMutate(sql, params);
      this.db.run(sql, params as import('sql.js').BindParams);
      markDirty();
      return false;
    } else {
      const now = new Date().toISOString();
      const sql = 'INSERT INTO favorites (item_type, item_id, created_at) VALUES (?, ?, ?)';
      const params = [type, id, now];
      await this.onMutate(sql, params);
      this.db.run(sql, params as import('sql.js').BindParams);
      markDirty();
      return true;
    }
  }

  // ── Search ─────────────────────────────────────────────────────────────

  async searchFiles(query: string): Promise<FileEntry[]> {
    const matchingIds = this.searchIndex.search(query);
    if (matchingIds.length === 0) return [];

    const placeholders = matchingIds.map(() => '?').join(', ');
    const rows = queryRows(
      this.db,
      `SELECT * FROM files WHERE id IN (${placeholders})`,
      matchingIds as import('sql.js').BindParams,
    );
    return this.decryptFileRows(rows);
  }

  async listImageFiles(): Promise<FileEntry[]> {
    const rows = queryRows(
      this.db,
      `SELECT * FROM files WHERE file_type = 'image' ORDER BY created_at DESC`,
      [],
    );
    return this.decryptFileRows(rows);
  }

  // ── Storage usage ──────────────────────────────────────────────────────

  async getStorageUsage(): Promise<StorageUsage> {
    const rows = queryRows(this.db, 'SELECT COALESCE(SUM(size), 0) AS total FROM files');
    const used = rows[0]?.['total'] as number ?? 0;
    return { used, quota: null };
  }

  // ── Key versions ───────────────────────────────────────────────────────

  async getActivePublicKeysJson(): Promise<string> {
    const rows = queryRows(
      this.db,
      "SELECT mlkem_public_key, x25519_public_key FROM key_versions WHERE status = 'active' ORDER BY version DESC LIMIT 1",
    );
    if (rows.length === 0) throw new Error('No active key version found');

    const row = rows[0];
    return JSON.stringify({
      mlkem_public_key: bytesToBase64(row['mlkem_public_key'] as Uint8Array),
      x25519_public_key: bytesToBase64(row['x25519_public_key'] as Uint8Array),
    });
  }

  async getActiveKeyVersionId(): Promise<number> {
    const rows = queryRows(
      this.db,
      "SELECT id FROM key_versions WHERE status = 'active' ORDER BY version DESC LIMIT 1",
    );
    if (rows.length === 0) throw new Error('No active key version found');
    return rows[0]['id'] as number;
  }

  // ── Cross-provider move ────────────────────────────────────────────────

  /**
   * Move files to a different provider by transferring raw V7 ciphertext blobs.
   *
   * Because V7 file encryption is independent of the vault key (per-file content
   * keys are wrapped with the user's ML-KEM/X25519 public key inside the V7 header),
   * the ciphertext can be transferred as-is to the destination provider without
   * re-encryption. The destination vault row is updated with the new provider_id
   * and storage_ref; the source blob is deleted after a successful upload.
   *
   * Files are moved to the root of the destination provider (folder_id = NULL).
   *
   * @param fileIds         IDs of files to move (must all be from the same provider)
   * @param dstProviderId   provider_id of the destination provider
   * @param onProgress      callback with { done, total } after each file
   */
  /**
   * Returns the share_ids that were revoked as a result of the move.
   * Callers should display a toast informing the user.
   */
  async crossProviderMove(
    fileIds: number[],
    dstProviderId: string,
    onProgress?: (progress: { done: number; total: number }) => void,
  ): Promise<{ revokedShareIds: string[] }> {
    this.checkOperational();

    const dstProvider = await this.resolveProvider(dstProviderId);
    if (!dstProvider) throw new Error(`Provider ${dstProviderId} not available`);

    let done = 0;
    const total = fileIds.length;
    const revokedShareIds: string[] = [];

    for (const fileId of fileIds) {
      const rows = queryRows(this.db, 'SELECT * FROM files WHERE id = ?', [fileId]);
      if (rows.length === 0) continue;
      const row = rows[0] as Record<string, unknown>;

      const srcProviderId = row['provider_id'] as string;
      const storageRef = row['storage_ref'] as string;

      if (srcProviderId === dstProviderId) {
        // Already on destination provider — no blob transfer needed
        done++;
        onProgress?.({ done, total });
        continue;
      }

      const srcProvider = await this.resolveProvider(srcProviderId);

      // 0. Revoke any active share links for this file before touching blobs.
      //    A/A+ shares point directly to the source blob (which will be deleted),
      //    so all variants must be revoked. Recipients who want to share the
      //    moved file must re-share from its new location.
      const activeShares = queryRows(
        this.db,
        'SELECT share_id FROM share_tokens WHERE file_id = ? AND revoked = 0',
        [fileId],
      );
      for (const shareRow of activeShares) {
        const sid = (shareRow as Record<string, unknown>)['share_id'] as string;
        await this.revokeShare(sid);
        revokedShareIds.push(sid);
      }

      // 1. Stream V7 ciphertext verbatim from source to destination.
      //    ZK-6: blobName is an opaque UUID, never a plaintext filename.
      //    Phase 3c: if both providers are WASM-backed, pipe entirely inside WASM
      //    so no ciphertext bytes cross the JS boundary. Falls back to TS pipeTo
      //    for SFTP (RelayTransport, not WASM-backed).
      const encryptedSize = (row['encrypted_size'] as number) ?? 0;
      const blobName = `data/${crypto.randomUUID()}`;
      let dstRef: string;

      const srcHandle = (srcProvider as { getConfigHandle?(): string | null }).getConfigHandle?.() ?? null;
      const dstHandle = (dstProvider as { getConfigHandle?(): string | null }).getConfigHandle?.() ?? null;

      if (srcHandle && dstHandle) {
        // WASM pipe: no ciphertext in JS heap.
        const uploadResult = await byoWorker.Worker.byoCrossProviderStreamCopy(
          srcProvider.type, srcHandle,
          dstProvider.type, dstHandle,
          storageRef, blobName, encryptedSize,
        );
        dstRef = uploadResult.ref;
      } else {
        // TS fallback (e.g. src or dst is SFTP): pipeTo keeps only a transit buffer.
        const dlStream = await this.withAuthRetry(
          () => srcProvider.downloadStream(storageRef), srcProvider);
        const { stream: writable, result: uploadResultP } = await this.withAuthRetry(
          () => dstProvider.uploadStream(null, blobName, encryptedSize, {}), dstProvider);
        try {
          await dlStream.pipeTo(writable);
        } catch (err) {
          uploadResultP.catch(() => {}); // prevent unhandled rejection
          await writable.abort(err).catch(() => {});
          throw err;
        }
        dstRef = (await uploadResultP).ref;
      }

      // 3. Update SQLite row — move to dst provider, place at root.
      //    storage_ref = the ref returned by the provider (opaque on GDrive;
      //    path-like on S3/Dropbox) so future download/delete calls are correct.
      const now = new Date().toISOString();
      const updateSql = `
        UPDATE files SET provider_id = ?, storage_ref = ?, folder_id = NULL, updated_at = ? WHERE id = ?
      `;
      const updateParams = [dstProviderId, dstRef, now, fileId];
      await this.onMutate(updateSql, updateParams);
      this.db.run(updateSql, updateParams as import('sql.js').BindParams);

      // 4. Journal the blob-delete intent BEFORE executing the delete.
      //    If we crash after journaling but before the provider call completes,
      //    the reconciler on the next unlock will retry the delete (using
      //    byo_cross_provider_move_decide_replay) because the dst row now exists.
      const srcWalKey = getWalKeyForProvider(srcProviderId);
      const vaultId = getVaultId();
      if (srcWalKey && vaultId) {
        const stepJson = JSON.stringify({
          DeleteSourceBlob: { provider_id: srcProviderId, provider_ref: storageRef },
        });
        const stepBytes = new TextEncoder().encode(stepJson);
        const stepB64 = _bytesToBase64(stepBytes);
        await appendWalBlobDelete(
          vaultId + ':' + srcProviderId,
          srcWalKey,
          srcProviderId,
          storageRef,
          fileId,
          stepB64,
        ).catch(() => {/* non-fatal — proceed with delete anyway */});
      }

      // 5. Delete source blob (best-effort — do not abort if this fails).
      //    The WAL entry above ensures this is retried on the next unlock if
      //    the process crashes before this completes.
      try {
        await srcProvider.delete(storageRef);
      } catch {
        // Source delete failed — WAL entry retained for reconciler
        console.warn('[crossProviderMove] Source delete failed for', storageRef, '— will retry on next unlock');
      }

      // Mark both providers dirty
      markDirty(srcProviderId);
      markDirty(dstProviderId);

      done++;
      onProgress?.({ done, total });
    }

    return { revokedShareIds };
  }

  // ── Trash access ───────────────────────────────────────────────────────

  listTrash(): TrashEntry[] {
    return this.trash.listTrash();
  }

  async checkBlobAvailability(entry: TrashEntry): Promise<boolean> {
    return this.trash.checkBlobAvailability(entry);
  }

  async restoreItem(trashId: number): Promise<boolean> {
    return this.trash.restoreItem(trashId);
  }

  async permanentDelete(trashId: number): Promise<void> {
    return this.trash.permanentDelete(trashId);
  }

  async emptyTrash(): Promise<void> {
    return this.trash.emptyTrash();
  }

  // ── Share links (P10) ──────────────────────────────────────────────────

  /**
   * Create a share link for a single file.
   *
   * ZK invariants:
   *   - content_key never leaves WASM (byo_create_share_fragment decapsulates
   *     the V7 header inside WASM and returns only the fragment string).
   *   - For A+: password wraps the content_key inside WASM via Argon2id.
   *   - For B1/B2: relay cookie is acquired fresh per call (PoW-gated).
   *   - Server/relay receive: relay cookie + share metadata + (B2: V7 ciphertext).
   *     Server NEVER receives content_key, password, or any key-derivable secret.
   */
  async createShareLink(
    fileId: number,
    variant: ShareVariant,
    options?: { password?: string; ttlSeconds?: number },
  ): Promise<{ entry: ShareEntry; fragment: string }> {
    // 1. Fetch file row from SQLite.
    const rows = queryRows(this.db, 'SELECT * FROM files WHERE id = ?', [fileId]);
    if (rows.length === 0) throw new Error('File not found');
    const row = rows[0] as Record<string, unknown>;
    const storageRef = row['storage_ref'] as string;
    const providerId = row['provider_id'] as string;

    // 2. Resolve provider for this file.
    const provider = await this.resolveProvider(providerId);

    // 3. Download raw V7 ciphertext from the provider (needed for header extraction + B2 upload).
    const ciphertextBytes = await this.withAuthRetry(async () => {
      const readable = await provider.downloadStream(storageRef);
      const reader = readable.getReader();
      const chunks: Uint8Array[] = [];
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
      reader.releaseLock();
      const total = chunks.reduce((n, c) => n + c.length, 0);
      const buf = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { buf.set(c, off); off += c.length; }
      return buf;
    }, provider);

    // 4. Extract V7 header (first 1709 bytes) as base64 for WASM.
    const HEADER_SIZE = 1709;
    if (ciphertextBytes.length < HEADER_SIZE) {
      throw new Error('Ciphertext too small to be a valid V7 file');
    }
    const headerBytes = ciphertextBytes.slice(0, HEADER_SIZE);
    const headerB64 = _bytesToBase64(headerBytes);

    // 5. Create fragment — content_key stays inside WASM.
    const fragment = await byoWorker.Worker.byoCreateShareFragment(
      String(this.sessionId),
      headerB64,
      variant as 'A' | 'A+',
      options?.password,
    );

    // 6. Resolve public link and relay metadata.
    const shareId = crypto.randomUUID();
    const ttl = options?.ttlSeconds ?? 86400; // default 24 h
    let publicLink: string | null = null;
    let presignedExpiresAt: number | null = null;
    let ownerToken: string | null = null;

    if (variant === 'A') {
      // Use provider public link (direct download URL).
      publicLink = await this.withAuthRetry(() => provider.createPublicLink(storageRef), provider);
    } else if (variant === 'A+') {
      // Same as A — recipient needs the fragment password separately.
      publicLink = await this.withAuthRetry(() => provider.createPublicLink(storageRef), provider);
    } else if (variant === 'B1') {
      // Presigned URL — acquire relay cookie then register with relay.
      const presignedUrl = await this.withAuthRetry(
        () => provider.createPresignedUrl(storageRef, ttl),
        provider,
      );
      presignedExpiresAt = Date.now() + ttl * 1000;

      await acquireRelayCookie('share:b1');
      const b1Body = JSON.stringify({
        share_id: shareId,
        provider_url: presignedUrl,
        expires_in_secs: ttl,
      });
      const resp = await fetch('/relay/share/b1', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: b1Body,
      });
      if (!resp.ok) throw new Error(`Relay B1 create failed: ${resp.status}`);
      const b1RespText = await resp.text();
      addShareRelayBandwidth(b1Body.length + b1RespText.length);
      const b1Data = JSON.parse(b1RespText) as { owner_token?: string };
      ownerToken = b1Data.owner_token ?? null;
    } else if (variant === 'B2') {
      // Upload full ciphertext to relay blob store.
      presignedExpiresAt = Date.now() + ttl * 1000;

      await acquireRelayCookie('share:b2');
      const resp = await fetch('/relay/share/b2', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Share-Id': shareId,
          'X-Expires-In': String(ttl),
        },
        body: ciphertextBytes,
      });
      if (!resp.ok) throw new Error(`Relay B2 upload failed: ${resp.status}`);
      const b2RespText = await resp.text();
      // B2 upload: ciphertext (uploaded) + response (downloaded)
      addShareRelayBandwidth(ciphertextBytes.byteLength + b2RespText.length);
      const b2Data = JSON.parse(b2RespText) as { owner_token?: string };
      ownerToken = b2Data.owner_token ?? null;
    }

    // 7. Persist share record to vault SQLite (WAL + journal via onMutate).
    const createdAt = Date.now();
    const insertShareSql = `INSERT INTO share_tokens
         (share_id, file_id, provider_id, provider_ref, variant,
          public_link, presigned_expires_at, created_at, revoked, owner_token)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`;
    const insertShareParams = [shareId, fileId, providerId, storageRef, variant, publicLink, presignedExpiresAt, createdAt, ownerToken];
    await this.onMutate(insertShareSql, insertShareParams);
    this.db.run(insertShareSql, insertShareParams as import('sql.js').BindParams);
    markDirty();

    const entry: ShareEntry = {
      share_id: shareId,
      file_id: fileId,
      provider_id: providerId,
      provider_ref: storageRef,
      variant,
      public_link: publicLink,
      presigned_expires_at: presignedExpiresAt,
      created_at: createdAt,
      revoked: false,
    };

    recordEvent('share_create', { share_variant: variant });
    return { entry, fragment };
  }

  /** Revoke a share link — marks local record revoked and informs relay (B1/B2). */
  async revokeShare(shareId: string): Promise<void> {
    const rows = queryRows(this.db, 'SELECT * FROM share_tokens WHERE share_id = ?', [shareId]);
    if (rows.length === 0) throw new Error('Share not found');
    const row = rows[0] as Record<string, unknown>;
    const variant = row['variant'] as ShareVariant;
    const token = row['owner_token'] as string | null;

    // For A/A+: revoke provider public link.
    if (variant === 'A' || variant === 'A+') {
      const storageRef = row['provider_ref'] as string;
      const providerId = row['provider_id'] as string;
      const provider = await this.resolveProvider(providerId);
      try {
        await this.withAuthRetry(() => provider.revokePublicLink(storageRef), provider);
      } catch {
        // Best-effort; local revocation proceeds regardless.
      }
    }

    // For B1/B2: inform relay (DELETE) using HMAC ownership token — no relay cookie needed.
    if ((variant === 'B1' || variant === 'B2') && token) {
      const endpoint = variant === 'B1'
        ? `/relay/share/b1/${encodeURIComponent(shareId)}`
        : `/relay/share/b2/${encodeURIComponent(shareId)}`;
      try {
        const revokeResp = await fetch(endpoint, {
          method: 'DELETE',
          credentials: 'same-origin',
          headers: { 'X-Owner-Token': token },
        });
        // Track the revoke round-trip (request headers only; response is typically empty).
        addShareRelayBandwidth(endpoint.length + (await revokeResp.text()).length);
      } catch {
        // Best-effort; local revocation proceeds regardless.
      }
    }

    // Mark revoked locally (WAL + journal via onMutate).
    const revokeShareSql = 'UPDATE share_tokens SET revoked = 1 WHERE share_id = ?';
    await this.onMutate(revokeShareSql, [shareId]);
    this.db.run(revokeShareSql, [shareId]);
    markDirty();
    recordEvent('share_revoke', { share_variant: variant });
  }

  /** List all non-revoked share tokens from vault SQLite (synchronous). */
  async getDecryptedFileName(fileId: number): Promise<string> {
    const rows = queryRows(this.db, 'SELECT name, filename_key FROM files WHERE id = ?', [fileId]);
    if (rows.length === 0) return '[deleted]';
    const row = rows[0] as Record<string, unknown>;
    return this.decryptFilename(
      row['name'] as string | Uint8Array,
      row['filename_key'] as string | Uint8Array,
    );
  }

  listShares(): ShareEntry[] {
    const rows = queryRows(
      this.db,
      'SELECT * FROM share_tokens WHERE revoked = 0 ORDER BY created_at DESC',
      [],
    );
    return rows.map((r) => {
      const row = r as Record<string, unknown>;
      return {
        share_id: row['share_id'] as string,
        file_id: row['file_id'] as number,
        provider_id: (row['provider_id'] as string | null) ?? null,
        provider_ref: row['provider_ref'] as string,
        variant: row['variant'] as ShareVariant,
        public_link: (row['public_link'] as string | null) ?? null,
        presigned_expires_at: (row['presigned_expires_at'] as number | null) ?? null,
        created_at: row['created_at'] as number,
        revoked: false,
      };
    });
  }

  // ── Private: mutation helper ───────────────────────────────────────────

  /**
   * Called before every SQL mutation:
   *   1. Appends WAL entry for crash recovery
   *   2. Appends journal entry for cloud-side journal
   */
  private async onMutate(sql: string, params: unknown[]): Promise<void> {
    const vaultId = getVaultId();
    const walKey = getWalKey();
    const journal = getJournal();

    if (walKey) {
      await appendWal(vaultId, walKey, sql, params);
    }

    if (journal) {
      // Infer table name and entry type for journal
      const { type, table, rowId } = inferJournalMeta(sql, params);
      if (table) {
        await journal.append({
          type,
          table,
          rowId,
          data: JSON.stringify({ sql, params }),
        });
      }
    }
  }

  // ── Private: auth retry ────────────────────────────────────────────────

  private async withAuthRetry<T>(fn: () => Promise<T>, provider?: StorageProvider): Promise<T> {
    const p = provider ?? this.provider;
    try {
      return await fn();
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        await p.refreshAuth();
        // Credential updates are persisted via the manifest (R6), not provider_config table.
        return fn(); // Retry once
      }
      throw err;
    }
  }

  // ── Private: operational check ─────────────────────────────────────────

  private checkOperational(): void {
    const provider = getProvider();
    if (!provider) throw new Error('Vault not unlocked');
  }

  // ── Private: filename decryption ───────────────────────────────────────

  private async decryptFileRows(
    rows: Array<Record<string, unknown>>,
  ): Promise<FileEntry[]> {
    const results: FileEntry[] = new Array(rows.length);

    // Process in batches of DECRYPT_CONCURRENCY
    for (let i = 0; i < rows.length; i += DECRYPT_CONCURRENCY) {
      const batch = rows.slice(i, i + DECRYPT_CONCURRENCY);
      const decrypted = await Promise.all(
        batch.map((row) => this.decryptFilename(row['name'] as string | Uint8Array, row['filename_key'] as string | Uint8Array)),
      );
      for (let j = 0; j < batch.length; j++) {
        const row = batch[j];
        results[i + j] = rowToFileEntry(row, decrypted[j]);
      }
    }

    return results;
  }

  private async decryptFolderRows(
    rows: Array<Record<string, unknown>>,
  ): Promise<FolderEntry[]> {
    const results: FolderEntry[] = new Array(rows.length);

    for (let i = 0; i < rows.length; i += DECRYPT_CONCURRENCY) {
      const batch = rows.slice(i, i + DECRYPT_CONCURRENCY);
      const decrypted = await Promise.all(
        batch.map((row) => this.decryptFilename(row['name'] as string | Uint8Array, row['name_key'] as string | Uint8Array)),
      );
      for (let j = 0; j < batch.length; j++) {
        const row = batch[j];
        results[i + j] = rowToFolderEntry(row, decrypted[j]);
      }
    }

    return results;
  }

  /**
   * Decrypt a single filename using the encrypted key bundle.
   *
   * Filename encryption uses AES-GCM-SIV (deterministic). The filename_key
   * blob is a V7-format key bundle wrapping a fresh AES-GCM-SIV key.
   * Decryption delegates to the BYO worker via the V7 decryptor.
   *
   * For now, we use a simplified approach: the encrypted name and key are
   * passed to a dedicated worker function for decryption.
   */
  private async decryptFilename(
    encName: string | Uint8Array,
    encKey: string | Uint8Array,
  ): Promise<string> {
    try {
      const nameB64 = toBase64(encName);
      const keyB64 = toBase64(encKey);

      // The worker's encryptFilenameAtomic produced a WASM-encrypted AES-GCM-SIV blob.
      // The sdk-wasm exports decrypt_filename_with_key for decryption.
      // We use the V7 decrypt session with the active session keys.
      const result = await byoWorker.Worker.byoDecryptFilename(nameB64, keyB64, this.sessionId);
      return result.filename as string;
    } catch {
      return '[encrypted]';
    }
  }
}

// ── Row mappers ────────────────────────────────────────────────────────────

function rowToFileEntry(row: Record<string, unknown>, decryptedName: string): FileEntry {
  return {
    id: row['id'] as number,
    folder_id: row['folder_id'] as number | null,
    name: toBase64(row['name'] as string | Uint8Array),
    decrypted_name: decryptedName,
    size: row['size'] as number,
    encrypted_size: row['encrypted_size'] as number ?? 0,
    storage_ref: row['storage_ref'] as string,
    mime_type: row['mime_type'] as string ?? '',
    file_type: row['file_type'] as string ?? '',
    key_version_id: row['key_version_id'] as number,
    metadata: row['metadata'] as string ?? '',
    created_at: row['created_at'] as string,
    updated_at: row['updated_at'] as string,
  };
}

function rowToFolderEntry(row: Record<string, unknown>, decryptedName: string): FolderEntry {
  return {
    id: row['id'] as number,
    parent_id: row['parent_id'] as number | null,
    name: toBase64(row['name'] as string | Uint8Array),
    decrypted_name: decryptedName,
    name_key: toBase64(row['name_key'] as string | Uint8Array),
    created_at: row['created_at'] as string,
    updated_at: row['updated_at'] as string,
  };
}

// ── Utility ────────────────────────────────────────────────────────────────

function toBase64(val: string | Uint8Array): string {
  if (typeof val === 'string') return val;
  let binary = '';
  for (let i = 0; i < val.length; i++) binary += String.fromCharCode(val[i]);
  return btoa(binary);
}

function bytesToBase64(bytes: Uint8Array): string {
  return toBase64(bytes);
}

function inferFileType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'heif', 'avif'].includes(ext)) return 'image';
  if (['mp4', 'mov', 'avi', 'mkv', 'webm'].includes(ext)) return 'video';
  if (['mp3', 'wav', 'flac', 'aac', 'ogg'].includes(ext)) return 'audio';
  if (['pdf'].includes(ext)) return 'pdf';
  if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) return 'document';
  return 'file';
}

function inferJournalMeta(
  sql: string,
  params: unknown[],
): { type: import('./VaultJournal').JournalEntryType; table: string; rowId: number } {
  const upper = sql.trim().toUpperCase();
  let type: import('./VaultJournal').JournalEntryType = 'UPDATE';
  if (upper.startsWith('INSERT')) type = 'INSERT';
  else if (upper.startsWith('DELETE')) type = 'DELETE';

  // Extract table name from SQL
  const tableMatch = sql.match(/(?:INTO|FROM|UPDATE)\s+(\w+)/i);
  const table = tableMatch?.[1] ?? '';

  let rowId = 0;

  if (type === 'INSERT') {
    // M3: For INSERT, find the position of the `id` column in the column list
    // and use that param as the rowId. Falling back to `params[last]` would
    // pick the last column value (e.g. provider_id), not the primary key.
    const colListMatch = sql.match(/INSERT\s+(?:OR\s+\w+\s+)?INTO\s+\w+\s*\(([^)]+)\)/i);
    if (colListMatch) {
      const cols = colListMatch[1].split(',').map((c) => c.trim().toLowerCase());
      const idIdx = cols.indexOf('id');
      if (idIdx >= 0 && idIdx < params.length && typeof params[idIdx] === 'number') {
        rowId = params[idIdx] as number;
      }
    }
  } else {
    // UPDATE/DELETE: last param is typically the WHERE id = ? binding.
    // This holds for all current ByoDataProvider SQL patterns.
    const last = params[params.length - 1];
    if (typeof last === 'number') rowId = last;
  }

  return { type, table, rowId };
}
