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

import type { StorageProvider } from '@wattcloud/sdk';
import { UnauthorizedError, acquireRelayCookie, evictRelayCookieCache, recordEvent, addShareRelayBandwidth } from '@wattcloud/sdk';
import { ByoUploadStream } from '@wattcloud/sdk';
import { ByoDownloadStream } from '@wattcloud/sdk';
import { createZipStream, type ZipEntry } from '@wattcloud/sdk';
import * as byoWorker from '@wattcloud/sdk';
import type {
  DataProvider,
  FileEntry,
  FolderEntry,
  CollectionEntry,
  StorageUsage,
  TrashEntry,
  ShareEntry,
} from './DataProvider';
import { markDirty, getProvider, getJournalForProvider, getWalKeyForProvider, getVaultId, getOrInitProvider } from './VaultLifecycle';
import { extractExif, serializeExif } from './ExifExtractor';
import { bytesToBase64 as _bytesToBase64, base64ToBytes as _base64ToBytes } from './base64';
import { parseShareLimitError } from './shareLimitCopy';
import {
  supportsRequestStreams,
  peekHeaderAndResume,
  prependBytes,
  countingTap,
  drainToBuffer,
} from './shareUploadStreaming';
import { appendWal, appendWalBlobDelete } from './IndexedDBWal';
import { queryRows } from './ConflictResolver';
import { SearchIndex } from './SearchIndex';
import { TrashManager } from './TrashManager';
import { byoFiles, byoFolders } from './stores/byoFileStore';
import { refreshShareStats } from './stores/byoShareStats';

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
  /** Set on first searchFiles() call so existing rows are seeded into the
   *  filename index — the constructor can't await the per-row decrypt and
   *  on-mount upserts only cover newly-uploaded/renamed files. */
  private searchIndexBuilt = false;

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

  /** Decrypt every file row once and seed the in-memory filename index.
   *  Idempotent — guarded by `searchIndexBuilt`, so repeat search calls
   *  hit the already-populated map. Lazy on purpose: the search UI only
   *  exists on Files/Favorites and most users never invoke it, so we
   *  avoid the upfront decrypt cost on unlock. */
  private async ensureSearchIndex(): Promise<void> {
    if (this.searchIndexBuilt) return;
    const rows = queryRows(this.db, 'SELECT * FROM files');
    const files = await this.decryptFileRows(rows);
    this.searchIndex.build(files);
    this.searchIndexBuilt = true;
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

    // Extract EXIF metadata for images. Non-images skip the header-read;
    // failures fall through to empty metadata so upload is never blocked
    // by a malformed EXIF block. The head slice must be big enough to
    // include the EXIF GPS block — 256 KiB turned out to be too tight for
    // HEIC and larger JPEGs where GPS lives past the primary APP segment,
    // so we now read up to 4 MiB (still cheap; negligible vs. re-parsing
    // the whole file). Files smaller than the cap are read in full.
    let metadataJson = '';
    if (inferFileType(file.name) === 'image') {
      try {
        const headBlob = file.slice(0, Math.min(file.size, 4 * 1024 * 1024));
        const headBytes = new Uint8Array(await headBlob.arrayBuffer());
        const exif = await extractExif(headBytes);
        metadataJson = serializeExif(exif);
      } catch { /* leave metadata empty */ }
    }

    // Stream-encrypt and upload to the active provider's WattcloudVault/data folder.
    const activeProvider = await this.resolveProvider(this.activeProviderId);
    const uploadResult = await this.withAuthRetry(() =>
      ByoUploadStream.upload(activeProvider, file, 'WattcloudVault/data', publicKeysJson, {
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
      metadataJson,
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
    markDirty(this.activeProviderId);
    return entry;
  }

  /**
   * Record an OS share-sheet event in the per-vault `share_audit` table.
   *
   * Outbound entries record that the user invoked `navigator.share` for
   * a given file row; the OS does not disclose the receiving app, so
   * `counterpartyHint` is left empty. Inbound entries (reserved for the
   * Web Share Target flow) may carry the share-target `url` form field.
   *
   * Uses the standard onMutate path so the change is captured by the
   * crash-recovery WAL and the cloud journal alongside other vault
   * mutations. Caller schedules a save via the usual debounce.
   */
  async recordShareAudit(
    direction: 'outbound' | 'inbound',
    fileRef: string,
    counterpartyHint: string | null = null,
  ): Promise<void> {
    this.checkOperational();

    const sql =
      'INSERT INTO share_audit (ts, direction, file_ref, counterparty_hint) VALUES (?, ?, ?, ?)';
    const params: unknown[] = [Date.now(), direction, fileRef, counterpartyHint];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);
    markDirty(this.activeProviderId);
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

  async downloadFolderAsZip(folderId: number): Promise<{ stream: ReadableStream<Uint8Array>; filename: string }> {
    this.checkOperational();

    const folderRows = queryRows(this.db, 'SELECT * FROM folders WHERE id = ?', [folderId]);
    if (folderRows.length === 0) throw new Error('Folder not found');
    const rootName = await this.decryptFilename(
      folderRows[0]['name'] as string | Uint8Array,
      folderRows[0]['name_key'] as string | Uint8Array,
    );

    const descendants = await this.collectFolderDescendants(folderId);
    const files = await this.collectFilesInFolders(descendants.folderIds);
    if (files.length === 0) throw new Error('This folder is empty; nothing to download.');

    // Build path relative to the selected folder root — walks up the
    // parent chain, stopping at the root so we don't include the user's
    // vault ancestry above the folder they picked.
    const relPathForFile = (f: FileEntry): string => {
      const parts: string[] = [f.decrypted_name];
      let parent = f.folder_id;
      while (parent !== null && parent !== folderId) {
        const d = descendants.folderPaths.get(parent);
        if (!d) break;
        parts.unshift(d.name);
        parent = d.parent_id;
      }
      return parts.join('/');
    };

    const self = this;
    async function* entries(): AsyncIterable<ZipEntry> {
      for (const f of files) {
        const stream = await self.downloadFile(f.id);
        yield {
          name: `${rootName}/${relPathForFile(f)}`,
          input: stream,
          size: f.size,
          lastModified: new Date(f.updated_at || f.created_at),
        };
      }
    }

    return { stream: createZipStream(entries()), filename: `${rootName}.zip` };
  }

  async downloadFilesAsZip(fileIds: number[], zipName: string): Promise<ReadableStream<Uint8Array>> {
    this.checkOperational();
    if (fileIds.length === 0) throw new Error('No files to download.');

    const placeholders = fileIds.map(() => '?').join(',');
    const rows = queryRows(
      this.db,
      `SELECT * FROM files WHERE id IN (${placeholders})`,
      fileIds as import('sql.js').BindParams,
    );
    const files = await this.decryptFileRows(rows);
    if (files.length === 0) throw new Error('No matching files to download.');

    // De-dup names on collision. The input is a flat selection that can
    // span folders, so the same "photo.jpg" may appear twice; a zip with
    // duplicate paths confuses some extractors (silent overwrite or
    // dropped entries). Append " (n)" before the extension.
    const seen = new Map<string, number>();
    const uniq = (name: string): string => {
      const n = seen.get(name) ?? 0;
      seen.set(name, n + 1);
      if (n === 0) return name;
      const dot = name.lastIndexOf('.');
      return dot === -1
        ? `${name} (${n})`
        : `${name.slice(0, dot)} (${n})${name.slice(dot)}`;
    };

    const self = this;
    async function* entries(): AsyncIterable<ZipEntry> {
      for (const f of files) {
        const stream = await self.downloadFile(f.id);
        yield {
          name: uniq(f.decrypted_name),
          input: stream,
          size: f.size,
          lastModified: new Date(f.updated_at || f.created_at),
        };
      }
    }

    // `zipName` is retained for caller symmetry — the stream itself has
    // no embedded archive name, just entries; the caller passes this
    // into streamToDisk's save-as prompt.
    void zipName;
    return createZipStream(entries());
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
    markDirty(this.activeProviderId);
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
    markDirty(this.activeProviderId);
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
    markDirty(this.activeProviderId);
  }

  async updateFileMetadata(fileId: number, metadataJson: string): Promise<void> {
    this.checkOperational();

    const now = new Date().toISOString();
    const sql = 'UPDATE files SET metadata = ?, updated_at = ? WHERE id = ?';
    const params = [metadataJson, now, fileId];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);
    markDirty(this.activeProviderId);
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

    markDirty(this.activeProviderId);
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

    markDirty(this.activeProviderId);
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

    markDirty(this.activeProviderId);
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

    markDirty(this.activeProviderId);
  }

  // ── Favorites ──────────────────────────────────────────────────────────

  async getFavorites(): Promise<{ files: FileEntry[]; folders: FolderEntry[] }> {
    // Scoped to the active provider so navigating into a starred folder
    // can't dead-end on "empty" because the folder lives in another
    // provider's vault. Cross-provider browsing is intentionally absent
    // from the rest of the multi-provider UI; Favorites follows the same
    // rule for consistency. Switching providers from the drawer reloads
    // the favorites list (ByoDashboard $effect on activeProviderId).
    const pid = this.activeProviderId;
    const fileRows = queryRows(
      this.db,
      "SELECT f.* FROM files f JOIN favorites fav ON fav.item_id = f.id WHERE fav.item_type = 'file' AND f.provider_id = ?",
      [pid],
    );
    const folderRows = queryRows(
      this.db,
      "SELECT f.* FROM folders f JOIN favorites fav ON fav.item_id = f.id WHERE fav.item_type = 'folder' AND f.provider_id = ?",
      [pid],
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
      markDirty(this.activeProviderId);
      return false;
    } else {
      // Resolve the row's provider_id from the target table so the favorite
      // row satisfies the `provider_id NOT NULL` constraint and copyProviderRows
      // can route it into the right per-provider vault body on save.
      const srcTable = type === 'file' ? 'files' : 'folders';
      const srcRows = queryRows(this.db, `SELECT provider_id FROM ${srcTable} WHERE id = ?`, [id]);
      const providerId = (srcRows[0]?.['provider_id'] as string | undefined) ?? this.activeProviderId;

      const now = new Date().toISOString();
      const sql = 'INSERT INTO favorites (item_type, item_id, provider_id, created_at) VALUES (?, ?, ?, ?)';
      const params = [type, id, providerId, now];
      await this.onMutate(sql, params);
      this.db.run(sql, params as import('sql.js').BindParams);
      markDirty(this.activeProviderId);
      return true;
    }
  }

  // ── Search ─────────────────────────────────────────────────────────────

  async searchFiles(query: string): Promise<FileEntry[]> {
    await this.ensureSearchIndex();
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

  /** Substring search over folder names within the active provider.
   *  No per-folder index — folder counts stay small (low hundreds even
   *  for power users), so a one-shot decrypt + JS filter is fast enough
   *  and avoids the bookkeeping a separate index would need. */
  async searchFolders(query: string): Promise<FolderEntry[]> {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const folders = await this.listAllFolders();
    return folders.filter((f) => f.decrypted_name.toLowerCase().includes(q));
  }

  /** Every file belonging to the active provider, any folder. Used by
   *  search when only a type filter is set (no free-text query) so the
   *  Documents / Videos / Audio / … chips can return matches across the
   *  whole vault. listImageFiles is image-only and would silently empty
   *  the result set for non-image filters. */
  async listAllFiles(): Promise<FileEntry[]> {
    const rows = queryRows(
      this.db,
      `SELECT * FROM files WHERE provider_id = ? ORDER BY created_at DESC`,
      [this.activeProviderId],
    );
    return this.decryptFileRows(rows);
  }

  async listImageFiles(folderId?: number | null): Promise<FileEntry[]> {
    // folderId:
    //   undefined → all images for the active provider, any folder.
    //   null      → images at the vault root (no folder) for the active provider.
    //   number    → images inside that folder and all its descendants.
    //
    // Scoped to the active provider so the timeline tracks the drawer's
    // provider switcher, matching how listFiles / listAllFolders behave.
    // Cross-provider photo browsing is a future affordance; today the
    // user's mental model is "this is the SFTP-Hetzner-2 vault" and the
    // timeline should reflect that.
    const pid = this.activeProviderId;
    let rows: Array<Record<string, unknown>>;
    if (folderId === undefined) {
      rows = queryRows(
        this.db,
        `SELECT * FROM files WHERE file_type = 'image' AND provider_id = ? ORDER BY created_at DESC`,
        [pid],
      );
    } else if (folderId === null) {
      rows = queryRows(
        this.db,
        `SELECT * FROM files WHERE file_type = 'image' AND folder_id IS NULL AND provider_id = ? ORDER BY created_at DESC`,
        [pid],
      );
    } else {
      // Recursive descent — pull all descendant folder ids then filter files.
      const ids = new Set<number>([folderId]);
      const stack: number[] = [folderId];
      while (stack.length > 0) {
        const parentId = stack.pop()!;
        const children = queryRows(this.db, 'SELECT id FROM folders WHERE parent_id = ?', [parentId]);
        for (const c of children) {
          const cid = c['id'] as number;
          if (!ids.has(cid)) { ids.add(cid); stack.push(cid); }
        }
      }
      const placeholders = Array.from(ids).map(() => '?').join(', ');
      rows = queryRows(
        this.db,
        `SELECT * FROM files WHERE file_type = 'image' AND folder_id IN (${placeholders}) AND provider_id = ? ORDER BY created_at DESC`,
        [...Array.from(ids), pid] as import('sql.js').BindParams,
      );
    }
    return this.decryptFileRows(rows);
  }

  /** List every folder across the active provider (flat), for folder pickers. */
  async listAllFolders(): Promise<FolderEntry[]> {
    const rows = queryRows(
      this.db,
      'SELECT * FROM folders WHERE provider_id = ? ORDER BY created_at ASC',
      [this.activeProviderId],
    );
    return this.decryptFolderRows(rows);
  }

  // ── Collections ────────────────────────────────────────────────────────

  async listCollections(): Promise<CollectionEntry[]> {
    const pid = this.activeProviderId;
    const rows = queryRows(
      this.db,
      `SELECT c.*,
              (SELECT COUNT(*) FROM collection_files cf WHERE cf.collection_id = c.id) AS photo_count
       FROM collections c
       WHERE c.provider_id = ?
       ORDER BY c.created_at DESC`,
      [pid],
    );
    const results: CollectionEntry[] = new Array(rows.length);
    for (let i = 0; i < rows.length; i += DECRYPT_CONCURRENCY) {
      const batch = rows.slice(i, i + DECRYPT_CONCURRENCY);
      const decrypted = await Promise.all(
        batch.map((row) => this.decryptFilename(row['name'] as string | Uint8Array, row['name_key'] as string | Uint8Array)),
      );
      for (let j = 0; j < batch.length; j++) {
        const row = batch[j];
        results[i + j] = {
          id: row['id'] as number,
          name: toBase64(row['name'] as string | Uint8Array),
          decrypted_name: decrypted[j],
          name_key: toBase64(row['name_key'] as string | Uint8Array),
          cover_file_id: (row['cover_file_id'] as number | null) ?? null,
          photo_count: (row['photo_count'] as number | null) ?? 0,
          created_at: row['created_at'] as string,
          updated_at: row['updated_at'] as string,
          provider_id: row['provider_id'] as string | null,
        };
      }
    }
    return results;
  }

  async createCollection(name: string): Promise<CollectionEntry> {
    this.checkOperational();

    const publicKeysJson = await this.getActivePublicKeysJson();
    const { encrypted_filename: encName, encrypted_filename_key: nameKey } =
      await byoWorker.Worker.encryptFilenameAtomic(name, publicKeysJson);

    const now = new Date().toISOString();
    const sql = 'INSERT INTO collections (name, name_key, provider_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)';
    const params = [encName, nameKey, this.activeProviderId, now, now];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);

    const lastId = queryRows(this.db, 'SELECT last_insert_rowid() AS id')[0]['id'] as number;
    markDirty(this.activeProviderId);

    return {
      id: lastId,
      name: encName,
      decrypted_name: name,
      name_key: nameKey,
      cover_file_id: null,
      photo_count: 0,
      created_at: now,
      updated_at: now,
      provider_id: this.activeProviderId,
    };
  }

  async renameCollection(collectionId: number, newName: string): Promise<void> {
    this.checkOperational();

    const publicKeysJson = await this.getActivePublicKeysJson();
    const { encrypted_filename: encName, encrypted_filename_key: nameKey } =
      await byoWorker.Worker.encryptFilenameAtomic(newName, publicKeysJson);

    const now = new Date().toISOString();
    const sql = 'UPDATE collections SET name = ?, name_key = ?, updated_at = ? WHERE id = ?';
    const params = [encName, nameKey, now, collectionId];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);
    markDirty(this.activeProviderId);
  }

  async deleteCollection(collectionId: number): Promise<void> {
    this.checkOperational();

    // Cascade: remove membership rows first (ON DELETE CASCADE handles it in
    // the schema, but we explicitly journal both steps so the mutation log
    // reconstructs identically on replay).
    const memberSql = 'DELETE FROM collection_files WHERE collection_id = ?';
    await this.onMutate(memberSql, [collectionId]);
    this.db.run(memberSql, [collectionId]);

    const sql = 'DELETE FROM collections WHERE id = ?';
    await this.onMutate(sql, [collectionId]);
    this.db.run(sql, [collectionId]);
    markDirty(this.activeProviderId);
  }

  async listCollectionFiles(collectionId: number): Promise<FileEntry[]> {
    const rows = queryRows(
      this.db,
      `SELECT f.* FROM files f
       JOIN collection_files cf ON cf.file_id = f.id
       WHERE cf.collection_id = ?
       ORDER BY cf.added_at DESC`,
      [collectionId],
    );
    return this.decryptFileRows(rows);
  }

  async addFilesToCollection(collectionId: number, fileIds: number[]): Promise<void> {
    this.checkOperational();
    if (fileIds.length === 0) return;

    const now = new Date().toISOString();
    const sql = 'INSERT OR IGNORE INTO collection_files (collection_id, file_id, added_at) VALUES (?, ?, ?)';

    for (const fid of fileIds) {
      const params = [collectionId, fid, now];
      await this.onMutate(sql, params);
      this.db.run(sql, params as import('sql.js').BindParams);
    }

    // Seed the collection cover with the first added file if none yet.
    const coverRow = queryRows(this.db, 'SELECT cover_file_id FROM collections WHERE id = ?', [collectionId])[0];
    if (coverRow && coverRow['cover_file_id'] == null) {
      const coverSql = 'UPDATE collections SET cover_file_id = ?, updated_at = ? WHERE id = ?';
      const coverParams = [fileIds[0], now, collectionId];
      await this.onMutate(coverSql, coverParams);
      this.db.run(coverSql, coverParams as import('sql.js').BindParams);
    }

    markDirty(this.activeProviderId);
  }

  async setCollectionCover(collectionId: number, fileId: number | null): Promise<void> {
    this.checkOperational();
    const now = new Date().toISOString();
    const sql = 'UPDATE collections SET cover_file_id = ?, updated_at = ? WHERE id = ?';
    const params = [fileId, now, collectionId];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);
    markDirty(this.activeProviderId);
  }

  async removeFilesFromCollection(collectionId: number, fileIds: number[]): Promise<void> {
    this.checkOperational();
    if (fileIds.length === 0) return;

    const sql = 'DELETE FROM collection_files WHERE collection_id = ? AND file_id = ?';
    for (const fid of fileIds) {
      const params = [collectionId, fid];
      await this.onMutate(sql, params);
      this.db.run(sql, params as import('sql.js').BindParams);
    }

    // Clear the cover if it's been removed; don't eagerly pick a replacement
    // (UI can pick one lazily from the remaining rows).
    const coverRow = queryRows(this.db, 'SELECT cover_file_id FROM collections WHERE id = ?', [collectionId])[0];
    if (coverRow && fileIds.includes(coverRow['cover_file_id'] as number)) {
      const remaining = queryRows(
        this.db,
        'SELECT file_id FROM collection_files WHERE collection_id = ? ORDER BY added_at DESC LIMIT 1',
        [collectionId],
      );
      const newCover = remaining[0]?.['file_id'] as number | undefined ?? null;
      const now = new Date().toISOString();
      const coverSql = 'UPDATE collections SET cover_file_id = ?, updated_at = ? WHERE id = ?';
      const coverParams = [newCover, now, collectionId];
      await this.onMutate(coverSql, coverParams);
      this.db.run(coverSql, coverParams as import('sql.js').BindParams);
    }

    markDirty(this.activeProviderId);
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
      //    ZK-6: blob name is an opaque UUID, never a plaintext filename.
      //    Phase 3c: if both providers are WASM-backed, pipe entirely inside WASM
      //    so no ciphertext bytes cross the JS boundary. Falls back to TS pipeTo
      //    for SFTP (RelayTransport, not WASM-backed).
      const encryptedSize = (row['encrypted_size'] as number) ?? 0;
      const blobUuid = crypto.randomUUID();
      let dstRef: string;

      const srcHandle = (srcProvider as { getConfigHandle?(): string | null }).getConfigHandle?.() ?? null;
      const dstHandle = (dstProvider as { getConfigHandle?(): string | null }).getConfigHandle?.() ?? null;

      if (srcHandle && dstHandle) {
        // WASM pipe: no ciphertext in JS heap. The WASM stream-copy entry
        // takes a single dstName (no separate parentRef), so encode the
        // vault data dir in the name itself.
        const uploadResult = await byoWorker.Worker.byoCrossProviderStreamCopy(
          srcProvider.type, srcHandle,
          dstProvider.type, dstHandle,
          storageRef, `data/${blobUuid}`, encryptedSize,
        );
        dstRef = uploadResult.ref;
      } else {
        // TS fallback (e.g. src or dst is SFTP): pipeTo keeps only a transit
        // buffer. Provider.uploadStream's `name` is the leaf filename;
        // each provider owns its own parent-dir convention (SFTP's relay
        // auto-prefixes /WattcloudVault/data/, so passing "data/<uuid>"
        // here would produce /WattcloudVault/data/data/<uuid>).
        const dlStream = await this.withAuthRetry(
          () => srcProvider.downloadStream(storageRef), srcProvider);
        const { stream: writable, result: uploadResultP } = await this.withAuthRetry(
          () => dstProvider.uploadStream(null, blobUuid, encryptedSize, {}), dstProvider);
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
   * Create a share link for a single file. Storage backing is always the
   * Wattcloud relay (single blob uploaded to `/relay/share/b2`), so
   * recipients don't need provider access. The fragment carries the V7
   * content_key — raw by default, Argon2id-wrapped when `options.password`
   * is provided. Sharing into a presigned-URL or provider-public-link path
   * is no longer offered: most providers never supported it, and the
   * recipient page speaks only to the relay.
   *
   * ZK invariants:
   *   - content_key never leaves WASM (byo_create_share_fragment
   *     decapsulates the V7 header inside WASM and returns only the
   *     fragment string).
   *   - With password: Argon2id 128 MiB / 3 iter / 4 parallel wraps the
   *     content_key inside WASM (sdk-core/src/byo/share.rs).
   *   - Relay cookie is acquired fresh per call (PoW-gated `share:b2`).
   *   - Relay receives: cookie + share_id + expiry header + V7 ciphertext.
   *     Never: content_key, password, filename, plaintext.
   *   - The original filename is appended to the URL fragment as
   *     `&n=<percent-encoded>` for recipient-side Save As. Fragments
   *     never reach a server, so ZK-6 (no plaintext filenames on the
   *     relay) still holds. An attacker who intercepts the link already
   *     has the decryption key; the name alongside is no weaker.
   */
  async createShareLink(
    fileId: number,
    options?: { password?: string; ttlSeconds?: number; filename?: string; label?: string },
  ): Promise<{ entry: ShareEntry; fragment: string }> {
    // 1. Fetch file row from SQLite.
    const rows = queryRows(this.db, 'SELECT * FROM files WHERE id = ?', [fileId]);
    if (rows.length === 0) throw new Error('File not found');
    const row = rows[0] as Record<string, unknown>;
    const storageRef = row['storage_ref'] as string;
    const providerId = row['provider_id'] as string;
    const plaintextSize = (row['size'] as number | null) ?? 0;

    // 2. Resolve provider for this file.
    const provider = await this.resolveProvider(providerId);

    // 3. Open a streaming download, peek the V7 header off the front, resume
    //    the rest directly into the relay POST body. Supported browsers
    //    (Chrome/Firefox 105+, Safari 17.4+) never materialise the full
    //    ciphertext in JS heap; older browsers fall back to a buffered POST.
    const HEADER_SIZE = 1709;
    const shareId = crypto.randomUUID();
    const ttl = options?.ttlSeconds ?? 86400; // default 24 h
    const presignedExpiresAt = Date.now() + ttl * 1000;
    await acquireRelayCookie('share:b2');

    // The relay consumes this cookie's JTI on /relay/share/b2 POST (see
    // share_relay.rs::upload_b2_share), so a second share hitting the
    // cached purpose would replay a dead cookie and 401. Evict in
    // `.finally` so success and failure paths both force re-PoW next
    // time.
    const { headerBytes, ciphertextSize, respText } = await this.withAuthRetry(async () => {
      const readable = await provider.downloadStream(storageRef);
      const { header, body } = await peekHeaderAndResume(readable, HEADER_SIZE);
      const fullBody = prependBytes(header, body);
      const streamingOk = supportsRequestStreams();
      let size: number;
      let text: string;
      if (streamingOk) {
        const tapped = countingTap(fullBody);
        const resp = await fetch('/relay/share/b2', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-Share-Id': shareId,
            'X-Expires-In': String(ttl),
          },
          body: tapped.body,
          // `duplex: 'half'` is required by the fetch spec when body is a
          // ReadableStream. `RequestInit` types in some lib.dom versions
          // don't surface the field yet; the cast keeps strict mode happy
          // without masking the real option.
          duplex: 'half',
        } as RequestInit & { duplex: 'half' });
        if (!resp.ok) {
          const limit = parseShareLimitError(resp);
          if (limit) throw limit;
          throw new Error(`Share upload failed: ${resp.status}`);
        }
        text = await resp.text();
        size = tapped.bytes();
      } else {
        // Fallback: drain first, then POST as a Uint8Array. Firefox gates
        // fetch upload streams behind `network.fetch.upload_streams` —
        // ShareLinkSheet surfaces a one-time hint to the user.
        console.warn(
          '[share] browser lacks streaming request bodies — buffering ciphertext (peak heap ≈ ciphertext size)',
        );
        const buf = await drainToBuffer(fullBody);
        const resp = await fetch('/relay/share/b2', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-Share-Id': shareId,
            'X-Expires-In': String(ttl),
          },
          body: buf as BodyInit,
        });
        if (!resp.ok) {
          const limit = parseShareLimitError(resp);
          if (limit) throw limit;
          throw new Error(`Share upload failed: ${resp.status}`);
        }
        text = await resp.text();
        size = buf.byteLength;
      }
      return { headerBytes: header, ciphertextSize: size, respText: text };
    }, provider).finally(() => evictRelayCookieCache('share:b2'));

    const headerB64 = _bytesToBase64(headerBytes);

    // 4. Create fragment — content_key stays inside WASM. The fragment
    //    variant ('A' vs 'A+') is an encoding detail, not a storage
    //    variant: A+ wraps the same key with Argon2id.
    const fragmentVariant: 'A' | 'A+' = options?.password ? 'A+' : 'A';
    const fragmentKey = await byoWorker.Worker.byoCreateShareFragment(
      String(this.sessionId),
      headerB64,
      fragmentVariant,
      options?.password,
    );
    // Append the recipient-facing display name so the recipient lands on
    // a page titled with something meaningful and saves the download
    // under that name. Prefer the user-supplied label over the original
    // filename so the two ends of the share agree on the title. Plain
    // percent-encoded — the fragment never reaches a server; anyone who
    // has the link can already decrypt the content, so the name being
    // readable alongside the key adds no privacy surface.
    const recipientName = options?.label?.trim() || options?.filename;
    const fragment = recipientName
      ? `${fragmentKey}&n=${encodeURIComponent(recipientName)}`
      : fragmentKey;

    addShareRelayBandwidth(ciphertextSize + respText.length);
    const relayResp = JSON.parse(respText) as { owner_token?: string };
    const ownerToken = relayResp.owner_token ?? null;

    // 5. Persist share record to vault SQLite (WAL + journal via onMutate).
    const createdAt = Date.now();
    const entry = await this.persistShareRow({
      shareId,
      kind: 'file',
      fileId,
      folderId: null,
      collectionId: null,
      providerId,
      providerRef: storageRef,
      presignedExpiresAt,
      createdAt,
      ownerToken,
      totalBytes: ciphertextSize,
      blobCount: 1,
      plaintextSize,
      fragment,
      bundleKind: 'file',
      label: options?.label?.trim() || null,
    });

    recordEvent('share_create', { share_variant: 'B2' });
    refreshShareStats(this);
    return { entry, fragment };
  }

  async createFolderShare(
    folderId: number,
    options?: { password?: string; ttlSeconds?: number; onProgress?: (done: number, total: number) => void; label?: string },
  ): Promise<{ entry: ShareEntry; fragment: string }> {
    // Collect folder + descendants; build rel_path for each file relative
    // to the folder root so the recipient reconstructs the tree.
    const folderRows = queryRows(this.db, 'SELECT * FROM folders WHERE id = ?', [folderId]);
    if (folderRows.length === 0) throw new Error('Folder not found');

    const descendants = await this.collectFolderDescendants(folderId);
    const files = await this.collectFilesInFolders(descendants.folderIds);
    if (files.length === 0) throw new Error('This folder is empty; nothing to share.');
    const rootName = await this.decryptFilename(
      folderRows[0]['name'] as string | Uint8Array,
      folderRows[0]['name_key'] as string | Uint8Array,
    );
    const relPathForFile = (f: FileEntry): string => {
      const parts: string[] = [f.decrypted_name];
      let parent = f.folder_id;
      while (parent !== null && parent !== folderId) {
        const d = descendants.folderPaths.get(parent);
        if (!d) break;
        parts.unshift(d.name);
        parent = d.parent_id;
      }
      return parts.join('/');
    };

    const { entry, fragment } = await this.createBundleShare({
      kind: 'folder',
      bundleKind: 'folder',
      folderId,
      collectionId: null,
      files: files.map((f) => ({ file: f, relPath: `${rootName}/${relPathForFile(f)}` })),
      bundleName: rootName,
      options,
    });
    return { entry, fragment };
  }

  async createCollectionShare(
    collectionId: number,
    options?: { password?: string; ttlSeconds?: number; onProgress?: (done: number, total: number) => void; label?: string },
  ): Promise<{ entry: ShareEntry; fragment: string }> {
    const files = await this.listCollectionFiles(collectionId);
    if (files.length === 0) throw new Error('This collection is empty; nothing to share.');
    const collectionName = await this.getDecryptedCollectionName(collectionId);

    const { entry, fragment } = await this.createBundleShare({
      kind: 'collection',
      bundleKind: 'collection',
      folderId: null,
      collectionId,
      files: files.map((f) => ({ file: f, relPath: f.decrypted_name })),
      bundleName: collectionName,
      options,
    });
    return { entry, fragment };
  }

  async createFilesShare(
    fileIds: number[],
    options?: { password?: string; ttlSeconds?: number; onProgress?: (done: number, total: number) => void; label?: string },
  ): Promise<{ entry: ShareEntry; fragment: string }> {
    if (fileIds.length === 0) throw new Error('No files selected for share.');

    const placeholders = fileIds.map(() => '?').join(',');
    const rows = queryRows(
      this.db,
      `SELECT * FROM files WHERE id IN (${placeholders})`,
      fileIds as import('sql.js').BindParams,
    );
    const files = await this.decryptFileRows(rows);
    if (files.length === 0) throw new Error('Selected files are unavailable.');

    // Flat selection can span folders — de-dup colliding decrypted
    // filenames with " (n)" before the extension so the recipient's
    // extracted zip doesn't silently overwrite or drop duplicates.
    const seen = new Map<string, number>();
    const uniq = (name: string): string => {
      const n = seen.get(name) ?? 0;
      seen.set(name, n + 1);
      if (n === 0) return name;
      const dot = name.lastIndexOf('.');
      return dot === -1
        ? `${name} (${n})`
        : `${name.slice(0, dot)} (${n})${name.slice(dot)}`;
    };

    // Relay schema constrains share kind to ('file','folder','collection'),
    // so multi-file bundles ride the 'folder' kind with a null folder_id.
    // The recipient never sees this distinction — the manifest drives
    // what lands in the zip.
    const bundleName = `${files.length} files`;
    const { entry, fragment } = await this.createBundleShare({
      kind: 'folder',
      bundleKind: 'multi-files',
      folderId: null,
      collectionId: null,
      files: files.map((f) => ({ file: f, relPath: uniq(f.decrypted_name) })),
      bundleName,
      options,
    });
    return { entry, fragment };
  }

  /**
   * Mixed-source share — one link covering any combination of folders +
   * loose files. Folder descendants are walked the same way as a single-
   * folder share (rel_path = `<folder>/<nested>/<file>`); loose files
   * land at the bundle root with their decrypted name. Filename
   * collisions across the merged tree are de-duplicated with " (n)" so
   * the recipient's zip extraction doesn't silently overwrite anything.
   *
   * Rides the same 'folder' kind on the relay (relay schema is closed at
   * file/folder/collection — multi-source bundles already share the
   * 'folder' lane with folder_id=null, see createFilesShare).
   */
  async createMixedShare(
    args: { folderIds: number[]; fileIds: number[] },
    options?: { password?: string; ttlSeconds?: number; onProgress?: (done: number, total: number) => void; label?: string },
  ): Promise<{ entry: ShareEntry; fragment: string }> {
    const folderIds = [...new Set(args.folderIds)];
    const fileIds = [...new Set(args.fileIds)];
    if (folderIds.length === 0 && fileIds.length === 0) {
      throw new Error('Nothing selected to share.');
    }

    type Item = { file: FileEntry; relPath: string };
    const items: Item[] = [];

    // 1. Walk every selected folder, prefix entries with the folder's name.
    for (const folderId of folderIds) {
      const folderRows = queryRows(this.db, 'SELECT * FROM folders WHERE id = ?', [folderId]);
      if (folderRows.length === 0) continue;
      const descendants = await this.collectFolderDescendants(folderId);
      const folderFiles = await this.collectFilesInFolders(descendants.folderIds);
      if (folderFiles.length === 0) continue;
      const rootName = await this.decryptFilename(
        folderRows[0]['name'] as string | Uint8Array,
        folderRows[0]['name_key'] as string | Uint8Array,
      );
      const relPathForFile = (f: FileEntry): string => {
        const parts: string[] = [f.decrypted_name];
        let parent = f.folder_id;
        while (parent !== null && parent !== folderId) {
          const d = descendants.folderPaths.get(parent);
          if (!d) break;
          parts.unshift(d.name);
          parent = d.parent_id;
        }
        return parts.join('/');
      };
      for (const f of folderFiles) {
        items.push({ file: f, relPath: `${rootName}/${relPathForFile(f)}` });
      }
    }

    // 2. Append loose files at the bundle root.
    if (fileIds.length > 0) {
      const placeholders = fileIds.map(() => '?').join(',');
      const rows = queryRows(
        this.db,
        `SELECT * FROM files WHERE id IN (${placeholders})`,
        fileIds as import('sql.js').BindParams,
      );
      const looseFiles = await this.decryptFileRows(rows);
      for (const f of looseFiles) {
        items.push({ file: f, relPath: f.decrypted_name });
      }
    }

    if (items.length === 0) {
      throw new Error('Selection is empty (folders had no files, or loose files were unavailable).');
    }

    // 3. Deduplicate colliding rel_paths so the recipient's zip extraction
    //    doesn't drop or overwrite. Mirrors the createFilesShare uniq() but
    //    keys on the full rel_path so a name collision deep inside a folder
    //    + same name at root doesn't surface.
    const seenPath = new Map<string, number>();
    const dedupe = (rel: string): string => {
      const n = seenPath.get(rel) ?? 0;
      seenPath.set(rel, n + 1);
      if (n === 0) return rel;
      const slash = rel.lastIndexOf('/');
      const dir = slash >= 0 ? rel.slice(0, slash + 1) : '';
      const tail = slash >= 0 ? rel.slice(slash + 1) : rel;
      const dot = tail.lastIndexOf('.');
      const dedupedTail = dot === -1
        ? `${tail} (${n})`
        : `${tail.slice(0, dot)} (${n})${tail.slice(dot)}`;
      return `${dir}${dedupedTail}`;
    };
    for (const it of items) it.relPath = dedupe(it.relPath);

    const total = folderIds.length + fileIds.length;
    const bundleName = total === 1
      ? (items[0]?.relPath.split('/')[0] ?? `${total} items`)
      : `${total} items`;

    return await this.createBundleShare({
      kind: 'folder',
      bundleKind: 'mixed',
      folderId: null,
      collectionId: null,
      files: items,
      bundleName,
      options,
    });
  }

  // ── Private: bundle share builder ───────────────────────────────────────

  /**
   * Shared implementation for folder + collection shares. Uploads each
   * file's V7 ciphertext (reused byte-for-byte from the provider) to the
   * relay as its own bundle blob, then uploads a V7-encrypted manifest
   * mapping blob_id → rel_path + per-file content_key. The bundle_key
   * carried in the URL fragment is the only thing that decrypts the
   * manifest; per-file content_keys are therefore never reachable from
   * the relay.
   */
  private async createBundleShare(args: {
    kind: 'folder' | 'collection';
    /** Finer-grained UI classification — what kind of bundle this row is
     *  in the creator's Settings view (Folder / Collection / Files / Mixed). */
    bundleKind: 'folder' | 'collection' | 'multi-files' | 'mixed';
    folderId: number | null;
    collectionId: number | null;
    files: Array<{ file: FileEntry; relPath: string }>;
    /** Display name for the recipient landing page (folder or collection
     *  name). Rides in the URL fragment as &n=<percent-encoded>; the
     *  fragment never reaches the server, so exposing the name there is
     *  no weaker than the decryption key that already sits alongside it.
     *  When `options.label` is set, that wins — otherwise this default
     *  carries through. */
    bundleName?: string;
    options?: { password?: string; ttlSeconds?: number; onProgress?: (done: number, total: number) => void; label?: string };
  }): Promise<{ entry: ShareEntry; fragment: string }> {
    const HEADER_SIZE = 1709;
    const ttl = args.options?.ttlSeconds ?? 86400;

    // 1. Fresh random bundle_key. Generated client-side; lives only long
    //    enough to build the fragment, encrypt the manifest, and zero out.
    const bundleKey = new Uint8Array(32);
    crypto.getRandomValues(bundleKey);
    const bundleKeyB64 = _bytesToBase64(bundleKey);

    // 2. Build fragment from the bundle_key (raw for public shares,
    //    Argon2id-wrapped when a password is set). Append the bundle
    //    display name as `&n=<percent-encoded>` so the recipient's
    //    landing page can show a real title instead of a generic
    //    "Folder" placeholder. The fragment is client-only — never sent
    //    to the relay — so exposing the name there is no weaker than
    //    the key that already rides alongside it.
    // User-supplied label wins over the inferred bundleName. Both ends
    // of the share will then read the same string from the fragment.
    const recipientName = args.options?.label?.trim() || args.bundleName;
    let fragment: string;
    try {
      if (args.options?.password) {
        const wrapped = await byoWorker.Worker.byoShareWrapKey(bundleKeyB64, args.options.password);
        fragment = `s=${wrapped.saltB64url}&e=${wrapped.encryptedCkB64url}`;
      } else {
        fragment = await byoWorker.Worker.byoShareEncodeVariantA(bundleKeyB64);
      }
      if (recipientName) {
        fragment = `${fragment}&n=${encodeURIComponent(recipientName)}`;
      }
    } finally {
      bundleKey.fill(0);
    }

    // 3. init_bundle — PoW-gated cookie + returns bundle_token.
    // The relay consumes the cookie's JTI on this POST (share_relay.rs
    // line 547), so the cached purpose entry would replay a dead cookie
    // on the next bundle share and 401. Evict immediately regardless of
    // success so the following share re-PoWs. Subsequent blob uploads +
    // seal use X-Bundle-Token, not the cookie, so no follow-up fetches
    // depend on the cache entry.
    await acquireRelayCookie('share:bundle:init');
    let initResp: Response;
    try {
      initResp = await fetch('/relay/share/bundle/init', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind: args.kind, expires_in_secs: ttl }),
      });
    } finally {
      evictRelayCookieCache('share:bundle:init');
    }
    if (!initResp.ok) {
      const limit = parseShareLimitError(initResp);
      if (limit) throw limit;
      throw new Error(`Bundle init failed: ${initResp.status}`);
    }
    const initText = await initResp.text();
    addShareRelayBandwidth(initText.length);
    const initData = JSON.parse(initText) as {
      share_id: string;
      expires_at: number;
      owner_token: string;
      bundle_token: string;
    };
    const { share_id: shareId, owner_token: ownerToken, bundle_token: bundleToken } = initData;

    // 4. Per-file: pull ciphertext from provider, extract per-file
    //    content_key from its V7 header, upload to /relay/share/bundle/...
    //    On any failure, best-effort revoke the half-built share so the
    //    orphan sweeper doesn't have to wait 4 h.
    const entries: Array<{
      blob_id: string;
      rel_path: string;
      content_key_b64: string;
      size: number;
      ciphertext_size: number;
      mime: string;
    }> = [];
    let totalCiphertextBytes = 0;
    try {
      for (let i = 0; i < args.files.length; i++) {
        const { file, relPath } = args.files[i];
        const provider = await this.resolveProvider(file.provider_id ?? this.activeProviderId);
        const blobId = crypto.randomUUID();
        const blobUrl = `/relay/share/bundle/${encodeURIComponent(shareId)}/blob/${encodeURIComponent(blobId)}`;

        const { header, ciphertextBytes } = await this.withAuthRetry(async () => {
          const readable = await provider.downloadStream(file.storage_ref);
          const peeked = await peekHeaderAndResume(readable, HEADER_SIZE).catch((e) => {
            throw new Error(`File "${file.decrypted_name}" is too small to be a valid V7 blob: ${e}`);
          });
          const fullBody = prependBytes(peeked.header, peeked.body);
          const streamingOk = supportsRequestStreams();
          let size: number;
          if (streamingOk) {
            const tapped = countingTap(fullBody);
            const resp = await fetch(blobUrl, {
              method: 'POST',
              credentials: 'same-origin',
              headers: {
                'Content-Type': 'application/octet-stream',
                'X-Bundle-Token': bundleToken,
              },
              body: tapped.body,
              duplex: 'half',
            } as RequestInit & { duplex: 'half' });
            if (!resp.ok) {
              const limit = parseShareLimitError(resp);
              if (limit) throw limit;
              throw new Error(`Blob upload failed (${resp.status}) for "${file.decrypted_name}"`);
            }
            size = tapped.bytes();
          } else {
            // See ByoDataProvider line ~1118 — Firefox-default fallback.
            console.warn(
              '[share] browser lacks streaming request bodies — buffering ciphertext (peak heap ≈ ciphertext size)',
            );
            const buf = await drainToBuffer(fullBody);
            const resp = await fetch(blobUrl, {
              method: 'POST',
              credentials: 'same-origin',
              headers: {
                'Content-Type': 'application/octet-stream',
                'X-Bundle-Token': bundleToken,
              },
              body: buf as BodyInit,
            });
            if (!resp.ok) {
              const limit = parseShareLimitError(resp);
              if (limit) throw limit;
              throw new Error(`Blob upload failed (${resp.status}) for "${file.decrypted_name}"`);
            }
            size = buf.byteLength;
          }
          return { header: peeked.header, ciphertextBytes: size };
        }, provider);

        const headerB64 = _bytesToBase64(header);
        const contentKeyB64 = await byoWorker.Worker.byoBundleExtractFileKey(
          String(this.sessionId),
          headerB64,
        );

        addShareRelayBandwidth(ciphertextBytes);

        entries.push({
          blob_id: blobId,
          rel_path: relPath,
          content_key_b64: contentKeyB64,
          size: file.size,
          ciphertext_size: ciphertextBytes,
          mime: file.mime_type || 'application/octet-stream',
        });
        totalCiphertextBytes += ciphertextBytes;
        args.options?.onProgress?.(i + 1, args.files.length);
      }

      // 5. Build + V7-encrypt manifest under the bundle_key.
      const manifestJson = JSON.stringify({ version: 1, entries });
      const manifestBytes = new TextEncoder().encode(manifestJson);
      const manifestBytesB64 = _bytesToBase64(manifestBytes);
      const manifestCtB64 = await byoWorker.Worker.byoEncryptManifestV7(
        manifestBytesB64,
        bundleKeyB64,
      );
      // Copy into a fresh ArrayBuffer-backed Uint8Array so fetch's BodyInit
      // overload accepts it without a generic-arg mismatch.
      const manifestCtSource = _base64ToBytes(manifestCtB64);
      const manifestCt = new Uint8Array(manifestCtSource.byteLength);
      manifestCt.set(manifestCtSource);
      totalCiphertextBytes += manifestCt.byteLength;

      // 6. seal_bundle — uploads the _manifest blob and flips sealed=1.
      const sealResp = await fetch(
        `/relay/share/bundle/${encodeURIComponent(shareId)}/seal`,
        {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-Bundle-Token': bundleToken,
          },
          body: manifestCt,
        },
      );
      if (!sealResp.ok) {
        const limit = parseShareLimitError(sealResp);
        if (limit) throw limit;
        throw new Error(`Bundle seal failed: ${sealResp.status}`);
      }
      addShareRelayBandwidth(manifestCt.byteLength);
    } catch (e) {
      // Best-effort cleanup of a half-built share.
      try {
        await fetch(`/relay/share/b2/${encodeURIComponent(shareId)}`, {
          method: 'DELETE',
          credentials: 'same-origin',
          headers: { 'X-Owner-Token': ownerToken },
        });
      } catch {
        /* orphan sweeper will get it after UNSEALED_MAX_LIFETIME_SECS */
      }
      throw e;
    }

    // 7. Persist share row.
    const createdAt = Date.now();
    const presignedExpiresAt = initData.expires_at * 1000;
    const entry = await this.persistShareRow({
      shareId,
      kind: args.kind,
      fileId: null,
      folderId: args.folderId,
      collectionId: args.collectionId,
      providerId: this.activeProviderId,
      providerRef: null,
      presignedExpiresAt,
      createdAt,
      ownerToken,
      totalBytes: totalCiphertextBytes,
      blobCount: entries.length + 1, // +1 for _manifest
      plaintextSize: 0,
      fragment,
      bundleKind: args.bundleKind,
      label: args.options?.label?.trim() || null,
    });
    recordEvent('share_create', { share_variant: 'B2' });
    refreshShareStats(this);
    return { entry, fragment };
  }

  /** Insert a share_tokens row + return the corresponding ShareEntry. */
  private async persistShareRow(row: {
    shareId: string;
    kind: 'file' | 'folder' | 'collection';
    fileId: number | null;
    folderId: number | null;
    collectionId: number | null;
    providerId: string;
    providerRef: string | null;
    presignedExpiresAt: number;
    createdAt: number;
    ownerToken: string | null;
    totalBytes: number;
    blobCount: number;
    plaintextSize: number;
    /** URL fragment carrying the decryption key + bundle name. Stored so
     *  the user can copy the share link again from Settings later. Never
     *  reaches the relay. */
    fragment: string;
    /** Finer-grained classification than `kind` for UI badges. */
    bundleKind: 'file' | 'folder' | 'collection' | 'multi-files' | 'mixed';
    /** Optional user-supplied display name. NULL → UI infers from kind. */
    label: string | null;
  }): Promise<ShareEntry> {
    const sql = `INSERT INTO share_tokens
         (share_id, kind, file_id, folder_id, collection_id, provider_id,
          provider_ref, public_link, presigned_expires_at,
          owner_token, total_bytes, blob_count, created_at, revoked,
          fragment, bundle_kind, label)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, 0, ?, ?, ?)`;
    const params = [
      row.shareId,
      row.kind,
      row.fileId,
      row.folderId,
      row.collectionId,
      row.providerId,
      row.providerRef,
      row.presignedExpiresAt,
      row.ownerToken,
      row.totalBytes,
      row.blobCount,
      row.createdAt,
      row.fragment,
      row.bundleKind,
      row.label,
    ];
    await this.onMutate(sql, params);
    this.db.run(sql, params as import('sql.js').BindParams);
    markDirty(this.activeProviderId);
    return {
      share_id: row.shareId,
      kind: row.kind,
      file_id: row.fileId,
      folder_id: row.folderId,
      collection_id: row.collectionId,
      provider_id: row.providerId,
      provider_ref: row.providerRef,
      public_link: null,
      presigned_expires_at: row.presignedExpiresAt,
      total_bytes: row.totalBytes,
      blob_count: row.blobCount,
      created_at: row.createdAt,
      revoked: false,
      fragment: row.fragment,
      bundle_kind: row.bundleKind,
      label: row.label,
    };
  }

  /** Walk a folder subtree; return every descendant folder id (inclusive)
   *  plus a lookup of decrypted name + parent id per folder. */
  private async collectFolderDescendants(rootId: number): Promise<{
    folderIds: Set<number>;
    folderPaths: Map<number, { name: string; parent_id: number | null }>;
  }> {
    const folderIds = new Set<number>([rootId]);
    const stack: number[] = [rootId];
    const allRows: Array<Record<string, unknown>> = [];
    while (stack.length > 0) {
      const pid = stack.pop() as number;
      const children = queryRows(this.db, 'SELECT * FROM folders WHERE parent_id = ?', [pid]);
      for (const c of children) {
        const cid = c['id'] as number;
        if (!folderIds.has(cid)) {
          folderIds.add(cid);
          stack.push(cid);
          allRows.push(c);
        }
      }
    }
    const decrypted = await Promise.all(
      allRows.map((r) => this.decryptFilename(
        r['name'] as string | Uint8Array,
        r['name_key'] as string | Uint8Array,
      )),
    );
    const folderPaths = new Map<number, { name: string; parent_id: number | null }>();
    for (let i = 0; i < allRows.length; i++) {
      folderPaths.set(allRows[i]['id'] as number, {
        name: decrypted[i],
        parent_id: allRows[i]['parent_id'] as number | null,
      });
    }
    return { folderIds, folderPaths };
  }

  /** Decrypt every file row whose folder_id is in `folderIds`. */
  private async collectFilesInFolders(folderIds: Set<number>): Promise<FileEntry[]> {
    if (folderIds.size === 0) return [];
    const placeholders = Array.from(folderIds).map(() => '?').join(',');
    const rows = queryRows(
      this.db,
      `SELECT * FROM files WHERE folder_id IN (${placeholders}) ORDER BY name`,
      Array.from(folderIds) as import('sql.js').BindParams,
    );
    return this.decryptFileRows(rows);
  }

  async revokeShare(shareId: string): Promise<void> {
    const rows = queryRows(this.db, 'SELECT * FROM share_tokens WHERE share_id = ?', [shareId]);
    if (rows.length === 0) throw new Error('Share not found');
    const row = rows[0] as Record<string, unknown>;
    const token = row['owner_token'] as string | null;

    if (token) {
      const endpoint = `/relay/share/b2/${encodeURIComponent(shareId)}`;
      try {
        const revokeResp = await fetch(endpoint, {
          method: 'DELETE',
          credentials: 'same-origin',
          headers: { 'X-Owner-Token': token },
        });
        addShareRelayBandwidth(endpoint.length + (await revokeResp.text()).length);
      } catch {
        // Best-effort; local revocation proceeds regardless.
      }
    }

    const revokeShareSql = 'UPDATE share_tokens SET revoked = 1 WHERE share_id = ?';
    await this.onMutate(revokeShareSql, [shareId]);
    this.db.run(revokeShareSql, [shareId]);
    markDirty(this.activeProviderId);
    recordEvent('share_revoke', { share_variant: 'B2' });
    refreshShareStats(this);
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

  async getDecryptedFolderName(folderId: number): Promise<string> {
    const rows = queryRows(this.db, 'SELECT name, name_key FROM folders WHERE id = ?', [folderId]);
    if (rows.length === 0) return '[deleted]';
    const row = rows[0] as Record<string, unknown>;
    return this.decryptFilename(
      row['name'] as string | Uint8Array,
      row['name_key'] as string | Uint8Array,
    );
  }

  async getDecryptedCollectionName(collectionId: number): Promise<string> {
    const rows = queryRows(this.db, 'SELECT name, name_key FROM collections WHERE id = ?', [collectionId]);
    if (rows.length === 0) return '[deleted]';
    const row = rows[0] as Record<string, unknown>;
    return this.decryptFilename(
      row['name'] as string | Uint8Array,
      row['name_key'] as string | Uint8Array,
    );
  }

  listShares(): ShareEntry[] {
    // Filter out shares whose expires_at has passed — the relay sweeper
    // already purged the blob, so the local row is dead weight. Hiding
    // them here also avoids the UX cliff the user reported: an expired
    // row offering a "Revoke" button with the same confirmation copy as
    // an active share. Extending isn't possible without re-uploading the
    // ciphertext (the relay's blob is gone), so cleanup is the right
    // default here. Rows are kept in the DB so a future history view
    // could surface them; only the live-shares list filters.
    const now = Date.now();
    const rows = queryRows(
      this.db,
      `SELECT * FROM share_tokens
       WHERE revoked = 0
         AND (presigned_expires_at IS NULL OR presigned_expires_at > ?)
       ORDER BY created_at DESC`,
      [now],
    );
    return rows.map((r) => {
      const row = r as Record<string, unknown>;
      const kind = ((row['kind'] as string | null) ?? 'file') as 'file' | 'folder' | 'collection';
      return {
        share_id: row['share_id'] as string,
        kind,
        file_id: (row['file_id'] as number | null) ?? null,
        folder_id: (row['folder_id'] as number | null) ?? null,
        collection_id: (row['collection_id'] as number | null) ?? null,
        provider_id: (row['provider_id'] as string | null) ?? null,
        provider_ref: (row['provider_ref'] as string | null) ?? null,
        public_link: (row['public_link'] as string | null) ?? null,
        presigned_expires_at: (row['presigned_expires_at'] as number | null) ?? null,
        total_bytes: (row['total_bytes'] as number | null) ?? null,
        blob_count: (row['blob_count'] as number | null) ?? null,
        created_at: row['created_at'] as number,
        revoked: false,
        fragment: (row['fragment'] as string | null) ?? null,
        bundle_kind: (row['bundle_kind'] as string | null) ?? null,
        label: (row['label'] as string | null) ?? null,
      };
    });
  }

  // ── Private: mutation helper ───────────────────────────────────────────

  /**
   * Called before every SQL mutation:
   *   1. Appends WAL entry for crash recovery
   *   2. Appends journal entry for cloud-side journal
   *
   * Both the WAL and the journal are per-provider — pre-fix this used
   * the primary's key/journal regardless of which provider's slice was
   * being mutated, so writes via a secondary never made it into that
   * secondary's WAL/journal and were silently lost on reload when the
   * secondary was offline (saveVault skips body uploads for offline
   * dirty providers, and WAL replay was the safety net that would have
   * caught it). Scope to `activeProviderId` so the WAL key matches the
   * walId saveVault clears (`vaultId + ':' + pid`) and the journal
   * matches the one saveVault commits.
   */
  private async onMutate(sql: string, params: unknown[]): Promise<void> {
    const vaultId = getVaultId();
    const pid = this.activeProviderId;
    if (!pid) return;
    const walKey = getWalKeyForProvider(pid);
    const journal = getJournalForProvider(pid);

    if (walKey) {
      await appendWal(`${vaultId}:${pid}`, walKey, sql, params);
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
