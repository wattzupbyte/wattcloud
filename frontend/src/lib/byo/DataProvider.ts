/**
 * BYO DataProvider interface.
 *
 * Decouples BYO UI components from the underlying data source (local SQLite
 * vault + cloud storage). This is BYO-only — managed mode components continue
 * calling `api.*` directly and are untouched.
 *
 * The implementing class is ByoDataProvider, which orchestrates:
 *   - sql.js in-memory SQLite (decrypted vault body)
 *   - StorageProvider (cloud blob I/O)
 *   - BYO Web Worker via byoWorkerClient (all crypto operations)
 *   - IndexedDB WAL (crash recovery)
 *   - VaultJournal (cloud-side append-only mutation log)
 *
 * See BYO_PLAN §6.1 for the full interface specification.
 */

// ── File entry ─────────────────────────────────────────────────────────────

/**
 * A decrypted file entry from the BYO vault SQLite.
 * Compatible with `FileRecord` from frontend/src/lib/stores/files.ts in shape;
 * differences reflect BYO-specific fields (storage_ref vs storage_path, etc.).
 */
export interface FileEntry {
  id: number;
  folder_id: number | null;
  /** Encrypted filename blob (base64). Stored in vault SQLite. */
  name: string;
  /** Decrypted filename for display. Always populated in BYO mode. */
  decrypted_name: string;
  /** File size in plaintext bytes. */
  size: number;
  /** Encrypted file size (V7 wire format). */
  encrypted_size: number;
  /** Provider-specific blob identifier (UUID). Used to locate V7 blob on provider. */
  storage_ref: string;
  /** MIME type detected at upload time. */
  mime_type: string;
  /** File type category (image, video, document, etc.). */
  file_type: string;
  /** key_versions row id used to encrypt this file. */
  key_version_id: number;
  /** Encrypted EXIF metadata JSON (base64), or empty string. */
  metadata: string;
  created_at: string;
  updated_at: string;
  /** Provider ID that holds this file's blob (P9 multi-provider). */
  provider_id?: string | null;
}

// ── Folder entry ───────────────────────────────────────────────────────────

/**
 * A decrypted folder entry from the BYO vault SQLite.
 * Compatible with `Folder` from frontend/src/lib/stores/files.ts in shape.
 */
export interface FolderEntry {
  id: number;
  parent_id: number | null;
  /** Encrypted folder name blob (base64). */
  name: string;
  /** Decrypted folder name for display. Always populated in BYO mode. */
  decrypted_name: string;
  /** Encrypted key used for folder name (base64). */
  name_key: string;
  created_at: string;
  updated_at: string;
  /** Provider ID that owns this folder (P9 multi-provider). */
  provider_id?: string | null;
}

// ── Collection entry ───────────────────────────────────────────────────────

export interface CollectionEntry {
  id: number;
  name: string;
  decrypted_name: string;
  name_key: string;
  cover_file_id: number | null;
  photo_count: number;
  created_at: string;
  updated_at: string;
  provider_id?: string | null;
}

// ── Trash entry ────────────────────────────────────────────────────────────

// ── Share entry ────────────────────────────────────────────────────────────

export type ShareKind = 'file' | 'folder' | 'collection';

export interface ShareEntry {
  share_id: string;
  /** What the share points at: a single file, a folder bundle, or a photo collection. */
  kind: ShareKind;
  /** Source file id — NULL for folder / collection shares. */
  file_id: number | null;
  /** Source folder id — non-null only for `kind = 'folder'`. */
  folder_id: number | null;
  /** Source collection id — non-null only for `kind = 'collection'`. */
  collection_id: number | null;
  provider_id: string | null;
  /** Provider storage_ref for single-file shares; NULL for bundles (content lives on the relay). */
  provider_ref: string | null;
  /** Unused in the relay-only flow; kept for row-shape stability. */
  public_link: string | null;
  /** Share expiry timestamp (Unix ms). */
  presigned_expires_at: number | null;
  /** Sum of ciphertext bytes stored on the relay for this share. */
  total_bytes: number | null;
  /** Blob count on the relay: 1 for single-file, N+1 (manifest) for bundles. */
  blob_count: number | null;
  created_at: number;
  revoked: boolean;
  /** URL fragment (key + optional bundle name) needed to reconstruct the
   *  share link after the create-flow modal is dismissed. NULL for shares
   *  created before the recoverable-link change shipped — those remain
   *  copy-once. Never POSTed; vault SQLite is wrapped under vault_key. */
  fragment: string | null;
  /** Finer-grained classification than `kind` for UI badges. Values:
   *  'file' | 'folder' | 'collection' | 'multi-files' | 'mixed'.
   *  NULL for legacy rows — UI falls back to `kind`. */
  bundle_kind: string | null;
  /** Optional user-supplied display name. Same value surfaces on the
   *  recipient's landing page (via fragment) so the two ends agree.
   *  NULL → both ends fall back to the inferred name. */
  label: string | null;
}

export interface TrashEntry {
  id: number;
  item_type: 'file' | 'folder';
  original_id: number;
  /** Serialized original row (JSON). */
  data: string;
  deleted_at: string;
  expires_at: string;
  /** Whether the provider blob still exists. null = not yet checked. */
  blob_available?: boolean | null;
}

// ── Key version ────────────────────────────────────────────────────────────

export interface KeyVersion {
  id: number;
  version: number;
  mlkem_public_key: Uint8Array;
  x25519_public_key: Uint8Array;
  status: 'active' | 'archived';
  created_at: string;
}

// ── Storage usage ──────────────────────────────────────────────────────────

export interface StorageUsage {
  /** Total bytes across all files in vault (plaintext sizes). */
  used: number;
  /** Provider quota in bytes, or null if provider doesn't expose it. */
  quota: number | null;
}

// ── DataProvider interface ─────────────────────────────────────────────────

/**
 * Primary interface for BYO data operations.
 *
 * All mutating methods (upload, delete, rename, move, createFolder, etc.)
 * automatically:
 *   1. Append a WAL entry to IndexedDB
 *   2. Execute the SQL mutation
 *   3. Append a journal entry to the cloud journal buffer
 *   4. Mark the vault dirty (triggers adaptive debounced save)
 */
export interface DataProvider {
  // ── File operations ──────────────────────────────────────────────────

  listFiles(folderId: number | null): Promise<FileEntry[]>;

  uploadFile(
    folderId: number | null,
    file: File,
    onProgress?: (bytesWritten: number) => void,
    uploadOpts?: { pauseSignal?: { isPaused(): boolean; wait(): Promise<void> } },
  ): Promise<FileEntry>;

  /** Returns a ReadableStream of plaintext bytes. */
  downloadFile(fileId: number): Promise<ReadableStream<Uint8Array>>;

  /**
   * Append a row to the per-vault `share_audit` table.
   * Used by OS share-sheet flows (outbound `navigator.share`, inbound
   * Web Share Target). Goes through the standard mutation path so the
   * change is captured in the WAL + cloud journal.
   */
  recordShareAudit(
    direction: 'outbound' | 'inbound',
    fileRef: string,
    counterpartyHint?: string | null,
  ): Promise<void>;

  /**
   * Returns a ReadableStream of zip bytes containing the folder and all
   * its descendants (files + nested subfolders), with each entry's path
   * preserved relative to the root folder so the zip restores the tree.
   * Streaming end-to-end — no full-file buffering.
   */
  downloadFolderAsZip(folderId: number): Promise<{ stream: ReadableStream<Uint8Array>; filename: string }>;

  /**
   * Returns a ReadableStream of zip bytes containing the listed files,
   * flat (no folder structure). Each entry uses the file's own name.
   */
  downloadFilesAsZip(fileIds: number[], zipName: string): Promise<ReadableStream<Uint8Array>>;

  /** Moves file to trash table. Does NOT delete provider blob immediately. */
  deleteFile(fileId: number): Promise<void>;

  moveFile(fileId: number, targetFolderId: number | null): Promise<void>;

  renameFile(fileId: number, newName: string): Promise<void>;

  /**
   * Overwrite the `metadata` column for a file. Used by the EXIF re-extract
   * backfill — callers download the file, parse EXIF, serialize via
   * `serializeExif`, then persist the new JSON here.
   */
  updateFileMetadata(fileId: number, metadataJson: string): Promise<void>;

  // ── Folder operations ─────────────────────────────────────────────

  listFolders(parentId: number | null): Promise<FolderEntry[]>;

  createFolder(parentId: number | null, name: string): Promise<FolderEntry>;

  /** Moves folder to trash table. */
  deleteFolder(folderId: number): Promise<void>;

  renameFolder(folderId: number, newName: string): Promise<void>;

  moveFolder(folderId: number, targetParentId: number | null): Promise<void>;

  // ── Favorites ─────────────────────────────────────────────────────

  getFavorites(): Promise<{ files: FileEntry[]; folders: FolderEntry[] }>;

  /** Toggles favorite state. Returns true if now favorited, false if unfavorited. */
  toggleFavorite(type: 'file' | 'folder', id: number): Promise<boolean>;

  // ── Search ────────────────────────────────────────────────────────

  /** Case-insensitive substring search over decrypted filenames. */
  searchFiles(query: string): Promise<FileEntry[]>;

  /** Case-insensitive substring search over decrypted folder names. */
  searchFolders(query: string): Promise<FolderEntry[]>;

  /** All files belonging to the active provider, any folder. Used as a
   *  type-filter fallback when the search has no free-text query. */
  listAllFiles(): Promise<FileEntry[]>;

  /**
   * List image files sorted by created_at descending.
   * - `undefined` → all images in the active provider.
   * - `null`      → images at the vault root only.
   * - `number`    → images inside that folder and all its descendants.
   */
  listImageFiles(folderId?: number | null): Promise<FileEntry[]>;
  /** Flat list of every folder in the active provider (for folder pickers). */
  listAllFolders(): Promise<FolderEntry[]>;

  // ── Collections ──────────────────────────────────────────────────
  listCollections(): Promise<CollectionEntry[]>;
  createCollection(name: string): Promise<CollectionEntry>;
  renameCollection(collectionId: number, newName: string): Promise<void>;
  deleteCollection(collectionId: number): Promise<void>;
  listCollectionFiles(collectionId: number): Promise<FileEntry[]>;
  addFilesToCollection(collectionId: number, fileIds: number[]): Promise<void>;
  removeFilesFromCollection(collectionId: number, fileIds: number[]): Promise<void>;
  /** Set the `cover_file_id` on a collection. Pass null to clear the cover. */
  setCollectionCover(collectionId: number, fileId: number | null): Promise<void>;

  // ── Storage ───────────────────────────────────────────────────────

  getStorageUsage(): Promise<StorageUsage>;

  // ── Key versions ──────────────────────────────────────────────────

  /** Returns the current active key version's public keys as JSON string for the worker. */
  getActivePublicKeysJson(): Promise<string>;

  /** Returns the current active key version id. */
  getActiveKeyVersionId(): Promise<number>;

  // ── Share links (P10) ─────────────────────────────────────────────

  /**
   * Create a share link for a file. Always uploads to the Wattcloud relay
   * so the recipient doesn't need provider access. The `password` option
   * wraps the URL-fragment content_key in an Argon2id-derived key.
   */
  createShareLink(
    fileId: number,
    options?: {
      password?: string;
      ttlSeconds?: number;
      /** Original decrypted filename to ride on the fragment as `&n=`,
       *  so the recipient lands on a page titled with the real name
       *  and saves the download under that name instead of a generic
       *  sentinel. Fragment never reaches the relay. */
      filename?: string;
      /** Optional user-supplied display name. When set, OVERRIDES `filename`
       *  on the recipient's landing page and is persisted to share_tokens
       *  so Settings shows the same name. */
      label?: string;
    },
  ): Promise<{ entry: ShareEntry; fragment: string }>;

  /**
   * Create a share link for a folder and all its descendants. Each file is
   * re-uploaded to the relay as its own V7 blob; a manifest maps blob_id →
   * relative path + per-file content_key. The bundle_key in the URL fragment
   * decrypts the manifest; per-file keys live only inside the manifest and
   * never reach the relay.
   */
  createFolderShare(
    folderId: number,
    options?: { password?: string; ttlSeconds?: number; onProgress?: (done: number, total: number) => void; label?: string },
  ): Promise<{ entry: ShareEntry; fragment: string }>;

  /** Same as `createFolderShare` but for a photo collection. */
  createCollectionShare(
    collectionId: number,
    options?: { password?: string; ttlSeconds?: number; onProgress?: (done: number, total: number) => void; label?: string },
  ): Promise<{ entry: ShareEntry; fragment: string }>;

  /**
   * Bundle share for an arbitrary selection of files (flat — no folder
   * structure preserved, since the selection can span multiple folders
   * and there is no single root). Recipient downloads one zip containing
   * each file at the top level; colliding names get a " (n)" suffix.
   */
  createFilesShare(
    fileIds: number[],
    options?: { password?: string; ttlSeconds?: number; onProgress?: (done: number, total: number) => void; label?: string },
  ): Promise<{ entry: ShareEntry; fragment: string }>;

  /**
   * Mixed-source bundle share — any combination of folders + loose files
   * in a single link. Folder descendants keep their tree (rel_path =
   * `<folder>/<nested>/<file>`); loose files land at the bundle root.
   * Use this when the selection has folders AND files, or two-or-more
   * folders. Single-folder / single-file flows still go through their
   * dedicated methods for clearer recipient titles.
   */
  createMixedShare(
    args: { folderIds: number[]; fileIds: number[] },
    options?: { password?: string; ttlSeconds?: number; onProgress?: (done: number, total: number) => void; label?: string },
  ): Promise<{ entry: ShareEntry; fragment: string }>;

  /** Revoke a share link by share_id. */
  revokeShare(shareId: string): Promise<void>;

  /** List all active (non-revoked) share tokens. */
  listShares(): ShareEntry[];

  /** Decrypt and return the filename for a file_id; returns '[deleted]' if not found. */
  getDecryptedFileName(fileId: number): Promise<string>;

  /** Decrypt and return the folder name for a folder_id; returns '[deleted]' if not found. */
  getDecryptedFolderName(folderId: number): Promise<string>;

  /** Decrypt and return the collection name for a collection_id; returns '[deleted]' if not found. */
  getDecryptedCollectionName(collectionId: number): Promise<string>;

  // ── Trash ──────────────────────────────────────────────────────────

  /** List all trash entries, sorted by deleted_at descending. */
  listTrash(): TrashEntry[];

  /** Check whether the provider blob for a trash entry still exists. */
  checkBlobAvailability(entry: TrashEntry): Promise<boolean>;

  /**
   * Restore a trash entry to its original table.
   * Returns false if the file blob is no longer available.
   */
  restoreItem(trashId: number): Promise<boolean>;

  /** Permanently delete a trash entry and its provider blob. */
  permanentDelete(trashId: number): Promise<void>;

  /** Permanently delete all trash entries and their provider blobs. */
  emptyTrash(): Promise<void>;
}
