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

// ── Trash entry ────────────────────────────────────────────────────────────

// ── Share entry ────────────────────────────────────────────────────────────

export type ShareVariant = 'A' | 'A+' | 'B1' | 'B2';

export interface ShareEntry {
  share_id: string;
  file_id: number;
  provider_id: string | null;
  provider_ref: string;
  variant: ShareVariant;
  /** Provider public link URL (Variant A / A+). */
  public_link: string | null;
  /** Expiry timestamp in Unix ms for B1 presigned URLs. */
  presigned_expires_at: number | null;
  created_at: number;
  revoked: boolean;
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

  /** Moves file to trash table. Does NOT delete provider blob immediately. */
  deleteFile(fileId: number): Promise<void>;

  moveFile(fileId: number, targetFolderId: number | null): Promise<void>;

  renameFile(fileId: number, newName: string): Promise<void>;

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

  /** List all image files across all folders, sorted by created_at descending. */
  listImageFiles(): Promise<FileEntry[]>;

  // ── Storage ───────────────────────────────────────────────────────

  getStorageUsage(): Promise<StorageUsage>;

  // ── Key versions ──────────────────────────────────────────────────

  /** Returns the current active key version's public keys as JSON string for the worker. */
  getActivePublicKeysJson(): Promise<string>;

  /** Returns the current active key version id. */
  getActiveKeyVersionId(): Promise<number>;

  // ── Share links (P10) ─────────────────────────────────────────────

  /**
   * Create a share link for a file.
   * Returns the share entry and the URL fragment (e.g. "k=<base64url>").
   */
  createShareLink(
    fileId: number,
    variant: ShareVariant,
    options?: { password?: string; ttlSeconds?: number },
  ): Promise<{ entry: ShareEntry; fragment: string }>;

  /** Revoke a share link by share_id. */
  revokeShare(shareId: string): Promise<void>;

  /** List all active (non-revoked) share tokens. */
  listShares(): ShareEntry[];

  /** Decrypt and return the filename for a file_id; returns '[deleted]' if not found. */
  getDecryptedFileName(fileId: number): Promise<string>;

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
