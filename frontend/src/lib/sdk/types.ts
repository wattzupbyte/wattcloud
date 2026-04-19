/**
 * BYO Storage Provider types.
 *
 * All file content passed to StorageProvider methods is already encrypted
 * as V7 wire format. The provider never sees plaintext — it handles opaque
 * blob I/O only.
 */

// ── Provider type discriminator ────────────────────────────────────────────

export type ProviderType = 'gdrive' | 'dropbox' | 'onedrive' | 'webdav' | 'sftp' | 'box' | 'pcloud' | 's3';

// ── Storage entries ────────────────────────────────────────────────────────

export interface StorageEntry {
  /** Provider-specific file/folder identifier (file ID, path, etc.) */
  ref: string;
  /** Display name of the file or folder */
  name: string;
  /** Size in bytes (0 for folders) */
  size: number;
  /** Whether this entry is a folder */
  isFolder: boolean;
  /** MIME type if available */
  mimeType?: string;
  /** Last modification time (ISO 8601) */
  modifiedAt?: string;
}

// ── Upload / Download options ──────────────────────────────────────────────

export interface UploadOptions {
  /** Parent folder ref (null = root SecureCloud/ directory) */
  parentRef?: string;
  /** ETag/rev for optimistic concurrency (vault saves) */
  expectedVersion?: string;
  /** Content-Type override */
  mimeType?: string;
  /** Progress callback — bytes written so far */
  onProgress?: (bytesWritten: number) => void;
}

export interface UploadResult {
  /** Provider-specific file identifier */
  ref: string;
  /** ETag/rev for subsequent conflict detection */
  version: string;
}

// ── Provider configuration ──────────────────────────────────────────────────
//
// Carried encrypted inside vault SQLite provider_config table.
// Encryption/decryption is handled by ByoDataProvider (Phase 5),
// not by StorageProvider itself.

export interface ProviderConfig {
  type: ProviderType;
  /** Stable UUID identifying this provider connection within the vault. */
  providerId?: string;

  // OAuth providers (GDrive, Dropbox, OneDrive)
  accessToken?: string;
  refreshToken?: string;
  /** Unix timestamp in ms when accessToken expires */
  tokenExpiry?: number;

  // WebDAV
  serverUrl?: string;
  username?: string;
  /** App password or digest auth password */
  password?: string;

  /**
   * User-supplied OAuth client ID. When set, overrides the build-time
   * VITE_BYO_*_CLIENT_ID env var. Allows self-hosters to bring their own
   * OAuth application without rebuilding the frontend.
   * Stored encrypted inside the vault alongside other provider credentials.
   */
  clientId?: string;

  // SFTP
  sftpHost?: string;
  sftpPort?: number;
  sftpUsername?: string;
  sftpPassword?: string;
  /** PEM-encoded private key */
  sftpPrivateKey?: string;
  /** Optional passphrase for private key */
  sftpPassphrase?: string;
  /**
   * SHA-256 fingerprint of the SFTP server's host key (TOFU).
   * Stored in the vault on first successful connection.
   * On subsequent connections the relay sends the fingerprint before auth;
   * the client rejects connections where fingerprint != storedFingerprint.
   * Format: "SHA256:<base64>" (same as ssh-keygen -l -E sha256).
   */
  sftpHostKeyFingerprint?: string;
  /** pCloud region: 'us' (default) or 'eu'. pCloud accounts are datacenter-locked. */
  pcloudRegion?: string;

  // S3-family (AWS S3, Cloudflare R2, Backblaze B2, Wasabi, MinIO)
  s3Endpoint?: string;
  s3Region?: string;
  s3Bucket?: string;
  s3AccessKeyId?: string;
  s3SecretAccessKey?: string;
  /** true for MinIO / path-style endpoints. Default: virtual-hosted (false). */
  s3PathStyle?: boolean;
}

// ── StorageProvider interface ──────────────────────────────────────────────

export interface StorageProvider {
  readonly type: ProviderType;
  readonly displayName: string;

  // ── Lifecycle ──────────────────────────────────────────────────────────

  /** Initialize with saved config (from encrypted vault storage) or trigger OAuth. */
  init(savedConfig?: ProviderConfig): Promise<void>;

  /** Whether the provider is ready for I/O operations. */
  isReady(): boolean;

  /** Clean up: close WS connections, revoke tokens, etc. */
  disconnect(): Promise<void>;

  /** Get current config for encrypted persistence in vault. */
  getConfig(): ProviderConfig;

  // ── Auth ───────────────────────────────────────────────────────────────

  /** Re-authenticate when OAuth tokens expire. Prompts user on invalid_grant. */
  refreshAuth(): Promise<void>;

  // ── Blob I/O (vault file uploads/downloads — complete blobs) ────────

  /** Upload a complete blob. null ref = new file, string ref = overwrite. */
  upload(ref: string | null, name: string, data: Uint8Array, options?: UploadOptions): Promise<UploadResult>;

  /** Download a complete blob with its current version tag. */
  download(ref: string): Promise<{ data: Uint8Array; version: string }>;

  /** Delete a file by ref. */
  delete(ref: string): Promise<void>;

  /** Get the current version/ETag of a file for conflict detection. */
  getVersion(ref: string): Promise<string>;

  /**
   * Lightweight reachability probe (M1).
   *
   * Implementations should use the cheapest available mechanism:
   *   - HTTP providers: HEAD request or a free account-info endpoint
   *   - SFTP relay: stat or a no-op write_open/write_abort
   *
   * If omitted, OfflineDetector falls back to `getVersion(MANIFEST_PATH)`.
   * This is optional so that providers that have not yet implemented a cheap
   * probe do not break — they will be upgraded in a follow-up pass.
   */
  probe?(): Promise<void>;

  // ── Streaming I/O (large file uploads/downloads — V7 wire format) ────

  /**
   * Open a writable stream for uploading V7 ciphertext chunks.
   * The caller writes ciphertext frames (header, body chunks, footer)
   * produced by the V7 streaming encryptor in the crypto worker.
   *
   * Providers with resumable upload APIs (GDrive, OneDrive) use native
   * chunked upload endpoints. Others accumulate and upload on close.
   *
   * Returns:
   *   stream — writable stream to pipe ciphertext into
   *   result — resolves with the real UploadResult (ref + version) once
   *            stream.close() completes. Callers must await result AFTER
   *            closing the stream to get the actual file ref and ETag.
   */
  uploadStream(
    ref: string | null,
    name: string,
    totalSize: number,
    options?: UploadOptions,
  ): Promise<{ stream: WritableStream<Uint8Array>; result: Promise<UploadResult> }>;

  /**
   * Open a readable stream for downloading V7 ciphertext.
   * The caller reads ciphertext frames and feeds them to the V7 streaming
   * decryptor in the crypto worker.
   */
  downloadStream(ref: string): Promise<ReadableStream<Uint8Array>>;

  // ── Directory operations ──────────────────────────────────────────────

  /** List contents of a directory. null parentRef = root SecureCloud/ */
  list(parentRef?: string): Promise<StorageEntry[]>;

  /** Create a folder. Returns its ref. */
  createFolder(name: string, parentRef?: string): Promise<{ ref: string }>;

  /** Delete a folder and its contents. */
  deleteFolder(ref: string): Promise<void>;

  // ── Share link operations (P10) ───────────────────────────────────────

  /**
   * Create a permanent public link to the ciphertext object.
   * Returns the direct-download URL. Throws ProviderError if unsupported.
   */
  createPublicLink(ref: string): Promise<string>;

  /**
   * Revoke a public link previously created with createPublicLink.
   * Best-effort: callers should proceed even if this throws.
   */
  revokePublicLink(ref: string): Promise<void>;

  /**
   * Create a time-bounded presigned URL for the ciphertext object.
   * ttlSeconds: maximum lifetime (capped at provider limit or 24 h).
   * Throws ProviderError if unsupported.
   */
  createPresignedUrl(ref: string, ttlSeconds: number): Promise<string>;
}