// Platform abstraction traits for vault body caching and WAL storage.
//
// These traits define the interface that host platforms (TS/IDB, Android/Room,
// iOS/CoreData) must implement. No logic lives here — only the contract.

// ── VaultBodyCache ────────────────────────────────────────────────────────────

/// Platform abstraction for caching encrypted vault bodies and manifests.
///
/// The cache stores per-provider encrypted blobs between unlocks so the vault
/// can be opened when a provider is temporarily offline (H2 offline fallback).
///
/// Cache entries are keyed by (`vault_id`, `provider_id`).  A `version` string
/// (typically an ETag or opaque server cursor) allows stale-cache detection.
pub trait VaultBodyCache: Send + Sync {
    /// Retrieve a cached body blob for the given vault + provider pair.
    ///
    /// Returns `None` when no cache entry exists.  The returned bytes are the
    /// raw encrypted body blob (not plaintext SQLite).
    fn load_body(&self, vault_id: &str, provider_id: &str) -> Option<Vec<u8>>;

    /// Persist an encrypted body blob for the given vault + provider pair.
    ///
    /// `version` is the ETag / opaque cursor from the storage provider.
    /// Pass an empty string when the provider does not support versioning.
    fn store_body(&mut self, vault_id: &str, provider_id: &str, data: &[u8], version: &str);

    /// Remove a cached body (e.g. after provider tombstone).
    fn invalidate_body(&mut self, vault_id: &str, provider_id: &str);

    /// Retrieve the cached manifest body + optional header bytes for a vault.
    ///
    /// Returns `(body_blob, header_bytes_opt, version)`.  `header_bytes_opt` is
    /// populated only when the implementation stored the vault header alongside
    /// the manifest body (required for primary-offline unlock).
    fn load_manifest(&self, vault_id: &str) -> Option<(Vec<u8>, Option<Vec<u8>>, String)>;

    /// Persist the encrypted manifest body (and optionally the vault header).
    fn store_manifest(
        &mut self,
        vault_id: &str,
        body: &[u8],
        header: Option<&[u8]>,
        version: &str,
        manifest_version: u64,
    );
}

// ── WalStorage ────────────────────────────────────────────────────────────────

/// Error type for WAL operations.
#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("WAL storage write failed: {0}")]
    Write(String),
    #[error("WAL storage read failed: {0}")]
    Read(String),
}

/// Platform abstraction for Write-Ahead Log (WAL) storage.
///
/// The WAL persists pending mutations (serialised `MergeOp`-compatible rows)
/// across crashes so that a failed save can be retried on next unlock without
/// data loss.
///
/// Entries are opaque encrypted bytes produced by the journal codec
/// (`vault_journal.rs`).  The implementation must be durable (survives process
/// restart) and atomic per-append (no partial entries).
pub trait WalStorage: Send + Sync {
    /// Return all pending WAL entries in insertion order.
    ///
    /// Returns an empty vec when the WAL is empty.  Entries are opaque bytes
    /// encrypted by the vault journal codec.
    fn get_entries(&self) -> Result<Vec<Vec<u8>>, WalError>;

    /// Append a single encrypted entry to the WAL.
    ///
    /// Must be atomic: either the full `entry` is persisted or nothing is.
    fn append(&mut self, entry: &[u8]) -> Result<(), WalError>;

    /// Remove all WAL entries (called after a successful save).
    fn clear(&mut self) -> Result<(), WalError>;
}
