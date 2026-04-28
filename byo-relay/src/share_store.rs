//! Persistent share storage — filesystem blobs + SQLite metadata index.
//!
//! Replaces the prior in-memory `HashMap<share_id, ciphertext>` with:
//!   - `SHARE_STORAGE_DIR/<share_id>/<blob_id>.v7` — the encrypted blob bytes
//!   - `SHARE_DB_PATH` (SQLite) — metadata: kind, expiry, revoked, sealed,
//!     owner-token nonce, per-blob sizes
//!
//! Why two surfaces: blobs can be arbitrarily large (no cap) so storing them
//! inside SQLite as BLOBs would blow the row-size cache. The on-disk file
//! layout lets us stream uploads and range-GETs without ever materializing the
//! full ciphertext in memory.
//!
//! Zero-knowledge note: every byte written here is V7 ciphertext. The relay
//! never sees plaintext, filenames, content keys, or recipient identity. See
//! SECURITY.md §Share relay storage surface.

use rusqlite::Connection;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ── Types ─────────────────────────────────────────────────────────────────────

/// Kind of share. `file` = single encrypted file; `folder`/`collection` =
/// bundle share with a manifest blob + per-entry content blobs (Phase 1c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareKind {
    File,
    Folder,
    Collection,
}

impl ShareKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareKind::File => "file",
            ShareKind::Folder => "folder",
            ShareKind::Collection => "collection",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "file" => Some(ShareKind::File),
            "folder" => Some(ShareKind::Folder),
            "collection" => Some(ShareKind::Collection),
            _ => None,
        }
    }
}

/// Public metadata for a share. Returned from lookups — ciphertext bytes are
/// fetched separately via `blob_path`.
#[derive(Debug, Clone)]
pub struct ShareMeta {
    pub share_id: String,
    pub kind: ShareKind,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked: bool,
    pub sealed: bool,
    pub token_nonce: [u8; 16],
    pub total_bytes: i64,
}

/// How long an unsealed bundle share can sit half-uploaded before the sweeper
/// reaps it. Applies only to bundles (file shares seal atomically at upload
/// time). Chosen to exceed a plausible multi-GB bundle upload on a 1 Mbit
/// uplink while bounding orphan blob retention.
pub const UNSEALED_MAX_LIFETIME_SECS: i64 = 4 * 3600;

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    Io(io::Error),
    Conflict,
    NotFound,
    InvalidKind,
    LockPoisoned,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Sqlite(e) => write!(f, "sqlite: {e}"),
            StoreError::Io(e) => write!(f, "io: {e}"),
            StoreError::Conflict => write!(f, "conflict"),
            StoreError::NotFound => write!(f, "not found"),
            StoreError::InvalidKind => write!(f, "invalid kind"),
            StoreError::LockPoisoned => write!(f, "lock poisoned"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e)
    }
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Filesystem + SQLite share store. Thread-safe via `Arc<Mutex<Connection>>`.
/// Blob I/O is performed outside the connection lock so large transfers don't
/// block metadata lookups.
pub struct ShareStore {
    conn: Mutex<Connection>,
    blobs_dir: PathBuf,
}

impl ShareStore {
    /// Open/create both the SQLite metadata DB and the blobs directory. The
    /// blobs directory is created with mode 0700 where the OS supports it.
    pub fn open(db_path: &Path, blobs_dir: &Path) -> Result<Arc<Self>, StoreError> {
        fs::create_dir_all(blobs_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(blobs_dir, fs::Permissions::from_mode(0o700));
        }
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; \
             PRAGMA synchronous=NORMAL; \
             PRAGMA foreign_keys=ON; \
             PRAGMA busy_timeout=5000;",
        )?;
        conn.execute_batch(SCHEMA)?;

        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
            blobs_dir: blobs_dir.to_path_buf(),
        }))
    }

    /// Create a new share record. Returns conflict if share_id already exists.
    /// For single-file shares caller follows up with `write_blob(share_id,
    /// "main", ...)` and `mark_sealed(share_id)` (or `put_file_share` which
    /// does both atomically, see the convenience wrapper below).
    pub fn create_share(
        &self,
        share_id: &str,
        kind: ShareKind,
        expires_at: i64,
        token_nonce: &[u8; 16],
    ) -> Result<(), StoreError> {
        let now = now_unix();
        let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
        let changed = conn.execute(
            "INSERT OR IGNORE INTO shares \
             (share_id, kind, created_at, expires_at, revoked, sealed, token_nonce, total_bytes) \
             VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, 0)",
            rusqlite::params![
                share_id,
                kind.as_str(),
                now,
                expires_at,
                token_nonce.as_slice(),
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::Conflict);
        }
        // Pre-create the per-share blob dir.
        let dir = self.share_dir(share_id);
        fs::create_dir_all(&dir)?;
        Ok(())
    }

    /// Mark a share as sealed (all blobs uploaded, ready to serve). Also
    /// wipes `bundle_token` so the upload window closes — a stolen token
    /// cannot inject additional blobs after seal. Idempotent.
    pub fn mark_sealed(&self, share_id: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
        let n = conn.execute(
            "UPDATE shares SET sealed=1, bundle_token=NULL WHERE share_id=?1",
            rusqlite::params![share_id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Attach a random 32-byte bundle token. Authorises subsequent blob
    /// uploads + the seal call for this bundle share without re-running PoW.
    /// Only valid on unsealed bundle shares — a sealed share rejects any
    /// follow-up writes regardless of token.
    pub fn set_bundle_token(&self, share_id: &str, token: &[u8; 32]) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
        let n = conn.execute(
            "UPDATE shares SET bundle_token=?2 WHERE share_id=?1 AND sealed=0",
            rusqlite::params![share_id, token.as_slice()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Constant-time verify a presented bundle token against the stored one.
    /// Returns `true` only when the share exists, is unsealed, not revoked,
    /// within its unsealed lifetime, and the token bytes match exactly.
    pub fn verify_bundle_token(
        &self,
        share_id: &str,
        presented: &[u8],
        now: i64,
    ) -> Result<bool, StoreError> {
        struct TokenRow {
            sealed: i64,
            revoked: i64,
            stored: Option<Vec<u8>>,
            created_at: i64,
            expires_at: i64,
        }
        let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
        let row: Option<TokenRow> = conn
            .query_row(
                "SELECT sealed, revoked, bundle_token, created_at, expires_at \
                 FROM shares WHERE share_id=?1",
                rusqlite::params![share_id],
                |row| {
                    Ok(TokenRow {
                        sealed: row.get(0)?,
                        revoked: row.get(1)?,
                        stored: row.get(2)?,
                        created_at: row.get(3)?,
                        expires_at: row.get(4)?,
                    })
                },
            )
            .ok();
        let Some(TokenRow {
            sealed,
            revoked,
            stored,
            created_at,
            expires_at,
        }) = row
        else {
            return Ok(false);
        };
        if sealed != 0 || revoked != 0 {
            return Ok(false);
        }
        if expires_at <= now || created_at + UNSEALED_MAX_LIFETIME_SECS <= now {
            return Ok(false);
        }
        let Some(stored_bytes) = stored else {
            return Ok(false);
        };
        if stored_bytes.len() != presented.len() {
            return Ok(false);
        }
        // Constant-time compare so a timing side channel can't distinguish
        // leading-byte match from full-match.
        let mut diff = 0u8;
        for (a, b) in stored_bytes.iter().zip(presented.iter()) {
            diff |= a ^ b;
        }
        Ok(diff == 0)
    }

    /// Look up share metadata. Returns `None` when the share does not exist.
    /// Callers should treat revoked or expired shares as 404 at the HTTP layer
    /// (opaque response — see share_relay handlers).
    pub fn get_meta(&self, share_id: &str) -> Result<Option<ShareMeta>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT share_id, kind, created_at, expires_at, revoked, sealed, token_nonce, total_bytes \
             FROM shares WHERE share_id = ?1",
        )?;
        let row: Option<ShareMeta> = stmt
            .query_row(rusqlite::params![share_id], |row| {
                let kind_str: String = row.get(1)?;
                let nonce_vec: Vec<u8> = row.get(6)?;
                let mut nonce = [0u8; 16];
                if nonce_vec.len() == 16 {
                    nonce.copy_from_slice(&nonce_vec);
                }
                let kind = ShareKind::parse(&kind_str).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::other("invalid kind")),
                    )
                })?;
                Ok(ShareMeta {
                    share_id: row.get(0)?,
                    kind,
                    created_at: row.get(2)?,
                    expires_at: row.get(3)?,
                    revoked: row.get::<_, i64>(4)? != 0,
                    sealed: row.get::<_, i64>(5)? != 0,
                    token_nonce: nonce,
                    total_bytes: row.get(7)?,
                })
            })
            .ok();
        Ok(row)
    }

    /// Record a blob's size in the index. Caller has already written the bytes
    /// to `blob_path(share_id, blob_id)` and passes the final length. Updates
    /// `shares.total_bytes` transactionally so a partial crash can't leave a
    /// stale sum on disk.
    pub fn record_blob(&self, share_id: &str, blob_id: &str, bytes: i64) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
        let tx = conn.transaction()?;
        let now = now_unix();
        let n = tx.execute(
            "INSERT OR REPLACE INTO blobs (share_id, blob_id, bytes, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![share_id, blob_id, bytes, now],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        tx.execute(
            "UPDATE shares SET total_bytes = (SELECT COALESCE(SUM(bytes), 0) FROM blobs WHERE share_id=?1) \
             WHERE share_id=?1",
            rusqlite::params![share_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Revoke a share: flip the flag in SQLite and delete the on-disk
    /// ciphertext directory. The row stays so GETs can return opaque 404 based
    /// on `revoked=1` without racing against the sweeper. The sweeper collects
    /// the orphan row on the next pass.
    pub fn revoke_share(&self, share_id: &str) -> Result<(), StoreError> {
        {
            let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
            let n = conn.execute(
                "UPDATE shares SET revoked=1, total_bytes=0 WHERE share_id=?1",
                rusqlite::params![share_id],
            )?;
            if n == 0 {
                return Err(StoreError::NotFound);
            }
            conn.execute(
                "DELETE FROM blobs WHERE share_id=?1",
                rusqlite::params![share_id],
            )?;
        }
        let dir = self.share_dir(share_id);
        if dir.exists() {
            let _ = fs::remove_dir_all(&dir);
        }
        Ok(())
    }

    /// Absolute path to a blob file. The file may not exist yet (caller is
    /// expected to write it before calling `record_blob`).
    pub fn blob_path(&self, share_id: &str, blob_id: &str) -> PathBuf {
        self.share_dir(share_id).join(format!("{blob_id}.v7"))
    }

    /// Drop a single blob from a share. Used when a streaming upload aborts
    /// mid-transfer so the client can retry the same blob_id without hitting
    /// a PRIMARY KEY conflict on the next attempt.
    pub fn delete_blob(&self, share_id: &str, blob_id: &str) -> Result<(), StoreError> {
        {
            let mut conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
            let tx = conn.transaction()?;
            tx.execute(
                "DELETE FROM blobs WHERE share_id=?1 AND blob_id=?2",
                rusqlite::params![share_id, blob_id],
            )?;
            tx.execute(
                "UPDATE shares SET total_bytes = (SELECT COALESCE(SUM(bytes), 0) FROM blobs WHERE share_id=?1) \
                 WHERE share_id=?1",
                rusqlite::params![share_id],
            )?;
            tx.commit()?;
        }
        let path = self.blob_path(share_id, blob_id);
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
        Ok(())
    }

    /// List the (blob_id, bytes) pairs for a share. The recipient page uses
    /// this via the metadata endpoint to know what to download.
    pub fn list_blobs(&self, share_id: &str) -> Result<Vec<(String, i64)>, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
        let mut stmt =
            conn.prepare("SELECT blob_id, bytes FROM blobs WHERE share_id=?1 ORDER BY blob_id")?;
        let rows = stmt.query_map(rusqlite::params![share_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let collected: Vec<(String, i64)> = rows.filter_map(Result::ok).collect();
        Ok(collected)
    }

    fn share_dir(&self, share_id: &str) -> PathBuf {
        self.blobs_dir.join(share_id)
    }

    /// Drop all expired or revoked rows and their backing directories. Called
    /// periodically by the ShareSweeper. Returns (removed_share_ids,
    /// freed_bytes) — the caller (sweeper) uses the ids to release the
    /// ShareStoragePerIpTracker entries so the per-IP aggregate cap frees
    /// up as shares expire.
    ///
    /// Atomicity: filesystem cleanup happens before the SQL DELETE, and the
    /// index row is only removed for shares whose directory was successfully
    /// gone (or never existed). If `remove_dir_all` fails (permissions,
    /// ENOSPC during journal log, race with a concurrent upload), the row
    /// stays so the next sweep tick retries — preferable to silently
    /// orphaning `.v7` files. Download endpoints already enforce
    /// `revoked || expires_at <= now` at request time, so a lingering
    /// row is inert from the user's perspective.
    pub fn purge_expired_and_revoked(&self, now: i64) -> Result<(Vec<String>, i64), StoreError> {
        // Gather victims first, release the lock before filesystem work.
        // "Victim" = revoked, expired, OR an unsealed bundle that missed its
        // upload deadline (orphan cleanup).
        let stale_unsealed_cutoff = now - UNSEALED_MAX_LIFETIME_SECS;
        let victims: Vec<(String, i64)> = {
            let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
            let mut stmt = conn.prepare(
                "SELECT share_id, total_bytes FROM shares \
                 WHERE revoked=1 \
                    OR expires_at <= ?1 \
                    OR (sealed=0 AND created_at <= ?2)",
            )?;
            let rows = stmt.query_map(rusqlite::params![now, stale_unsealed_cutoff], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            let collected: Vec<(String, i64)> = rows.filter_map(Result::ok).collect();
            drop(stmt);
            drop(conn);
            collected
        };

        let mut to_clear: Vec<String> = Vec::with_capacity(victims.len());
        let mut freed = 0i64;
        for (share_id, bytes) in &victims {
            let dir = self.share_dir(share_id);
            match fs::remove_dir_all(&dir) {
                Ok(()) => {
                    to_clear.push(share_id.clone());
                    freed += bytes;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // Directory was never created or got cleaned up out-of-band
                    // (revoke path also wipes the dir). The row is still ours
                    // to delete.
                    to_clear.push(share_id.clone());
                    freed += bytes;
                }
                Err(e) => {
                    tracing::warn!(
                        share_id = %share_id,
                        error = %e,
                        "share sweep: failed to remove on-disk directory; \
                         leaving index row for next tick to retry"
                    );
                    // Skip the SQL delete — try again on the next sweep.
                }
            }
        }

        // Clear the index rows. FK cascade handles blobs rows.
        if !to_clear.is_empty() {
            let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
            for share_id in &to_clear {
                conn.execute(
                    "DELETE FROM shares WHERE share_id=?1",
                    rusqlite::params![share_id],
                )?;
            }
        }

        Ok((to_clear, freed))
    }

    /// Return the path to the blobs directory — used by the disk-watermark
    /// check to statvfs the filesystem hosting the share storage.
    pub fn blobs_dir(&self) -> &Path {
        &self.blobs_dir
    }

    /// Total bytes stored by live (non-revoked, non-expired) shares. Exposed
    /// later for the headroom endpoint + operator visibility.
    pub fn total_live_bytes(&self, now: i64) -> Result<i64, StoreError> {
        let conn = self.conn.lock().map_err(|_| StoreError::LockPoisoned)?;
        let total: i64 = conn.query_row(
            "SELECT COALESCE(SUM(total_bytes), 0) FROM shares \
             WHERE revoked=0 AND expires_at > ?1",
            rusqlite::params![now],
            |r| r.get(0),
        )?;
        Ok(total)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS shares (
    share_id     TEXT PRIMARY KEY,
    kind         TEXT NOT NULL CHECK(kind IN ('file','folder','collection')),
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    sealed       INTEGER NOT NULL DEFAULT 0,
    token_nonce  BLOB NOT NULL,
    total_bytes  INTEGER NOT NULL DEFAULT 0,
    bundle_token BLOB
);
CREATE INDEX IF NOT EXISTS idx_shares_expires ON shares(expires_at);
CREATE INDEX IF NOT EXISTS idx_shares_revoked ON shares(revoked);

CREATE TABLE IF NOT EXISTS blobs (
    share_id   TEXT NOT NULL,
    blob_id    TEXT NOT NULL,
    bytes      INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (share_id, blob_id),
    FOREIGN KEY (share_id) REFERENCES shares(share_id) ON DELETE CASCADE
);
"#;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_store() -> (Arc<ShareStore>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = dir.path().join("shares.sqlite3");
        let blobs = dir.path().join("shares");
        let store = ShareStore::open(&db, &blobs).unwrap();
        (store, dir)
    }

    #[test]
    fn create_and_get_single_file_share() {
        let (store, _d) = fresh_store();
        let nonce = [9u8; 16];
        store
            .create_share("aaaa", ShareKind::File, now_unix() + 3600, &nonce)
            .unwrap();
        let meta = store.get_meta("aaaa").unwrap().expect("must exist");
        assert_eq!(meta.kind, ShareKind::File);
        assert!(!meta.revoked);
        assert!(!meta.sealed);
        assert_eq!(meta.token_nonce, nonce);
    }

    #[test]
    fn duplicate_share_id_rejected() {
        let (store, _d) = fresh_store();
        let nonce = [0u8; 16];
        store
            .create_share("dup", ShareKind::File, now_unix() + 60, &nonce)
            .unwrap();
        let err = store
            .create_share("dup", ShareKind::File, now_unix() + 60, &nonce)
            .unwrap_err();
        matches!(err, StoreError::Conflict);
    }

    #[test]
    fn record_blob_updates_total_bytes() {
        let (store, _d) = fresh_store();
        let nonce = [1u8; 16];
        store
            .create_share("totals", ShareKind::File, now_unix() + 60, &nonce)
            .unwrap();
        // Create the blob file so record_blob's invariant (file exists) holds.
        let path = store.blob_path("totals", "main");
        fs::write(&path, vec![0u8; 123]).unwrap();
        store.record_blob("totals", "main", 123).unwrap();
        let meta = store.get_meta("totals").unwrap().unwrap();
        assert_eq!(meta.total_bytes, 123);
    }

    #[test]
    fn revoke_wipes_directory_and_bytes() {
        let (store, _d) = fresh_store();
        let nonce = [2u8; 16];
        store
            .create_share("revoke-me", ShareKind::File, now_unix() + 60, &nonce)
            .unwrap();
        let path = store.blob_path("revoke-me", "main");
        fs::write(&path, b"deadbeef").unwrap();
        store.record_blob("revoke-me", "main", 8).unwrap();
        store.revoke_share("revoke-me").unwrap();
        let meta = store.get_meta("revoke-me").unwrap().unwrap();
        assert!(meta.revoked);
        assert_eq!(meta.total_bytes, 0);
        assert!(!path.exists(), "blob file must be gone after revoke");
    }

    #[test]
    fn purge_removes_expired() {
        let (store, _d) = fresh_store();
        let nonce = [3u8; 16];
        store
            .create_share("old", ShareKind::File, 1_000, &nonce)
            .unwrap();
        let (removed, _) = store.purge_expired_and_revoked(2_000).unwrap();
        assert_eq!(removed.len(), 1);
        assert!(store.get_meta("old").unwrap().is_none());
    }

    #[test]
    fn purge_removes_blob_files_from_disk() {
        let (store, _d) = fresh_store();
        let nonce = [11u8; 16];
        store
            .create_share("disk-bye", ShareKind::Folder, 1_000, &nonce)
            .unwrap();
        let blob_a = store.blob_path("disk-bye", "a");
        let blob_b = store.blob_path("disk-bye", "b");
        fs::write(&blob_a, vec![0u8; 50]).unwrap();
        fs::write(&blob_b, vec![0u8; 70]).unwrap();
        store.record_blob("disk-bye", "a", 50).unwrap();
        store.record_blob("disk-bye", "b", 70).unwrap();

        let (removed, freed) = store.purge_expired_and_revoked(2_000).unwrap();
        assert_eq!(removed, vec!["disk-bye".to_string()]);
        assert_eq!(freed, 120);
        assert!(!blob_a.exists(), ".v7 must be gone after sweep");
        assert!(!blob_b.exists(), ".v7 must be gone after sweep");
        assert!(store.get_meta("disk-bye").unwrap().is_none());
    }

    #[test]
    fn purge_handles_missing_directory() {
        // If the on-disk dir is already gone (e.g. operator manually
        // cleaned up, or revoke path raced), the sweeper still drops the
        // index row instead of looping on it forever.
        let (store, _d) = fresh_store();
        let nonce = [12u8; 16];
        store
            .create_share("dirless", ShareKind::File, 1_000, &nonce)
            .unwrap();
        fs::remove_dir_all(store.share_dir("dirless")).unwrap();
        let (removed, _) = store.purge_expired_and_revoked(2_000).unwrap();
        assert_eq!(removed, vec!["dirless".to_string()]);
        assert!(store.get_meta("dirless").unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn purge_retains_row_on_fs_failure() {
        // Drop the parent's write bit so remove_dir_all on the share dir
        // hits EACCES. We expect the index row to remain so the next
        // sweep tick retries — silently orphaning the .v7 files would be
        // worse than a row lingering past expiry (downloads already 404
        // expired shares regardless of whether the index row is gone).
        use std::os::unix::fs::PermissionsExt;
        let (store, _d) = fresh_store();
        let nonce = [13u8; 16];
        store
            .create_share("stuck", ShareKind::File, 1_000, &nonce)
            .unwrap();
        let blob = store.blob_path("stuck", "main");
        fs::write(&blob, b"deadbeef").unwrap();
        store.record_blob("stuck", "main", 8).unwrap();

        let parent = store.blobs_dir().to_path_buf();
        let original = fs::metadata(&parent).unwrap().permissions();
        let mut locked = original.clone();
        locked.set_mode(0o500); // r-x for owner — can't unlink children
        fs::set_permissions(&parent, locked).unwrap();

        let result = store.purge_expired_and_revoked(2_000);

        // Restore permissions BEFORE asserting so TempDir's drop cleanup works
        // even if the assertion below fails.
        fs::set_permissions(&parent, original).unwrap();

        let (removed, freed) = result.unwrap();
        assert_eq!(
            removed.len(),
            0,
            "fs-failed share must NOT be reported as removed"
        );
        assert_eq!(freed, 0);
        assert!(
            store.get_meta("stuck").unwrap().is_some(),
            "row must remain so the next sweep retries"
        );
    }

    #[test]
    fn purge_keeps_future_shares() {
        let (store, _d) = fresh_store();
        let nonce = [4u8; 16];
        store
            .create_share("future", ShareKind::File, now_unix() + 3600, &nonce)
            .unwrap();
        let (removed, _) = store.purge_expired_and_revoked(now_unix()).unwrap();
        assert_eq!(removed.len(), 0);
        assert!(store.get_meta("future").unwrap().is_some());
    }

    #[test]
    fn total_live_bytes_sums_non_expired_non_revoked() {
        let (store, _d) = fresh_store();
        let nonce = [5u8; 16];
        store
            .create_share("live-1", ShareKind::File, now_unix() + 3600, &nonce)
            .unwrap();
        fs::write(store.blob_path("live-1", "main"), vec![0u8; 100]).unwrap();
        store.record_blob("live-1", "main", 100).unwrap();

        store
            .create_share("live-2", ShareKind::File, now_unix() + 3600, &nonce)
            .unwrap();
        fs::write(store.blob_path("live-2", "main"), vec![0u8; 250]).unwrap();
        store.record_blob("live-2", "main", 250).unwrap();

        store
            .create_share("expired", ShareKind::File, now_unix() - 1, &nonce)
            .unwrap();
        fs::write(store.blob_path("expired", "main"), vec![0u8; 99]).unwrap();
        store.record_blob("expired", "main", 99).unwrap();

        let now = now_unix();
        let live = store.total_live_bytes(now).unwrap();
        assert_eq!(live, 350);
    }

    #[test]
    fn mark_sealed_idempotent() {
        let (store, _d) = fresh_store();
        let nonce = [6u8; 16];
        store
            .create_share("seal-me", ShareKind::Folder, now_unix() + 60, &nonce)
            .unwrap();
        store.mark_sealed("seal-me").unwrap();
        store.mark_sealed("seal-me").unwrap();
        let meta = store.get_meta("seal-me").unwrap().unwrap();
        assert!(meta.sealed);
    }

    #[test]
    fn share_kind_roundtrip() {
        for k in &[ShareKind::File, ShareKind::Folder, ShareKind::Collection] {
            assert_eq!(ShareKind::parse(k.as_str()), Some(*k));
        }
        assert!(ShareKind::parse("legacy").is_none());
    }

    // ── Bundle token tests ────────────────────────────────────────────────────

    #[test]
    fn bundle_token_verify_matches_stored() {
        let (store, _d) = fresh_store();
        let nonce = [7u8; 16];
        store
            .create_share("b1", ShareKind::Folder, now_unix() + 3600, &nonce)
            .unwrap();
        let token = [0xABu8; 32];
        store.set_bundle_token("b1", &token).unwrap();
        assert!(store.verify_bundle_token("b1", &token, now_unix()).unwrap());
    }

    #[test]
    fn bundle_token_rejects_wrong_value() {
        let (store, _d) = fresh_store();
        let nonce = [7u8; 16];
        store
            .create_share("b2", ShareKind::Folder, now_unix() + 3600, &nonce)
            .unwrap();
        let token = [0xABu8; 32];
        store.set_bundle_token("b2", &token).unwrap();
        let wrong = [0xCDu8; 32];
        assert!(!store.verify_bundle_token("b2", &wrong, now_unix()).unwrap());
    }

    #[test]
    fn bundle_token_rejects_after_seal() {
        let (store, _d) = fresh_store();
        let nonce = [7u8; 16];
        store
            .create_share("b3", ShareKind::Folder, now_unix() + 3600, &nonce)
            .unwrap();
        let token = [0xABu8; 32];
        store.set_bundle_token("b3", &token).unwrap();
        store.mark_sealed("b3").unwrap();
        // Post-seal the token is wiped; no presented value verifies.
        assert!(!store.verify_bundle_token("b3", &token, now_unix()).unwrap());
    }

    #[test]
    fn bundle_token_rejects_after_upload_deadline() {
        let (store, _d) = fresh_store();
        let nonce = [8u8; 16];
        // Share created 5h ago — past UNSEALED_MAX_LIFETIME_SECS (4h).
        store
            .create_share("b4", ShareKind::Folder, now_unix() + 3600, &nonce)
            .unwrap();
        let token = [0xABu8; 32];
        store.set_bundle_token("b4", &token).unwrap();
        let future = now_unix() + UNSEALED_MAX_LIFETIME_SECS + 60;
        assert!(!store.verify_bundle_token("b4", &token, future).unwrap());
    }

    #[test]
    fn purge_collects_stale_unsealed_bundles() {
        let (store, _d) = fresh_store();
        let nonce = [9u8; 16];
        store
            .create_share("stale", ShareKind::Folder, now_unix() + 3600, &nonce)
            .unwrap();
        // Advance the clock past the upload deadline.
        let future = now_unix() + UNSEALED_MAX_LIFETIME_SECS + 60;
        let (removed, _) = store.purge_expired_and_revoked(future).unwrap();
        assert_eq!(removed.len(), 1);
        assert!(store.get_meta("stale").unwrap().is_none());
    }

    #[test]
    fn delete_blob_decrements_total_bytes() {
        let (store, _d) = fresh_store();
        let nonce = [10u8; 16];
        store
            .create_share("trim", ShareKind::Folder, now_unix() + 3600, &nonce)
            .unwrap();
        fs::write(store.blob_path("trim", "a"), vec![0u8; 50]).unwrap();
        store.record_blob("trim", "a", 50).unwrap();
        fs::write(store.blob_path("trim", "b"), vec![0u8; 70]).unwrap();
        store.record_blob("trim", "b", 70).unwrap();
        assert_eq!(store.get_meta("trim").unwrap().unwrap().total_bytes, 120);
        store.delete_blob("trim", "a").unwrap();
        assert_eq!(store.get_meta("trim").unwrap().unwrap().total_bytes, 70);
        assert!(!store.blob_path("trim", "a").exists());
    }

    #[test]
    fn list_blobs_returns_sorted_entries() {
        let (store, _d) = fresh_store();
        let nonce = [11u8; 16];
        store
            .create_share("ls", ShareKind::Folder, now_unix() + 3600, &nonce)
            .unwrap();
        for id in ["c", "a", "b"] {
            fs::write(store.blob_path("ls", id), vec![0u8; 10]).unwrap();
            store.record_blob("ls", id, 10).unwrap();
        }
        let blobs = store.list_blobs("ls").unwrap();
        assert_eq!(
            blobs,
            vec![
                ("a".to_string(), 10),
                ("b".to_string(), 10),
                ("c".to_string(), 10),
            ]
        );
    }
}
