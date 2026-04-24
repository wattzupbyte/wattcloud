//! Restricted enrollment — config flag, on-disk schema, and `/relay/info` handler.
//!
//! Phase 1 of the restricted-enrollment feature (see SPEC.md §Access Control).
//! Scope of this module *at phase 1*:
//!
//!   - [`EnrollmentMode`] enum + env parsing (default [`EnrollmentMode::Open`]
//!     for existing installs; deploy-vps.sh writes `restricted` on fresh
//!     installs).
//!   - [`EnrollmentStore`] — SQLite wrapper around `enrollment_schema.sql`.
//!     Lazily created. Exposes `owner_count()` for the `bootstrapped` flag on
//!     `/relay/info`. Read/write helpers for `authorized_devices`,
//!     `invite_codes`, and `bootstrap_token` land in phase 2.
//!   - [`get_info`] — public `GET /relay/info` handler returning
//!     `{mode, bootstrapped, version}` behind an IP-keyed rate limit.
//!   - [`require_device_in_restricted_mode`] — middleware scaffold. In
//!     `Open` mode it passes through; in `Restricted` mode it returns
//!     **501 Not Implemented** until phase 2 wires the device-cookie check.
//!     Not applied to any route yet — layering onto operational endpoints is
//!     part of phase 2 so existing traffic is unaffected.
//!
//! Zero-logging posture: admin SQLite is local state only; neither IP nor
//! device identifiers are persisted in logs.

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::client_ip::extract_client_ip;
use crate::rate_limit::SlidingWindowLimiterByKey;
use crate::relay_auth::AppState;

// ── Mode enum ────────────────────────────────────────────────────────────────

/// Whether operational relay surfaces require an enrolled device.
///
/// * `Open` (default on existing installs) — no change to current behaviour;
///   anyone can hit `/relay/auth/challenge`, upload shares, etc.
/// * `Restricted` — `/relay/auth/challenge` and share-write endpoints require
///   a valid `wattcloud_device` cookie; invitees must redeem an owner-minted
///   code first. Read paths for share recipients stay public by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnrollmentMode {
    Open,
    Restricted,
}

impl EnrollmentMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EnrollmentMode::Open => "open",
            EnrollmentMode::Restricted => "restricted",
        }
    }

    /// Parse the mode from an env value. Accepts case-insensitive "open" or
    /// "restricted". Any other value — including the variable being absent —
    /// returns `None` so the caller can log + pick the backcompat default.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "open" => Some(EnrollmentMode::Open),
            "restricted" => Some(EnrollmentMode::Restricted),
            _ => None,
        }
    }

    /// Read `WATTCLOUD_ENROLLMENT_MODE` from the environment. Unset / unknown
    /// values → `Open` with a single warning line. This preserves backcompat
    /// for existing installs that upgrade; fresh installs get `restricted`
    /// written into the env file by `deploy-vps.sh`.
    pub fn from_env() -> Self {
        match std::env::var("WATTCLOUD_ENROLLMENT_MODE") {
            Ok(raw) => match EnrollmentMode::parse(&raw) {
                Some(mode) => mode,
                None => {
                    tracing::warn!(
                        value = %raw,
                        "WATTCLOUD_ENROLLMENT_MODE is set but unrecognised; falling back to 'open' — valid values are 'open' or 'restricted'"
                    );
                    EnrollmentMode::Open
                }
            },
            Err(_) => EnrollmentMode::Open,
        }
    }
}

// ── Store ────────────────────────────────────────────────────────────────────

/// Errors from the enrollment store.
#[derive(Debug)]
pub enum EnrollmentStoreError {
    Sqlite(rusqlite::Error),
    LockPoisoned,
    /// The row violates a uniqueness or foreign-key invariant — e.g. a
    /// duplicate device pubkey, or an invite referencing a non-existent
    /// owner. Separate variant so callers can distinguish "bad input"
    /// from "database broke".
    Conflict,
    /// The invite code wasn't found, had already been redeemed, or was
    /// past its expiry. Redeem callers map this to a 401/403.
    InvalidInvite,
    /// Bootstrap token didn't match, was already consumed, or has expired.
    InvalidBootstrapToken,
    /// The device referenced by an admin action doesn't exist.
    DeviceNotFound,
    /// Caller attempted to revoke the last remaining owner device. Guarded
    /// so operators can't accidentally lock themselves out of the web path;
    /// recovery still works via the `regenerate-claim-token` CLI.
    LastOwner,
}

impl std::fmt::Display for EnrollmentStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollmentStoreError::Sqlite(e) => write!(f, "sqlite: {e}"),
            EnrollmentStoreError::LockPoisoned => write!(f, "enrollment store lock poisoned"),
            EnrollmentStoreError::Conflict => write!(f, "unique/foreign-key conflict"),
            EnrollmentStoreError::InvalidInvite => write!(f, "invite code invalid, used, or expired"),
            EnrollmentStoreError::InvalidBootstrapToken => {
                write!(f, "bootstrap token invalid, consumed, or expired")
            }
            EnrollmentStoreError::DeviceNotFound => write!(f, "device not found"),
            EnrollmentStoreError::LastOwner => {
                write!(f, "cannot revoke the last owner device")
            }
        }
    }
}

impl std::error::Error for EnrollmentStoreError {}

impl From<rusqlite::Error> for EnrollmentStoreError {
    fn from(e: rusqlite::Error) -> Self {
        if matches!(&e, rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation)
        {
            return EnrollmentStoreError::Conflict;
        }
        EnrollmentStoreError::Sqlite(e)
    }
}

/// Persistent store for authorized devices, invite codes, and the bootstrap
/// token. Phase 1 only needs `owner_count()` for `/relay/info`; the remaining
/// CRUD lands in phase 2 alongside the admin endpoints.
pub struct EnrollmentStore {
    conn: Mutex<Connection>,
}

const SCHEMA_SQL: &str = include_str!("enrollment_schema.sql");

impl EnrollmentStore {
    /// Open (or create) the store at `path`. Creates the parent directory if
    /// missing, applies WAL + busy timeout, and runs the schema idempotently.
    pub fn open(path: &Path) -> Result<Arc<Self>, EnrollmentStoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5_000i64)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
        }))
    }

    /// Active (non-revoked) owner device count. Used to answer the
    /// `bootstrapped` flag on `/relay/info`: non-zero = bootstrapped.
    pub fn owner_count(&self) -> Result<u64, EnrollmentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        Self::count_owners(&conn)
    }

    fn count_owners(conn: &Connection) -> Result<u64, EnrollmentStoreError> {
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM authorized_devices WHERE is_owner = 1 AND revoked_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    /// Record a new bootstrap token (single-row table). Any prior row is
    /// deleted atomically so regeneration is a straightforward REPLACE.
    /// `expires_at` is unix seconds.
    pub fn set_bootstrap_token(
        &self,
        token_hash: &[u8],
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), EnrollmentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        conn.execute("DELETE FROM bootstrap_token", [])?;
        conn.execute(
            "INSERT INTO bootstrap_token (id, token_hash, created_at, expires_at) \
             VALUES (1, ?1, ?2, ?3)",
            rusqlite::params![token_hash, created_at, expires_at],
        )?;
        Ok(())
    }

    /// True if a non-expired bootstrap token row currently exists.
    pub fn has_bootstrap_token(&self, now: i64) -> Result<bool, EnrollmentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM bootstrap_token WHERE expires_at > ?1",
            rusqlite::params![now],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// Consume a bootstrap token and install an owner device in one
    /// transaction.
    ///
    /// The token's validity (stored hash, non-expired) is the *only*
    /// authorization — we deliberately don't refuse when owners already
    /// exist. Rationale: a bootstrap token is minted either at startup
    /// (fresh install, zero owners) or by the operator running
    /// `wattcloud regenerate-claim-token` on the server (recovery from a
    /// web-path lockout). Both cases are legitimate paths to "install a
    /// new owner." Refusing the second case forces operators into
    /// destructive SQL surgery, which is worse than just honouring a
    /// valid token.
    ///
    /// Every successful claim inserts the device with `is_owner=1` and
    /// atomically wipes the token row (single-use). Existing owners are
    /// not touched, so recovery is non-destructive by design.
    pub fn claim_bootstrap(
        &self,
        candidate_hash: &[u8],
        device_id: &str,
        pubkey: &[u8],
        label: &str,
        now: i64,
    ) -> Result<(), EnrollmentStoreError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        let tx = conn.transaction()?;

        // The stored token must match and not be expired.
        let (stored_hash, expires_at): (Vec<u8>, i64) = match tx
            .query_row(
                "SELECT token_hash, expires_at FROM bootstrap_token WHERE id = 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(EnrollmentStoreError::from)
        {
            Ok(v) => v,
            Err(EnrollmentStoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows)) => {
                return Err(EnrollmentStoreError::InvalidBootstrapToken);
            }
            Err(e) => return Err(e),
        };

        if expires_at <= now {
            return Err(EnrollmentStoreError::InvalidBootstrapToken);
        }
        if !constant_time_eq(&stored_hash, candidate_hash) {
            return Err(EnrollmentStoreError::InvalidBootstrapToken);
        }

        // Insert the owner device.
        let hour = now / 3600;
        tx.execute(
            "INSERT INTO authorized_devices \
               (device_id, pubkey, label, is_owner, created_at, last_seen_hour) \
             VALUES (?1, ?2, ?3, 1, ?4, ?5)",
            rusqlite::params![device_id, pubkey, label, now, hour],
        )?;

        // Wipe the single-use token.
        tx.execute("DELETE FROM bootstrap_token", [])?;

        tx.commit()?;
        Ok(())
    }

    /// Insert a new invite row. Returns immediately — the plaintext code is
    /// the caller's responsibility (typically shown once in the mint response).
    pub fn insert_invite(
        &self,
        id: &str,
        code_hash: &[u8],
        label: &str,
        issued_by: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<(), EnrollmentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        conn.execute(
            "INSERT INTO invite_codes \
               (id, code_hash, label, issued_by, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![id, code_hash, label, issued_by, created_at, expires_at],
        )?;
        Ok(())
    }

    /// List active invites owned by the relay, newest first. Hashes are
    /// never returned — the plaintext code is reveal-once, and the hash is
    /// an internal opaque index.
    pub fn list_invites(&self) -> Result<Vec<InviteRow>, EnrollmentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT id, label, issued_by, created_at, expires_at, used_by, used_at \
             FROM invite_codes ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(InviteRow {
                    id: row.get(0)?,
                    label: row.get(1)?,
                    issued_by: row.get(2)?,
                    created_at: row.get(3)?,
                    expires_at: row.get(4)?,
                    used_by: row.get(5)?,
                    used_at: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete an invite by id. Phase 2 treats revoke and delete as the same
    /// operation since an unused invite has no follow-up history worth
    /// retaining. Returns Ok even when the row was already gone — the caller
    /// just wants the end-state "this invite can no longer be redeemed."
    pub fn revoke_invite(&self, id: &str) -> Result<(), EnrollmentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        conn.execute("DELETE FROM invite_codes WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    }

    /// Atomically redeem an invite code: validates, marks used, and inserts
    /// the new device row. `candidate_hash` is HMAC(relay_signing_key, code).
    /// Returns the id of the consumed invite for audit purposes.
    pub fn redeem_invite(
        &self,
        candidate_hash: &[u8],
        device_id: &str,
        pubkey: &[u8],
        label: &str,
        now: i64,
    ) -> Result<String, EnrollmentStoreError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        let tx = conn.transaction()?;

        // Atomic find-and-mark. UPDATE … WHERE used_by IS NULL AND expires_at > now
        // ensures only a single concurrent redeemer can win.
        let hour = now / 3600;
        let invite_id: String = match tx.query_row(
            "SELECT id FROM invite_codes \
             WHERE code_hash = ?1 AND used_by IS NULL AND expires_at > ?2",
            rusqlite::params![candidate_hash, now],
            |row| row.get::<_, String>(0),
        ) {
            Ok(id) => id,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(EnrollmentStoreError::InvalidInvite);
            }
            Err(e) => return Err(EnrollmentStoreError::from(e)),
        };

        let updated = tx.execute(
            "UPDATE invite_codes \
               SET used_by = ?1, used_at = ?2 \
             WHERE id = ?3 AND used_by IS NULL",
            rusqlite::params![device_id, now, invite_id],
        )?;
        if updated != 1 {
            // Lost the race to another concurrent redeemer.
            return Err(EnrollmentStoreError::InvalidInvite);
        }

        tx.execute(
            "INSERT INTO authorized_devices \
               (device_id, pubkey, label, is_owner, created_at, last_seen_hour) \
             VALUES (?1, ?2, ?3, 0, ?4, ?5)",
            rusqlite::params![device_id, pubkey, label, now, hour],
        )?;

        tx.commit()?;
        Ok(invite_id)
    }

    /// Look up a device by id. Returns `None` if absent.
    pub fn get_device(&self, device_id: &str) -> Result<Option<DeviceRow>, EnrollmentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        match conn.query_row(
            "SELECT device_id, label, is_owner, created_at, last_seen_hour, revoked_at \
             FROM authorized_devices WHERE device_id = ?1",
            rusqlite::params![device_id],
            |row| {
                Ok(DeviceRow {
                    device_id: row.get(0)?,
                    label: row.get(1)?,
                    is_owner: row.get::<_, i64>(2)? != 0,
                    created_at: row.get(3)?,
                    last_seen_hour: row.get(4)?,
                    revoked_at: row.get(5)?,
                })
            },
        ) {
            Ok(d) => Ok(Some(d)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(EnrollmentStoreError::from(e)),
        }
    }

    /// Best-effort `last_seen_hour` bump. Failure is logged at error level by
    /// the caller but does not block the request — last_seen is UX, not
    /// security.
    pub fn touch_last_seen(&self, device_id: &str, now: i64) -> Result<(), EnrollmentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        let hour = now / 3600;
        conn.execute(
            "UPDATE authorized_devices SET last_seen_hour = ?1 \
             WHERE device_id = ?2 AND (last_seen_hour IS NULL OR last_seen_hour < ?1)",
            rusqlite::params![hour, device_id],
        )?;
        Ok(())
    }

    /// List all devices (active + revoked), newest first.
    pub fn list_devices(&self) -> Result<Vec<DeviceRow>, EnrollmentStoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT device_id, label, is_owner, created_at, last_seen_hour, revoked_at \
             FROM authorized_devices ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DeviceRow {
                    device_id: row.get(0)?,
                    label: row.get(1)?,
                    is_owner: row.get::<_, i64>(2)? != 0,
                    created_at: row.get(3)?,
                    last_seen_hour: row.get(4)?,
                    revoked_at: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Revoke a device by setting its `revoked_at`. Guards against removing
    /// the last non-revoked owner so the operator can't brick their own
    /// ownership chain from the web. If they need to, the CLI
    /// `regenerate-claim-token` path still works for full recovery.
    pub fn revoke_device(&self, device_id: &str, now: i64) -> Result<(), EnrollmentStoreError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| EnrollmentStoreError::LockPoisoned)?;
        let tx = conn.transaction()?;

        let (is_owner, already_revoked): (bool, bool) = match tx.query_row(
            "SELECT is_owner, revoked_at FROM authorized_devices WHERE device_id = ?1",
            rusqlite::params![device_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? != 0,
                    row.get::<_, Option<i64>>(1)?.is_some(),
                ))
            },
        ) {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(EnrollmentStoreError::DeviceNotFound);
            }
            Err(e) => return Err(EnrollmentStoreError::from(e)),
        };

        if already_revoked {
            // Idempotent — treat "already revoked" as success.
            return Ok(());
        }

        if is_owner {
            let owners = Self::count_owners(&tx)?;
            if owners <= 1 {
                return Err(EnrollmentStoreError::LastOwner);
            }
        }

        tx.execute(
            "UPDATE authorized_devices SET revoked_at = ?1 WHERE device_id = ?2",
            rusqlite::params![now, device_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// One row from `invite_codes`.
#[derive(Debug, Clone, Serialize)]
pub struct InviteRow {
    pub id: String,
    pub label: String,
    pub issued_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_by: Option<String>,
    pub used_at: Option<i64>,
}

/// One row from `authorized_devices`.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceRow {
    pub device_id: String,
    pub label: String,
    pub is_owner: bool,
    pub created_at: i64,
    pub last_seen_hour: i64,
    pub revoked_at: Option<i64>,
}

/// Constant-time byte-slice equality — short-circuit-free to avoid timing
/// leaks on hash compares. `subtle::ConstantTimeEq` isn't in the relay's
/// dep tree; this local variant is sufficient for the hash shapes we use.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Rate limiter for /relay/info ─────────────────────────────────────────────

/// Per-IP-bucket sliding-window limiter for `/relay/info`. Endpoint is cheap
/// and public, but we still cap it so it can't be used as a free firehose.
pub struct EnrollmentInfoLimiter {
    inner: SlidingWindowLimiterByKey<crate::rate_limit::IpBucket>,
}

/// Safety cap on distinct IP-bucket keys in memory.
const INFO_LIMITER_MAX_KEYS: usize = 50_000;

impl EnrollmentInfoLimiter {
    pub fn new(max_per_min: u32) -> Self {
        Self {
            inner: SlidingWindowLimiterByKey::new_with_cap(
                60,
                max_per_min as usize,
                Some(INFO_LIMITER_MAX_KEYS),
            ),
        }
    }

    pub fn check_and_record(&self, ip: std::net::IpAddr) -> bool {
        self.inner
            .check_and_record(crate::rate_limit::IpBucket::from(ip))
    }
}

// ── GET /relay/info ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct InfoResponse {
    /// Enrollment gate posture — `"open"` or `"restricted"`. SPA uses this to
    /// decide whether to show the invite-entry screen.
    pub mode: &'static str,
    /// `true` once at least one (non-revoked) owner device exists. The SPA
    /// switches between the bootstrap-claim screen and the invite-entry
    /// screen based on this flag.
    pub bootstrapped: bool,
    /// Relay semver — lets the SPA detect stale-cached-bundle mismatches.
    pub version: &'static str,
}

/// `GET /relay/info` — public, rate-limited.
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);

    if !state.enrollment_info_limiter.check_and_record(client_ip) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let bootstrapped = match state.enrollment_store.owner_count() {
        Ok(n) => n > 0,
        Err(e) => {
            tracing::error!(error = %e, "enrollment store owner_count failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Json(InfoResponse {
        mode: state.config.enrollment_mode.as_str(),
        bootstrapped,
        version: env!("CARGO_PKG_VERSION"),
    })
    .into_response()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parse_mode_accepts_canonical_spellings() {
        assert_eq!(EnrollmentMode::parse("open"), Some(EnrollmentMode::Open));
        assert_eq!(
            EnrollmentMode::parse("restricted"),
            Some(EnrollmentMode::Restricted)
        );
        assert_eq!(
            EnrollmentMode::parse("  RESTRICTED\n"),
            Some(EnrollmentMode::Restricted)
        );
        assert_eq!(
            EnrollmentMode::parse("Open"),
            Some(EnrollmentMode::Open)
        );
    }

    #[test]
    fn parse_mode_rejects_unknown() {
        assert_eq!(EnrollmentMode::parse(""), None);
        assert_eq!(EnrollmentMode::parse("closed"), None);
        assert_eq!(EnrollmentMode::parse("true"), None);
    }

    #[test]
    fn store_opens_and_reports_zero_owners_on_fresh_db() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("enrollment.sqlite3");
        let store = EnrollmentStore::open(&path).expect("open fresh store");
        assert_eq!(store.owner_count().expect("owner_count"), 0);
    }

    #[test]
    fn store_is_idempotent_on_reopen() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("enrollment.sqlite3");
        let _first = EnrollmentStore::open(&path).expect("open first");
        drop(_first);
        let second = EnrollmentStore::open(&path).expect("reopen");
        assert_eq!(second.owner_count().expect("owner_count"), 0);
    }

    #[test]
    fn info_response_serializes_to_expected_shape() {
        let body = serde_json::to_value(InfoResponse {
            mode: "restricted",
            bootstrapped: false,
            version: "1.2.3",
        })
        .expect("serialize");
        assert_eq!(body["mode"], "restricted");
        assert_eq!(body["bootstrapped"], false);
        assert_eq!(body["version"], "1.2.3");
        // Lock the shape: no extra fields we didn't intend to expose.
        let obj = body.as_object().expect("object");
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn bootstrap_token_roundtrip() {
        let dir = TempDir::new().expect("tempdir");
        let store = EnrollmentStore::open(&dir.path().join("db.sqlite3")).expect("open");

        assert!(!store.has_bootstrap_token(0).expect("has"));
        store
            .set_bootstrap_token(b"hash1", 1000, 2000)
            .expect("set");
        assert!(store.has_bootstrap_token(1500).expect("has"));
        assert!(!store.has_bootstrap_token(2000).expect("has expired"));

        // Regenerate replaces the prior row.
        store
            .set_bootstrap_token(b"hash2", 1500, 3000)
            .expect("replace");
        let conn = store.conn.lock().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM bootstrap_token", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "replacement must keep the table single-rowed");
    }

    #[test]
    fn claim_bootstrap_is_non_destructive_recovery_path() {
        // Post-phase-4 semantics: a valid token always produces an owner,
        // even if the vault is already bootstrapped. Motivated by the
        // `wattcloud regenerate-claim-token` recovery flow — operator
        // minted a fresh token on the server to re-gain web admin, and
        // shouldn't have to do destructive SQL surgery to make it count.
        // Existing owners stay put; the new device joins alongside them.
        let dir = TempDir::new().expect("tempdir");
        let store = EnrollmentStore::open(&dir.path().join("db.sqlite3")).expect("open");

        store.set_bootstrap_token(b"hash", 0, 10_000).unwrap();
        store
            .claim_bootstrap(b"hash", "owner-1", &[0xA; 32], "Alice", 100)
            .expect("first claim");
        assert_eq!(store.owner_count().unwrap(), 1);

        // Regenerate + second claim — new owner added, existing one unchanged.
        store.set_bootstrap_token(b"hash2", 200, 10_000).unwrap();
        store
            .claim_bootstrap(b"hash2", "owner-2", &[0xB; 32], "Bob", 300)
            .expect("second claim (recovery)");
        assert_eq!(store.owner_count().unwrap(), 2);

        // Replay of the same (consumed) token is still rejected — token row
        // is single-use and wipes on success.
        let err = store
            .claim_bootstrap(b"hash2", "owner-3", &[0xC; 32], "Carol", 400)
            .expect_err("replay rejected");
        assert!(matches!(err, EnrollmentStoreError::InvalidBootstrapToken));
    }

    #[test]
    fn claim_bootstrap_rejects_wrong_or_expired_token() {
        let dir = TempDir::new().expect("tempdir");
        let store = EnrollmentStore::open(&dir.path().join("db.sqlite3")).expect("open");
        store.set_bootstrap_token(b"right", 0, 10_000).unwrap();

        let wrong = store
            .claim_bootstrap(b"wrong", "d1", &[0; 32], "x", 100)
            .expect_err("wrong token rejected");
        assert!(matches!(wrong, EnrollmentStoreError::InvalidBootstrapToken));

        let expired = store
            .claim_bootstrap(b"right", "d1", &[0; 32], "x", 20_000)
            .expect_err("expired token rejected");
        assert!(matches!(expired, EnrollmentStoreError::InvalidBootstrapToken));
    }

    #[test]
    fn redeem_invite_single_use_and_expiry() {
        let dir = TempDir::new().expect("tempdir");
        let store = EnrollmentStore::open(&dir.path().join("db.sqlite3")).expect("open");

        // Seed an owner to issue the invite.
        store.set_bootstrap_token(b"t", 0, 1_000_000).unwrap();
        store
            .claim_bootstrap(b"t", "owner", &[0; 32], "o", 100)
            .unwrap();

        store
            .insert_invite("inv-1", b"code-hash", "Bob", "owner", 200, 10_000)
            .expect("insert");

        // First redeem succeeds.
        store
            .redeem_invite(b"code-hash", "device-1", &[1; 32], "Bob's laptop", 300)
            .expect("first redeem");

        // Second redeem of the same code is rejected.
        let err = store
            .redeem_invite(b"code-hash", "device-2", &[2; 32], "Mallory", 400)
            .expect_err("second redeem rejected");
        assert!(matches!(err, EnrollmentStoreError::InvalidInvite));

        // Expired code rejected.
        store
            .insert_invite("inv-2", b"other-hash", "Carol", "owner", 500, 1000)
            .expect("insert expired");
        let err = store
            .redeem_invite(b"other-hash", "device-3", &[3; 32], "Carol", 2000)
            .expect_err("expired rejected");
        assert!(matches!(err, EnrollmentStoreError::InvalidInvite));
    }

    #[test]
    fn revoke_device_protects_last_owner() {
        let dir = TempDir::new().expect("tempdir");
        let store = EnrollmentStore::open(&dir.path().join("db.sqlite3")).expect("open");
        store.set_bootstrap_token(b"t", 0, 1_000_000).unwrap();
        store
            .claim_bootstrap(b"t", "owner-1", &[1; 32], "o1", 100)
            .unwrap();

        // Cannot revoke the only owner.
        let err = store
            .revoke_device("owner-1", 200)
            .expect_err("last owner protected");
        assert!(matches!(err, EnrollmentStoreError::LastOwner));

        // Seed a second owner via direct insert (phase-2 only exposes this
        // via admin endpoints, but the SQL-level check is what matters here).
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO authorized_devices \
                   (device_id, pubkey, label, is_owner, created_at, last_seen_hour) \
                 VALUES ('owner-2', X'02', '', 1, 200, 0)",
                [],
            )
            .unwrap();
        }
        // Now revoking owner-1 is allowed.
        store.revoke_device("owner-1", 300).expect("revoke");
        assert_eq!(store.owner_count().unwrap(), 1);

        // Second revoke is idempotent.
        store
            .revoke_device("owner-1", 400)
            .expect("idempotent revoke");
    }

    #[test]
    fn touch_last_seen_only_advances() {
        let dir = TempDir::new().expect("tempdir");
        let store = EnrollmentStore::open(&dir.path().join("db.sqlite3")).expect("open");
        store.set_bootstrap_token(b"t", 0, 1_000_000).unwrap();
        // `claim_bootstrap` uses now/3600 for the initial last_seen_hour.
        // Start at unix ts 5*3600 so the first hour bucket is 5.
        store
            .claim_bootstrap(b"t", "d", &[0; 32], "", 5 * 3600)
            .unwrap();

        // Earlier touch — no-op.
        store.touch_last_seen("d", 3 * 3600).unwrap();
        assert_eq!(store.get_device("d").unwrap().unwrap().last_seen_hour, 5);

        // Later touch — advances.
        store.touch_last_seen("d", 9 * 3600).unwrap();
        assert_eq!(store.get_device("d").unwrap().unwrap().last_seen_hour, 9);
    }

    #[test]
    fn list_invites_returns_newest_first() {
        let dir = TempDir::new().expect("tempdir");
        let store = EnrollmentStore::open(&dir.path().join("db.sqlite3")).expect("open");
        store.set_bootstrap_token(b"t", 0, 1_000_000).unwrap();
        store
            .claim_bootstrap(b"t", "owner", &[0; 32], "", 100)
            .unwrap();

        store.insert_invite("a", b"h1", "A", "owner", 100, 1_000_000).unwrap();
        store.insert_invite("b", b"h2", "B", "owner", 200, 1_000_000).unwrap();
        store.insert_invite("c", b"h3", "C", "owner", 150, 1_000_000).unwrap();

        let rows = store.list_invites().unwrap();
        let ids: Vec<_> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "c", "a"]);
    }

    #[test]
    fn revoke_invite_is_idempotent() {
        let dir = TempDir::new().expect("tempdir");
        let store = EnrollmentStore::open(&dir.path().join("db.sqlite3")).expect("open");
        store.set_bootstrap_token(b"t", 0, 1_000_000).unwrap();
        store
            .claim_bootstrap(b"t", "owner", &[0; 32], "", 100)
            .unwrap();
        store.insert_invite("a", b"h1", "", "owner", 100, 1_000_000).unwrap();

        store.revoke_invite("a").unwrap();
        store.revoke_invite("a").unwrap(); // no-op
        store.revoke_invite("nonexistent").unwrap(); // also no-op
        assert!(store.list_invites().unwrap().is_empty());
    }

    #[test]
    fn store_owner_count_reflects_inserts() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("enrollment.sqlite3");
        let store = EnrollmentStore::open(&path).expect("open");

        // Simulate phase-2 inserts at the SQL level so phase-1 `owner_count`
        // still has something meaningful to test against.
        {
            let conn = store.conn.lock().expect("lock");
            conn.execute(
                "INSERT INTO authorized_devices \
                   (device_id, pubkey, label, is_owner, created_at, last_seen_hour) \
                 VALUES ('d1', X'01', 'owner', 1, 0, 0)",
                [],
            )
            .expect("insert owner");
            conn.execute(
                "INSERT INTO authorized_devices \
                   (device_id, pubkey, label, is_owner, created_at, last_seen_hour) \
                 VALUES ('d2', X'02', 'member', 0, 0, 0)",
                [],
            )
            .expect("insert non-owner");
            conn.execute(
                "INSERT INTO authorized_devices \
                   (device_id, pubkey, label, is_owner, created_at, last_seen_hour, revoked_at) \
                 VALUES ('d3', X'03', 'old owner', 1, 0, 0, 1)",
                [],
            )
            .expect("insert revoked owner");
        }

        assert_eq!(
            store.owner_count().expect("owner_count"),
            1,
            "only non-revoked owners count"
        );
    }
}
