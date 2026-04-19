// BYO stats ingest handler + SQLite store.
//
// Privacy invariants (MUST NOT be violated):
// - Raw device_id never persisted.  It is HMAC-SHA256 hashed in handler memory
//   before any storage call.
// - No tracing::info!/warn!/error! referencing device_id, event counts, or body.
//   Only generic schema/IO errors are logged at error level.
// - Rate-limit keyed on device_id_hash — preserves no-IP-logging invariant.

use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use serde::Deserialize;
use sha2::Sha256;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tower_cookies::Cookies;

use crate::rate_limit::SlidingWindowLimiterByKey;
use crate::relay_auth::{verify_relay_cookie, AppState};

type HmacSha256 = Hmac<Sha256>;

// ── Whitelists ────────────────────────────────────────────────────────────────

const KNOWN_KINDS: &[&str] = &[
    "vault_unlock",
    "vault_lock",
    "vault_save",
    "upload",
    "download",
    "error",
    "share_create",
    "share_resolve",
    "share_revoke",
    "relay_bandwidth_sftp",
    "relay_bandwidth_share",
    "device_size_snapshot",
];

const KNOWN_PROVIDERS: &[&str] =
    &["gdrive", "dropbox", "onedrive", "webdav", "sftp", "box", "pcloud", "s3"];

const KNOWN_ERROR_CLASSES: &[&str] =
    &["Network", "Unauthorized", "RateLimited", "Conflict", "Other", "Aborted"];

const KNOWN_SHARE_VARIANTS: &[&str] = &["A", "A+", "B1", "B2"];

/// Max time a client timestamp may be in the past (2 days).
const TS_MAX_PAST_SECS: i64 = 2 * 24 * 3600;
/// Max time a client timestamp may be in the future (5 minutes).
const TS_MAX_FUTURE_SECS: i64 = 5 * 60;
/// Ciphertext bytes sanity cap: 1 TiB.
const MAX_BYTES: u64 = 1u64 << 40;

// ── Rate limiter ──────────────────────────────────────────────────────────────

/// Per-device rate limiter for stats ingest, keyed on device_id_hash.
pub struct StatsIngestLimiter {
    inner: SlidingWindowLimiterByKey<[u8; 32]>,
}

/// Maximum number of device hashes tracked concurrently in the rate-limit map.
/// Prevents unbounded memory growth from churning device UUIDs.
const STATS_LIMITER_MAX_KEYS: usize = 100_000;

impl StatsIngestLimiter {
    pub fn new(max_per_min: u32) -> Self {
        Self {
            inner: SlidingWindowLimiterByKey::new_with_cap(
                60,
                max_per_min as usize,
                Some(STATS_LIMITER_MAX_KEYS),
            ),
        }
    }

    pub fn check_and_record(&self, device_hash: [u8; 32]) -> bool {
        self.inner.check_and_record(device_hash)
    }
}

// ── SQLite store ──────────────────────────────────────────────────────────────

/// SQLite-backed stats store.  WAL mode enables concurrent admin reads.
pub struct StatsStore {
    conn: Mutex<Connection>,
}

impl StatsStore {
    /// Open (or create) the SQLite database at `path` and apply the schema.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; \
             PRAGMA synchronous=NORMAL; \
             PRAGMA busy_timeout=5000;",
        )?;
        conn.execute_batch(include_str!("stats_schema.sql"))?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Open the database read-only (for `byo-admin log`).  WAL mode means
    /// read-only opens do not block concurrent server writes.
    pub fn open_readonly(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// HMAC-SHA256(hmac_key, device_id) → 32-byte hash.
    /// Raw device_id is never written to disk.
    pub fn hash_device(hmac_key: &[u8], device_id: &str) -> [u8; 32] {
        // new_from_slice fails only for an empty key; STATS_HMAC_KEY is validated
        // to be ≥32 B at startup, so this path is unreachable in practice.
        let mut mac = HmacSha256::new_from_slice(hmac_key)
            .unwrap_or_else(|_| unreachable!("HMAC key is always ≥32 B — validated at startup"));
        mac.update(device_id.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Persist a validated batch of events.
    ///
    /// Unknown `kind`/`provider_type`/`error_class`/`share_variant` values and
    /// out-of-window `ts` values are silently dropped (forward-compatibility).
    pub fn apply_batch(
        &self,
        device_id_hash: &[u8; 32],
        events: &[RawEvent],
        now_secs: i64,
    ) -> rusqlite::Result<()> {
        let mut conn = self.conn.lock().expect("stats conn lock poisoned");
        let tx = conn.transaction()?;
        for ev in events {
            if !KNOWN_KINDS.contains(&ev.kind.as_str()) {
                continue;
            }
            let ts = match ev.ts {
                Some(t) => t,
                None => continue,
            };
            if ts < now_secs - TS_MAX_PAST_SECS || ts > now_secs + TS_MAX_FUTURE_SECS {
                continue;
            }
            let date = ts_to_date(ts);
            match ev.kind.as_str() {
                "device_size_snapshot" => {
                    let provider = match ev.provider_type.as_deref() {
                        Some(p) if KNOWN_PROVIDERS.contains(&p) => p,
                        _ => continue,
                    };
                    let fcb = ev.file_count_bucket.unwrap_or(0);
                    let vsb = ev.vault_size_bucket.unwrap_or(0);
                    tx.execute(
                        "INSERT OR REPLACE INTO device_day_size \
                         (bucket_date, device_id_hash, provider_type, \
                          file_count_bucket, vault_size_bucket) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![date, device_id_hash.as_slice(), provider, fcb, vsb],
                    )?;
                }
                "upload" | "download" => {
                    let provider = match ev.provider_type.as_deref() {
                        Some(p) if KNOWN_PROVIDERS.contains(&p) => p,
                        _ => continue,
                    };
                    // Drop events with bytes exceeding the sanity cap (spec: oversize → drop).
                    if ev.bytes.is_some_and(|b| b > MAX_BYTES) {
                        continue;
                    }
                    let bytes = ev.bytes.unwrap_or(0) as i64;
                    upsert_counter(&tx, &date, &ev.kind, provider, "", "", bytes)?;
                    tx.execute(
                        "INSERT OR IGNORE INTO device_day_provider \
                         (bucket_date, device_id_hash, provider_type) \
                         VALUES (?1, ?2, ?3)",
                        rusqlite::params![date, device_id_hash.as_slice(), provider],
                    )?;
                }
                "error" => {
                    let provider = match ev.provider_type.as_deref() {
                        Some(p) if KNOWN_PROVIDERS.contains(&p) => p,
                        _ => continue,
                    };
                    let error_class = match ev.error_class.as_deref() {
                        Some(e) if KNOWN_ERROR_CLASSES.contains(&e) => e,
                        _ => continue,
                    };
                    upsert_counter(&tx, &date, &ev.kind, provider, error_class, "", 0)?;
                    tx.execute(
                        "INSERT OR IGNORE INTO device_day_provider \
                         (bucket_date, device_id_hash, provider_type) \
                         VALUES (?1, ?2, ?3)",
                        rusqlite::params![date, device_id_hash.as_slice(), provider],
                    )?;
                }
                "share_create" | "share_resolve" | "share_revoke" => {
                    let variant = match ev.share_variant.as_deref() {
                        Some(v) if KNOWN_SHARE_VARIANTS.contains(&v) => v,
                        _ => continue,
                    };
                    upsert_counter(&tx, &date, &ev.kind, "", "", variant, 0)?;
                }
                "relay_bandwidth_sftp" | "relay_bandwidth_share" => {
                    // Drop events with bytes exceeding the sanity cap (spec: oversize → drop).
                    if ev.bytes.is_some_and(|b| b > MAX_BYTES) {
                        continue;
                    }
                    let bytes = ev.bytes.unwrap_or(0) as i64;
                    upsert_counter(&tx, &date, &ev.kind, "", "", "", bytes)?;
                }
                "vault_unlock" | "vault_lock" | "vault_save" => {
                    upsert_counter(&tx, &date, &ev.kind, "", "", "", 0)?;
                }
                _ => {}
            }
        }
        tx.commit()
    }

    /// Probe liveness: query `schema_meta` to verify the DB is both openable
    /// *and* schema-populated.  Used by /ready; returns Err on lock poisoning,
    /// missing tables, corruption, or busy-timeout.
    pub fn ping(&self) -> rusqlite::Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.query_row(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'",
            [],
            |_| Ok(()),
        )?;
        Ok(())
    }

    /// Wipe all stats rows from all tables.  Leaves `schema_meta` intact.
    pub fn clear_all(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("stats conn lock poisoned");
        conn.execute_batch(
            "BEGIN IMMEDIATE; \
             DELETE FROM counters; \
             DELETE FROM device_day_provider; \
             DELETE FROM device_day_size; \
             COMMIT;",
        )
    }

    /// Query aggregated counters for the given granularity and date range.
    ///
    /// `granularity`: one of `"daily"`, `"weekly"`, `"monthly"`, `"yearly"`.
    /// `from` / `to`: optional inclusive bounds as `"YYYY-MM-DD"`.
    pub fn aggregate_counters(
        &self,
        granularity: &str,
        from: Option<&str>,
        to: Option<&str>,
    ) -> rusqlite::Result<Vec<CounterRow>> {
        let period_expr = granularity_to_strftime(granularity);
        let conn = self.conn.lock().expect("stats conn lock poisoned");
        let mut stmt = conn.prepare(&format!(
            "SELECT strftime('{period_expr}', bucket_date) AS period, \
                    event_kind, provider_type, error_class, share_variant, \
                    SUM(count) AS total_count, SUM(bytes_sum) AS total_bytes \
             FROM counters \
             WHERE (?1 IS NULL OR bucket_date >= ?1) \
               AND (?2 IS NULL OR bucket_date <= ?2) \
             GROUP BY period, event_kind, provider_type, error_class, share_variant \
             ORDER BY period, event_kind, provider_type, error_class, share_variant"
        ))?;
        let rows = stmt.query_map(rusqlite::params![from, to], |row| {
            Ok(CounterRow {
                period: row.get(0)?,
                event_kind: row.get(1)?,
                provider_type: row.get(2)?,
                error_class: row.get(3)?,
                share_variant: row.get(4)?,
                count: row.get(5)?,
                bytes_sum: row.get(6)?,
            })
        })?;
        rows.collect()
    }

    /// Query provider-mix: distinct device count per (period, provider).
    pub fn aggregate_provider_mix(
        &self,
        granularity: &str,
        from: Option<&str>,
        to: Option<&str>,
    ) -> rusqlite::Result<Vec<ProviderMixRow>> {
        let period_expr = granularity_to_strftime(granularity);
        let conn = self.conn.lock().expect("stats conn lock poisoned");
        let mut stmt = conn.prepare(&format!(
            "SELECT strftime('{period_expr}', bucket_date) AS period, \
                    provider_type, COUNT(*) AS device_count \
             FROM device_day_provider \
             WHERE (?1 IS NULL OR bucket_date >= ?1) \
               AND (?2 IS NULL OR bucket_date <= ?2) \
             GROUP BY period, provider_type \
             ORDER BY period, device_count DESC"
        ))?;
        let rows = stmt.query_map(rusqlite::params![from, to], |row| {
            Ok(ProviderMixRow {
                period: row.get(0)?,
                provider_type: row.get(1)?,
                device_count: row.get(2)?,
            })
        })?;
        rows.collect()
    }
}

fn granularity_to_strftime(g: &str) -> &'static str {
    match g {
        "weekly" => "%Y-W%W",
        "monthly" => "%Y-%m",
        "yearly" => "%Y",
        _ => "%Y-%m-%d", // "daily" + fallback
    }
}

fn upsert_counter(
    tx: &rusqlite::Transaction<'_>,
    date: &str,
    kind: &str,
    provider: &str,
    error_class: &str,
    share_variant: &str,
    bytes: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO counters \
         (bucket_date, event_kind, provider_type, error_class, share_variant, count, bytes_sum) \
         VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6) \
         ON CONFLICT(bucket_date, event_kind, provider_type, error_class, share_variant) \
         DO UPDATE SET count = count + 1, bytes_sum = bytes_sum + excluded.bytes_sum",
        rusqlite::params![date, kind, provider, error_class, share_variant, bytes],
    )?;
    Ok(())
}

// ── Date helpers ──────────────────────────────────────────────────────────────

fn ts_to_date(ts: i64) -> String {
    let secs = ts.max(0) as u64;
    let days = secs / 86400;
    calendar_date(days)
}

/// Days since Unix epoch (1970-01-01) → "YYYY-MM-DD" (UTC).
/// Uses Howard Hinnant's algorithm — no external date library needed.
fn calendar_date(days_since_epoch: u64) -> String {
    let z: i64 = days_since_epoch as i64 + 719468;
    let era: i64 = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

// ── Output row types (used by byo-admin CLI) ──────────────────────────────────

pub struct CounterRow {
    pub period: String,
    pub event_kind: String,
    pub provider_type: String,
    pub error_class: String,
    pub share_variant: String,
    pub count: i64,
    pub bytes_sum: i64,
}

pub struct ProviderMixRow {
    pub period: String,
    pub provider_type: String,
    pub device_count: i64,
}

// ── Wire format ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StatsPayload {
    #[allow(dead_code)]
    device_id: String,
    events: Vec<RawEvent>,
}

#[derive(Debug, Deserialize)]
pub struct RawEvent {
    pub kind: String,
    pub ts: Option<i64>,
    pub provider_type: Option<String>,
    pub error_class: Option<String>,
    pub share_variant: Option<String>,
    pub bytes: Option<u64>,
    pub file_count_bucket: Option<i64>,
    pub vault_size_bucket: Option<i64>,
}

/// Validate lowercase UUIDv4 format: 36 chars, hyphens at [8,13,18,23], hex lowercase.
fn validate_device_id(id: &str) -> bool {
    if id.len() != 36 {
        return false;
    }
    let bytes = id.as_bytes();
    let hyphen_pos = [8usize, 13, 18, 23];
    for (i, &b) in bytes.iter().enumerate() {
        if hyphen_pos.contains(&i) {
            if b != b'-' {
                return false;
            }
        } else if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
            return false;
        }
    }
    true
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// Minimal pre-parse struct for early rate-limiting — extracts only device_id.
/// serde ignores unknown fields by default, so this is cheap and forward-compatible.
#[derive(Deserialize)]
struct DeviceIdOnly {
    device_id: String,
}

/// POST /relay/stats — accept a batch of stats events.
///
/// Auth: relay_auth cookie with purpose="stats".
/// JTI is NOT consumed (counter-only endpoint; replay is harmless and avoids
/// 401 on multi-flush within the cookie's TTL).
///
/// Order: cookie → size → pre-parse device_id → HMAC → rate-limit → full parse → apply.
/// Rate-limiting before full parse prevents CPU amplification on large bodies.
pub async fn ingest_stats(
    cookies: Cookies,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    // Verify relay_auth cookie; purpose must be exactly "stats".
    let claims = match verify_relay_cookie(&cookies, &state.config.relay_signing_key) {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if claims.purpose != "stats" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // JTI intentionally not consumed — see module doc.

    // Body size guard.
    if body.len() > state.config.stats_max_body_bytes {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }

    // Pre-parse device_id only — cheap single-field extraction for rate-limit keying.
    let envelope: DeviceIdOnly = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !validate_device_id(&envelope.device_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Hash device_id — raw UUID only in stack memory from here.
    let device_hash = StatsStore::hash_device(&state.config.stats_hmac_key, &envelope.device_id);

    // Per-device rate limit (keyed on hash — no IP involvement).
    // Runs before full parse to prevent CPU amplification.
    if !state.stats_ingest_limiter.check_and_record(device_hash) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // Full parse — only reached for non-rate-limited clients.
    let payload: StatsPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Event count cap.
    if payload.events.len() > state.config.stats_batch_max_events {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Persist.
    let now = now_secs();
    if let Err(_e) = state.stats_store.apply_batch(&device_hash, &payload.events, now) {
        tracing::error!("stats: apply_batch failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    StatusCode::NO_CONTENT.into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn open_mem() -> StatsStore {
        StatsStore::open(":memory:").unwrap()
    }

    fn now() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    }

    fn hash() -> [u8; 32] {
        StatsStore::hash_device(b"test_hmac_key_32_bytes_minimum!!", "5f3b1234-1234-1234-1234-1234567890ab")
    }

    // ── validate_device_id ────────────────────────────────────────────────────

    #[test]
    fn valid_device_id() {
        assert!(validate_device_id("5f3b1234-1234-4321-a123-1234567890ab"));
        assert!(validate_device_id("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn invalid_device_id_uppercase() {
        assert!(!validate_device_id("5F3B1234-1234-1234-1234-1234567890AB"));
    }

    #[test]
    fn invalid_device_id_wrong_length() {
        assert!(!validate_device_id("5f3b1234-1234-1234-1234-1234567890abc"));
        assert!(!validate_device_id(""));
        assert!(!validate_device_id("not-a-uuid"));
    }

    // ── calendar_date ─────────────────────────────────────────────────────────

    #[test]
    fn epoch_date() {
        assert_eq!(calendar_date(0), "1970-01-01");
    }

    #[test]
    fn known_date() {
        // 2024-04-16 = 19829 days since epoch
        // 19829 * 86400 = 1713225600
        assert_eq!(ts_to_date(1713225600), "2024-04-16");
    }

    // ── apply_batch ───────────────────────────────────────────────────────────

    #[test]
    fn unknown_kind_silently_dropped() {
        let store = open_mem();
        let h = hash();
        let now = now();
        let events = vec![RawEvent {
            kind: "unknown_future_kind".into(),
            ts: Some(now),
            provider_type: None,
            error_class: None,
            share_variant: None,
            bytes: None,
            file_count_bucket: None,
            vault_size_bucket: None,
        }];
        store.apply_batch(&h, &events, now).unwrap();
        // No rows should be in counters.
        let rows = store.aggregate_counters("daily", None, None).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn vault_unlock_counted() {
        let store = open_mem();
        let h = hash();
        let now = now();
        let events = vec![RawEvent {
            kind: "vault_unlock".into(),
            ts: Some(now),
            provider_type: None,
            error_class: None,
            share_variant: None,
            bytes: None,
            file_count_bucket: None,
            vault_size_bucket: None,
        }];
        store.apply_batch(&h, &events, now).unwrap();
        let rows = store.aggregate_counters("daily", None, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_kind, "vault_unlock");
        assert_eq!(rows[0].count, 1);
    }

    #[test]
    fn upload_with_bytes_accumulates() {
        let store = open_mem();
        let h = hash();
        let now = now();
        let events = vec![
            RawEvent {
                kind: "upload".into(),
                ts: Some(now),
                provider_type: Some("gdrive".into()),
                bytes: Some(1024),
                error_class: None,
                share_variant: None,
                file_count_bucket: None,
                vault_size_bucket: None,
            },
            RawEvent {
                kind: "upload".into(),
                ts: Some(now),
                provider_type: Some("gdrive".into()),
                bytes: Some(2048),
                error_class: None,
                share_variant: None,
                file_count_bucket: None,
                vault_size_bucket: None,
            },
        ];
        store.apply_batch(&h, &events, now).unwrap();
        let rows = store.aggregate_counters("daily", None, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].count, 2);
        assert_eq!(rows[0].bytes_sum, 3072);
    }

    #[test]
    fn ts_too_old_dropped() {
        let store = open_mem();
        let h = hash();
        let now = now();
        let events = vec![RawEvent {
            kind: "vault_unlock".into(),
            ts: Some(now - TS_MAX_PAST_SECS - 1),
            provider_type: None,
            error_class: None,
            share_variant: None,
            bytes: None,
            file_count_bucket: None,
            vault_size_bucket: None,
        }];
        store.apply_batch(&h, &events, now).unwrap();
        let rows = store.aggregate_counters("daily", None, None).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn unknown_provider_dropped() {
        let store = open_mem();
        let h = hash();
        let now = now();
        let events = vec![RawEvent {
            kind: "upload".into(),
            ts: Some(now),
            provider_type: Some("unknown_provider".into()),
            bytes: Some(100),
            error_class: None,
            share_variant: None,
            file_count_bucket: None,
            vault_size_bucket: None,
        }];
        store.apply_batch(&h, &events, now).unwrap();
        assert!(store.aggregate_counters("daily", None, None).unwrap().is_empty());
    }

    #[test]
    fn clear_all_removes_rows_keeps_schema_meta() {
        let store = open_mem();
        let h = hash();
        let now = now();
        let events = vec![RawEvent {
            kind: "vault_unlock".into(),
            ts: Some(now),
            provider_type: None,
            error_class: None,
            share_variant: None,
            bytes: None,
            file_count_bucket: None,
            vault_size_bucket: None,
        }];
        store.apply_batch(&h, &events, now).unwrap();
        store.clear_all().unwrap();
        assert!(store.aggregate_counters("daily", None, None).unwrap().is_empty());
        // schema_meta must still have the version row.
        let conn = store.conn.lock().unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key='schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }

    #[test]
    fn device_size_snapshot_stored() {
        let store = open_mem();
        let h = hash();
        let now = now();
        let events = vec![RawEvent {
            kind: "device_size_snapshot".into(),
            ts: Some(now),
            provider_type: Some("s3".into()),
            file_count_bucket: Some(10),
            vault_size_bucket: Some(30),
            bytes: None,
            error_class: None,
            share_variant: None,
        }];
        store.apply_batch(&h, &events, now).unwrap();
        let conn = store.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM device_day_size", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn share_create_b2_counted() {
        let store = open_mem();
        let h = hash();
        let now = now();
        let events = vec![RawEvent {
            kind: "share_create".into(),
            ts: Some(now),
            share_variant: Some("B2".into()),
            provider_type: None,
            error_class: None,
            bytes: None,
            file_count_bucket: None,
            vault_size_bucket: None,
        }];
        store.apply_batch(&h, &events, now).unwrap();
        let rows = store.aggregate_counters("daily", None, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_kind, "share_create");
        assert_eq!(rows[0].share_variant, "B2");
    }
}
