//! Share relay HTTP handlers.
//!
//! All ciphertext now lives in `ShareStore` (filesystem + SQLite). This module
//! owns the HTTP surface: auth checks, rate-limiting, validation, and the
//! ownership-token HMAC scheme used for revocations.
//!
//! Endpoints:
//!   Single-file shares (phase 1a/b)
//!     POST   /relay/share/b2                          create+upload (PoW-gated, streaming)
//!     GET    /relay/share/b2/:share_id                fetch (unauth, rate-limited, streaming)
//!     DELETE /relay/share/b2/:share_id                revoke (X-Owner-Token gated)
//!
//!   Bundle shares — folder / collection (phase 1c)
//!     POST   /relay/share/bundle/init                 create empty bundle (PoW-gated); returns bundle_token
//!     POST   /relay/share/bundle/:share_id/blob/:bid  stream one content blob (bundle-token gated)
//!     POST   /relay/share/bundle/:share_id/seal       stream manifest + seal (bundle-token gated)
//!
//!   Unified recipient read surface (phase 1c)
//!     GET    /relay/share/:share_id/meta              {kind, blob_count, blobs:[{id,bytes}]} (unauth, rate-limited)
//!     GET    /relay/share/:share_id/blob/:blob_id     streaming blob fetch (unauth, rate-limited)
//!
//! All uploads + downloads stream. No per-request size cap at this layer;
//! the per-IP daily byte budget (phase 1d) is the only DoS backstop. The
//! bundle_token is 32 random bytes minted at init and stored server-side;
//! `mark_sealed` wipes it so a stolen token cannot inject blobs post-seal.
//!
//! Zero-knowledge invariants unchanged: body is always V7 ciphertext; we never
//! inspect or decrypt it. The V7_MARKER + V7_MIN_SIZE checks keep junk out of
//! the store, nothing more.

use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::time;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::client_ip::extract_client_ip;
use crate::rate_limit::{IpBucket, SlidingWindowLimiterByKey};
use crate::relay_auth::{verify_relay_cookie, AppState, RELAY_COOKIE_NAME_SHARE};
use crate::share_store::{ShareKind, ShareStore, StoreError};

type HmacSha256 = Hmac<Sha256>;

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_EXPIRES_SECS: u32 = 30 * 24 * 3600; // 30 days
const V7_MARKER: u8 = 0x07;
const V7_MIN_SIZE: usize = 1709 + 32;
const SHARE_GET_PER_SHARE_LIMIT: usize = 10;
const SHARE_GET_PER_IP_LIMIT: usize = 60;
/// Response chunk size when streaming a blob back to the recipient. Balances
/// syscall count vs. latency for 8 KiB chunks in axum/hyper.
const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;

// ── Rate limiter (unchanged shape) ───────────────────────────────────────────

/// Dual-key rate limiter for share GET endpoints:
///   - 10 req/min per share_id
///   - 60 req/min per source IP (bucketed to /64 for IPv6)
pub struct ShareGetLimiter {
    per_share: SlidingWindowLimiterByKey<String>,
    per_ip: SlidingWindowLimiterByKey<IpBucket>,
}

/// Cap the rate-limiter maps so an attacker can't exhaust memory by cycling
/// through synthetic share_ids or IPv6 /64 prefixes.
const SHARE_LIMITER_MAX_KEYS: usize = 50_000;

impl Default for ShareGetLimiter {
    fn default() -> Self {
        Self {
            per_share: SlidingWindowLimiterByKey::new_with_cap(
                60,
                SHARE_GET_PER_SHARE_LIMIT,
                Some(SHARE_LIMITER_MAX_KEYS),
            ),
            per_ip: SlidingWindowLimiterByKey::new_with_cap(
                60,
                SHARE_GET_PER_IP_LIMIT,
                Some(SHARE_LIMITER_MAX_KEYS),
            ),
        }
    }
}

impl ShareGetLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true when both per-share and per-IP buckets pass.
    /// Short-circuits on the per-share check so an attacker cycling fake
    /// share_ids cannot drain a legitimate client's per-IP budget (D4).
    pub fn check_and_record(&self, share_id: &str, ip: std::net::IpAddr) -> bool {
        if !self.per_share.check_and_record(share_id.to_string()) {
            return false;
        }
        self.per_ip.check_and_record(IpBucket::from(ip))
    }
}

// ── Response type ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ShareCreateResponse {
    pub share_id: String,
    pub expires_at: i64,
    /// HMAC-SHA256(share_signing_key, share_id || token_nonce || ":owner") —
    /// bearer token for revocation. Client stores this in
    /// share_tokens.owner_token.
    pub owner_token: String,
}

// ── Owner token helpers ──────────────────────────────────────────────────────

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Validate share_id format: 36 chars, alphanumerics + hyphens (UUID shape).
fn is_valid_share_id(id: &str) -> bool {
    id.len() == 36 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn generate_token_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// HMAC-SHA256 owner token.
/// Token = hex(HMAC-SHA256(signing_key, share_id || nonce || ":owner")).
fn compute_owner_token(signing_key: &[u8], share_id: &str, nonce: &[u8; 16]) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC accepts any key length");
    mac.update(share_id.as_bytes());
    mac.update(nonce.as_slice());
    mac.update(b":owner");
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time verify. Nonce must come from the stored record, never the
/// client (otherwise an attacker picks the nonce and forges tokens).
fn verify_owner_token(
    signing_key: &[u8],
    share_id: &str,
    nonce: &[u8; 16],
    presented: &str,
) -> bool {
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC accepts any key length");
    mac.update(share_id.as_bytes());
    mac.update(nonce.as_slice());
    mac.update(b":owner");
    match hex::decode(presented) {
        Ok(bytes) => mac.verify_slice(&bytes).is_ok(),
        Err(_) => {
            // Constant-time dummy verify to blunt timing side channels.
            let _ = mac.verify_slice(&[0u8; 32]);
            false
        }
    }
}

// ── Rejection helper ─────────────────────────────────────────────────────────
//
// Abuse-protection rejections all carry two response headers the frontend
// relies on for user-facing copy:
//
//   X-Wattcloud-Reason: <token>   — stable machine-readable reason code.
//   Retry-After: <seconds>        — (where predictable) RFC 7231 hint.
//
// The token set is the contract for UI strings; see
// frontend/src/lib/byo/shareLimitCopy.ts for the mapping. Don't rename
// an emitted reason without updating that table — older clients would
// fall back to the generic "action failed" copy.

/// Stable reason tokens emitted on X-Wattcloud-Reason. Kept as constants
/// rather than an enum so the frontend can match against fixed strings
/// even if a future release adds new reasons.
const REASON_DISK_WATERMARK: &str = "disk-watermark";
const REASON_RATE_HOUR: &str = "rate-hour";
const REASON_RATE_DAY: &str = "rate-day";
const REASON_IP_STORAGE_FULL: &str = "ip-storage-full";
const REASON_DAILY_BYTES: &str = "per-ip-daily-budget";
const REASON_TOO_LARGE: &str = "too-large";
const REASON_BYTES_HOUR: &str = "bytes-hour";
const REASON_CONCURRENT: &str = "concurrent";
const REASON_FETCH_RATE: &str = "fetch-rate";

fn limit_rejection(
    status: StatusCode,
    reason: &'static str,
    retry_after_secs: Option<u32>,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("X-Wattcloud-Reason", HeaderValue::from_static(reason));
    if let Some(s) = retry_after_secs {
        if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
            headers.insert(axum::http::header::RETRY_AFTER, v);
        }
    }
    (status, headers).into_response()
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// POST /relay/share/b2 — upload a V7 ciphertext blob for a single-file share.
///
/// Headers: X-Share-Id, X-Expires-In (seconds).
/// Body: raw V7 ciphertext (first byte 0x07). No size cap enforced here —
/// per-IP daily byte budget is the abuse backstop. The upload layer disables
/// `DefaultBodyLimit` via main.rs route wiring.
///
/// Crash safety: the body streams to `<blob_id>.v7.tmp` and is atomically
/// renamed only after the full stream is received and the V7 min-size check
/// passes. A client disconnect mid-upload leaves a .tmp file behind that the
/// unsealed-share sweeper cleans up.
pub async fn upload_b2_share(
    cookies: tower_cookies::Cookies,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    // Auth: purpose-scoped single-use relay auth cookie.
    let claims = match verify_relay_cookie(
        &cookies,
        RELAY_COOKIE_NAME_SHARE,
        &state.config.relay_signing_key,
    ) {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if claims.purpose != "share:b2" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !state.jti_consumed.try_consume(&claims.jti, claims.exp) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let share_id = match headers
        .get("X-Share-Id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    {
        Some(id) => id,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let expires_in_secs: u32 = match headers
        .get("X-Expires-In")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
    {
        Some(v) => v,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    if !is_valid_share_id(&share_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // ── Abuse gates ───────────────────────────────────────────────────────
    // Each returns before we touch the disk or the metadata row, so a
    // denied client costs us only the auth + header parse. Order matters:
    // cheapest check first. Every rejection carries X-Wattcloud-Reason +
    // Retry-After so the frontend can show a specific message.

    // 1. Disk watermark — global. Operator-level stop before individual
    //    clients get blamed.
    if let Some(pct) = crate::rate_limit::disk_usage_percent(state.share_store.blobs_dir()) {
        if pct >= state.config.disk_watermark_percent {
            return limit_rejection(
                StatusCode::INSUFFICIENT_STORAGE,
                REASON_DISK_WATERMARK,
                Some(300),
            );
        }
    }

    // 2. Content-Length cap. Cheap to check, and rejects a runaway upload
    //    before it consumes bandwidth + temp-file IO.
    let declared_len = content_length(&headers);
    if let Some(len) = declared_len {
        if len > state.config.share_max_blob_bytes {
            return limit_rejection(StatusCode::PAYLOAD_TOO_LARGE, REASON_TOO_LARGE, None);
        }
    }

    // 3. Per-IP creation rate (hour + day). Blocks a device that's gone
    //    berserk from consuming any of the share_id namespace.
    match state.share_create_limiter.check_and_record(client_ip) {
        crate::rate_limit::ShareCreationDecision::Allow => {}
        crate::rate_limit::ShareCreationDecision::HourCapExceeded => {
            return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_RATE_HOUR, Some(3600));
        }
        crate::rate_limit::ShareCreationDecision::DayCapExceeded => {
            return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_RATE_DAY, Some(86_400));
        }
    }

    // 4. Per-IP aggregate storage cap. Uses the declared Content-Length
    //    as a forward reservation — commits the actual size via register()
    //    after the upload succeeds. If CL is absent, skip the pre-check
    //    and rely on the post-upload register to catch it (bounded by
    //    share_max_blob_bytes already).
    if let Some(len) = declared_len {
        if !state.share_storage_tracker.would_accept(client_ip, len) {
            return limit_rejection(
                StatusCode::INSUFFICIENT_STORAGE,
                REASON_IP_STORAGE_FULL,
                None,
            );
        }
    }

    let expires_in = expires_in_secs.min(MAX_EXPIRES_SECS);
    let expires_at = now_unix() + expires_in as i64;
    let token_nonce = generate_token_nonce();

    // Create the metadata row first — if Conflict we avoid touching the fs.
    match state
        .share_store
        .create_share(&share_id, ShareKind::File, expires_at, &token_nonce)
    {
        Ok(()) => {}
        Err(StoreError::Conflict) => return StatusCode::CONFLICT.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }

    let final_path = state.share_store.blob_path(&share_id, "main");
    let tmp_path = final_path.with_extension("v7.tmp");

    // Stream body → tmp file. Enforces the V7 marker on the first byte and
    // the V7_MIN_SIZE floor on total length; both reject payloads early
    // before they ever reach the sealed state. The per-IP byte budget is
    // consumed chunk-by-chunk — if it overflows mid-stream the transfer is
    // aborted and the tmp file cleaned up. `max_blob_bytes` enforces the
    // single-share size ceiling against clients that omit / lie about
    // Content-Length (we already Content-Length-checked above when present).
    let budget = &state.share_byte_budget;
    let now_s = now_unix();
    let max_blob = state.config.share_max_blob_bytes;
    let stream_result = stream_body_to_file_capped(body, &tmp_path, max_blob, |n| {
        budget.try_consume(client_ip, n as u64, now_s)
    })
    .await;
    let total = match stream_result {
        Ok(n) => n,
        Err(StreamError::BudgetExceeded) => {
            rollback(&state.share_store, &share_id, &tmp_path).await;
            return limit_rejection(
                StatusCode::INSUFFICIENT_STORAGE,
                REASON_DAILY_BYTES,
                Some(86_400),
            );
        }
        Err(StreamError::TooLarge) => {
            rollback(&state.share_store, &share_id, &tmp_path).await;
            return limit_rejection(StatusCode::PAYLOAD_TOO_LARGE, REASON_TOO_LARGE, None);
        }
        Err(StreamError::Transport) | Err(StreamError::InvalidV7) => {
            rollback(&state.share_store, &share_id, &tmp_path).await;
            return StatusCode::BAD_REQUEST.into_response();
        }
        Err(StreamError::Io) => {
            rollback(&state.share_store, &share_id, &tmp_path).await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if total < V7_MIN_SIZE as u64 {
        rollback(&state.share_store, &share_id, &tmp_path).await;
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Atomic publish: rename tmp → final. If the rename fails, the tmp stays
    // on disk for the sweeper and we return 500 so the caller retries.
    if tokio::fs::rename(&tmp_path, &final_path).await.is_err() {
        rollback(&state.share_store, &share_id, &tmp_path).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if state
        .share_store
        .record_blob(&share_id, "main", total as i64)
        .is_err()
        || state.share_store.mark_sealed(&share_id).is_err()
    {
        let _ = state.share_store.revoke_share(&share_id);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Only register against the per-IP storage cap after the upload is
    // durably sealed. A failure above results in rollback + revoke; the
    // tracker never saw this share so nothing needs to be released.
    state
        .share_storage_tracker
        .register(client_ip, &share_id, total);

    let owner_token = compute_owner_token(&state.config.share_signing_key, &share_id, &token_nonce);
    Json(ShareCreateResponse {
        share_id,
        expires_at,
        owner_token,
    })
    .into_response()
}

/// Stream errors the upload path needs to map to HTTP codes.
#[derive(Debug)]
enum StreamError {
    /// Body stream errored or aborted mid-transfer.
    Transport,
    /// First byte is not the V7 marker.
    InvalidV7,
    /// Disk write failed.
    Io,
    /// Per-IP daily byte budget exceeded mid-stream → 507.
    BudgetExceeded,
    /// Payload exceeded the configured `SHARE_MAX_BLOB_BYTES` → 413.
    /// Backstop against clients that omit or misreport Content-Length.
    TooLarge,
}

/// Parse the Content-Length header. Absent / malformed → None; treated as
/// "unknown, enforce via stream-level cap instead."
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// Stream `body` into `path` chunk-by-chunk, enforcing both the V7 marker
/// on the first byte and a hard size ceiling. `max_bytes = 0` disables the
/// cap (for callers that only need the per-IP byte budget).
async fn stream_body_to_file_capped<F>(
    body: Body,
    path: &std::path::Path,
    max_bytes: u64,
    mut budget_check: F,
) -> Result<u64, StreamError>
where
    F: FnMut(usize) -> bool,
{
    let file = match tokio::fs::File::create(path).await {
        Ok(f) => f,
        Err(_) => return Err(StreamError::Io),
    };
    let mut writer = tokio::io::BufWriter::with_capacity(256 * 1024, file);
    let mut stream = body.into_data_stream();
    let mut total: u64 = 0;
    let mut marker_checked = false;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StreamError::Transport)?;
        if chunk.is_empty() {
            continue;
        }
        if !marker_checked {
            if chunk.first() != Some(&V7_MARKER) {
                return Err(StreamError::InvalidV7);
            }
            marker_checked = true;
        }
        if max_bytes > 0 && total.saturating_add(chunk.len() as u64) > max_bytes {
            return Err(StreamError::TooLarge);
        }
        if !budget_check(chunk.len()) {
            return Err(StreamError::BudgetExceeded);
        }
        writer
            .write_all(&chunk)
            .await
            .map_err(|_| StreamError::Io)?;
        total += chunk.len() as u64;
    }
    writer.flush().await.map_err(|_| StreamError::Io)?;
    writer.shutdown().await.map_err(|_| StreamError::Io)?;
    Ok(total)
}

/// Roll back a failed upload: delete the tmp file and remove the share row
/// so the share_id is free to retry.
async fn rollback(store: &ShareStore, share_id: &str, tmp_path: &std::path::Path) {
    let _ = tokio::fs::remove_file(tmp_path).await;
    let _ = store.revoke_share(share_id);
}

/// GET /relay/share/b2/:share_id — stream V7 ciphertext to recipient.
/// Unauthenticated; rate-limited per share_id + per IP.
///
/// Response body streams the file from disk via `ReaderStream`, so a 50 GB
/// share does not allocate 50 GB of RAM in the relay. Content-Length is set
/// from the stored size for progress bars on the recipient side.
pub async fn get_b2_share(
    Path(share_id): Path<String>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !state
        .share_get_limiter
        .check_and_record(&share_id, client_ip)
    {
        return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_FETCH_RATE, Some(60));
    }

    // SH1: opaque 404 for not-found, revoked, expired, or unsealed so callers
    // can't distinguish states.
    let meta = match state.share_store.get_meta(&share_id) {
        Ok(Some(m)) => m,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if meta.revoked || meta.expires_at <= now_unix() || !meta.sealed {
        return StatusCode::NOT_FOUND.into_response();
    }
    if meta.kind != ShareKind::File {
        // Bundle shares use a different endpoint (Phase 1c). Avoid returning
        // a bundle's manifest here where a client expects a single blob.
        return StatusCode::NOT_FOUND.into_response();
    }

    let path = state.share_store.blob_path(&share_id, "main");
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let size = match file.metadata().await {
        Ok(m) => m.len(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Same download-side gates as get_share_blob — per-share bytes/hour
    // budget, concurrency cap, slow-start throttle. Kept in sync between
    // the two endpoints so clients can't pick the looser one.
    if !state.share_download_bytes.try_consume(&share_id, size) {
        return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_BYTES_HOUR, Some(3600));
    }
    let _concurrency_guard = match state.share_concurrency.try_acquire(&share_id) {
        Some(g) => g,
        None => {
            return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_CONCURRENT, Some(5));
        }
    };
    let slow_start_bps = crate::rate_limit::share_slow_start_bps(
        meta.created_at,
        now_unix(),
        state.config.share_slow_start_secs,
        state.config.share_slow_start_max_bps,
    );

    let reader = tokio::io::BufReader::with_capacity(DOWNLOAD_CHUNK_BYTES, file);
    let stream = ReaderStream::with_capacity(reader, DOWNLOAD_CHUNK_BYTES);
    let body = if let Some(bps) = slow_start_bps {
        Body::from_stream(throttle_stream(stream, bps, _concurrency_guard))
    } else {
        Body::from_stream(carry_guard(stream, _concurrency_guard))
    };

    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (axum::http::header::CONTENT_LENGTH, size.to_string()),
        ],
        body,
    )
        .into_response()
}

/// DELETE /relay/share/b2/:share_id — revoke share.
/// Token-gated via `X-Owner-Token`; no relay cookie needed.
pub async fn revoke_b2_share(
    Path(share_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match headers.get("X-Owner-Token").and_then(|v| v.to_str().ok()) {
        Some(t) => t.to_string(),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let meta = match state.share_store.get_meta(&share_id) {
        Ok(Some(m)) => m,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };

    if !verify_owner_token(
        &state.config.share_signing_key,
        &share_id,
        &meta.token_nonce,
        &token,
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }

    match state.share_store.revoke_share(&share_id) {
        Ok(()) => {
            // Free the per-IP storage-cap slot immediately. The sweeper
            // would catch it on the next tick anyway, but early release
            // lets the owner re-use their quota without waiting.
            state.share_storage_tracker.release(&share_id);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(StoreError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ── Bundle endpoints ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateBundleRequest {
    /// "folder" or "collection". "file" is rejected here — single-file
    /// shares use POST /relay/share/b2 which seals atomically.
    pub kind: String,
    pub expires_in_secs: u32,
}

#[derive(Debug, Serialize)]
pub struct CreateBundleResponse {
    pub share_id: String,
    pub expires_at: i64,
    pub owner_token: String,
    /// Hex-encoded 32-byte random token returned only at init. Client presents
    /// it in `X-Bundle-Token` on every subsequent blob / seal POST. The
    /// server-side copy is wiped on seal so the upload window closes once the
    /// client declares the bundle complete.
    pub bundle_token: String,
}

/// Validate a client-provided blob_id for bundle content uploads. Must be a
/// 36-char UUID-shaped string; reserved names ("main", "_manifest") are
/// rejected so clients can't overwrite the single-file path or forge a
/// manifest outside the seal call.
fn is_valid_client_blob_id(id: &str) -> bool {
    id.len() == 36
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && id != "main"
        && id != "_manifest"
}

/// Validate a blob_id for public GET. Accepts UUIDs, plus the two reserved
/// names so recipients can pull `main` (single-file share) or `_manifest`
/// (bundle index).
fn is_valid_public_blob_id(id: &str) -> bool {
    if id == "main" || id == "_manifest" {
        return true;
    }
    id.len() == 36 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// POST /relay/share/bundle/init — create an empty bundle share.
/// PoW-gated via a `share:bundle:init` cookie.
pub async fn init_bundle(
    cookies: tower_cookies::Cookies,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CreateBundleRequest>,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    let claims = match verify_relay_cookie(
        &cookies,
        RELAY_COOKIE_NAME_SHARE,
        &state.config.relay_signing_key,
    ) {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if claims.purpose != "share:bundle:init" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !state.jti_consumed.try_consume(&claims.jti, claims.exp) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let kind = match body.kind.as_str() {
        "folder" => ShareKind::Folder,
        "collection" => ShareKind::Collection,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Abuse gates — same order as upload_b2_share. Disk watermark is a
    // global stop; the creation-rate check is per-IP.
    if let Some(pct) = crate::rate_limit::disk_usage_percent(state.share_store.blobs_dir()) {
        if pct >= state.config.disk_watermark_percent {
            return limit_rejection(
                StatusCode::INSUFFICIENT_STORAGE,
                REASON_DISK_WATERMARK,
                Some(300),
            );
        }
    }
    match state.share_create_limiter.check_and_record(client_ip) {
        crate::rate_limit::ShareCreationDecision::Allow => {}
        crate::rate_limit::ShareCreationDecision::HourCapExceeded => {
            return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_RATE_HOUR, Some(3600));
        }
        crate::rate_limit::ShareCreationDecision::DayCapExceeded => {
            return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_RATE_DAY, Some(86_400));
        }
    }

    let expires_in = body.expires_in_secs.min(MAX_EXPIRES_SECS);
    let expires_at = now_unix() + expires_in as i64;
    let share_id = Uuid::new_v4().to_string();
    let token_nonce = generate_token_nonce();

    // Create share row.
    match state
        .share_store
        .create_share(&share_id, kind, expires_at, &token_nonce)
    {
        Ok(()) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }

    // Mint + persist a 32-byte bundle token.
    let mut bundle_token_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bundle_token_bytes);
    if state
        .share_store
        .set_bundle_token(&share_id, &bundle_token_bytes)
        .is_err()
    {
        let _ = state.share_store.revoke_share(&share_id);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let owner_token = compute_owner_token(&state.config.share_signing_key, &share_id, &token_nonce);

    Json(CreateBundleResponse {
        share_id,
        expires_at,
        owner_token,
        bundle_token: hex::encode(bundle_token_bytes),
    })
    .into_response()
}

/// POST /relay/share/bundle/:share_id/blob/:blob_id — stream one content blob.
/// Gated by `X-Bundle-Token` header that matches the value minted at init.
pub async fn upload_bundle_blob(
    Path((share_id, blob_id)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !is_valid_share_id(&share_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if !is_valid_client_blob_id(&blob_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let presented_hex = match headers.get("X-Bundle-Token").and_then(|v| v.to_str().ok()) {
        Some(t) => t,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let presented = match hex::decode(presented_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match state
        .share_store
        .verify_bundle_token(&share_id, &presented, now_unix())
    {
        Ok(true) => {}
        Ok(false) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }

    // Reject attempts to upload into a file-kind share through the bundle
    // path. Bundle shares have kind=folder or collection.
    let meta = match state.share_store.get_meta(&share_id) {
        Ok(Some(m)) => m,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if matches!(meta.kind, ShareKind::File) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Content-Length + per-IP aggregate storage pre-check, same shape as
    // the single-file path. Bundle blobs accumulate into the share's
    // storage footprint — register each on success below.
    let declared_len = content_length(&headers);
    if let Some(len) = declared_len {
        if len > state.config.share_max_blob_bytes {
            return limit_rejection(StatusCode::PAYLOAD_TOO_LARGE, REASON_TOO_LARGE, None);
        }
        if !state.share_storage_tracker.would_accept(client_ip, len) {
            return limit_rejection(
                StatusCode::INSUFFICIENT_STORAGE,
                REASON_IP_STORAGE_FULL,
                None,
            );
        }
    }

    let final_path = state.share_store.blob_path(&share_id, &blob_id);
    let tmp_path = final_path.with_extension("v7.tmp");

    // Per-blob max size matches the single-file share cap: the wire format
    // is the same V7 ciphertext, and an attacker shouldn't be able to pack
    // a 10 GB payload inside a bundle just because per-blob is unchecked.
    let budget = &state.share_byte_budget;
    let now_s = now_unix();
    let max_blob = state.config.share_max_blob_bytes;
    let stream_result = stream_body_to_file_capped(body, &tmp_path, max_blob, |n| {
        budget.try_consume(client_ip, n as u64, now_s)
    })
    .await;
    let total = match stream_result {
        Ok(n) => n,
        Err(StreamError::BudgetExceeded) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return limit_rejection(
                StatusCode::INSUFFICIENT_STORAGE,
                REASON_DAILY_BYTES,
                Some(86_400),
            );
        }
        Err(StreamError::TooLarge) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            let _ = state.share_store.delete_blob(&share_id, &blob_id);
            return limit_rejection(StatusCode::PAYLOAD_TOO_LARGE, REASON_TOO_LARGE, None);
        }
        Err(_) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            let _ = state.share_store.delete_blob(&share_id, &blob_id);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    if total < V7_MIN_SIZE as u64 {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return StatusCode::BAD_REQUEST.into_response();
    }

    if tokio::fs::rename(&tmp_path, &final_path).await.is_err() {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if state
        .share_store
        .record_blob(&share_id, &blob_id, total as i64)
        .is_err()
    {
        let _ = state.share_store.delete_blob(&share_id, &blob_id);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state
        .share_storage_tracker
        .register(client_ip, &share_id, total);

    StatusCode::NO_CONTENT.into_response()
}

/// POST /relay/share/bundle/:share_id/seal — stream manifest + flip sealed=1.
/// The manifest is just another V7 ciphertext, stored as blob id `_manifest`.
/// The bundle_token is wiped on success so further uploads are rejected.
pub async fn seal_bundle(
    Path(share_id): Path<String>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !is_valid_share_id(&share_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let presented_hex = match headers.get("X-Bundle-Token").and_then(|v| v.to_str().ok()) {
        Some(t) => t,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let presented = match hex::decode(presented_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match state
        .share_store
        .verify_bundle_token(&share_id, &presented, now_unix())
    {
        Ok(true) => {}
        Ok(false) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }

    // Only bundle kinds can be sealed through this path.
    let meta = match state.share_store.get_meta(&share_id) {
        Ok(Some(m)) => m,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if matches!(meta.kind, ShareKind::File) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let final_path = state.share_store.blob_path(&share_id, "_manifest");
    let tmp_path = final_path.with_extension("v7.tmp");

    let budget = &state.share_byte_budget;
    let now_s = now_unix();
    let max_blob = state.config.share_max_blob_bytes;
    let stream_result = stream_body_to_file_capped(body, &tmp_path, max_blob, |n| {
        budget.try_consume(client_ip, n as u64, now_s)
    })
    .await;
    let total = match stream_result {
        Ok(n) => n,
        Err(StreamError::BudgetExceeded) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return limit_rejection(
                StatusCode::INSUFFICIENT_STORAGE,
                REASON_DAILY_BYTES,
                Some(86_400),
            );
        }
        Err(StreamError::TooLarge) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return limit_rejection(StatusCode::PAYLOAD_TOO_LARGE, REASON_TOO_LARGE, None);
        }
        Err(_) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    if total < V7_MIN_SIZE as u64 {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return StatusCode::BAD_REQUEST.into_response();
    }

    if tokio::fs::rename(&tmp_path, &final_path).await.is_err() {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if state
        .share_store
        .record_blob(&share_id, "_manifest", total as i64)
        .is_err()
        || state.share_store.mark_sealed(&share_id).is_err()
    {
        let _ = state.share_store.delete_blob(&share_id, "_manifest");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state
        .share_storage_tracker
        .register(client_ip, &share_id, total);

    StatusCode::NO_CONTENT.into_response()
}

// ── Unified recipient read surface ────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ShareMetaResponse {
    kind: &'static str,
    expires_at: i64,
    total_bytes: i64,
    blob_count: usize,
    blobs: Vec<ShareMetaBlob>,
}

#[derive(Debug, Serialize)]
struct ShareMetaBlob {
    blob_id: String,
    bytes: i64,
}

/// GET /relay/share/:share_id/meta — metadata only (no ciphertext).
/// Unauthenticated + rate-limited. The recipient page hits this first to
/// decide whether to fetch `main` (single-file) or `_manifest` + per-file
/// blobs (bundle).
pub async fn get_share_meta(
    Path(share_id): Path<String>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !state
        .share_get_limiter
        .check_and_record(&share_id, client_ip)
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let meta = match state.share_store.get_meta(&share_id) {
        Ok(Some(m)) => m,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if meta.revoked || meta.expires_at <= now_unix() || !meta.sealed {
        return StatusCode::NOT_FOUND.into_response();
    }

    let blobs = match state.share_store.list_blobs(&share_id) {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let kind_str = match meta.kind {
        ShareKind::File => "file",
        ShareKind::Folder => "folder",
        ShareKind::Collection => "collection",
    };
    let blob_list: Vec<ShareMetaBlob> = blobs
        .into_iter()
        .map(|(blob_id, bytes)| ShareMetaBlob { blob_id, bytes })
        .collect();

    Json(ShareMetaResponse {
        kind: kind_str,
        expires_at: meta.expires_at,
        total_bytes: meta.total_bytes,
        blob_count: blob_list.len(),
        blobs: blob_list,
    })
    .into_response()
}

/// GET /relay/share/:share_id/blob/:blob_id — stream a named blob.
/// Unauthenticated + rate-limited. Accepts any valid blob_id including
/// reserved `main` (single-file) and `_manifest` (bundle index).
pub async fn get_share_blob(
    Path((share_id, blob_id)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_valid_share_id(&share_id) || !is_valid_public_blob_id(&blob_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !state
        .share_get_limiter
        .check_and_record(&share_id, client_ip)
    {
        return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_FETCH_RATE, Some(60));
    }

    let meta = match state.share_store.get_meta(&share_id) {
        Ok(Some(m)) => m,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if meta.revoked || meta.expires_at <= now_unix() || !meta.sealed {
        return StatusCode::NOT_FOUND.into_response();
    }

    let path = state.share_store.blob_path(&share_id, &blob_id);
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let size = match file.metadata().await {
        Ok(m) => m.len(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // ── Download-side abuse gates ──────────────────────────────────────────
    // Pre-reserve bytes against the per-share-id bytes-per-hour budget. If
    // this share's quota is exhausted, reject outright — no partial reads
    // mid-window. Concurrency guard comes next; its RAII drop releases the
    // slot when the response body finishes or the connection dies.
    if !state.share_download_bytes.try_consume(&share_id, size) {
        return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_BYTES_HOUR, Some(3600));
    }
    let _concurrency_guard = match state.share_concurrency.try_acquire(&share_id) {
        Some(g) => g,
        None => {
            return limit_rejection(StatusCode::TOO_MANY_REQUESTS, REASON_CONCURRENT, Some(5));
        }
    };

    // Slow-start: throttle the first N seconds post-creation to SLOW_MAX_BPS.
    // Holds the RAII guard until the response body finishes streaming; no
    // explicit release needed. The guard is carried into the stream closure.
    let slow_start_bps = crate::rate_limit::share_slow_start_bps(
        meta.created_at,
        now_unix(),
        state.config.share_slow_start_secs,
        state.config.share_slow_start_max_bps,
    );

    let reader = tokio::io::BufReader::with_capacity(DOWNLOAD_CHUNK_BYTES, file);
    let stream = ReaderStream::with_capacity(reader, DOWNLOAD_CHUNK_BYTES);
    let body = if let Some(bps) = slow_start_bps {
        Body::from_stream(throttle_stream(stream, bps, _concurrency_guard))
    } else {
        Body::from_stream(carry_guard(stream, _concurrency_guard))
    };

    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (axum::http::header::CONTENT_LENGTH, size.to_string()),
        ],
        body,
    )
        .into_response()
}

/// Simple token-bucket throttle: emits at most `bps` bytes per second from
/// the upstream `ReaderStream`. Refills once per second. The concurrency
/// guard is carried so it's released when the response body completes or
/// the client disconnects.
fn throttle_stream<S>(
    inner: S,
    bps: u64,
    _guard: crate::rate_limit::ShareConcurrencyGuard,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Unpin,
{
    async_stream::try_stream! {
        let mut s = inner;
        let mut tokens: u64 = bps;
        let mut last_refill = std::time::Instant::now();
        let _guard = _guard; // keep alive
        while let Some(chunk) = futures_util::StreamExt::next(&mut s).await {
            let chunk = chunk?;
            let mut remaining = chunk.as_ref();
            while !remaining.is_empty() {
                let now = std::time::Instant::now();
                if now.duration_since(last_refill) >= std::time::Duration::from_secs(1) {
                    tokens = bps;
                    last_refill = now;
                }
                if tokens == 0 {
                    // Sleep the remainder of the refill interval.
                    let wait = std::time::Duration::from_secs(1)
                        .saturating_sub(now.duration_since(last_refill));
                    tokio::time::sleep(wait).await;
                    tokens = bps;
                    last_refill = std::time::Instant::now();
                    continue;
                }
                let take = (tokens as usize).min(remaining.len());
                let (head, tail) = remaining.split_at(take);
                yield axum::body::Bytes::copy_from_slice(head);
                tokens = tokens.saturating_sub(take as u64);
                remaining = tail;
            }
        }
    }
}

/// Wrap a stream with a concurrency guard that's dropped only when the
/// stream is fully consumed / dropped. Needed for the non-throttled
/// branch so the Drop-on-close semantics are uniform.
fn carry_guard<S>(
    inner: S,
    _guard: crate::rate_limit::ShareConcurrencyGuard,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Unpin,
{
    async_stream::try_stream! {
        let mut s = inner;
        let _guard = _guard;
        while let Some(chunk) = futures_util::StreamExt::next(&mut s).await {
            yield chunk?;
        }
    }
}

// ── Headroom (disk + per-IP byte budget) ─────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HeadroomResponse {
    /// Bytes available on the share-storage filesystem. Informs UI copy
    /// like "X GB free on Wattcloud relay".
    pub free_bytes: u64,
    /// Total filesystem bytes (free + used). Lets the UI show a ratio.
    pub total_bytes: u64,
    /// Live share ciphertext the relay is currently holding.
    pub used_by_shares_bytes: u64,
    /// Bytes the caller's IP can still upload today before the daily
    /// budget kicks in.
    pub your_remaining_bytes_today: u64,
    /// Configured daily cap per IP, so the UI can show utilisation.
    pub daily_bytes_per_ip: u64,
}

/// Rate limiter for `/relay/share/headroom`. Using the same share_id-anchored
/// limiter would mix with actual share IDs; use a dedicated per-IP bucket via
/// a fixed pseudo-id.
const HEADROOM_RATE_KEY: &str = "__headroom__";

/// GET /relay/share/headroom — unauthenticated; returns disk headroom and
/// the caller's remaining per-IP byte budget.
///
/// The data is not sensitive (no PII, no share ids) but the endpoint is
/// rate-limited so an attacker can't use it as a free ping amplifier.
pub async fn get_share_headroom(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !state
        .share_get_limiter
        .check_and_record(HEADROOM_RATE_KEY, client_ip)
    {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let (free_bytes, total_bytes) =
        filesystem_headroom(&state.config.share_storage_dir).unwrap_or((0, 0));

    let used_by_shares_bytes = state
        .share_store
        .total_live_bytes(now_unix())
        .unwrap_or(0)
        .max(0) as u64;

    let your_remaining_bytes_today = state.share_byte_budget.remaining(client_ip, now_unix());

    let daily_bytes_per_ip = state.share_byte_budget.limit_per_day();

    Json(HeadroomResponse {
        free_bytes,
        total_bytes,
        used_by_shares_bytes,
        your_remaining_bytes_today,
        daily_bytes_per_ip,
    })
    .into_response()
}

/// Query the filesystem for its free + total byte counts via `statvfs`.
/// Returns `None` on any failure — the handler then reports zeros, which
/// the UI shows as "unknown" without crashing.
fn filesystem_headroom(path: &std::path::Path) -> Option<(u64, u64)> {
    let path_c = std::ffi::CString::new(path.to_string_lossy().as_ref().as_bytes()).ok()?;
    // SAFETY: path_c is valid for the duration of the call; we zero-init
    // the statvfs struct so reading it is well-defined. All subsequent
    // reads are of plain integer fields — no dangling pointers.
    let stat = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(path_c.as_ptr(), &mut stat) != 0 {
            return None;
        }
        stat
    };
    let block_size = stat.f_frsize as u64;
    let free = (stat.f_bavail as u64).saturating_mul(block_size);
    let total = (stat.f_blocks as u64).saturating_mul(block_size);
    Some((free, total))
}

// ── Sweeper ──────────────────────────────────────────────────────────────────

pub struct ShareSweeper;

impl ShareSweeper {
    /// Purges expired + revoked shares every hour. Blob directories are
    /// removed alongside the SQLite rows.
    pub fn start(state: Arc<AppState>) {
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let store: &ShareStore = &state.share_store;
                match store.purge_expired_and_revoked(now_unix()) {
                    Ok((ids, freed)) if !ids.is_empty() => {
                        // Free the storage tracker slot for each purged
                        // share so the per-IP aggregate cap frees up
                        // alongside disk. This is the only path that
                        // decrements the tracker; everything else is
                        // creation-side addition.
                        for id in &ids {
                            state.share_storage_tracker.release(id);
                        }
                        tracing::debug!(
                            removed = ids.len(),
                            freed_bytes = freed,
                            "share sweeper: pruned expired/revoked shares"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("share sweeper error: {e}");
                    }
                }
            }
        });
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn valid_share_id_accepted() {
        assert!(is_valid_share_id("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn share_id_wrong_length_rejected() {
        assert!(!is_valid_share_id("short"));
        assert!(!is_valid_share_id("550e8400-e29b-41d4-a716-4466554400001"));
    }

    #[test]
    fn share_id_invalid_chars_rejected() {
        assert!(!is_valid_share_id("550e8400-e29b-41d4-a716-44665544000!"));
    }

    #[test]
    fn expires_cap_enforced() {
        let over_limit: u32 = MAX_EXPIRES_SECS + 1000;
        assert_eq!(over_limit.min(MAX_EXPIRES_SECS), MAX_EXPIRES_SECS);
    }

    #[test]
    fn v7_marker_value() {
        assert_eq!(V7_MARKER, 0x07);
    }

    #[test]
    fn v7_min_size_value() {
        assert_eq!(V7_MIN_SIZE, 1741);
    }

    // ── Owner token tests ─────────────────────────────────────────────────────

    const TEST_KEY: &[u8] = b"test-signing-key-32bytes-padding!";
    const TEST_SHARE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const FIXED_NONCE: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    #[test]
    fn owner_token_deterministic_with_same_nonce() {
        let t1 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        let t2 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64);
    }

    #[test]
    fn owner_token_differs_across_nonces() {
        let nonce2: [u8; 16] = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let t1 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        let t2 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &nonce2);
        assert_ne!(t1, t2);
    }

    #[test]
    fn owner_token_differs_across_shares() {
        let id2 = "550e8400-e29b-41d4-a716-446655440001";
        let t1 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        let t2 = compute_owner_token(TEST_KEY, id2, &FIXED_NONCE);
        assert_ne!(t1, t2);
    }

    #[test]
    fn owner_token_differs_across_keys() {
        let key2 = b"signing-key-two-32bytes-padding!!";
        let t1 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        let t2 = compute_owner_token(key2, TEST_SHARE_ID, &FIXED_NONCE);
        assert_ne!(t1, t2);
    }

    #[test]
    fn verify_correct_token_accepted() {
        let token = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        assert!(verify_owner_token(
            TEST_KEY,
            TEST_SHARE_ID,
            &FIXED_NONCE,
            &token
        ));
    }

    #[test]
    fn verify_rejects_wrong_tokens() {
        assert!(!verify_owner_token(
            TEST_KEY,
            TEST_SHARE_ID,
            &FIXED_NONCE,
            "deadbeef"
        ));
        assert!(!verify_owner_token(
            TEST_KEY,
            TEST_SHARE_ID,
            &FIXED_NONCE,
            ""
        ));
    }

    #[test]
    fn verify_rejects_wrong_share_id() {
        let id2 = "550e8400-e29b-41d4-a716-446655440001";
        let token = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        assert!(!verify_owner_token(TEST_KEY, id2, &FIXED_NONCE, &token));
    }

    #[test]
    fn verify_rejects_invalid_hex() {
        assert!(!verify_owner_token(
            TEST_KEY,
            TEST_SHARE_ID,
            &FIXED_NONCE,
            "not-hex!!!"
        ));
    }

    #[test]
    fn token_from_old_nonce_rejected_on_new_record() {
        let nonce1: [u8; 16] = [0xAA; 16];
        let nonce2: [u8; 16] = [0xBB; 16];
        let old_token = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &nonce1);
        assert!(!verify_owner_token(
            TEST_KEY,
            TEST_SHARE_ID,
            &nonce2,
            &old_token
        ));
    }

    #[test]
    fn generate_token_nonce_unique() {
        let n1 = generate_token_nonce();
        let n2 = generate_token_nonce();
        assert_ne!(n1, n2);
    }

    // ── Streaming helper tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn stream_body_to_file_writes_v7_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.v7.tmp");
        let mut payload = vec![V7_MARKER];
        payload.extend(std::iter::repeat_n(0u8, 4095));
        let body = axum::body::Body::from(payload.clone());
        let n = stream_body_to_file_capped(body, &path, 0, |_| true)
            .await
            .expect("stream ok");
        assert_eq!(n as usize, payload.len());
        let read = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read, payload);
    }

    #[tokio::test]
    async fn stream_body_to_file_rejects_wrong_first_byte() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.v7.tmp");
        // First byte 0x06 (prior V6 marker) — must be rejected before any
        // meaningful write hits the sealed path.
        let body = axum::body::Body::from(vec![0x06u8; 4096]);
        let err = stream_body_to_file_capped(body, &path, 0, |_| true)
            .await
            .unwrap_err();
        assert!(matches!(err, StreamError::InvalidV7));
    }

    #[tokio::test]
    async fn stream_body_to_file_handles_empty_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.v7.tmp");
        let body = axum::body::Body::from(Vec::<u8>::new());
        let n = stream_body_to_file_capped(body, &path, 0, |_| true)
            .await
            .expect("stream ok");
        // Empty body never receives a marker byte; upload_b2_share then
        // trips the V7_MIN_SIZE check afterward.
        assert_eq!(n, 0);
    }

    // ── Blob id validators ────────────────────────────────────────────────────

    #[test]
    fn client_blob_id_accepts_uuid() {
        assert!(is_valid_client_blob_id(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
    }

    #[test]
    fn client_blob_id_rejects_reserved_names() {
        assert!(!is_valid_client_blob_id("main"));
        assert!(!is_valid_client_blob_id("_manifest"));
    }

    #[test]
    fn client_blob_id_rejects_traversal() {
        assert!(!is_valid_client_blob_id("../../../etc/passwd"));
        assert!(!is_valid_client_blob_id(
            "550e8400-e29b-41d4-a716-446655440./."
        ));
    }

    #[test]
    fn public_blob_id_accepts_reserved() {
        assert!(is_valid_public_blob_id("main"));
        assert!(is_valid_public_blob_id("_manifest"));
    }

    #[test]
    fn public_blob_id_accepts_uuid() {
        assert!(is_valid_public_blob_id(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
    }

    #[test]
    fn public_blob_id_rejects_bad_input() {
        assert!(!is_valid_public_blob_id(".."));
        assert!(!is_valid_public_blob_id("foo bar"));
        assert!(!is_valid_public_blob_id(""));
    }

    // ── Budget integration ───────────────────────────────────────────────────

    #[tokio::test]
    async fn stream_aborts_when_budget_rejects_a_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.v7.tmp");
        // 2 KB V7-shaped body, but budget rejects the very first chunk.
        let mut payload = vec![V7_MARKER];
        payload.extend(std::iter::repeat_n(0u8, 2047));
        let body = axum::body::Body::from(payload);
        let err = stream_body_to_file_capped(body, &path, 0, |_| false)
            .await
            .unwrap_err();
        assert!(matches!(err, StreamError::BudgetExceeded));
    }

    #[test]
    fn filesystem_headroom_returns_values_for_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let (free, total) = filesystem_headroom(dir.path()).expect("statvfs ok");
        // Sanity: something is free, total ≥ free, and neither overflows.
        assert!(total > 0, "total_bytes must be positive");
        assert!(free <= total, "free {free} cannot exceed total {total}");
    }
}
