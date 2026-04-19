use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;

use crate::client_ip::extract_client_ip;
use crate::rate_limit::{IpBucket, SlidingWindowLimiterByKey};
use crate::relay_auth::{verify_relay_cookie, AppState};

type HmacSha256 = Hmac<Sha256>;

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_EXPIRES_SECS: u32 = 30 * 24 * 3600; // 30 days
const MAX_B2_SIZE: usize = 200 * 1024 * 1024; // 200 MiB
const V7_MARKER: u8 = 0x07;
/// Minimum valid V7 payload: 1709-byte header + 32-byte HMAC footer (no body chunks).
const V7_MIN_SIZE: usize = 1709 + 32;
const SHARE_GET_PER_SHARE_LIMIT: usize = 10; // per share_id per minute
const SHARE_GET_PER_IP_LIMIT: usize = 60; // per IP per minute

// ── Data structures ──────────────────────────────────────────────────────────

pub struct B1ShareRecord {
    pub share_id: String,
    pub provider_url: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub revoked: bool,
    /// Per-record nonce bound into the owner_token HMAC so that a token minted
    /// for one generation of a share_id cannot verify against a future generation
    /// of the same id (e.g., after sweeper purge + re-registration).
    pub token_nonce: [u8; 16],
}

pub struct B2ShareRecord {
    pub share_id: String,
    pub ciphertext: Vec<u8>,
    pub expires_at: i64,
    pub created_at: i64,
    pub revoked: bool,
    /// Per-record nonce — same purpose as in B1ShareRecord.
    pub token_nonce: [u8; 16],
}

// ── Rate limiters ─────────────────────────────────────────────────────────────

/// Dual-key rate limiter for share GET endpoints:
///   - 10 req/min per share_id
///   - 60 req/min per source IP (bucketed to /64 for IPv6)
pub struct ShareGetLimiter {
    per_share: SlidingWindowLimiterByKey<String>,
    per_ip: SlidingWindowLimiterByKey<IpBucket>,
}

/// RS5: cap the rate-limiter maps at a fixed number of distinct keys so an
/// attacker can't exhaust memory by cycling through synthetic share_ids or
/// IPv6 /64 prefixes. Once at capacity the inner limiter allows new keys
/// through without inserting them — legitimate clients aren't blocked, but
/// the map cannot grow past the cap. 50k is ample (an installation with
/// 50k distinct share_ids active in one 60s window is already far out of
/// spec for a stateless relay).
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

    /// Returns true if both per-share and per-IP limits pass.
    ///
    /// D4: short-circuit on the per-share check — the original `share_ok &&
    /// ip_ok` always recorded a hit on the IP bucket even when the share-ID
    /// bucket already refused the request. An attacker could cycle through
    /// fresh share IDs and drain a legitimate user's per-IP budget without
    /// any valid share ever existing.
    pub fn check_and_record(&self, share_id: &str, ip: std::net::IpAddr) -> bool {
        if !self.per_share.check_and_record(share_id.to_string()) {
            return false;
        }
        self.per_ip.check_and_record(IpBucket::from(ip))
    }
}

// ── Request/response types ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateB1Request {
    pub share_id: String,
    pub provider_url: String,
    pub expires_in_secs: u32,
}

#[derive(Debug, Serialize)]
pub struct ShareCreateResponse {
    pub share_id: String,
    pub expires_at: i64,
    /// HMAC-SHA256(signing_key, share_id || ":owner") — bearer token for revocation.
    /// Client stores this in vault SQLite share_tokens.owner_token.
    pub owner_token: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Validate share_id: exactly 36 chars, alphanumeric or hyphen (UUID-like).
fn is_valid_share_id(id: &str) -> bool {
    id.len() == 36 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Generate a fresh 16-byte nonce for a new share record.
fn generate_token_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Compute the HMAC-SHA256 ownership token for a share.
///
/// Token = hex(HMAC-SHA256(signing_key, share_id || nonce || ":owner"))
///
/// The `nonce` is stored in the share record and makes the token generation-
/// specific: after a sweeper purge + re-registration, a fresh nonce ensures
/// the old owner_token cannot be replayed against the new record.
fn compute_owner_token(signing_key: &[u8], share_id: &str, nonce: &[u8; 16]) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_key)
        .expect("HMAC accepts any key length");
    mac.update(share_id.as_bytes());
    mac.update(nonce.as_slice());
    mac.update(b":owner");
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time comparison of an owner token against the expected value.
///
/// `nonce` must come from the stored share record — not from the client request.
fn verify_owner_token(signing_key: &[u8], share_id: &str, nonce: &[u8; 16], presented: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(signing_key)
        .expect("HMAC accepts any key length");
    mac.update(share_id.as_bytes());
    mac.update(nonce.as_slice());
    mac.update(b":owner");
    // Decode the presented hex token; reject if not valid hex or wrong length.
    match hex::decode(presented) {
        Ok(bytes) => mac.verify_slice(&bytes).is_ok(),
        Err(_) => {
            // Constant-time dummy verify to avoid timing difference.
            let _ = mac.verify_slice(&[0u8; 32]);
            false
        }
    }
}

// ── B1 handlers ───────────────────────────────────────────────────────────────

/// POST /relay/share/b1 — create a B1 share record (requires relay auth)
pub async fn create_b1_share(
    cookies: tower_cookies::Cookies,
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateB1Request>,
) -> impl IntoResponse {
    // Verify relay auth cookie: purpose must be "share:b1", JTI is consumed (single-use).
    let claims = match verify_relay_cookie(&cookies, &state.config.relay_signing_key) {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if claims.purpose != "share:b1" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !state.jti_consumed.try_consume(&claims.jti, claims.exp) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Validate share_id format.
    if !is_valid_share_id(&body.share_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Cap expiry.
    let expires_in = body.expires_in_secs.min(MAX_EXPIRES_SECS);
    let now = now_unix();
    let expires_at = now + expires_in as i64;

    let token_nonce = generate_token_nonce();
    let record = B1ShareRecord {
        share_id: body.share_id.clone(),
        provider_url: body.provider_url,
        expires_at,
        created_at: now,
        revoked: false,
        token_nonce,
    };

    {
        let mut store = state.b1_shares.write().expect("b1 store lock poisoned");
        if store.contains_key(&body.share_id) {
            return StatusCode::CONFLICT.into_response();
        }
        store.insert(body.share_id.clone(), record);
    }

    let owner_token = compute_owner_token(&state.config.share_signing_key, &body.share_id, &token_nonce);
    Json(ShareCreateResponse { share_id: body.share_id, expires_at, owner_token }).into_response()
}

/// GET /relay/share/b1/:share_id — retrieve B1 record (unauthenticated)
pub async fn get_b1_share(
    Path(share_id): Path<String>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    // Rate limit: per share_id + per IP.
    if !state.share_get_limiter.check_and_record(&share_id, client_ip) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let store = state.b1_shares.read().expect("b1 store lock poisoned");
    match store.get(&share_id) {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(record) => {
            // SH1: return 404 for both revoked and expired so callers cannot
            // infer whether a share was explicitly revoked by the owner. The
            // internal `revoked` flag is still evaluated; only the wire
            // response is normalised.
            if record.revoked {
                return StatusCode::NOT_FOUND.into_response();
            }
            if record.expires_at <= now_unix() {
                return StatusCode::NOT_FOUND.into_response();
            }
            Json(serde_json::json!({
                "provider_url": record.provider_url,
                "expires_at": record.expires_at,
            }))
            .into_response()
        }
    }
}

/// DELETE /relay/share/b1/:share_id — revoke B1 record
///
/// Auth: X-Owner-Token header must present the HMAC ownership token returned
/// at creation time. No relay cookie required — the token is itself the proof.
pub async fn revoke_b1_share(
    Path(share_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match headers
        .get("X-Owner-Token")
        .and_then(|v| v.to_str().ok())
    {
        Some(t) => t.to_string(),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let mut store = state.b1_shares.write().expect("b1 store lock poisoned");
    match store.get_mut(&share_id) {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(record) => {
            if !verify_owner_token(&state.config.share_signing_key, &share_id, &record.token_nonce, &token) {
                return StatusCode::FORBIDDEN.into_response();
            }
            record.revoked = true;
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

// ── B2 handlers ───────────────────────────────────────────────────────────────

/// POST /relay/share/b2 — upload B2 ciphertext blob (requires relay auth)
///
/// Headers: X-Share-Id, X-Expires-In (seconds)
/// Body: raw V7 ciphertext (first byte must be 0x07), max 200 MiB
pub async fn upload_b2_share(
    cookies: tower_cookies::Cookies,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Verify relay auth cookie: purpose must be "share:b2", JTI is consumed (single-use).
    let claims = match verify_relay_cookie(&cookies, &state.config.relay_signing_key) {
        Ok(c) => c,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if claims.purpose != "share:b2" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !state.jti_consumed.try_consume(&claims.jti, claims.exp) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Extract required headers.
    let share_id = match headers
        .get("X-Share-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
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

    // Validate share_id format.
    if !is_valid_share_id(&share_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Validate size.
    if body.len() > MAX_B2_SIZE {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }

    // Validate V7 structure: first byte must be 0x07, minimum size must hold a header + footer.
    if body.first() != Some(&V7_MARKER) || body.len() < V7_MIN_SIZE {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Cap expiry at 30 days.
    let expires_in = expires_in_secs.min(MAX_EXPIRES_SECS);
    let now = now_unix();
    let expires_at = now + expires_in as i64;

    let token_nonce = generate_token_nonce();
    let record = B2ShareRecord {
        share_id: share_id.clone(),
        ciphertext: body.to_vec(),
        expires_at,
        created_at: now,
        revoked: false,
        token_nonce,
    };

    {
        let mut store = state.b2_shares.write().expect("b2 store lock poisoned");
        if store.contains_key(&share_id) {
            return StatusCode::CONFLICT.into_response();
        }
        store.insert(share_id.clone(), record);
    }

    let owner_token = compute_owner_token(&state.config.share_signing_key, &share_id, &token_nonce);
    Json(ShareCreateResponse { share_id, expires_at, owner_token }).into_response()
}

/// GET /relay/share/b2/:share_id — stream B2 ciphertext to recipient (unauthenticated)
pub async fn get_b2_share(
    Path(share_id): Path<String>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    // Rate limit: per share_id + per IP.
    if !state.share_get_limiter.check_and_record(&share_id, client_ip) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let store = state.b2_shares.read().expect("b2 store lock poisoned");
    match store.get(&share_id) {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(record) => {
            // SH1: 404 for both revoked and expired (see B1 GET).
            if record.revoked {
                return StatusCode::NOT_FOUND.into_response();
            }
            if record.expires_at <= now_unix() {
                return StatusCode::NOT_FOUND.into_response();
            }
            let ciphertext = record.ciphertext.clone();
            drop(store);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                ciphertext,
            )
                .into_response()
        }
    }
}

/// DELETE /relay/share/b2/:share_id — revoke B2 record
///
/// Auth: X-Owner-Token header must present the HMAC ownership token returned
/// at upload time. No relay cookie required — the token is itself the proof.
pub async fn revoke_b2_share(
    Path(share_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = match headers
        .get("X-Owner-Token")
        .and_then(|v| v.to_str().ok())
    {
        Some(t) => t.to_string(),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let mut store = state.b2_shares.write().expect("b2 store lock poisoned");
    match store.get_mut(&share_id) {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(record) => {
            if !verify_owner_token(&state.config.share_signing_key, &share_id, &record.token_nonce, &token) {
                return StatusCode::FORBIDDEN.into_response();
            }
            // D10: drop the ciphertext immediately on revoke so a revoked
            // B2 share (up to 200 MiB) doesn't linger in memory until the
            // hourly sweeper. The `revoked` flag still triggers opaque-404
            // responses to GET, so the observable behaviour is unchanged.
            record.revoked = true;
            record.ciphertext = Vec::new();
            record.ciphertext.shrink_to_fit();
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

// ── Sweeper ───────────────────────────────────────────────────────────────────

pub struct ShareSweeper;

impl ShareSweeper {
    /// Start a background task that purges expired and revoked B1/B2 entries every hour.
    pub fn start(state: Arc<AppState>) {
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let now = now_unix();

                {
                    let mut store = state.b1_shares.write().expect("b1 store lock poisoned");
                    // Purge expired entries. Revoked entries are also purged — they have
                    // already returned 410 Gone and no longer need to be retained.
                    store.retain(|_, record| record.expires_at > now && !record.revoked);
                }
                {
                    let mut store = state.b2_shares.write().expect("b2 store lock poisoned");
                    store.retain(|_, record| record.expires_at > now && !record.revoked);
                }

                tracing::debug!("share sweeper: pruned expired/revoked B1/B2 entries");
            }
        });
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
        assert!(!is_valid_share_id("550e8400-e29b-41d4-a716-4466554400001")); // 37 chars
    }

    #[test]
    fn share_id_invalid_chars_rejected() {
        // 36 chars but contains invalid char '!'
        assert!(!is_valid_share_id("550e8400-e29b-41d4-a716-44665544000!"));
    }

    #[test]
    fn expires_cap_enforced() {
        let over_limit: u32 = MAX_EXPIRES_SECS + 1000;
        assert_eq!(over_limit.min(MAX_EXPIRES_SECS), MAX_EXPIRES_SECS);
    }

    #[test]
    fn v7_marker_check() {
        assert_eq!(V7_MARKER, 0x07);
        let bad: Vec<u8> = vec![0x06, 0x01, 0x02];
        assert_ne!(bad.first(), Some(&V7_MARKER));
        let good: Vec<u8> = vec![0x07, 0x01, 0x02];
        assert_eq!(good.first(), Some(&V7_MARKER));
    }

    #[test]
    fn v7_min_size_constant() {
        // Header (1709) + footer (32) = 1741 bytes minimum.
        assert_eq!(V7_MIN_SIZE, 1741);
        // A too-short payload must be rejected even if first byte is 0x07.
        let too_short: Vec<u8> = std::iter::once(V7_MARKER).chain(std::iter::repeat(0u8).take(V7_MIN_SIZE - 2)).collect();
        assert!(too_short.first() == Some(&V7_MARKER));
        assert!(too_short.len() < V7_MIN_SIZE);
        // A payload of exactly V7_MIN_SIZE passes both checks.
        let min_valid: Vec<u8> = std::iter::once(V7_MARKER).chain(std::iter::repeat(0u8).take(V7_MIN_SIZE - 1)).collect();
        assert_eq!(min_valid.len(), V7_MIN_SIZE);
    }

    #[test]
    fn max_b2_size_constant() {
        assert_eq!(MAX_B2_SIZE, 200 * 1024 * 1024);
    }

    #[test]
    fn now_unix_is_reasonable() {
        let t = now_unix();
        // 2024-01-01 in unix seconds is ~1704067200; must be after that.
        assert!(t > 1_704_067_200);
    }

    // ── Owner token tests ─────────────────────────────────────────────────────

    const TEST_KEY: &[u8] = b"test-signing-key-32bytes-padding!";
    const TEST_SHARE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const FIXED_NONCE: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    #[test]
    fn owner_token_is_deterministic_with_same_nonce() {
        let t1 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        let t2 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64); // 32 bytes → 64 hex chars
    }

    #[test]
    fn owner_token_differs_across_nonces() {
        let nonce2: [u8; 16] = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let t1 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        let t2 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &nonce2);
        assert_ne!(t1, t2, "different nonces must produce different tokens");
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
    fn verify_owner_token_correct_token_accepted() {
        let token = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        assert!(verify_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE, &token));
    }

    #[test]
    fn verify_owner_token_wrong_token_rejected() {
        assert!(!verify_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE, "deadbeef"));
        assert!(!verify_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE, ""));
    }

    #[test]
    fn verify_owner_token_wrong_share_id_rejected() {
        let id2 = "550e8400-e29b-41d4-a716-446655440001";
        let token_for_id1 = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE);
        assert!(!verify_owner_token(TEST_KEY, id2, &FIXED_NONCE, &token_for_id1));
    }

    #[test]
    fn verify_owner_token_invalid_hex_rejected() {
        assert!(!verify_owner_token(TEST_KEY, TEST_SHARE_ID, &FIXED_NONCE, "not-hex!!!"));
    }

    #[test]
    fn token_from_old_nonce_does_not_verify_against_new_nonce() {
        // Simulates: share created with nonce1, token1 stored by client.
        // Sweeper purges the record. Client re-registers same share_id with nonce2.
        // The old token1 must not verify against the new record.
        let nonce1: [u8; 16] = [0xAA; 16];
        let nonce2: [u8; 16] = [0xBB; 16];
        let old_token = compute_owner_token(TEST_KEY, TEST_SHARE_ID, &nonce1);
        assert!(!verify_owner_token(TEST_KEY, TEST_SHARE_ID, &nonce2, &old_token),
            "token bound to nonce1 must not verify against nonce2");
    }

    #[test]
    fn generate_token_nonce_is_random() {
        // Two generated nonces should not be equal (birthday-bound risk is ~2^-63 per pair).
        let n1 = generate_token_nonce();
        let n2 = generate_token_nonce();
        assert_ne!(n1, n2, "two fresh nonces should not be identical");
    }
}
