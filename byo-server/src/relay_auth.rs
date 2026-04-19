use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tower_cookies::{Cookie, Cookies};
use uuid::Uuid;

use crate::client_ip::extract_client_ip;
use crate::errors::RelayError;
use crate::rate_limit::{AuthChallengeLimiter, SftpAuthFailureTracker};
use crate::share_relay::{B1ShareRecord, B2ShareRecord, ShareGetLimiter};

pub const RELAY_COOKIE_NAME: &str = "relay_auth";

// ── PoW helpers (vendored from sdk-core logic; no cross-crate dep) ─────────

fn pow_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Verify a PoW answer: sha256(nonce_raw || purpose_utf8 || answer_le64)
/// must have >= difficulty leading zero bits.
fn verify_pow(nonce_hex: &str, purpose: &str, difficulty: u32, answer: u64) -> bool {
    let Ok(nonce) = hex::decode(nonce_hex) else {
        return false;
    };
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&nonce);
    hasher.update(purpose.as_bytes());
    hasher.update(answer.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    pow_leading_zero_bits(&hash) >= difficulty
}

/// Derive the SFTP purpose: "sftp:<first 16 bytes of sha256(host_lower:port) as hex>"
pub fn derive_sftp_purpose(host: &str, port: u16) -> String {
    use sha2::{Digest, Sha256};
    let input = format!("{}:{}", host.to_lowercase(), port);
    let hash: [u8; 32] = Sha256::digest(input.as_bytes()).into();
    format!("sftp:{}", hex::encode(&hash[..16]))
}

/// Derive the enrollment purpose: "enroll:<channel_id>"
pub fn derive_enrollment_purpose(channel_id: &str) -> String {
    format!("enroll:{channel_id}")
}

// ── Challenge store ─────────────────────────────────────────────────────────

const CHALLENGE_TTL_SECS: u64 = 60;

struct ChallengeEntry {
    nonce_hex: String,
    purpose: String,
    created_at: Instant,
    /// IP that requested this challenge. Used to bind the PoW answer to the same IP,
    /// preventing challenge harvesting attacks where IP A harvests a challenge and IP B
    /// solves it (e.g., from a powerful remote machine) to obtain a relay cookie.
    client_ip: std::net::IpAddr,
}

/// In-memory store for pending PoW challenges. Each entry has a 60-second TTL
/// and is consumed on first use (single-use nonce).
pub struct ChallengeStore {
    entries: Mutex<HashMap<String, ChallengeEntry>>,
    ttl: Duration,
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(CHALLENGE_TTL_SECS),
        }
    }

    pub fn insert(
        &self,
        nonce_id: String,
        purpose: String,
        nonce_hex: String,
        client_ip: std::net::IpAddr,
    ) {
        let mut entries = self.entries.lock().expect("challenge store lock poisoned");
        let now = Instant::now();
        // Prune expired entries on every insert to bound memory.
        entries.retain(|_, v| now.duration_since(v.created_at) < self.ttl);
        entries.insert(
            nonce_id,
            ChallengeEntry { nonce_hex, purpose, created_at: now, client_ip },
        );
    }

    /// Take (consume) an entry by nonce_id. Returns None if not found or expired.
    fn take(&self, nonce_id: &str) -> Option<ChallengeEntry> {
        let mut entries = self.entries.lock().expect("challenge store lock poisoned");
        let entry = entries.remove(nonce_id)?;
        if Instant::now().duration_since(entry.created_at) >= self.ttl {
            return None; // expired — do not reinsert (already removed)
        }
        Some(entry)
    }
}

// ── JTI consumed set ────────────────────────────────────────────────────────

/// Tracks consumed cookie jtis (single-use enforcement).
/// Entries are kept until their cookie's expiry time, then pruned.
pub struct JtiConsumedSet {
    // jti → unix expiry timestamp (seconds)
    entries: Mutex<HashMap<String, i64>>,
}

impl Default for JtiConsumedSet {
    fn default() -> Self {
        Self::new()
    }
}

impl JtiConsumedSet {
    pub fn new() -> Self {
        Self { entries: Mutex::new(HashMap::new()) }
    }

    /// Attempt to consume `jti`. Returns `true` (first use) or `false` (already consumed).
    /// Prunes expired entries on every call.
    pub fn try_consume(&self, jti: &str, exp: i64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut entries = self.entries.lock().expect("jti set lock poisoned");
        // Prune entries whose cookie has already expired.
        entries.retain(|_, &mut e| e > now);

        if entries.contains_key(jti) {
            return false; // already consumed
        }
        entries.insert(jti.to_string(), exp);
        true
    }
}

// ── JWT claims ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayClaims {
    pub jti: String,
    /// Purpose of this cookie: "sftp:<hex>" or "enroll:<channel_id>".
    pub purpose: String,
    pub iat: i64,
    pub exp: i64,
}

// ── App state ───────────────────────────────────────────────────────────────

/// Shared application state — referenced from main.rs.
pub struct AppState {
    pub config: crate::config::Config,
    pub channel_registry: Arc<crate::channel::ChannelRegistry>,
    pub join_limiter: crate::rate_limit::ChannelJoinLimiter,
    pub sftp_tracker: crate::rate_limit::SftpConnectionTracker,
    pub sftp_auth_tracker: Arc<SftpAuthFailureTracker>,
    pub challenge_store: Arc<ChallengeStore>,
    pub jti_consumed: Arc<JtiConsumedSet>,
    pub auth_challenge_limiter: AuthChallengeLimiter,
    // Share relay stores (in-memory, no persistence).
    pub b1_shares: Arc<RwLock<HashMap<String, B1ShareRecord>>>,
    pub b2_shares: Arc<RwLock<HashMap<String, B2ShareRecord>>>,
    pub share_get_limiter: ShareGetLimiter,
    // Stats (SQLite-backed).
    pub stats_store: Arc<crate::stats::StatsStore>,
    pub stats_ingest_limiter: crate::stats::StatsIngestLimiter,
}

// ── Query / body types ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ChallengeQuery {
    pub purpose: String,
}

#[derive(Debug, Deserialize)]
pub struct PowAnswer {
    pub nonce_id: String,
    pub answer: u64,
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// GET /relay/auth/challenge?purpose=<purpose>
///
/// Validates purpose format, rate-limits per IP (10/min), generates and stores
/// a 16-byte nonce and returns {nonce_id, nonce, difficulty}.
pub async fn get_challenge(
    Query(params): Query<ChallengeQuery>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);

    // Rate-limit challenges per IP.
    if !state.auth_challenge_limiter.check_and_record(client_ip) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // Validate purpose format: must start with "sftp:" or "enroll:" and be
    // reasonable length to prevent junk storage.
    let purpose = params.purpose.trim().to_string();
    if !is_valid_purpose(&purpose) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Generate nonce_id (UUID) and 16-byte nonce.
    let nonce_id = Uuid::new_v4().to_string();
    let mut nonce_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);

    state.challenge_store.insert(nonce_id.clone(), purpose, nonce_hex.clone(), client_ip);

    Json(serde_json::json!({
        "nonce_id": nonce_id,
        "nonce": nonce_hex,
        "difficulty": state.config.pow_difficulty_bits,
    }))
    .into_response()
}

/// POST /relay/auth — verify PoW answer and issue purpose-scoped single-use cookie.
///
/// Body: { nonce_id: string, answer: u64 }
/// On success: 204 No Content + Set-Cookie: relay_auth=<jwt>; HttpOnly; Secure; SameSite=Strict; Path=/relay
pub async fn post_relay_auth(
    cookies: Cookies,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PowAnswer>,
) -> impl IntoResponse {
    let requester_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);

    // Look up and consume the challenge (single-use nonce).
    let challenge = match state.challenge_store.take(&body.nonce_id) {
        Some(c) => c,
        None => return StatusCode::BAD_REQUEST.into_response(), // expired or unknown
    };

    // IP binding: the PoW answer must come from the same IP that requested the challenge.
    // This prevents challenge-harvesting attacks where one IP farms challenges for another
    // (e.g., offloading computation to a powerful machine to obtain a relay cookie).
    if challenge.client_ip != requester_ip {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Verify PoW answer.
    if !verify_pow(
        &challenge.nonce_hex,
        &challenge.purpose,
        state.config.pow_difficulty_bits,
        body.answer,
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // ST1: stats cookies intentionally keep JTI non-consumed (the BYO worker
    // flushes every 60s, so consuming would 401 most flushes). To limit
    // replay exposure of a leaked stats cookie, use a shorter TTL for stats
    // than for other purposes. 120s covers a normal 60s flush plus one
    // retry window; other purposes keep the configurable default.
    const STATS_COOKIE_TTL_SECS: i64 = 120;
    let ttl = if challenge.purpose == "stats" {
        STATS_COOKIE_TTL_SECS
    } else {
        state.config.relay_cookie_ttl_secs as i64
    };

    let claims = RelayClaims {
        jti: Uuid::new_v4().to_string(),
        purpose: challenge.purpose,
        iat: now,
        exp: now + ttl,
    };

    let token = encode(
        &Header::default(), // HS256
        &claims,
        &EncodingKey::from_secret(&state.config.relay_signing_key),
    );

    match token {
        Ok(jwt) => {
            let mut cookie = Cookie::new(RELAY_COOKIE_NAME, jwt);
            cookie.set_http_only(true);
            cookie.set_secure(true);
            cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            cookie.set_path("/relay");
            cookie.set_max_age(time::Duration::seconds(ttl));
            cookies.add(cookie);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ── Cookie verification ─────────────────────────────────────────────────────

/// Verify the relay_auth cookie and return its claims.
/// Used by WebSocket upgrade handlers before accepting connections.
pub fn verify_relay_cookie(
    cookies: &Cookies,
    signing_key: &[u8],
) -> Result<RelayClaims, RelayError> {
    let cookie = cookies
        .get(RELAY_COOKIE_NAME)
        .ok_or(RelayError::Unauthenticated)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["jti", "iat", "exp"]);

    let token_data = decode::<RelayClaims>(
        cookie.value(),
        &DecodingKey::from_secret(signing_key),
        &validation,
    )
    .map_err(|e| {
        if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
            RelayError::TokenExpired
        } else {
            RelayError::Unauthenticated
        }
    })?;

    Ok(token_data.claims)
}

// ── Purpose validation ──────────────────────────────────────────────────────

/// Validate purpose string format. Accepted forms:
///   "sftp:<32 lowercase hex chars>"  (37 bytes total)
///   "enroll:<22 base64url chars>"    (29 bytes total; 22 = ceil(16*4/3) for a 16-byte channel_id)
///   "share:b1" or "share:b2"         (fixed strings for share-relay endpoints)
fn is_valid_purpose(purpose: &str) -> bool {
    if let Some(rest) = purpose.strip_prefix("sftp:") {
        // Must be exactly 32 lowercase hex chars.
        rest.len() == 32 && rest.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    } else if let Some(rest) = purpose.strip_prefix("enroll:") {
        // channel_id: exactly 22 base64url-no-pad chars (16-byte ID).
        // Cap prevents ChallengeStore inflation attacks.
        rest.len() == 22
            && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    } else if let Some(rest) = purpose.strip_prefix("share:") {
        // Fixed discriminators for share-relay operations.
        rest == "b1" || rest == "b2"
    } else if purpose == "stats" {
        // Stats ingest — single fixed purpose string.
        true
    } else {
        false
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_KEY: &[u8] = b"test_signing_key_32_bytes_minimum";

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn make_token(claims: &RelayClaims) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(TEST_KEY),
        )
        .unwrap()
    }

    // ── Purpose validation ──────────────────────────────────────────────

    #[test]
    fn valid_sftp_purpose() {
        assert!(is_valid_purpose("sftp:deadbeef01234567deadbeef01234567"));
    }

    #[test]
    fn invalid_sftp_purpose_uppercase() {
        assert!(!is_valid_purpose("sftp:DEADBEEF01234567deadbeef01234567"));
    }

    #[test]
    fn invalid_sftp_purpose_short() {
        assert!(!is_valid_purpose("sftp:deadbeef"));
    }

    #[test]
    fn valid_enroll_purpose() {
        // Exactly 22 base64url chars = a valid 16-byte channel_id encoding.
        assert!(is_valid_purpose("enroll:abcdefghijklmnopqrstuv"));
    }

    #[test]
    fn invalid_enroll_purpose_too_short() {
        // 21 chars — one too few.
        assert!(!is_valid_purpose("enroll:abcdefghijklmnopqrstu"));
    }

    #[test]
    fn invalid_enroll_purpose_too_long() {
        // 23 chars — one too many.
        assert!(!is_valid_purpose("enroll:abcdefghijklmnopqrstuvw"));
    }

    #[test]
    fn purpose_length_cap_enforced() {
        // A purpose longer than the max should be rejected.
        let long_enroll = format!("enroll:{}", "a".repeat(100));
        assert!(!is_valid_purpose(&long_enroll));
    }

    #[test]
    fn invalid_purpose_unknown_prefix() {
        assert!(!is_valid_purpose("managed:something"));
    }

    #[test]
    fn valid_share_b1_purpose() {
        assert!(is_valid_purpose("share:b1"));
    }

    #[test]
    fn valid_share_b2_purpose() {
        assert!(is_valid_purpose("share:b2"));
    }

    #[test]
    fn invalid_share_purpose_unknown_discriminator() {
        assert!(!is_valid_purpose("share:b3"));
        assert!(!is_valid_purpose("share:"));
        assert!(!is_valid_purpose("share:create"));
    }

    #[test]
    fn valid_stats_purpose() {
        assert!(is_valid_purpose("stats"));
    }

    #[test]
    fn invalid_stats_purpose_with_suffix() {
        assert!(!is_valid_purpose("stats:extra"));
        assert!(!is_valid_purpose("stats "));
    }

    // ── PoW verification ────────────────────────────────────────────────

    #[test]
    fn verify_pow_invalid_nonce() {
        assert!(!verify_pow("not_hex", "sftp:abc", 1, 0));
    }

    #[test]
    fn verify_pow_trivial_difficulty() {
        // difficulty=0 means any hash qualifies.
        assert!(verify_pow(
            "0102030405060708090a0b0c0d0e0f10",
            "sftp:deadbeef01234567deadbeef01234567",
            0,
            0,
        ));
    }

    // ── ChallengeStore ───────────────────────────────────────────────────

    fn test_ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn challenge_store_take_consumes() {
        let store = ChallengeStore::new();
        store.insert("id1".into(), "sftp:xx".into(), "nonce1".into(), test_ip("1.2.3.4"));
        assert!(store.take("id1").is_some());
        assert!(store.take("id1").is_none()); // consumed
    }

    #[test]
    fn challenge_store_unknown_id() {
        let store = ChallengeStore::new();
        assert!(store.take("unknown").is_none());
    }

    #[test]
    fn challenge_ip_binding_stored() {
        let store = ChallengeStore::new();
        let ip = test_ip("10.0.0.1");
        store.insert("id2".into(), "sftp:xx".into(), "nonce2".into(), ip);
        let entry = store.take("id2").expect("entry must exist");
        assert_eq!(entry.client_ip, ip);
    }

    // ── JtiConsumedSet ───────────────────────────────────────────────────

    #[test]
    fn jti_set_first_use_accepted() {
        let set = JtiConsumedSet::new();
        let exp = now_secs() + 600;
        assert!(set.try_consume("jti-abc", exp));
    }

    #[test]
    fn jti_set_replay_rejected() {
        let set = JtiConsumedSet::new();
        let exp = now_secs() + 600;
        assert!(set.try_consume("jti-abc", exp));
        assert!(!set.try_consume("jti-abc", exp));
    }

    #[test]
    fn jti_set_different_jtis_independent() {
        let set = JtiConsumedSet::new();
        let exp = now_secs() + 600;
        assert!(set.try_consume("jti-1", exp));
        assert!(set.try_consume("jti-2", exp));
    }

    // ── JWT round-trip ────────────────────────────────────────────────────

    #[test]
    fn valid_token_verifies() {
        let now = now_secs();
        let claims = RelayClaims {
            jti: Uuid::new_v4().to_string(),
            purpose: "sftp:deadbeef01234567deadbeef01234567".into(),
            iat: now,
            exp: now + 600,
        };
        let token = make_token(&claims);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["jti", "iat", "exp"]);
        let result = decode::<RelayClaims>(&token, &DecodingKey::from_secret(TEST_KEY), &validation);
        assert!(result.is_ok());
        let decoded = result.unwrap().claims;
        assert_eq!(decoded.purpose, claims.purpose);
        assert_eq!(decoded.jti, claims.jti);
    }

    #[test]
    fn expired_token_rejected() {
        let old = now_secs() - 700; // expired
        let claims = RelayClaims {
            jti: Uuid::new_v4().to_string(),
            purpose: "sftp:deadbeef01234567deadbeef01234567".into(),
            iat: old,
            exp: old + 600,
        };
        let token = make_token(&claims);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["jti", "iat", "exp"]);
        let result = decode::<RelayClaims>(&token, &DecodingKey::from_secret(TEST_KEY), &validation);
        assert!(result.is_err());
    }

    // ── Purpose derivation ────────────────────────────────────────────────

    #[test]
    fn derive_sftp_purpose_format() {
        let p = derive_sftp_purpose("sftp.example.com", 22);
        assert!(p.starts_with("sftp:"));
        assert_eq!(p.len(), 5 + 32);
    }

    #[test]
    fn derive_sftp_purpose_case_insensitive() {
        assert_eq!(
            derive_sftp_purpose("EXAMPLE.COM", 22),
            derive_sftp_purpose("example.com", 22),
        );
    }

    #[test]
    fn derive_enrollment_purpose_format() {
        let p = derive_enrollment_purpose("abc123");
        assert_eq!(p, "enroll:abc123");
    }
}
