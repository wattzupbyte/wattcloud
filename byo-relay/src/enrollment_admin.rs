//! Restricted-enrollment admin surface — bootstrap claim, invite mint/list/
//! revoke, redeem, device list/revoke, and the `wattcloud_device` cookie
//! that gates every operational relay request when
//! `WATTCLOUD_ENROLLMENT_MODE=restricted`.
//!
//! Threat model + invariants live in SPEC.md §Access Control. Rules the
//! handlers below enforce:
//!
//!   - Bootstrap may be consumed exactly once per generated token; reclaim
//!     attempts after an owner exists return `409 already_bootstrapped`.
//!   - Invite codes are single-use, time-bounded, HMAC-hashed at rest
//!     (never stored plaintext). Response reveals the plaintext once.
//!   - Redeem validates `(code_hash, used_by IS NULL, expires_at > now)`
//!     and inserts the device row in one transaction.
//!   - Device revoke refuses to remove the last non-revoked owner; the
//!     operator falls back to the CLI `regenerate-claim-token` path to
//!     recover.
//!   - All admin endpoints except `/relay/admin/claim` require a
//!     `wattcloud_device` cookie whose device is non-revoked + `is_owner=1`.
//!   - Rate limits are per-IP (5/min for claim + redeem, 20/hr for invite
//!     mint). Matches the `SlidingWindowLimiterByKey` pattern already used
//!     elsewhere in the relay. No IP addresses are persisted — limiter
//!     state is in-memory only, consistent with the zero-logging posture.
//!
//! Zero-knowledge note: this module stores no user plaintext, no passwords,
//! no vault material. The only secrets it handles are the bootstrap token
//! and invite codes, both of which are fresh random bytes minted on the
//! relay and HMAC-hashed before persistence.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_cookies::{Cookie, Cookies};
use uuid::Uuid;

use crate::client_ip::extract_client_ip;
use crate::enrollment::{DeviceRow, EnrollmentStoreError};
use crate::rate_limit::{IpBucket, SlidingWindowLimiterByKey};
use crate::relay_auth::AppState;

type HmacSha256 = Hmac<Sha256>;

// ── Cookie + JWT ─────────────────────────────────────────────────────────────

/// Cookie holding the device JWT. Separate name space from the per-purpose
/// `relay_auth_*` cookies so a stale operational cookie can't collide with
/// the long-lived device credential.
pub const COOKIE_NAME_DEVICE: &str = "wattcloud_device";

/// 90-day TTL. Sliding refresh (below) rotates it when within 7 days of
/// expiry so active devices never have to re-enrol.
const DEVICE_COOKIE_TTL_SECS: i64 = 90 * 24 * 3600;

/// Window before `exp` where a new cookie is minted on the same request.
const DEVICE_COOKIE_REFRESH_WINDOW_SECS: i64 = 7 * 24 * 3600;

/// JWT claims for the device credential.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceClaims {
    pub sub: String,
    /// Literal `"device"` — domain-separates this JWT from the operational
    /// `relay_auth_*` cookies that share the signing key.
    pub kind: String,
    /// Owner bit cached from the DB at mint time. Middleware always
    /// re-queries the DB for authority, so a stale bit here can only cause
    /// a failed authorization check, never privilege escalation.
    pub is_owner: bool,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn mint_device_jwt(
    signing_key: &[u8],
    device_id: &str,
    is_owner: bool,
) -> Result<(String, DeviceClaims), jsonwebtoken::errors::Error> {
    let now = now_secs();
    let claims = DeviceClaims {
        sub: device_id.to_string(),
        kind: "device".to_string(),
        is_owner,
        iat: now,
        exp: now + DEVICE_COOKIE_TTL_SECS,
        jti: Uuid::new_v4().to_string(),
    };
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(signing_key);
    let tok = jsonwebtoken::encode(&header, &claims, &key)?;
    Ok((tok, claims))
}

fn verify_device_jwt(
    signing_key: &[u8],
    token: &str,
) -> Result<DeviceClaims, jsonwebtoken::errors::Error> {
    let key = jsonwebtoken::DecodingKey::from_secret(signing_key);
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "iat", "sub"]);
    validation.leeway = 5;
    let data = jsonwebtoken::decode::<DeviceClaims>(token, &key, &validation)?;
    if data.claims.kind != "device" {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
    }
    Ok(data.claims)
}

fn set_device_cookie(cookies: &Cookies, token: String) {
    let mut cookie = Cookie::new(COOKIE_NAME_DEVICE, token);
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_path("/");
    cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    cookie.set_max_age(tower_cookies::cookie::time::Duration::seconds(
        DEVICE_COOKIE_TTL_SECS,
    ));
    cookies.add(cookie);
}

fn clear_device_cookie(cookies: &Cookies) {
    let mut cookie = Cookie::new(COOKIE_NAME_DEVICE, "");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_path("/");
    cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    cookie.set_max_age(tower_cookies::cookie::time::Duration::ZERO);
    cookies.add(cookie);
}

// ── Invite + bootstrap code helpers ──────────────────────────────────────────

/// Alphabet for invite codes — base32 minus visually ambiguous glyphs
/// (0/O, 1/I, l). 31^11 ≈ 3×10^16 combinations. Paired with per-IP rate
/// limits, brute-force is effectively impossible.
const INVITE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const INVITE_LEN: usize = 11;

/// Generate a plaintext invite code ready for display. Format:
/// `XXXX-XXXX-XXX` (4-4-3). The dash positions are display-only;
/// normalization strips them before hashing.
pub fn generate_invite_code() -> String {
    let mut raw = [0u8; INVITE_LEN];
    let mut rng = rand::rng();
    for slot in raw.iter_mut() {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        *slot = INVITE_ALPHABET[(b[0] as usize) % INVITE_ALPHABET.len()];
    }
    let chars = std::str::from_utf8(&raw).unwrap_or("");
    format!("{}-{}-{}", &chars[..4], &chars[4..8], &chars[8..11])
}

/// Canonicalise user input for hashing: uppercase, drop any non-alphanumeric.
/// Tolerates dashes, spaces, lowercase input without being lenient on the
/// alphabet itself (characters outside [A-Z0-9] are stripped).
pub fn normalize_invite_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// HMAC-SHA256 over the normalized code with the relay signing key. The
/// signing key already lives in env; it's reused here because the hash
/// never leaves the relay DB and the primitive is orthogonal to JWT
/// signing. If a future rotate-keys flow ships, invite rows will need
/// re-hashing or expiring with the old key.
pub fn hash_invite_code(signing_key: &[u8], normalized: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(signing_key).expect(
        "HMAC accepts any key length; signing_key len-checked in config::parse_signing_key",
    );
    mac.update(normalized.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Bootstrap token: 32 random bytes, hex-encoded. Operator pastes into the
/// bootstrap claim screen verbatim. HMAC-hashed at rest so a DB read never
/// reveals the plaintext.
pub fn generate_bootstrap_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn hash_bootstrap_token(signing_key: &[u8], token: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(signing_key).expect("valid HMAC key");
    mac.update(token.trim().as_bytes());
    mac.finalize().into_bytes().to_vec()
}

// ── Rate limiters ────────────────────────────────────────────────────────────

const RATE_LIMITER_MAX_KEYS: usize = 50_000;

/// Two-tier limit on `/relay/admin/claim`: 5 per 5 minutes + 10 per hour
/// per IP. Bootstrap is a once-in-a-lifetime event per relay, so even a
/// fumble-prone operator copy/pasting from terminal stays well under
/// these numbers; the windows exist to harden the 32-byte token against
/// slow-drip brute force from rotated IPs.
pub struct ClaimLimiter {
    per_5min: SlidingWindowLimiterByKey<IpBucket>,
    per_hour: SlidingWindowLimiterByKey<IpBucket>,
}

impl ClaimLimiter {
    pub fn new() -> Self {
        Self {
            per_5min: SlidingWindowLimiterByKey::new_with_cap(
                5 * 60,
                5,
                Some(RATE_LIMITER_MAX_KEYS),
            ),
            per_hour: SlidingWindowLimiterByKey::new_with_cap(
                3600,
                10,
                Some(RATE_LIMITER_MAX_KEYS),
            ),
        }
    }
    pub fn check(&self, ip: std::net::IpAddr) -> bool {
        let bucket = IpBucket::from(ip);
        self.per_5min.check_and_record(bucket) && self.per_hour.check_and_record(bucket)
    }
}

impl Default for ClaimLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Two-tier limit on `/relay/admin/redeem`: 5 per 5 minutes + 10 per hour
/// per IP. Matches ClaimLimiter — the threat profile is symmetric
/// (short-lived secret on the client, HMAC-hashed on the server). The
/// 5-minute window stops trivial guessing; the hourly cap backstops a
/// patient botnet.
pub struct RedeemLimiter {
    per_5min: SlidingWindowLimiterByKey<IpBucket>,
    per_hour: SlidingWindowLimiterByKey<IpBucket>,
}

impl RedeemLimiter {
    pub fn new() -> Self {
        Self {
            per_5min: SlidingWindowLimiterByKey::new_with_cap(
                5 * 60,
                5,
                Some(RATE_LIMITER_MAX_KEYS),
            ),
            per_hour: SlidingWindowLimiterByKey::new_with_cap(
                3600,
                10,
                Some(RATE_LIMITER_MAX_KEYS),
            ),
        }
    }
    pub fn check(&self, ip: std::net::IpAddr) -> bool {
        let bucket = IpBucket::from(ip);
        self.per_5min.check_and_record(bucket) && self.per_hour.check_and_record(bucket)
    }
}

impl Default for RedeemLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// 10 invites minted per IP per hour. Owner-initiated, so legitimate rates
/// are tiny; this exists to backstop a compromised owner-cookie scenario.
pub struct InviteMintLimiter {
    inner: SlidingWindowLimiterByKey<IpBucket>,
}

impl InviteMintLimiter {
    pub fn new() -> Self {
        Self {
            inner: SlidingWindowLimiterByKey::new_with_cap(3600, 10, Some(RATE_LIMITER_MAX_KEYS)),
        }
    }
    pub fn check(&self, ip: std::net::IpAddr) -> bool {
        self.inner.check_and_record(IpBucket::from(ip))
    }
}

impl Default for InviteMintLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Request / response bodies ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ClaimBody {
    pub token: String,
    pub label: String,
    /// 32-byte ed25519 pubkey (base64url, no padding). Reserved for v1.1
    /// WebAuthn/PRF integration; stored verbatim for phase 2.
    pub pubkey_b64: String,
    /// PoW nonce_id from `GET /relay/auth/challenge?purpose=admin:claim`.
    pub nonce_id: String,
    /// PoW answer solving sha256(nonce_raw ‖ "admin:claim" ‖ answer_le64).
    pub answer: u64,
}

#[derive(Debug, Deserialize)]
pub struct RedeemBody {
    pub code: String,
    pub label: String,
    pub pubkey_b64: String,
    /// PoW nonce_id from `GET /relay/auth/challenge?purpose=admin:redeem`.
    pub nonce_id: String,
    /// PoW answer solving sha256(nonce_raw ‖ "admin:redeem" ‖ answer_le64).
    pub answer: u64,
}

#[derive(Debug, Deserialize)]
pub struct InviteCreateBody {
    pub label: String,
    /// Time-to-live in seconds. Clamped to [60, 7 * 24 * 3600].
    pub ttl_secs: i64,
}

#[derive(Debug, Serialize)]
pub struct ClaimOrRedeemResponse {
    pub device_id: String,
    pub is_owner: bool,
}

#[derive(Debug, Serialize)]
pub struct InviteCreateResponse {
    pub id: String,
    pub code: String,
    pub label: String,
    pub expires_at: i64,
}

// ── Helpers: decode + validate bodies ────────────────────────────────────────

const PUBKEY_LEN: usize = 32;
const MAX_LABEL_CHARS: usize = 64;

fn decode_pubkey(b64: &str) -> Result<Vec<u8>, (StatusCode, &'static str)> {
    use base64::Engine as _;
    let trimmed = b64.trim();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed))
        .map_err(|_| (StatusCode::BAD_REQUEST, "pubkey_b64 not base64"))?;
    if bytes.len() != PUBKEY_LEN {
        return Err((StatusCode::BAD_REQUEST, "pubkey must decode to 32 bytes"));
    }
    Ok(bytes)
}

fn trim_label(label: &str) -> Result<String, (StatusCode, &'static str)> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "label required"));
    }
    if trimmed.chars().count() > MAX_LABEL_CHARS {
        return Err((StatusCode::BAD_REQUEST, "label too long"));
    }
    Ok(trimmed.to_string())
}

// ── Error → HTTP mapping ─────────────────────────────────────────────────────

fn store_error_to_status(err: EnrollmentStoreError) -> (StatusCode, &'static str) {
    match err {
        EnrollmentStoreError::InvalidBootstrapToken => (StatusCode::UNAUTHORIZED, "invalid_token"),
        EnrollmentStoreError::InvalidInvite => (StatusCode::UNAUTHORIZED, "invalid_invite"),
        EnrollmentStoreError::LastOwner => (StatusCode::CONFLICT, "last_owner"),
        EnrollmentStoreError::DeviceNotFound => (StatusCode::NOT_FOUND, "device_not_found"),
        EnrollmentStoreError::Conflict => (StatusCode::CONFLICT, "conflict"),
        // Opaque 500 for internal DB/lock errors — don't leak detail.
        EnrollmentStoreError::Sqlite(_) | EnrollmentStoreError::LockPoisoned => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// ── Admin challenge issuance (public, PoW gate) ──────────────────────────────
//
// The operational middleware (`require_device_cookie`) protects
// `/relay/auth/challenge`, so the pre-claim PoW can't reach it. These
// two dedicated endpoints live in `admin_public` and issue challenges
// only for the `admin:claim` / `admin:redeem` purposes. Per-IP rate
// limited via the existing `auth_challenge_limiter` — shared because the
// threat model is identical (challenge farming).

async fn issue_admin_challenge(
    state: Arc<AppState>,
    addr: SocketAddr,
    headers: axum::http::HeaderMap,
    purpose: &'static str,
) -> Response {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !state.auth_challenge_limiter.check_and_record(client_ip) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let nonce_id = Uuid::new_v4().to_string();
    let mut nonce_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);
    state.challenge_store.insert(
        nonce_id.clone(),
        purpose.to_string(),
        nonce_hex.clone(),
        client_ip,
    );
    Json(json!({
        "nonce_id": nonce_id,
        "nonce": nonce_hex,
        "difficulty": state.config.pow_difficulty_bits,
    }))
    .into_response()
}

pub async fn get_claim_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    issue_admin_challenge(state, addr, headers, "admin:claim").await
}

pub async fn get_redeem_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Response {
    issue_admin_challenge(state, addr, headers, "admin:redeem").await
}

/// `POST /relay/admin/claim` — consume bootstrap token, install first owner.
pub async fn post_claim(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    cookies: Cookies,
    Json(body): Json<ClaimBody>,
) -> Response {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !state.enrollment_claim_limiter.check(client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate_limited").into_response();
    }

    // PoW gate — same pattern as /relay/auth. Single-use nonce, IP-bound,
    // purpose-bound. Doesn't add cryptographic defence (entropy + rate
    // limits already make brute force infeasible) but raises the per-
    // attempt cost for bots and matches the rest of the relay's auth
    // surface.
    if state
        .challenge_store
        .consume_and_verify(
            &body.nonce_id,
            client_ip,
            "admin:claim",
            state.config.pow_difficulty_bits,
            body.answer,
        )
        .is_err()
    {
        return (StatusCode::FORBIDDEN, "bad_pow").into_response();
    }

    let label = match trim_label(&body.label) {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };
    let pubkey = match decode_pubkey(&body.pubkey_b64) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    if body.token.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "token required").into_response();
    }

    let candidate_hash = hash_bootstrap_token(&state.config.relay_signing_key, &body.token);
    let device_id = Uuid::new_v4().to_string();
    let now = now_secs();

    if let Err(e) =
        state
            .enrollment_store
            .claim_bootstrap(&candidate_hash, &device_id, &pubkey, &label, now)
    {
        return store_error_to_status(e).into_response();
    }

    // Mint the device cookie.
    let (tok, _claims) = match mint_device_jwt(&state.config.relay_signing_key, &device_id, true) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "mint_device_jwt failed during claim");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    set_device_cookie(&cookies, tok);

    Json(ClaimOrRedeemResponse {
        device_id,
        is_owner: true,
    })
    .into_response()
}

/// `POST /relay/admin/redeem` — consume an invite code, enrol a member.
pub async fn post_redeem(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    cookies: Cookies,
    Json(body): Json<RedeemBody>,
) -> Response {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !state.enrollment_redeem_limiter.check(client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate_limited").into_response();
    }

    // PoW gate — see post_claim for rationale.
    if state
        .challenge_store
        .consume_and_verify(
            &body.nonce_id,
            client_ip,
            "admin:redeem",
            state.config.pow_difficulty_bits,
            body.answer,
        )
        .is_err()
    {
        return (StatusCode::FORBIDDEN, "bad_pow").into_response();
    }

    let label = match trim_label(&body.label) {
        Ok(l) => l,
        Err(e) => return e.into_response(),
    };
    let pubkey = match decode_pubkey(&body.pubkey_b64) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let normalized = normalize_invite_code(&body.code);
    if normalized.chars().count() != INVITE_LEN {
        return (StatusCode::UNAUTHORIZED, "invalid_invite").into_response();
    }
    let candidate_hash = hash_invite_code(&state.config.relay_signing_key, &normalized);
    let device_id = Uuid::new_v4().to_string();
    let now = now_secs();

    if let Err(e) =
        state
            .enrollment_store
            .redeem_invite(&candidate_hash, &device_id, &pubkey, &label, now)
    {
        return store_error_to_status(e).into_response();
    }

    let (tok, _claims) = match mint_device_jwt(&state.config.relay_signing_key, &device_id, false) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "mint_device_jwt failed during redeem");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    set_device_cookie(&cookies, tok);

    Json(ClaimOrRedeemResponse {
        device_id,
        is_owner: false,
    })
    .into_response()
}

/// `POST /relay/admin/invite` — owner mints a new invite code. Requires the
/// admin middleware (below) to have authorised the caller.
pub async fn post_invite(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    owner: OwnerDevice,
    Json(body): Json<InviteCreateBody>,
) -> Response {
    let client_ip = extract_client_ip(addr.ip(), &headers, &state.config.trusted_proxies);
    if !state.enrollment_invite_limiter.check(client_ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate_limited").into_response();
    }

    let label = body.label.trim().to_string();
    if label.chars().count() > MAX_LABEL_CHARS {
        return (StatusCode::BAD_REQUEST, "label too long").into_response();
    }
    let ttl_secs = body.ttl_secs.clamp(60, 7 * 24 * 3600);
    let now = now_secs();
    let expires_at = now.saturating_add(ttl_secs);

    let code = generate_invite_code();
    let normalized = normalize_invite_code(&code);
    let code_hash = hash_invite_code(&state.config.relay_signing_key, &normalized);
    let id = Uuid::new_v4().to_string();

    if let Err(e) = state.enrollment_store.insert_invite(
        &id,
        &code_hash,
        &label,
        &owner.device_id,
        now,
        expires_at,
    ) {
        return store_error_to_status(e).into_response();
    }

    Json(InviteCreateResponse {
        id,
        code,
        label,
        expires_at,
    })
    .into_response()
}

/// `GET /relay/admin/invites` — owner-only list.
pub async fn get_invites(State(state): State<Arc<AppState>>, _owner: OwnerDevice) -> Response {
    match state.enrollment_store.list_invites() {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => store_error_to_status(e).into_response(),
    }
}

/// `DELETE /relay/admin/invites/:id` — idempotent.
pub async fn delete_invite(
    State(state): State<Arc<AppState>>,
    _owner: OwnerDevice,
    Path(id): Path<String>,
) -> Response {
    match state.enrollment_store.revoke_invite(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => store_error_to_status(e).into_response(),
    }
}

/// `GET /relay/admin/devices` — owner-only list.
pub async fn get_devices(State(state): State<Arc<AppState>>, _owner: OwnerDevice) -> Response {
    match state.enrollment_store.list_devices() {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => store_error_to_status(e).into_response(),
    }
}

/// `DELETE /relay/admin/devices/:id` — owner-only. Guarded by the
/// last-owner check inside the store; the HTTP layer translates it to 409.
pub async fn delete_device(
    State(state): State<Arc<AppState>>,
    _owner: OwnerDevice,
    Path(id): Path<String>,
) -> Response {
    match state.enrollment_store.revoke_device(&id, now_secs()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => store_error_to_status(e).into_response(),
    }
}

/// Response shape for `GET /relay/admin/me` — lets the SPA pick the right
/// first-run screen without probing with a gated request that has side
/// effects.
#[derive(Debug, Serialize)]
pub struct MeResponse {
    /// Mirrors `/relay/info` for convenience so the SPA can answer "am I
    /// authenticated + what's the posture" in one round-trip.
    pub mode: &'static str,
    /// `None` in Open mode (no device concept). In Restricted mode this
    /// is populated iff a valid non-revoked device cookie accompanied the
    /// request.
    pub device: Option<MeDevice>,
}

#[derive(Debug, Serialize)]
pub struct MeDevice {
    pub device_id: String,
    pub is_owner: bool,
    pub label: String,
}

/// `POST /relay/admin/signout` — revoke the device tied to the current
/// cookie and clear it. The whole point is "ensure this session is
/// gone server-side even if the cookie bytes leak later" — so we
/// actually flip `authorized_devices.revoked_at`, not just overwrite the
/// cookie.
///
/// The store's last-owner guard applies: a sole owner can't sign out
/// from the web without locking themselves out of admin. We surface that
/// as `409 last_owner` and the SPA points at the CLI recovery path.
/// On success (204) the SPA reloads and lands on the invite-entry screen;
/// recovery is via a fresh invite from another owner.
pub async fn post_signout(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    // In Open mode there's no device concept — calling signout is a no-op.
    if matches!(
        state.config.enrollment_mode,
        crate::enrollment::EnrollmentMode::Open
    ) {
        clear_device_cookie(&cookies);
        return StatusCode::NO_CONTENT.into_response();
    }

    let (_claims, device) = match authenticate_device(&state, &cookies) {
        Ok(v) => v,
        Err((code, msg)) => {
            clear_device_cookie(&cookies);
            return (code, msg).into_response();
        }
    };

    match state
        .enrollment_store
        .revoke_device(&device.device_id, now_secs())
    {
        Ok(()) => {
            clear_device_cookie(&cookies);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => store_error_to_status(e).into_response(),
    }
}

/// `GET /relay/admin/me` — identity probe. Always returns 200; the absence
/// of `device` (Restricted) tells the SPA to show the invite-entry screen.
/// In Open mode `device` is always `None`.
pub async fn get_me(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    let mode = state.config.enrollment_mode.as_str();
    if matches!(
        state.config.enrollment_mode,
        crate::enrollment::EnrollmentMode::Open
    ) {
        return Json(MeResponse { mode, device: None }).into_response();
    }

    // Restricted: inspect the cookie directly. This handler is public on
    // purpose — the SPA needs to distinguish "no cookie" from "valid cookie"
    // before any gated request. We do opportunistically bump last_seen and
    // slide the cookie refresh here so a user whose only traffic is the
    // SPA boot probe (this endpoint) still keeps their session warm.
    match authenticate_device(&state, &cookies) {
        Ok((claims, device)) => {
            refresh_and_touch(&state, &cookies, &claims, &device);
            Json(MeResponse {
                mode,
                device: Some(MeDevice {
                    device_id: device.device_id,
                    is_owner: device.is_owner,
                    label: device.label,
                }),
            })
            .into_response()
        }
        Err(_) => Json(MeResponse { mode, device: None }).into_response(),
    }
}

// ── Middleware: device cookie → authorized caller ────────────────────────────

/// Extractor wrapper used by admin handlers. Built by [`require_owner_device`]
/// middleware and injected into the handler signature.
#[derive(Debug, Clone)]
pub struct OwnerDevice {
    pub device_id: String,
}

#[axum::async_trait]
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for OwnerDevice {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<OwnerDevice>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "owner_required"))
    }
}

/// Authenticated-device marker placed on the request by
/// [`require_device_in_restricted_mode`]. Handlers that need the device id
/// can read it via `req.extensions().get::<AuthenticatedDevice>()`.
#[derive(Debug, Clone)]
pub struct AuthenticatedDevice {
    pub device_id: String,
    pub is_owner: bool,
}

/// Look up + validate the `wattcloud_device` cookie. Returns the authorized
/// caller on success, or a mapped HTTP status on failure.
fn authenticate_device(
    state: &Arc<AppState>,
    cookies: &Cookies,
) -> Result<(DeviceClaims, DeviceRow), (StatusCode, &'static str)> {
    let cookie = cookies
        .get(COOKIE_NAME_DEVICE)
        .ok_or((StatusCode::UNAUTHORIZED, "device_cookie_missing"))?;
    let token = cookie.value().to_string();

    let claims = verify_device_jwt(&state.config.relay_signing_key, &token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "device_cookie_invalid"))?;

    let device = state
        .enrollment_store
        .get_device(&claims.sub)
        .map_err(store_error_to_status)?
        .ok_or((StatusCode::UNAUTHORIZED, "device_unknown"))?;

    if device.revoked_at.is_some() {
        return Err((StatusCode::UNAUTHORIZED, "device_revoked"));
    }

    Ok((claims, device))
}

/// Bump `last_seen_hour` + mint a fresh cookie if the current one is within
/// the refresh window. Used by the operational middleware, the admin-owner
/// middleware, and `/relay/admin/me` so a user whose only traffic is the
/// boot probe still keeps their session warm. Failures are logged at warn
/// level but never block the caller — refresh is convenience, not
/// authorization.
fn refresh_and_touch(
    state: &Arc<AppState>,
    cookies: &Cookies,
    claims: &DeviceClaims,
    device: &DeviceRow,
) {
    let now = now_secs();

    if claims.exp - now < DEVICE_COOKIE_REFRESH_WINDOW_SECS {
        match mint_device_jwt(
            &state.config.relay_signing_key,
            &device.device_id,
            device.is_owner,
        ) {
            Ok((tok, _)) => set_device_cookie(cookies, tok),
            Err(e) => tracing::warn!(error = %e, "sliding refresh mint failed"),
        }
    }

    if let Err(e) = state
        .enrollment_store
        .touch_last_seen(&device.device_id, now)
    {
        tracing::warn!(error = %e, "touch_last_seen failed");
    }
}

/// Operational-gate middleware. Layered onto write-path routes when the
/// relay is in `restricted` mode; a no-op otherwise. Inserts an
/// [`AuthenticatedDevice`] into the request extensions so downstream
/// handlers can attribute actions.
///
/// Sliding-refresh: if the JWT is within
/// [`DEVICE_COOKIE_REFRESH_WINDOW_SECS`] of `exp`, mint + set a fresh one
/// before forwarding. Keeps active devices logged in indefinitely while
/// evicting stale cookies automatically.
pub async fn require_device_cookie(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    if matches!(
        state.config.enrollment_mode,
        crate::enrollment::EnrollmentMode::Open
    ) {
        return next.run(req).await;
    }

    let (claims, device) = match authenticate_device(&state, &cookies) {
        Ok(v) => v,
        Err((code, msg)) => {
            if code == StatusCode::UNAUTHORIZED {
                clear_device_cookie(&cookies);
            }
            return (code, msg).into_response();
        }
    };

    refresh_and_touch(&state, &cookies, &claims, &device);

    req.extensions_mut().insert(AuthenticatedDevice {
        device_id: device.device_id.clone(),
        is_owner: device.is_owner,
    });

    next.run(req).await
}

/// Admin-route middleware: requires a valid device cookie AND `is_owner=1`.
/// Used for every `/relay/admin/*` route except `/claim` + `/redeem` (which
/// mint their own cookies and run with their own rate limits).
pub async fn require_owner_device(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    let (claims, device) = match authenticate_device(&state, &cookies) {
        Ok(v) => v,
        Err((code, msg)) => return (code, msg).into_response(),
    };

    if !device.is_owner {
        return (StatusCode::FORBIDDEN, "owner_required").into_response();
    }

    refresh_and_touch(&state, &cookies, &claims, &device);

    req.extensions_mut().insert(OwnerDevice {
        device_id: device.device_id.clone(),
    });

    next.run(req).await
}

// ── Startup: bootstrap-token generation ──────────────────────────────────────

/// Bootstrap token written to disk so the claim-token wrapper can print it
/// (`sudo wattcloud claim-token` on prod, `make claim-token` on dev). File
/// mode 0644 inside a state dir that systemd pins to 0700 under
/// `DynamicUser=yes` — so reading requires root on a prod install.
/// Short-lived (TTL below), single-use, HMAC-hashed at rest.
pub const BOOTSTRAP_TOKEN_FILE_DEFAULT: &str = "/var/lib/byo-relay/bootstrap.txt";
/// 24h token lifetime — long enough for an operator to discover and paste,
/// short enough that an orphaned token (left after an abandoned install)
/// is harmless.
const BOOTSTRAP_TOKEN_TTL: Duration = Duration::from_secs(24 * 3600);

/// If the relay is in `restricted` mode with zero owner devices, mint a
/// bootstrap token and drop the plaintext at `path`. Idempotent if a
/// non-expired row already exists. Runs once at startup from main.rs.
pub fn bootstrap_if_needed(
    state: &Arc<AppState>,
    path: &std::path::Path,
) -> Result<Option<String>, EnrollmentStoreError> {
    if matches!(
        state.config.enrollment_mode,
        crate::enrollment::EnrollmentMode::Open
    ) {
        return Ok(None);
    }
    if state.enrollment_store.owner_count()? > 0 {
        return Ok(None);
    }
    let now = now_secs();
    if state.enrollment_store.has_bootstrap_token(now)? {
        return Ok(None);
    }

    let token = generate_bootstrap_token();
    let hash = hash_bootstrap_token(&state.config.relay_signing_key, &token);
    let expires_at = now + BOOTSTRAP_TOKEN_TTL.as_secs() as i64;
    state
        .enrollment_store
        .set_bootstrap_token(&hash, now, expires_at)?;

    // Write plaintext to disk for the claim-token wrapper to read.
    // File mode 0644; parent dir is systemd's StateDirectory (0700 under
    // DynamicUser=yes on prod), so reading effectively requires root —
    // the prod wrapper is `sudo wattcloud claim-token`.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    if let Err(e) = std::fs::write(path, &token) {
        tracing::warn!(path = %path.display(), error = %e, "bootstrap token file write failed — operator can still recover via byo-admin regenerate-claim-token");
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
        }
    }

    Ok(Some(token))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_code_format_and_alphabet() {
        for _ in 0..100 {
            let code = generate_invite_code();
            // 4-4-3 with two dashes = 13 chars total
            assert_eq!(code.len(), 13, "code: {code}");
            let normalized = normalize_invite_code(&code);
            assert_eq!(normalized.chars().count(), INVITE_LEN);
            for c in normalized.chars() {
                assert!(
                    INVITE_ALPHABET.contains(&(c as u8)),
                    "char {c} not in alphabet for code {code}"
                );
            }
        }
    }

    #[test]
    fn normalize_code_strips_dashes_and_case() {
        // Display format is 4-4-3 (11 alphanumeric chars total).
        assert_eq!(normalize_invite_code("a7kb-x9mq-r4s"), "A7KBX9MQR4S");
        assert_eq!(normalize_invite_code("A7KB X9MQ R4S"), "A7KBX9MQR4S");
        assert_eq!(normalize_invite_code("A7KB/X9MQ/R4S"), "A7KBX9MQR4S");
    }

    #[test]
    fn hash_invite_is_deterministic_and_key_dependent() {
        let k1 = b"key-one-32-bytes-minimum-okayyy!";
        let k2 = b"key-two-32-bytes-minimum-okayyy!";
        let code = "A7KX9MQR4SB";
        let h1a = hash_invite_code(k1, code);
        let h1b = hash_invite_code(k1, code);
        let h2 = hash_invite_code(k2, code);
        assert_eq!(h1a, h1b);
        assert_ne!(h1a, h2);
    }

    #[test]
    fn bootstrap_token_hex_64_chars() {
        let t = generate_bootstrap_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn jwt_roundtrip() {
        let key = b"some-relay-signing-key-32-bytes-!";
        let (tok, claims) = mint_device_jwt(key, "dev-1", true).unwrap();
        let decoded = verify_device_jwt(key, &tok).unwrap();
        assert_eq!(decoded.sub, "dev-1");
        assert!(decoded.is_owner);
        assert_eq!(decoded.kind, "device");
        assert_eq!(decoded.exp, claims.exp);
    }

    #[test]
    fn jwt_rejects_wrong_key() {
        let k1 = b"key-one-32-bytes-minimum-okayyy!";
        let k2 = b"key-two-32-bytes-minimum-okayyy!";
        let (tok, _) = mint_device_jwt(k1, "dev-1", false).unwrap();
        assert!(verify_device_jwt(k2, &tok).is_err());
    }

    #[test]
    fn jwt_rejects_non_device_kind() {
        // Hand-craft a token with kind=other to make sure the kind check
        // bites even when signature + spec claims are valid.
        let key = b"some-relay-signing-key-32-bytes-!";
        let claims = serde_json::json!({
            "sub": "dev-1",
            "kind": "other",
            "is_owner": true,
            "iat": now_secs(),
            "exp": now_secs() + 60,
            "jti": "x",
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let enc = jsonwebtoken::EncodingKey::from_secret(key);
        let tok = jsonwebtoken::encode(&header, &claims, &enc).unwrap();
        assert!(verify_device_jwt(key, &tok).is_err());
    }
}
