// PoW helpers and purpose derivation for the BYO relay auth cookie.
//
// These are pure functions (no I/O, no panics) used by:
//   - sdk-wasm (WASM bindings called from the BYO Web Worker)
//   - byo-server (server-side verification, vendored separately to avoid cross-crate dep)
//
// Protocol:
//   purpose = derive_sftp_purpose(host, port)  →  "sftp:<32 lowercase hex chars>"
//   purpose = derive_enrollment_purpose(ch)    →  "enroll:<channel_id>"
//   answer  = solve_pow(nonce_hex, purpose, difficulty)  →  u64
//   ok      = verify_pow(nonce_hex, purpose, difficulty, answer)  →  bool
//
//   hash input: sha256(nonce_raw_16_bytes || purpose_utf8 || answer_le64)
//   requirement: count_leading_zero_bits(hash) >= difficulty

use std::collections::HashMap;

use crate::crypto::hashing::sha256;
use crate::error::CryptoError;

// ─── RelayTicketCache ─────────────────────────────────────────────────────────

/// Relay ticket TTL: 9.5 minutes in milliseconds.
///
/// Relay auth JWTs are issued with a 10-minute window; we treat them as
/// expired 30 seconds early to account for clock skew and network latency.
pub const RELAY_TICKET_TTL_MS: u64 = 570_000; // 9 min 30 s

/// In-memory per-purpose cache of relay auth tickets (JWT strings).
///
/// Keyed by purpose string (e.g. `"sftp:abc..."`, `"share:b1"`).  Each entry
/// carries an absolute expiry timestamp (milliseconds since Unix epoch).
///
/// The cache is intentionally simple — no threading, no async.  The platform
/// layer (WASM single-threaded, Android coroutine mutex) owns synchronisation.
/// `now_ms` is passed in on every read/write so the caller controls the clock
/// (`Date.now()` in JS, `System.currentTimeMillis()` in Kotlin).
///
/// # Single-flight
///
/// The cache itself does NOT implement single-flight — concurrent callers that
/// miss the cache must each start their own PoW solve and race to set the
/// result.  The last writer wins (all tickets from the same challenge window
/// are equivalent).  Platforms that need true single-flight should wrap the
/// cache in a higher-level coordinator (e.g. a JS Promise map or a Kotlin
/// Mutex + Deferred).
pub struct RelayTicketCache {
    entries: HashMap<String, TicketEntry>,
}

struct TicketEntry {
    ticket: String,
    expires_at_ms: u64,
}

impl Default for RelayTicketCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayTicketCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Return the cached ticket for `purpose` if present and not yet expired.
    ///
    /// `now_ms` is the current time in milliseconds since Unix epoch.
    pub fn get(&self, purpose: &str, now_ms: u64) -> Option<&str> {
        self.entries.get(purpose).and_then(|e| {
            if now_ms < e.expires_at_ms {
                Some(e.ticket.as_str())
            } else {
                None
            }
        })
    }

    /// Store a ticket for `purpose` with an absolute expiry timestamp.
    ///
    /// Typically `expires_at_ms = now_ms + RELAY_TICKET_TTL_MS`.
    pub fn set(&mut self, purpose: impl Into<String>, ticket: impl Into<String>, expires_at_ms: u64) {
        self.entries.insert(purpose.into(), TicketEntry { ticket: ticket.into(), expires_at_ms });
    }

    /// Store a ticket using the default 9.5-minute TTL from `now_ms`.
    pub fn set_with_default_ttl(&mut self, purpose: impl Into<String>, ticket: impl Into<String>, now_ms: u64) {
        self.set(purpose, ticket, now_ms + RELAY_TICKET_TTL_MS);
    }

    /// Remove the cached ticket for `purpose` (e.g. after a 401 response).
    pub fn invalidate(&mut self, purpose: &str) {
        self.entries.remove(purpose);
    }

    /// Remove all expired entries from the cache.
    ///
    /// Callers may invoke this periodically to reclaim memory.
    pub fn evict_expired(&mut self, now_ms: u64) {
        self.entries.retain(|_, e| e.expires_at_ms > now_ms);
    }
}



/// Derive the SFTP relay cookie purpose for the given host and port.
///
/// Returns `"sftp:<32 lowercase hex chars>"` where the hex is the first
/// 16 bytes of sha256(host_lowercase + ":" + port).
pub fn derive_sftp_purpose(host: &str, port: u16) -> String {
    let input = format!("{}:{}", host.to_lowercase(), port);
    let hash = sha256(input.as_bytes());
    format!("sftp:{}", hex_encode(&hash[..16]))
}

/// Derive the enrollment relay cookie purpose for the given channel ID.
///
/// Returns `"enroll:<channel_id>"`.  `channel_id` is the opaque base64url
/// string that identifies the enrollment channel.
pub fn derive_enrollment_purpose(channel_id: &str) -> String {
    format!("enroll:{channel_id}")
}

/// Compute the preimage for the PoW hash.
///
/// sha256(nonce_raw || purpose_utf8 || answer_le64)
fn pow_hash(nonce: &[u8], purpose: &str, answer: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(nonce.len() + purpose.len() + 8);
    input.extend_from_slice(nonce);
    input.extend_from_slice(purpose.as_bytes());
    input.extend_from_slice(&answer.to_le_bytes());
    sha256(&input)
}

/// Count the number of leading zero bits in a 32-byte hash.
fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Maximum PoW difficulty the client will attempt. A compliant server issues
/// challenges with `difficulty ≤ 20`; anything higher is almost certainly a
/// malicious or misconfigured relay trying to stall the client.
/// At 24 the expected work is ~16 M hashes — still completes in seconds on
/// modern hardware but meaningfully bounds the worst case.
pub const MAX_POW_DIFFICULTY: u32 = 24;

/// Solve the PoW challenge.
///
/// Finds the smallest `answer: u64` such that
/// `count_leading_zero_bits(sha256(nonce_raw || purpose || answer_le64)) >= difficulty`.
///
/// Returns `Err(CryptoError::InvalidKeyMaterial)` if `nonce_hex` is not valid
/// hex or if `difficulty` exceeds [`MAX_POW_DIFFICULTY`] (refusing to burn the
/// worker thread for a malicious server).
pub fn solve_pow(nonce_hex: &str, purpose: &str, difficulty: u32) -> Result<u64, CryptoError> {
    // Cap purpose length to prevent a stall if a caller passes a very large string.
    if purpose.len() > 512 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    if difficulty > MAX_POW_DIFFICULTY {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let nonce = hex_decode(nonce_hex).ok_or(CryptoError::InvalidKeyMaterial)?;
    // Preallocate the input buffer to avoid repeated allocation in the hot loop.
    let mut input = Vec::with_capacity(nonce.len() + purpose.len() + 8);

    for answer in 0u64..=u64::MAX {
        input.clear();
        input.extend_from_slice(&nonce);
        input.extend_from_slice(purpose.as_bytes());
        input.extend_from_slice(&answer.to_le_bytes());
        let hash = sha256(&input);
        if leading_zero_bits(&hash) >= difficulty {
            return Ok(answer);
        }
    }
    // Unreachable for any difficulty < 64.
    Err(CryptoError::InvalidKeyMaterial)
}

/// Verify a PoW answer.
///
/// Returns true iff `sha256(nonce_raw || purpose || answer_le64)` has at least
/// `difficulty` leading zero bits.
pub fn verify_pow(nonce_hex: &str, purpose: &str, difficulty: u32, answer: u64) -> bool {
    let Some(nonce) = hex_decode(nonce_hex) else {
        return false;
    };
    let hash = pow_hash(&nonce, purpose, answer);
    leading_zero_bits(&hash) >= difficulty
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ─── RelayTicketCache ─────────────────────────────────────────────────────

    #[test]
    fn cache_miss_on_empty() {
        let cache = RelayTicketCache::new();
        assert!(cache.get("sftp:abc", 1000).is_none());
    }

    #[test]
    fn cache_hit_within_ttl() {
        let mut cache = RelayTicketCache::new();
        cache.set("sftp:abc", "jwt123", 2000);
        assert_eq!(cache.get("sftp:abc", 1000), Some("jwt123"));
    }

    #[test]
    fn cache_miss_after_expiry() {
        let mut cache = RelayTicketCache::new();
        cache.set("sftp:abc", "jwt123", 999);
        assert!(cache.get("sftp:abc", 1000).is_none()); // now_ms == expires_at_ms → expired
    }

    #[test]
    fn set_with_default_ttl_expires_correctly() {
        let mut cache = RelayTicketCache::new();
        let now = 1_000_000u64;
        cache.set_with_default_ttl("share:b1", "tok", now);
        assert!(cache.get("share:b1", now + RELAY_TICKET_TTL_MS - 1).is_some());
        assert!(cache.get("share:b1", now + RELAY_TICKET_TTL_MS).is_none());
    }

    #[test]
    fn invalidate_removes_entry() {
        let mut cache = RelayTicketCache::new();
        cache.set("sftp:abc", "jwt123", 9999999);
        cache.invalidate("sftp:abc");
        assert!(cache.get("sftp:abc", 0).is_none());
    }

    #[test]
    fn invalidate_unknown_key_is_noop() {
        let mut cache = RelayTicketCache::new();
        cache.invalidate("does-not-exist"); // must not panic
    }

    #[test]
    fn evict_expired_removes_stale_entries() {
        let mut cache = RelayTicketCache::new();
        cache.set("old", "expired", 500);
        cache.set("fresh", "valid", 2000);
        cache.evict_expired(1000);
        assert!(cache.get("old", 1000).is_none());
        assert!(cache.get("fresh", 1000).is_some());
    }

    #[test]
    fn multiple_purposes_independent() {
        let mut cache = RelayTicketCache::new();
        cache.set("sftp:x", "token-sftp", 5000);
        cache.set("share:b1", "token-b1", 5000);
        assert_eq!(cache.get("sftp:x", 0), Some("token-sftp"));
        assert_eq!(cache.get("share:b1", 0), Some("token-b1"));
        cache.invalidate("sftp:x");
        assert!(cache.get("sftp:x", 0).is_none());
        assert!(cache.get("share:b1", 0).is_some());
    }



    #[test]
    fn derive_sftp_purpose_format() {
        let p = derive_sftp_purpose("sftp.example.com", 22);
        assert!(p.starts_with("sftp:"));
        // 32 lowercase hex chars after "sftp:"
        let hex_part = &p[5..];
        assert_eq!(hex_part.len(), 32);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn derive_sftp_purpose_case_insensitive() {
        let p1 = derive_sftp_purpose("SFTP.EXAMPLE.COM", 22);
        let p2 = derive_sftp_purpose("sftp.example.com", 22);
        assert_eq!(p1, p2);
    }

    #[test]
    fn derive_sftp_purpose_port_matters() {
        let p22 = derive_sftp_purpose("sftp.example.com", 22);
        let p2222 = derive_sftp_purpose("sftp.example.com", 2222);
        assert_ne!(p22, p2222);
    }

    #[test]
    fn derive_enrollment_purpose_format() {
        let ch = "abc123XYZ_-";
        let p = derive_enrollment_purpose(ch);
        assert_eq!(p, format!("enroll:{ch}"));
    }

    #[test]
    fn verify_pow_correct_answer() {
        // Use difficulty=1 so we find an answer quickly in tests.
        let nonce_hex = "0102030405060708090a0b0c0d0e0f10";
        let purpose = "sftp:deadbeefcafe0000deadbeefcafe0000";
        let answer = solve_pow(nonce_hex, purpose, 1).unwrap();
        assert!(verify_pow(nonce_hex, purpose, 1, answer));
    }

    #[test]
    fn verify_pow_correct_answer_fails_at_higher_difficulty() {
        // An answer satisfying 1-bit difficulty has probability 2^(-31) of also
        // satisfying 32-bit difficulty — negligible for practical purposes.
        let nonce_hex = "0102030405060708090a0b0c0d0e0f10";
        let purpose = "sftp:deadbeefcafe0000deadbeefcafe0000";
        let answer = solve_pow(nonce_hex, purpose, 1).unwrap();
        assert!(verify_pow(nonce_hex, purpose, 1, answer)); // sanity check
        assert!(!verify_pow(nonce_hex, purpose, 32, answer)); // fails at higher difficulty
    }

    #[test]
    fn verify_pow_wrong_purpose_rejected() {
        let nonce_hex = "0102030405060708090a0b0c0d0e0f10";
        let purpose = "sftp:deadbeefcafe0000deadbeefcafe0000";
        let answer = solve_pow(nonce_hex, purpose, 1).unwrap();
        assert!(!verify_pow(nonce_hex, "sftp:0000000000000000deadbeefcafe0000", 1, answer));
    }

    #[test]
    fn verify_pow_invalid_hex_nonce() {
        assert!(!verify_pow("gg", "sftp:xx", 1, 0));
    }

    #[test]
    fn solve_pow_purpose_too_long_rejected() {
        let nonce_hex = "0102030405060708090a0b0c0d0e0f10";
        let long_purpose = "x".repeat(513);
        assert!(solve_pow(nonce_hex, &long_purpose, 1).is_err());
    }

    #[test]
    fn solve_pow_purpose_exactly_512_ok() {
        let nonce_hex = "0102030405060708090a0b0c0d0e0f10";
        let purpose = "a".repeat(512);
        // Should not error on length — may succeed or fail on valid answer.
        // Just assert no length error (i.e., it runs).
        let result = solve_pow(nonce_hex, &purpose, 1);
        assert!(result.is_ok(), "purpose of exactly 512 bytes should be accepted");
    }
}
