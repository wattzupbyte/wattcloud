// BYO device enrollment protocol: ephemeral X25519 ECDH, SAS verification, shard transfer.
//
// Implements the QR enrollment protocol from BYO_PLAN §2.3:
//   1. Existing device generates ephemeral X25519 keypair + channel_id, displays QR
//   2. New device scans QR, generates its own ephemeral keypair
//   3. Both devices perform X25519 DH → derive enc_key, mac_key, sas_code
//   4. User visually confirms 6-digit SAS matches on both devices
//   5. Existing device encrypts shard with enc_key, authenticates with mac_key
//   6. New device verifies HMAC, decrypts shard
//
// All functions are pure (no I/O). Follows sdk-core conventions:
//   - #![deny(clippy::unwrap_used, clippy::expect_used)]
//   - All key types derive Zeroize + ZeroizeOnDrop, no Clone
//   - Debug prints "[REDACTED]"
//   - No base64 — encode/decode at WASM boundary

use crate::crypto::asymmetric::{generate_x25519_keypair, x25519_dh};
use crate::crypto::constants::{BYO_ENROLL_ENC_V1, BYO_ENROLL_MAC_V1, BYO_ENROLL_SAS_V1};
use crate::crypto::hashing::{constant_time_eq, hmac_sha256};
use crate::crypto::kdf::hkdf_sha256;
use crate::crypto::symmetric::{aes_gcm_decrypt, aes_gcm_encrypt_with_nonce, generate_nonce};
use crate::crypto::zeroize_utils::{Nonce12, SymmetricKey, X25519SecretKey};
use crate::error::CryptoError;
use rand::RngCore;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error type for enrollment operations.
#[derive(Debug)]
pub enum EnrollmentError {
    /// A cryptographic operation failed.
    Crypto(CryptoError),
    /// HMAC verification failed — the shard envelope may have been tampered with.
    HmacMismatch,
    /// Invalid input length.
    InvalidInput(&'static str),
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrollmentError::Crypto(e) => write!(f, "enrollment crypto error: {e}"),
            EnrollmentError::HmacMismatch => write!(f, "HMAC verification failed"),
            EnrollmentError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
        }
    }
}

impl std::error::Error for EnrollmentError {}

impl From<CryptoError> for EnrollmentError {
    fn from(e: CryptoError) -> Self {
        EnrollmentError::Crypto(e)
    }
}

/// 6-digit Short Authentication String (000000–999999).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SasCode(u32);

impl SasCode {
    /// Raw numeric value (0–999999).
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Formatted as zero-padded 6-digit string, e.g. "042371".
    pub fn to_string_padded(&self) -> String {
        format!("{:06}", self.0)
    }
}

impl fmt::Debug for SasCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show only the formatted code, not the raw value that could leak via debug logs.
        write!(f, "SasCode({:06})", self.0)
    }
}

/// Session keys derived from the enrollment ECDH shared secret.
///
/// All fields are zeroized on drop. The caller must zeroize the shared secret
/// after constructing this struct — `enrollment_derive_session` does this internally.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EnrollmentSession {
    /// AES-256-GCM key for encrypting the shard during transfer.
    enc_key: SymmetricKey,
    /// HMAC-SHA256 key for authenticating the encrypted shard envelope.
    mac_key: SymmetricKey,
    /// 6-digit Short Authentication String for visual verification by both parties.
    sas_code: SasCode,
}

impl EnrollmentSession {
    /// The AES-256-GCM encryption key for shard transfer.
    pub fn enc_key(&self) -> &SymmetricKey {
        &self.enc_key
    }

    /// The HMAC-SHA256 authentication key for shard transfer.
    pub fn mac_key(&self) -> &SymmetricKey {
        &self.mac_key
    }

    /// The 6-digit SAS code for visual verification.
    pub fn sas_code(&self) -> &SasCode {
        &self.sas_code
    }
}

impl fmt::Debug for EnrollmentSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EnrollmentSession {{ enc_key: [REDACTED], mac_key: [REDACTED], sas_code: {:06} }}",
            self.sas_code.0
        )
    }
}

/// Encrypted shard envelope transmitted from existing device to new device.
///
/// Wire format: `nonce(12) + ciphertext+gcm_tag(48) + hmac(32)` = 92 bytes.
/// The nonce is random (OsRng), matching the managed-mode encrypt pattern.
/// HMAC authenticates the ciphertext (encrypt-then-MAC).
#[derive(Debug)]
pub struct ShardEnvelope {
    /// 12-byte AES-GCM nonce.
    pub nonce: Nonce12,
    /// 48-byte ciphertext+tag (32-byte shard + 16-byte GCM tag).
    pub ciphertext: Vec<u8>,
    /// 32-byte HMAC-SHA256 of the ciphertext.
    pub hmac: [u8; 32],
}

impl ShardEnvelope {
    /// Serialize to bytes: nonce(12) + ciphertext(len) + hmac(32).
    /// Total length = 12 + ciphertext.len() + 32.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.ciphertext.len() + 32);
        out.extend_from_slice(self.nonce.as_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.hmac);
        out
    }

    /// Parse from the wire format. Returns error if input is too short.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EnrollmentError> {
        // Exact size: nonce(12) + shard_ct(32+16=48) + hmac(32) = 92
        // Reject oversized inputs; an attacker passing a large buffer could cause
        // excessive allocation before the HMAC rejects the envelope.
        if data.len() != 92 {
            return Err(EnrollmentError::InvalidInput(
                "envelope must be exactly 92 bytes",
            ));
        }
        let nonce_bytes: [u8; 12] = data[..12]
            .try_into()
            .map_err(|_| EnrollmentError::InvalidInput("nonce must be 12 bytes"))?;
        let hmac: [u8; 32] = data[data.len() - 32..]
            .try_into()
            .map_err(|_| EnrollmentError::InvalidInput("hmac must be 32 bytes"))?;
        let ciphertext = data[12..data.len() - 32].to_vec();
        if ciphertext.len() < 16 {
            // Must include at least the GCM tag
            return Err(EnrollmentError::InvalidInput(
                "ciphertext too short (must include GCM tag)",
            ));
        }
        Ok(ShardEnvelope {
            nonce: Nonce12::new(nonce_bytes),
            ciphertext,
            hmac,
        })
    }
}

// ─── Initiate ──────────────────────────────────────────────────────────────

/// Generate enrollment initiation material: ephemeral X25519 keypair + random channel ID.
///
/// The existing device calls this, then encodes `{v:1, ch:channel_id, pk:eph_pk}`
/// into a QR code for the new device to scan.
///
/// Returns `(ephemeral_secret_key, ephemeral_public_key, channel_id)`.
/// The secret key is returned to the caller (Web Worker JS) for use in
/// `enrollment_derive_session` — it must be zeroized after the session is established.
///
/// E1: the SAS code derived downstream is only ~20 bits of effective entropy
/// (6 digits out of 10^6). This is sufficient for a single interactive
/// comparison but offers no protection against an attacker given many
/// attempts. **Platforms MUST enforce a short enrollment window (spec
/// recommends ≤ 5 minutes) by invalidating the QR and tearing down the
/// relay channel after the timeout, even if no peer has connected.** The
/// channel-TTL guard on the relay side is a lower bound; the UI should
/// show a visible countdown and force re-initiation on expiry.
pub fn enrollment_initiate() -> Result<(X25519SecretKey, [u8; 32], [u8; 16]), EnrollmentError> {
    let (eph_pk, eph_sk) = generate_x25519_keypair()?;
    let mut channel_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut channel_id);
    Ok((eph_sk, *eph_pk.as_bytes(), channel_id))
}

/// Generate enrollment material for the JOINING device (the one scanning a
/// QR). Generates only the ephemeral X25519 keypair — the channel ID is
/// taken from the QR payload, NOT freshly generated, so the joiner's
/// session shares the same `channel_id` with the initiator and HKDF
/// info-binding produces matching SAS codes.
///
/// Pairs with `enrollment_initiate` (initiator) and is consumed by
/// `enrollment_derive_session(eph_sk, peer_pk, channel_id)` exactly the
/// same way; the only difference is which device generates the channel
/// id (initiator) vs reuses it (joiner).
///
/// Returns `(ephemeral_secret_key, ephemeral_public_key)`.
pub fn enrollment_join() -> Result<(X25519SecretKey, [u8; 32]), EnrollmentError> {
    let (eph_pk, eph_sk) = generate_x25519_keypair()?;
    Ok((eph_sk, *eph_pk.as_bytes()))
}

// ─── Derive session ───────────────────────────────────────────────────────

/// Derive all enrollment session keys from an ephemeral Diffie-Hellman shared secret.
///
/// Combined function (per design decision documented in code): returns enc_key, mac_key,
/// AND sas_code from a single DH operation. This avoids exposing the raw shared secret
/// to JS and prevents accidental reuse of the shared secret across separate calls.
///
/// The shared secret is zeroized internally after key derivation.
///
/// `channel_id` is mixed into the HKDF info for each derivation, binding the session
/// keys to the specific enrollment channel and preventing cross-channel key reuse.
///
/// Both devices independently call this with their own eph_sk, the peer's eph_pk,
/// and the same channel_id, producing identical session keys and SAS code.
pub fn enrollment_derive_session(
    eph_sk: &X25519SecretKey,
    peer_pk: &[u8],
    channel_id: &[u8; 16],
) -> Result<EnrollmentSession, EnrollmentError> {
    // X25519 DH → shared secret
    let shared = x25519_dh(eph_sk, peer_pk)?;
    // Zeroizing<[u8; 32]> derefs to [u8; 32], which coerces to &[u8].
    let shared_ref: &[u8] = &*shared;

    // Derive three keys from the shared secret using HKDF with domain separation.
    // channel_id is appended to each info string to bind keys to this enrollment channel,
    // preventing cross-channel reuse even if the same DH pair is encountered.
    let mut enc_info = BYO_ENROLL_ENC_V1.to_vec();
    enc_info.extend_from_slice(channel_id);
    let mut mac_info = BYO_ENROLL_MAC_V1.to_vec();
    mac_info.extend_from_slice(channel_id);
    let mut sas_info = BYO_ENROLL_SAS_V1.to_vec();
    sas_info.extend_from_slice(channel_id);

    let enc_key_bytes = hkdf_sha256(shared_ref, &enc_info, 32)?;
    let mac_key_bytes = hkdf_sha256(shared_ref, &mac_info, 32)?;
    // A6: the spec reserves 6 HKDF bytes for the SAS; we consume the first 4
    // into a u32, mod 1_000_000. HKDF's keystream for L ≤ 32 is a single block,
    // so the first 4 bytes are identical whether we request 4 or 6 — we keep 6
    // to stay byte-for-byte compatible with the Android port. The modulo bias
    // (`2^32 mod 10^6 ≈ 4294`) is well below SAS resolution.
    let sas_bytes = hkdf_sha256(shared_ref, &sas_info, 6)?;

    // Convert SAS: 4 bytes as big-endian u32, mod 1_000_000.
    // 4 bytes = 32 bits of entropy → ~20 bits of SAS entropy (sufficient for
    // visual verification during the short enrollment window).
    let sas_raw = u32::from_be_bytes(
        sas_bytes[..4]
            .try_into()
            .map_err(|_| EnrollmentError::InvalidInput("SAS derivation output too short"))?,
    );
    let sas_code = SasCode(sas_raw % 1_000_000);

    let enc_key = SymmetricKey::from_slice(&enc_key_bytes)?;
    let mac_key = SymmetricKey::from_slice(&mac_key_bytes)?;

    // shared, enc_key_bytes, mac_key_bytes, sas_bytes are dropped here;
    // shared is Zeroizing<[u8;32]>, enc_key_bytes/mac_key_bytes/sas_bytes are Vec<u8>
    // which will be deallocated. The Zeroizing wrapper ensures shared is zeroized.
    Ok(EnrollmentSession {
        enc_key,
        mac_key,
        sas_code,
    })
}

// ─── Shard transfer ───────────────────────────────────────────────────────

/// Encrypt a shard for transfer from existing device to new device.
///
/// Uses encrypt-then-MAC: AES-256-GCM(enc_key, shard) → ciphertext, then
/// HMAC-SHA256(mac_key, ciphertext) → authentication tag.
///
/// Returns a `ShardEnvelope` with the nonce, ciphertext+tag, and HMAC.
/// The envelope is 92 bytes: nonce(12) + ct+tag(48) + hmac(32).
pub fn encrypt_shard_for_transfer(
    shard: &SymmetricKey,
    enc_key: &SymmetricKey,
    mac_key: &SymmetricKey,
) -> Result<ShardEnvelope, EnrollmentError> {
    // Random nonce via OsRng, matching managed-mode encrypt pattern.
    let nonce = generate_nonce()?;
    let ciphertext = aes_gcm_encrypt_with_nonce(shard.as_bytes(), enc_key, &nonce)?;
    // HMAC covers nonce || ciphertext (spec-conform encrypt-then-MAC).
    // Including the nonce prevents an attacker from swapping nonces between envelopes.
    let mut hmac_input = Vec::with_capacity(12 + ciphertext.len());
    hmac_input.extend_from_slice(nonce.as_bytes());
    hmac_input.extend_from_slice(&ciphertext);
    let hmac = hmac_sha256(mac_key.as_bytes(), &hmac_input)?;
    Ok(ShardEnvelope {
        nonce,
        ciphertext,
        hmac,
    })
}

/// Decrypt a shard from a transfer envelope.
///
/// Verifies HMAC first (encrypt-then-MAC: verify MAC before decrypt).
/// If HMAC fails, returns `EnrollmentError::HmacMismatch` — the envelope
/// may have been tampered with in transit (or the mac_key is wrong, which
/// would indicate a SAS mismatch that should have been caught earlier).
///
/// Returns the decrypted shard as a `SymmetricKey` (32 bytes).
pub fn decrypt_shard_from_transfer(
    envelope: &ShardEnvelope,
    enc_key: &SymmetricKey,
    mac_key: &SymmetricKey,
) -> Result<SymmetricKey, EnrollmentError> {
    // Verify-then-decrypt: check HMAC before attempting decryption.
    // HMAC input is nonce || ciphertext to match encrypt_shard_for_transfer.
    let mut hmac_input = Vec::with_capacity(12 + envelope.ciphertext.len());
    hmac_input.extend_from_slice(envelope.nonce.as_bytes());
    hmac_input.extend_from_slice(&envelope.ciphertext);
    let computed_hmac = hmac_sha256(mac_key.as_bytes(), &hmac_input)?;
    if !constant_time_eq(&envelope.hmac, &computed_hmac) {
        return Err(EnrollmentError::HmacMismatch);
    }

    let plaintext = aes_gcm_decrypt(&envelope.ciphertext, &envelope.nonce, enc_key)?;
    let shard = SymmetricKey::from_slice(&plaintext)?;
    Ok(shard)
}

// ─── Variable-length payload transfer ─────────────────────────────────────

/// Maximum plaintext size accepted by the payload envelope helpers.
/// 64 KiB is ample for a provider-config JSON (OAuth blobs ≈ 2 KiB, S3 ≈ 1 KiB).
/// Rejecting larger inputs keeps an attacker from ballooning allocations before
/// the MAC check runs.
pub const MAX_PAYLOAD_PLAINTEXT_LEN: usize = 64 * 1024;

/// Encrypted variable-length payload transmitted alongside the enrollment shard.
///
/// Identical construction to `ShardEnvelope` (AES-GCM + HMAC-SHA256 over
/// nonce‖ciphertext) but ciphertext length is variable, so the wire header
/// includes a big-endian u32 length prefix.
///
/// Wire format: `nonce(12) + ct_len_be(4) + ciphertext+gcm_tag(ct_len) + hmac(32)`.
#[derive(Debug)]
pub struct PayloadEnvelope {
    /// 12-byte AES-GCM nonce.
    pub nonce: Nonce12,
    /// Variable-length AES-GCM ciphertext (includes the 16-byte GCM tag).
    pub ciphertext: Vec<u8>,
    /// 32-byte HMAC-SHA256 of `nonce ‖ ct_len_be ‖ ciphertext`.
    pub hmac: [u8; 32],
}

impl PayloadEnvelope {
    /// Serialize to the wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_len_be = (self.ciphertext.len() as u32).to_be_bytes();
        let mut out = Vec::with_capacity(12 + 4 + self.ciphertext.len() + 32);
        out.extend_from_slice(self.nonce.as_bytes());
        out.extend_from_slice(&ct_len_be);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.hmac);
        out
    }

    /// Parse the wire format. Caps ciphertext length to keep parsing cheap for
    /// adversarial inputs — the HMAC check happens after parsing, so allocating
    /// a multi-megabyte `Vec` before rejection is undesirable.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EnrollmentError> {
        const HEADER: usize = 12 + 4;
        const TRAILER: usize = 32;
        if data.len() < HEADER + 16 + TRAILER {
            return Err(EnrollmentError::InvalidInput(
                "payload envelope too short (< nonce+len+tag+hmac)",
            ));
        }
        let nonce_bytes: [u8; 12] = data[..12]
            .try_into()
            .map_err(|_| EnrollmentError::InvalidInput("nonce must be 12 bytes"))?;
        let ct_len_be: [u8; 4] = data[12..16]
            .try_into()
            .map_err(|_| EnrollmentError::InvalidInput("ct_len must be 4 bytes"))?;
        let ct_len = u32::from_be_bytes(ct_len_be) as usize;
        // Includes GCM tag: ct_len must cover at least 16 bytes of tag.
        if ct_len < 16 {
            return Err(EnrollmentError::InvalidInput(
                "ciphertext too short (must include GCM tag)",
            ));
        }
        // Plaintext == ct_len - 16. Enforce the same cap the encryptor uses so
        // a malicious sender can't flood the receiver with an oversize buffer.
        if ct_len - 16 > MAX_PAYLOAD_PLAINTEXT_LEN {
            return Err(EnrollmentError::InvalidInput(
                "payload envelope exceeds max plaintext size",
            ));
        }
        if data.len() != HEADER + ct_len + TRAILER {
            return Err(EnrollmentError::InvalidInput(
                "payload envelope length does not match ct_len",
            ));
        }
        let ciphertext = data[HEADER..HEADER + ct_len].to_vec();
        let hmac: [u8; 32] = data[HEADER + ct_len..]
            .try_into()
            .map_err(|_| EnrollmentError::InvalidInput("hmac must be 32 bytes"))?;
        Ok(PayloadEnvelope {
            nonce: Nonce12::new(nonce_bytes),
            ciphertext,
            hmac,
        })
    }
}

/// Encrypt an arbitrary-length payload (e.g. a ProviderConfig JSON) using the
/// same session keys as the shard transfer. The payload must be no larger than
/// `MAX_PAYLOAD_PLAINTEXT_LEN`.
///
/// HMAC input is `nonce ‖ ct_len_be ‖ ciphertext` — the length is committed so
/// a man-in-the-middle cannot truncate the ciphertext without detection.
pub fn encrypt_payload_for_transfer(
    payload: &[u8],
    enc_key: &SymmetricKey,
    mac_key: &SymmetricKey,
) -> Result<PayloadEnvelope, EnrollmentError> {
    if payload.len() > MAX_PAYLOAD_PLAINTEXT_LEN {
        return Err(EnrollmentError::InvalidInput(
            "payload exceeds max plaintext size",
        ));
    }
    let nonce = generate_nonce()?;
    let ciphertext = aes_gcm_encrypt_with_nonce(payload, enc_key, &nonce)?;
    let ct_len_be = (ciphertext.len() as u32).to_be_bytes();
    let mut hmac_input = Vec::with_capacity(12 + 4 + ciphertext.len());
    hmac_input.extend_from_slice(nonce.as_bytes());
    hmac_input.extend_from_slice(&ct_len_be);
    hmac_input.extend_from_slice(&ciphertext);
    let hmac = hmac_sha256(mac_key.as_bytes(), &hmac_input)?;
    Ok(PayloadEnvelope {
        nonce,
        ciphertext,
        hmac,
    })
}

/// Decrypt a variable-length payload. Verifies HMAC before decrypt.
pub fn decrypt_payload_from_transfer(
    envelope: &PayloadEnvelope,
    enc_key: &SymmetricKey,
    mac_key: &SymmetricKey,
) -> Result<Vec<u8>, EnrollmentError> {
    let ct_len_be = (envelope.ciphertext.len() as u32).to_be_bytes();
    let mut hmac_input = Vec::with_capacity(12 + 4 + envelope.ciphertext.len());
    hmac_input.extend_from_slice(envelope.nonce.as_bytes());
    hmac_input.extend_from_slice(&ct_len_be);
    hmac_input.extend_from_slice(&envelope.ciphertext);
    let computed_hmac = hmac_sha256(mac_key.as_bytes(), &hmac_input)?;
    if !constant_time_eq(&envelope.hmac, &computed_hmac) {
        return Err(EnrollmentError::HmacMismatch);
    }
    let plaintext = aes_gcm_decrypt(&envelope.ciphertext, &envelope.nonce, enc_key)?;
    if plaintext.len() > MAX_PAYLOAD_PLAINTEXT_LEN {
        // Belt-and-suspenders: reject impossibly-large outputs even if HMAC passed.
        return Err(EnrollmentError::InvalidInput(
            "decrypted payload exceeds max plaintext size",
        ));
    }
    Ok(plaintext)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::symmetric::generate_aes_key;

    // ─── Initiate ───────────────────────────────────────────────────────

    #[test]
    fn enrollment_initiate_returns_keypair_and_channel_id() {
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        assert_eq!(pk.len(), 32);
        assert_eq!(ch.len(), 16);
        // Two initiations should produce different keys and channel IDs
        let (sk2, pk2, ch2) = enrollment_initiate().unwrap();
        assert_ne!(pk, pk2);
        assert_ne!(ch, ch2);
        // Secret keys should also differ
        assert_ne!(sk.as_bytes(), sk2.as_bytes());
    }

    // ─── Derive session ────────────────────────────────────────────────

    #[test]
    fn enrollment_derive_session_produces_different_sas_on_mismatched_channel_ids() {
        // Regression: the WASM joiner used to call `enrollment_initiate` and
        // generate a fresh channel_id, ignoring the one in the QR payload.
        // The shared X25519 secret matches across the two sides (DH is
        // commutative), but channel_id is HKDF-info-mixed into the SAS
        // derivation, so the codes diverge — exactly the "different SAS on
        // each device" symptom users hit. `enrollment_join` (below) fixes
        // this by leaving channel_id generation to the initiator.
        let (a_sk, a_pk, ch_a) = enrollment_initiate().unwrap();
        let (b_sk, b_pk, ch_b) = enrollment_initiate().unwrap();
        assert_ne!(ch_a, ch_b);

        let session_a = enrollment_derive_session(&a_sk, &b_pk, &ch_a).unwrap();
        let session_b = enrollment_derive_session(&b_sk, &a_pk, &ch_b).unwrap();
        assert_ne!(session_a.sas_code().value(), session_b.sas_code().value());
    }

    #[test]
    fn enrollment_join_uses_initiator_channel_for_matching_sas() {
        let (a_sk, a_pk, ch) = enrollment_initiate().unwrap();
        let (b_sk, b_pk) = enrollment_join().unwrap();
        // Joiner reuses initiator's `ch` rather than minting its own.
        let session_a = enrollment_derive_session(&a_sk, &b_pk, &ch).unwrap();
        let session_b = enrollment_derive_session(&b_sk, &a_pk, &ch).unwrap();
        assert_eq!(session_a.sas_code().value(), session_b.sas_code().value());
        assert_eq!(
            session_a.enc_key().as_bytes(),
            session_b.enc_key().as_bytes()
        );
        assert_eq!(
            session_a.mac_key().as_bytes(),
            session_b.mac_key().as_bytes()
        );
    }

    #[test]
    fn enrollment_derive_session_produces_identical_keys_on_both_sides() {
        // Simulate both sides of the enrollment
        let (a_sk, a_pk, ch) = enrollment_initiate().unwrap();
        let (b_sk, b_pk, _ch) = enrollment_initiate().unwrap();

        let session_a = enrollment_derive_session(&a_sk, &b_pk, &ch).unwrap();
        let session_b = enrollment_derive_session(&b_sk, &a_pk, &ch).unwrap();

        // Both sides derive the same keys and SAS code
        assert_eq!(
            session_a.enc_key().as_bytes(),
            session_b.enc_key().as_bytes()
        );
        assert_eq!(
            session_a.mac_key().as_bytes(),
            session_b.mac_key().as_bytes()
        );
        assert_eq!(session_a.sas_code().value(), session_b.sas_code().value());
        assert_eq!(
            session_a.sas_code().to_string_padded(),
            session_b.sas_code().to_string_padded()
        );
    }

    #[test]
    fn sas_code_is_six_digits() {
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();
        let code = session.sas_code().value();
        assert!(code < 1_000_000, "SAS code must be < 1_000_000, got {code}");
        let formatted = session.sas_code().to_string_padded();
        assert_eq!(formatted.len(), 6);
        assert!(formatted.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn derive_session_wrong_peer_produces_different_keys() {
        let (a_sk, _a_pk, ch) = enrollment_initiate().unwrap();
        let (_b_sk, b_pk, _) = enrollment_initiate().unwrap();
        let (_c_sk, c_pk, _) = enrollment_initiate().unwrap();

        let session_ab = enrollment_derive_session(&a_sk, &b_pk, &ch).unwrap();
        let session_ac = enrollment_derive_session(&a_sk, &c_pk, &ch).unwrap();

        // Wrong peer → different keys, different SAS
        assert_ne!(
            session_ab.enc_key().as_bytes(),
            session_ac.enc_key().as_bytes()
        );
        assert_ne!(
            session_ab.mac_key().as_bytes(),
            session_ac.mac_key().as_bytes()
        );
        assert_ne!(session_ab.sas_code().value(), session_ac.sas_code().value());
    }

    #[test]
    fn derive_session_invalid_peer_pk_length_fails() {
        let (sk, _, ch) = enrollment_initiate().unwrap();
        assert!(enrollment_derive_session(&sk, &[0u8; 31], &ch).is_err());
        assert!(enrollment_derive_session(&sk, &[0u8; 33], &ch).is_err());
    }

    // ─── Shard transfer ────────────────────────────────────────────────

    #[test]
    fn shard_encrypt_decrypt_roundtrip() {
        let shard = generate_aes_key().unwrap();
        let (sk, _pk, ch) = enrollment_initiate().unwrap();
        let (_, peer_pk, _) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &peer_pk, &ch).unwrap();

        let envelope =
            encrypt_shard_for_transfer(&shard, session.enc_key(), session.mac_key()).unwrap();
        let decrypted =
            decrypt_shard_from_transfer(&envelope, session.enc_key(), session.mac_key()).unwrap();

        assert_eq!(shard.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn shard_envelope_is_92_bytes() {
        let shard = generate_aes_key().unwrap();
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();

        let envelope =
            encrypt_shard_for_transfer(&shard, session.enc_key(), session.mac_key()).unwrap();
        assert_eq!(envelope.ciphertext.len(), 48); // 32-byte shard + 16-byte GCM tag
        assert_eq!(envelope.to_bytes().len(), 92); // 12 + 48 + 32
    }

    #[test]
    fn shard_envelope_serialize_parse_roundtrip() {
        let shard = generate_aes_key().unwrap();
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();

        let envelope =
            encrypt_shard_for_transfer(&shard, session.enc_key(), session.mac_key()).unwrap();
        let bytes = envelope.to_bytes();
        let parsed = ShardEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.nonce.as_bytes(), envelope.nonce.as_bytes());
        assert_eq!(parsed.ciphertext, envelope.ciphertext);
        assert_eq!(parsed.hmac, envelope.hmac);

        let decrypted =
            decrypt_shard_from_transfer(&parsed, session.enc_key(), session.mac_key()).unwrap();
        assert_eq!(shard.as_bytes(), decrypted.as_bytes());
    }

    #[test]
    fn shard_decrypt_wrong_mac_key_rejected() {
        let shard = generate_aes_key().unwrap();
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();
        let wrong_mac = generate_aes_key().unwrap();

        let envelope =
            encrypt_shard_for_transfer(&shard, session.enc_key(), session.mac_key()).unwrap();

        let result = decrypt_shard_from_transfer(&envelope, session.enc_key(), &wrong_mac);
        assert!(matches!(result, Err(EnrollmentError::HmacMismatch)));
    }

    #[test]
    fn shard_decrypt_tampered_ciphertext_rejected() {
        let shard = generate_aes_key().unwrap();
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();

        let mut envelope =
            encrypt_shard_for_transfer(&shard, session.enc_key(), session.mac_key()).unwrap();

        // Tamper with ciphertext (but keep HMAC of original — should fail HMAC)
        envelope.ciphertext[0] ^= 0xff;
        let result = decrypt_shard_from_transfer(&envelope, session.enc_key(), session.mac_key());
        assert!(matches!(result, Err(EnrollmentError::HmacMismatch)));
    }

    #[test]
    fn shard_decrypt_wrong_enc_key_fails() {
        let shard = generate_aes_key().unwrap();
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();
        let wrong_enc = generate_aes_key().unwrap();

        let envelope =
            encrypt_shard_for_transfer(&shard, session.enc_key(), session.mac_key()).unwrap();

        // HMAC verifies (same mac_key), but AES-GCM decryption with wrong key fails
        let result = decrypt_shard_from_transfer(&envelope, &wrong_enc, session.mac_key());
        assert!(result.is_err());
    }

    #[test]
    fn shard_envelope_too_short_rejected() {
        assert!(ShardEnvelope::from_bytes(&[0u8; 91]).is_err());
        assert!(ShardEnvelope::from_bytes(&[0u8; 10]).is_err());
        assert!(ShardEnvelope::from_bytes(&[]).is_err());
    }

    // ─── Full two-party enrollment simulation ──────────────────────────

    #[test]
    fn full_two_party_enrollment_roundtrip() {
        // Device A (existing): initiate + display QR
        let (a_sk, a_pk, channel_id) = enrollment_initiate().unwrap();

        // Device B (new): scan QR + generate own keypair
        let (b_sk, b_pk, _) = enrollment_initiate().unwrap();

        // Both derive session keys from the other's public key (using the same channel_id)
        let session_a = enrollment_derive_session(&a_sk, &b_pk, &channel_id).unwrap();
        let session_b = enrollment_derive_session(&b_sk, &a_pk, &channel_id).unwrap();

        // SAS codes must match
        assert_eq!(session_a.sas_code().value(), session_b.sas_code().value());
        let sas = session_a.sas_code().to_string_padded();

        // User visually confirms SAS matches (simulated: they do match)
        assert_eq!(sas.len(), 6);

        // Device A encrypts shard for transfer
        let shard = generate_aes_key().unwrap();
        let envelope =
            encrypt_shard_for_transfer(&shard, session_a.enc_key(), session_a.mac_key()).unwrap();

        // Simulate relay: serialize → transmit → parse
        let wire_bytes = envelope.to_bytes();
        let received = ShardEnvelope::from_bytes(&wire_bytes).unwrap();

        // Device B decrypts shard
        let decrypted_shard =
            decrypt_shard_from_transfer(&received, session_b.enc_key(), session_b.mac_key())
                .unwrap();

        // Shard matches
        assert_eq!(shard.as_bytes(), decrypted_shard.as_bytes());

        // Channel ID was preserved through the exchange
        assert_eq!(channel_id.len(), 16);
    }

    #[test]
    fn sas_mismatch_means_different_keys() {
        // Simulate: attacker (M) intercepts and replaces B's public key
        let (a_sk, _a_pk, _) = enrollment_initiate().unwrap();
        let (_b_sk, b_pk, _) = enrollment_initiate().unwrap();
        let (_m_sk, m_pk, _) = enrollment_initiate().unwrap(); // MitM

        // A thinks it's talking to B (actually M's key injected)
        let ch = [0u8; 16];
        let session_a_real = enrollment_derive_session(&a_sk, &b_pk, &ch).unwrap();
        let session_a_mitm = enrollment_derive_session(&a_sk, &m_pk, &ch).unwrap();

        // SAS codes differ → user catches the MitM
        assert_ne!(
            session_a_real.sas_code().value(),
            session_a_mitm.sas_code().value()
        );
    }

    // ─── Debug formatting ──────────────────────────────────────────────

    #[test]
    fn enrollment_session_debug_redacts_keys() {
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();
        let debug_str = format!("{session:?}");
        assert!(debug_str.contains("[REDACTED]"));
        // SAS code is intentionally shown in debug (it's a short-lived verification code)
        assert!(debug_str.contains("sas_code"));
    }

    // ─── ShardEnvelope bounds ──────────────────────────────────────────

    #[test]
    fn shard_envelope_from_bytes_exact_92_ok() {
        let data = [0u8; 92];
        // Will fail HMAC (expected), but length check must pass.
        let result = ShardEnvelope::from_bytes(&data);
        // Either Ok (zero envelope) or Err from HMAC — NOT InvalidInput about length.
        if let Err(EnrollmentError::InvalidInput(msg)) = result {
            assert!(
                !msg.contains("exactly 92"),
                "length check should pass for 92 bytes"
            );
        }
        // Ok or other error — length accepted.
    }

    #[test]
    fn shard_envelope_from_bytes_too_short_rejected() {
        let data = [0u8; 91];
        match ShardEnvelope::from_bytes(&data) {
            Err(EnrollmentError::InvalidInput(msg)) => assert!(msg.contains("exactly 92")),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn shard_envelope_from_bytes_too_long_rejected() {
        let data = [0u8; 93];
        match ShardEnvelope::from_bytes(&data) {
            Err(EnrollmentError::InvalidInput(msg)) => assert!(msg.contains("exactly 92")),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    // ─── channel_id binding ────────────────────────────────────────────

    #[test]
    fn channel_id_bound_into_derivation() {
        // Different channel_ids must produce different session keys even with same DH pair.
        let (a_sk, a_pk, ch1) = enrollment_initiate().unwrap();
        let (_b_sk, b_pk, ch2) = enrollment_initiate().unwrap();

        let session1 = enrollment_derive_session(&a_sk, &b_pk, &ch1).unwrap();
        let session2 = enrollment_derive_session(&a_sk, &b_pk, &ch2).unwrap();

        assert_ne!(
            session1.enc_key().as_bytes(),
            session2.enc_key().as_bytes(),
            "enc_key must differ for different channel_ids"
        );
        assert_ne!(
            session1.mac_key().as_bytes(),
            session2.mac_key().as_bytes(),
            "mac_key must differ for different channel_ids"
        );
        // a_pk is unused here — suppress warning
        let _ = a_pk;
    }

    // ─── ShardEnvelope HMAC nonce coverage ────────────────────────────

    #[test]
    fn shard_hmac_covers_nonce() {
        // Build a valid envelope, then swap the nonce — HMAC should fail.
        let shard = generate_aes_key().unwrap();
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();

        let envelope =
            encrypt_shard_for_transfer(&shard, session.enc_key(), session.mac_key()).unwrap();

        // Tamper with the nonce bytes only (HMAC covers nonce || ciphertext).
        let tampered = ShardEnvelope {
            nonce: {
                let mut n = [0u8; 12];
                // Flip all bits of the nonce
                for (i, b) in envelope.nonce.as_bytes().iter().enumerate() {
                    n[i] = b ^ 0xff;
                }
                crate::crypto::zeroize_utils::Nonce12::new(n)
            },
            ciphertext: envelope.ciphertext.clone(),
            hmac: envelope.hmac,
        };
        let result = decrypt_shard_from_transfer(&tampered, session.enc_key(), session.mac_key());
        assert!(
            matches!(result, Err(EnrollmentError::HmacMismatch)),
            "nonce tampering must be caught by HMAC"
        );
    }

    // ─── PayloadEnvelope round-trip ────────────────────────────────────

    #[test]
    fn payload_envelope_roundtrip_matches_input() {
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();

        let payload = br#"{"type":"sftp","sftpHost":"example.com"}"#;
        let envelope =
            encrypt_payload_for_transfer(payload, session.enc_key(), session.mac_key()).unwrap();
        let wire = envelope.to_bytes();
        let parsed = PayloadEnvelope::from_bytes(&wire).unwrap();
        let decrypted =
            decrypt_payload_from_transfer(&parsed, session.enc_key(), session.mac_key()).unwrap();
        assert_eq!(decrypted.as_slice(), payload.as_slice());
    }

    #[test]
    fn payload_envelope_empty_plaintext_roundtrip() {
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();

        let envelope =
            encrypt_payload_for_transfer(&[], session.enc_key(), session.mac_key()).unwrap();
        let wire = envelope.to_bytes();
        let parsed = PayloadEnvelope::from_bytes(&wire).unwrap();
        let decrypted =
            decrypt_payload_from_transfer(&parsed, session.enc_key(), session.mac_key()).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn payload_envelope_rejects_oversize_plaintext() {
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();

        let payload = vec![0u8; MAX_PAYLOAD_PLAINTEXT_LEN + 1];
        let result = encrypt_payload_for_transfer(&payload, session.enc_key(), session.mac_key());
        assert!(matches!(result, Err(EnrollmentError::InvalidInput(_))));
    }

    #[test]
    fn payload_envelope_rejects_tampered_hmac() {
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();

        let mut envelope =
            encrypt_payload_for_transfer(b"hello", session.enc_key(), session.mac_key()).unwrap();
        envelope.hmac[0] ^= 0x01;
        let result = decrypt_payload_from_transfer(&envelope, session.enc_key(), session.mac_key());
        assert!(matches!(result, Err(EnrollmentError::HmacMismatch)));
    }

    #[test]
    fn payload_envelope_hmac_covers_length_prefix() {
        // Construct a valid envelope, then reduce ct_len to simulate a truncation
        // attack. HMAC must refuse because ct_len is committed into the MAC input.
        let (sk, pk, ch) = enrollment_initiate().unwrap();
        let session = enrollment_derive_session(&sk, &pk, &ch).unwrap();

        let envelope =
            encrypt_payload_for_transfer(&[42u8; 1024], session.enc_key(), session.mac_key())
                .unwrap();
        // Rewrite ct_len to a smaller value directly in the serialized bytes.
        let mut wire = envelope.to_bytes();
        // ct_len sits at bytes [12..16] big-endian.
        let truncated_len = (envelope.ciphertext.len() - 1) as u32;
        wire[12..16].copy_from_slice(&truncated_len.to_be_bytes());
        // Parsing now fails length-vs-total, not HMAC — verify we refuse.
        let parsed = PayloadEnvelope::from_bytes(&wire);
        assert!(matches!(parsed, Err(EnrollmentError::InvalidInput(_))));
    }

    #[test]
    fn payload_envelope_from_bytes_too_short_rejected() {
        assert!(PayloadEnvelope::from_bytes(&[0u8; 10]).is_err());
        assert!(PayloadEnvelope::from_bytes(&[]).is_err());
    }

    #[test]
    fn payload_envelope_from_bytes_oversize_ct_rejected() {
        // Forge a header claiming a 128 KiB ciphertext — larger than the cap.
        let mut forged = vec![0u8; 12 + 4];
        let huge_ct = (MAX_PAYLOAD_PLAINTEXT_LEN as u32 + 32).to_be_bytes();
        forged[12..16].copy_from_slice(&huge_ct);
        // Pad out so length checks fail the oversize branch first.
        forged.extend(vec![0u8; 32]);
        let result = PayloadEnvelope::from_bytes(&forged);
        assert!(matches!(result, Err(EnrollmentError::InvalidInput(_))));
    }
}
