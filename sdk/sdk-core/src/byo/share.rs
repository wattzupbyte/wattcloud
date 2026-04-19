// P10 E2E share link serialisation, deserialisation, and key wrapping.
//
// Two variants:
//   Variant A  — raw content_key in URL fragment: `k=<base64url(content_key)>`
//   Variant A+ — password-wrapped:
//                `s=<base64url(salt)>&e=<base64url(nonce || ciphertext+tag)>`
//                salt: 16 random bytes
//                share_key = Argon2id(password, salt, m=65536, t=3, p=4) → 32 bytes
//                encrypted_ck = AES-GCM(share_key, random_nonce, content_key)
//
// No base64 in the core logic — encoding/decoding is done at the boundary here
// because share fragments are inherently a serialisation concern (URL strings),
// not raw key material passed between SDK layers.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::symmetric::{aes_gcm_decrypt, aes_gcm_encrypt_with_nonce, generate_nonce};
use crate::crypto::zeroize_utils::{Nonce12, SymmetricKey};
use crate::error::CryptoError;

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("invalid fragment: {0}")]
    InvalidFragment(String),
    #[error("wrong password or corrupted data")]
    WrongPassword,
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

// ─── Argon2id parameters (managed-mode account login parameters) ──────────────

const SHARE_ARGON2_MEMORY_KB: u32 = 65536; // 64 MB
const SHARE_ARGON2_ITERATIONS: u32 = 3;
const SHARE_ARGON2_PARALLELISM: u32 = 4;
const SHARE_ARGON2_OUTPUT_LEN: usize = 32;

/// Derive a 32-byte share_key using Argon2id.
/// Salt must be exactly 16 bytes (valid for argon2 crate; ≥ 8 bytes required).
fn argon2id_share_key(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, ShareError> {
    let params = Params::new(
        SHARE_ARGON2_MEMORY_KB,
        SHARE_ARGON2_ITERATIONS,
        SHARE_ARGON2_PARALLELISM,
        Some(SHARE_ARGON2_OUTPUT_LEN),
    )
    .map_err(|_| ShareError::Crypto(CryptoError::KdfFailed))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, output.as_mut())
        .map_err(|_| ShareError::Crypto(CryptoError::KdfFailed))?;

    Ok(output)
}

// ─── Variant A ────────────────────────────────────────────────────────────────

/// Encode a raw `content_key` as a Variant A fragment string `"k=<base64url>"`.
pub fn encode_variant_a(content_key: &[u8; 32]) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(content_key);
    format!("k={encoded}")
}

/// Decode a Variant A fragment `"k=<base64url>"`.
/// Returns the 32-byte `content_key`.
pub fn decode_variant_a(fragment: &str) -> Result<[u8; 32], ShareError> {
    let encoded = fragment
        .strip_prefix("k=")
        .ok_or_else(|| ShareError::InvalidFragment("missing k= prefix".to_string()))?;

    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ShareError::InvalidFragment("base64url decode failed".to_string()))?;

    bytes
        .as_slice()
        .try_into()
        .map_err(|_| ShareError::InvalidFragment("content_key must be 32 bytes".to_string()))
}

// ─── Variant A+ ───────────────────────────────────────────────────────────────

/// Wrap `content_key` with `password` using Argon2id + AES-GCM.
/// Returns `(salt_b64url, encrypted_ck_b64url)` where:
///   - `salt_b64url` = base64url(16-byte random salt)
///   - `encrypted_ck_b64url` = base64url(nonce(12) || ciphertext+tag(48)) = 60 bytes total
pub fn wrap_key_with_password(
    content_key: &[u8; 32],
    password: &str,
) -> Result<(String, String), ShareError> {
    // Generate random 16-byte salt.
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Derive share_key.
    let share_key_bytes = argon2id_share_key(password.as_bytes(), &salt)?;
    let share_key = SymmetricKey::from_slice(share_key_bytes.as_ref())?;

    // Generate random 12-byte nonce.
    let nonce = generate_nonce()?;

    // Encrypt: AES-GCM(share_key, nonce, content_key) → ciphertext+tag (48 bytes).
    let ciphertext = aes_gcm_encrypt_with_nonce(content_key, &share_key, &nonce)?;

    // Prepend nonce to ciphertext: nonce(12) || ct+tag(48) = 60 bytes.
    let mut encrypted_ck = Vec::with_capacity(12 + ciphertext.len());
    encrypted_ck.extend_from_slice(nonce.as_bytes());
    encrypted_ck.extend_from_slice(&ciphertext);

    let salt_b64 = URL_SAFE_NO_PAD.encode(salt);
    let encrypted_ck_b64 = URL_SAFE_NO_PAD.encode(&encrypted_ck);

    Ok((salt_b64, encrypted_ck_b64))
}

/// Unwrap a password-protected `content_key`.
/// `encrypted_ck_b64url` is base64url(nonce(12) || ciphertext+tag(48)).
/// Returns `CryptoError::DecryptionFailed` (wrapped as `ShareError::WrongPassword`) on mismatch.
pub fn unwrap_key_with_password(
    salt_b64url: &str,
    encrypted_ck_b64url: &str,
    password: &str,
) -> Result<[u8; 32], ShareError> {
    // Decode salt.
    let salt_bytes = URL_SAFE_NO_PAD
        .decode(salt_b64url)
        .map_err(|_| ShareError::InvalidFragment("salt base64url decode failed".to_string()))?;
    let salt: [u8; 16] = salt_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ShareError::InvalidFragment("salt must be 16 bytes".to_string()))?;

    // Decode encrypted_ck.
    let enc_bytes = URL_SAFE_NO_PAD
        .decode(encrypted_ck_b64url)
        .map_err(|_| ShareError::InvalidFragment("encrypted_ck base64url decode failed".to_string()))?;

    if enc_bytes.len() < 12 {
        return Err(ShareError::InvalidFragment(
            "encrypted_ck too short".to_string(),
        ));
    }
    let nonce = Nonce12::from_slice(&enc_bytes[..12])?;
    let ciphertext = &enc_bytes[12..];

    // Derive share_key.
    let share_key_bytes = argon2id_share_key(password.as_bytes(), &salt)?;
    let share_key = SymmetricKey::from_slice(share_key_bytes.as_ref())?;

    // Decrypt; map decryption failure to WrongPassword.
    let plaintext = aes_gcm_decrypt(ciphertext, &nonce, &share_key)
        .map_err(|_| ShareError::WrongPassword)?;

    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| ShareError::InvalidFragment("decrypted key must be 32 bytes".to_string()))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_variant_a_roundtrip() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let fragment = encode_variant_a(&key);
        assert!(fragment.starts_with("k="), "fragment: {fragment}");
        let decoded = decode_variant_a(&fragment).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn wrap_unwrap_password_roundtrip() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 3) as u8);
        let password = "hunter2-correct-horse";
        let (salt_b64, enc_b64) = wrap_key_with_password(&key, password).unwrap();
        let recovered = unwrap_key_with_password(&salt_b64, &enc_b64, password).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn unwrap_wrong_password_fails() {
        let key: [u8; 32] = [0xab; 32];
        let (salt_b64, enc_b64) = wrap_key_with_password(&key, "correct-password").unwrap();
        let result = unwrap_key_with_password(&salt_b64, &enc_b64, "wrong-password");
        assert!(
            matches!(result, Err(ShareError::WrongPassword)),
            "expected WrongPassword, got {result:?}",
        );
    }

    #[test]
    fn decode_invalid_fragment_fails() {
        assert!(decode_variant_a("not-a-valid-fragment").is_err());
        assert!(decode_variant_a("k=!!!notbase64!!!").is_err());
        // 31 bytes instead of 32
        let short = URL_SAFE_NO_PAD.encode([0u8; 31]);
        assert!(decode_variant_a(&format!("k={short}")).is_err());
    }
}
