// Parameterised vault-body encryption/decryption for R6 multi-vault architecture.
//
// These functions accept an explicit AEAD key so the caller can supply either:
//   - The manifest AEAD key  (derived via `per_vault_key::derive_manifest_aead_key`)
//   - A per-provider AEAD key (derived via `per_vault_key::derive_per_vault_aead_key`)
//
// Wire format for the opaque blob returned / consumed by these functions:
//   [ body_iv (12 bytes) | body_ciphertext_with_gcm_tag (n + 16 bytes) ]
//
// The GCM tag embedded in `body_ciphertext_with_gcm_tag` provides both
// confidentiality and integrity.  No separate HMAC is added.
//
// Follows sdk-core conventions (no panics, no base64, zeroize-on-drop).

use crate::crypto::symmetric::{aes_gcm_decrypt, aes_gcm_encrypt_with_nonce, generate_nonce};
use crate::crypto::zeroize_utils::{Nonce12, SymmetricKey};
use crate::error::CryptoError;
use zeroize::Zeroizing;

/// Encrypt `plaintext` with `aead_key` using AES-256-GCM.
///
/// Returns the wire blob `[ iv (12) | ciphertext_with_tag (n + 16) ]`.
/// A fresh random nonce is generated for each call.
pub fn encrypt_body(plaintext: &[u8], aead_key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
    let nonce = generate_nonce()?;
    let ct = aes_gcm_encrypt_with_nonce(plaintext, aead_key, &nonce)?;

    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(nonce.as_bytes());
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Decrypt a wire blob produced by `encrypt_body`.
///
/// Expects `blob = [ iv (12) | ciphertext_with_tag (n + 16) ]`.
/// Returns the decrypted plaintext, or an error if the GCM tag fails.
/// The returned `Zeroizing<Vec<u8>>` is scrubbed on drop.
pub fn decrypt_body(
    blob: &[u8],
    aead_key: &SymmetricKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < 28 {
        // 12 iv + 16 tag minimum; no plaintext = 28 bytes
        return Err(CryptoError::InvalidFormat(
            "vault body blob too short (need at least 28 bytes)".into(),
        ));
    }
    let iv: [u8; 12] = blob[..12]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat("iv extraction failed".into()))?;
    let nonce = Nonce12::new(iv);
    let plaintext = aes_gcm_decrypt(&blob[12..], &nonce, aead_key)?;
    Ok(Zeroizing::new(plaintext))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::symmetric::generate_aes_key;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_aes_key().unwrap();
        let plaintext = b"CREATE TABLE files (id INTEGER PRIMARY KEY);";

        let blob = encrypt_body(plaintext, &key).unwrap();
        assert!(blob.len() >= 28, "blob must be at least 28 bytes");
        assert_eq!(blob.len(), 12 + plaintext.len() + 16);

        let recovered = decrypt_body(&blob, &key).unwrap();
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = generate_aes_key().unwrap();
        let wrong = generate_aes_key().unwrap();
        let blob = encrypt_body(b"secret sqlite data", &key).unwrap();
        assert!(decrypt_body(&blob, &wrong).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_aes_key().unwrap();
        let mut blob = encrypt_body(b"some data", &key).unwrap();
        // Flip a bit in the ciphertext portion
        if let Some(b) = blob.get_mut(20) {
            *b ^= 0xFF;
        }
        assert!(decrypt_body(&blob, &key).is_err());
    }

    #[test]
    fn tampered_iv_fails() {
        let key = generate_aes_key().unwrap();
        let mut blob = encrypt_body(b"some data", &key).unwrap();
        // Flip a bit in the IV portion
        if let Some(b) = blob.get_mut(3) {
            *b ^= 0xFF;
        }
        assert!(decrypt_body(&blob, &key).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = generate_aes_key().unwrap();
        let blob = encrypt_body(&[], &key).unwrap();
        assert_eq!(blob.len(), 28); // 12 iv + 0 data + 16 tag
        let recovered = decrypt_body(&blob, &key).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn blob_too_short_rejected() {
        let key = generate_aes_key().unwrap();
        assert!(decrypt_body(&[0u8; 27], &key).is_err());
        assert!(decrypt_body(&[], &key).is_err());
    }

    #[test]
    fn fresh_nonce_each_call() {
        let key = generate_aes_key().unwrap();
        let data = b"determinism test";
        let b1 = encrypt_body(data, &key).unwrap();
        let b2 = encrypt_body(data, &key).unwrap();
        // Different nonces → different ciphertexts (with overwhelming probability)
        assert_ne!(&b1[..12], &b2[..12], "nonces should differ across calls");
        assert_ne!(
            &b1[12..],
            &b2[12..],
            "ciphertexts should differ across calls"
        );
    }
}
