// Private key re-encryption: decrypt with old KEK, re-encrypt with new KEK.
// Used when changing passwords or rotating keys.
// Input/output format: iv(12) || ciphertext+tag(N)

use zeroize::Zeroizing;

use crate::crypto::auth::{decrypt_with_key, encrypt_with_key, EncryptedBlob};
use crate::crypto::zeroize_utils::SymmetricKey;
use crate::error::CryptoError;

/// Re-encrypt an AES-256-GCM blob from `old_kek` to `new_kek`.
/// `encrypted_blob` must be in format: iv(12) || ciphertext+tag(N).
/// Returns new `iv(12) || ciphertext+tag(N)` with a fresh random IV.
pub fn reencrypt_private_key(
    encrypted_blob: &[u8],
    old_kek: &SymmetricKey,
    new_kek: &SymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    // Parse the encrypted blob
    let blob = EncryptedBlob::from_bytes(encrypted_blob)?;

    // Decrypt with old KEK
    let plaintext: Zeroizing<Vec<u8>> = decrypt_with_key(&blob, old_kek)?;

    // Re-encrypt with new KEK using a fresh IV
    let new_blob = encrypt_with_key(&plaintext, new_kek)?;

    Ok(new_blob.to_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::auth::encrypt_with_key;
    use crate::crypto::symmetric::generate_aes_key;

    #[test]
    fn reencrypt_roundtrip() {
        let old_kek = generate_aes_key().unwrap();
        let new_kek = generate_aes_key().unwrap();
        let plaintext = b"super secret private key bytes";

        let original = encrypt_with_key(plaintext, &old_kek).unwrap();
        let original_bytes = original.to_bytes();

        let reencrypted = reencrypt_private_key(&original_bytes, &old_kek, &new_kek).unwrap();

        // Verify re-encrypted version decrypts correctly with new KEK
        let new_blob = crate::crypto::auth::EncryptedBlob::from_bytes(&reencrypted).unwrap();
        let recovered = crate::crypto::auth::decrypt_with_key(&new_blob, &new_kek).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn reencrypt_uses_fresh_iv() {
        let old_kek = generate_aes_key().unwrap();
        let new_kek = generate_aes_key().unwrap();
        let plaintext = b"private key";

        let original = encrypt_with_key(plaintext, &old_kek).unwrap().to_bytes();
        let re1 = reencrypt_private_key(&original, &old_kek, &new_kek).unwrap();
        let re2 = reencrypt_private_key(&original, &old_kek, &new_kek).unwrap();

        // Different IVs → different ciphertexts (with overwhelming probability)
        assert_ne!(re1, re2);
    }

    #[test]
    fn reencrypt_wrong_old_key_fails() {
        let old_kek = generate_aes_key().unwrap();
        let wrong_kek = generate_aes_key().unwrap();
        let new_kek = generate_aes_key().unwrap();
        let original = encrypt_with_key(b"data", &old_kek).unwrap().to_bytes();
        assert!(reencrypt_private_key(&original, &wrong_kek, &new_kek).is_err());
    }

    #[test]
    fn reencrypt_too_short_fails() {
        let old_kek = generate_aes_key().unwrap();
        let new_kek = generate_aes_key().unwrap();
        assert!(reencrypt_private_key(&[0u8; 10], &old_kek, &new_kek).is_err());
    }
}
