// AES-256-GCM encrypt/decrypt, key and nonce generation, v7 chunk nonce construction.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::zeroize_utils::{Nonce12, SymmetricKey};
use crate::error::CryptoError;

/// Generate a random 256-bit AES key using the OS CSPRNG.
pub fn generate_aes_key() -> Result<SymmetricKey, CryptoError> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Ok(SymmetricKey::new(key))
}

/// Generate a random 96-bit nonce using the OS CSPRNG.
pub fn generate_nonce() -> Result<Nonce12, CryptoError> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    Ok(Nonce12::new(nonce))
}

/// AES-256-GCM encrypt `plaintext` under `key` with a freshly generated nonce.
/// Returns `(ciphertext+tag, nonce)`.
pub fn aes_gcm_encrypt(
    plaintext: &[u8],
    key: &SymmetricKey,
) -> Result<(Vec<u8>, Nonce12), CryptoError> {
    let nonce = generate_nonce()?;
    let ct = aes_gcm_encrypt_with_nonce(plaintext, key, &nonce)?;
    Ok((ct, nonce))
}

/// AES-256-GCM encrypt `plaintext` under `key` with the given `nonce`.
/// Returns `ciphertext+tag`.
pub fn aes_gcm_encrypt_with_nonce(
    plaintext: &[u8],
    key: &SymmetricKey,
    nonce: &Nonce12,
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let nonce_obj = Nonce::from_slice(nonce.as_bytes());
    cipher
        .encrypt(nonce_obj, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// AES-256-GCM decrypt. `ciphertext` must include the 16-byte GCM authentication tag.
pub fn aes_gcm_decrypt(
    ciphertext: &[u8],
    nonce: &Nonce12,
    key: &SymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let nonce_obj = Nonce::from_slice(nonce.as_bytes());
    cipher
        .decrypt(nonce_obj, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Construct a v7 chunk nonce: file_iv XOR LE96(chunk_index).
/// Only the lower 4 bytes of the 12-byte IV are XORed with the 32-bit chunk index.
pub fn v7_chunk_nonce(file_iv: &Nonce12, chunk_index: u32) -> Nonce12 {
    let mut nonce = *file_iv.as_bytes();
    let idx_bytes = chunk_index.to_le_bytes();
    for i in 0..4 {
        nonce[i] ^= idx_bytes[i];
    }
    Nonce12::new(nonce)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_roundtrip() {
        let key = generate_aes_key().unwrap();
        let plaintext = b"hello, world!";
        let (ct, nonce) = aes_gcm_encrypt(plaintext, &key).unwrap();
        let pt = aes_gcm_decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn aes_gcm_wrong_key_fails() {
        let key1 = generate_aes_key().unwrap();
        let key2 = generate_aes_key().unwrap();
        let (ct, nonce) = aes_gcm_encrypt(b"secret", &key1).unwrap();
        assert!(aes_gcm_decrypt(&ct, &nonce, &key2).is_err());
    }

    #[test]
    fn aes_gcm_tampered_ciphertext_fails() {
        let key = generate_aes_key().unwrap();
        let (mut ct, nonce) = aes_gcm_encrypt(b"secret data", &key).unwrap();
        ct[0] ^= 0xff;
        assert!(aes_gcm_decrypt(&ct, &nonce, &key).is_err());
    }

    #[test]
    fn v7_chunk_nonce_index_zero_is_file_iv() {
        let iv = Nonce12::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let nonce = v7_chunk_nonce(&iv, 0);
        assert_eq!(nonce.as_bytes(), iv.as_bytes());
    }

    #[test]
    fn v7_chunk_nonce_different_per_index() {
        let iv = Nonce12::new([0u8; 12]);
        let n0 = v7_chunk_nonce(&iv, 0);
        let n1 = v7_chunk_nonce(&iv, 1);
        assert_ne!(n0.as_bytes(), n1.as_bytes());
    }

    #[test]
    fn v7_chunk_nonce_only_modifies_lower_4_bytes() {
        let iv = Nonce12::new([0u8; 12]);
        let n = v7_chunk_nonce(&iv, 1);
        assert_eq!(n.as_bytes()[0], 1);
        assert_eq!(&n.as_bytes()[4..], &[0u8; 8]);
    }

    #[test]
    fn aes_gcm_empty_plaintext() {
        let key = generate_aes_key().unwrap();
        let (ct, nonce) = aes_gcm_encrypt(b"", &key).unwrap();
        let pt = aes_gcm_decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, b"");
    }

    #[test]
    fn aes_gcm_tampered_nonce_fails() {
        let key = generate_aes_key().unwrap();
        let (ct, nonce) = aes_gcm_encrypt(b"test", &key).unwrap();
        let bytes = nonce.as_bytes();
        let mut modified = *bytes;
        modified[0] ^= 0xFF;
        let bad_nonce = Nonce12::new(modified);
        assert!(aes_gcm_decrypt(&ct, &bad_nonce, &key).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn aes_gcm_roundtrip_arbitrary(plaintext in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let key = generate_aes_key().unwrap();
            let (ct, nonce) = aes_gcm_encrypt(&plaintext, &key).unwrap();
            let pt = aes_gcm_decrypt(&ct, &nonce, &key).unwrap();
            prop_assert_eq!(pt, plaintext);
        }

        #[test]
        fn aes_gcm_ciphertext_differs_from_plaintext(plaintext in proptest::collection::vec(any::<u8>(), 1..100)) {
            let key = generate_aes_key().unwrap();
            let (ct, _) = aes_gcm_encrypt(&plaintext, &key).unwrap();
            // The ciphertext+tag is larger (16-byte tag) and differs from plaintext
            prop_assert_ne!(ct, plaintext);
        }

        #[test]
        fn two_encryptions_of_same_data_produce_different_ciphertexts(
            plaintext in proptest::collection::vec(any::<u8>(), 1..100)
        ) {
            let key = generate_aes_key().unwrap();
            let (ct1, _) = aes_gcm_encrypt(&plaintext, &key).unwrap();
            let (ct2, _) = aes_gcm_encrypt(&plaintext, &key).unwrap();
            // Different random nonces → different ciphertexts
            prop_assert_ne!(ct1, ct2);
        }
    }
}
