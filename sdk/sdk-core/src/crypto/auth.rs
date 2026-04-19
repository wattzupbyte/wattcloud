// Authentication key derivation and symmetric encryption for key material storage.
// All functions operate on raw bytes — no base64 in sdk-core.

use zeroize::Zeroizing;

use crate::crypto::kdf::{argon2id_derive, derive_auth_hash, derive_encryption_key};
use crate::crypto::symmetric::{aes_gcm_decrypt, aes_gcm_encrypt_with_nonce, generate_nonce};
use crate::crypto::zeroize_utils::{Argon2Output, Nonce12, SymmetricKey};
use crate::error::CryptoError;

/// Result of key derivation from a password + salt.
pub struct AuthKeys {
    /// HKDF-derived hash sent to server for authentication.
    pub auth_hash: [u8; 32],
    /// HKDF-derived encryption key for master secret encryption.
    pub encryption_key: SymmetricKey,
    /// Raw Argon2id output — caller uses this to derive client_kek_half.
    /// Zeroized on drop.
    pub argon_output: Argon2Output,
}

/// AES-256-GCM encrypted blob: IV prepended.
/// Format: iv(12) || ciphertext+tag(N+16)
pub struct EncryptedBlob {
    pub iv: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    /// Serialize to `iv || ciphertext+tag`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(12 + self.ciphertext.len());
        v.extend_from_slice(&self.iv);
        v.extend_from_slice(&self.ciphertext);
        v
    }

    /// Parse from `iv || ciphertext+tag`. Minimum 12 + 16 = 28 bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 28 {
            return Err(CryptoError::InvalidFormat(
                "encrypted blob too short".to_string(),
            ));
        }
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&data[..12]);
        Ok(Self {
            iv,
            ciphertext: data[12..].to_vec(),
        })
    }
}

/// Derive auth hash and encryption key from password + salt.
/// `password` is the raw UTF-8 password bytes.
/// `salt` is exactly 32 bytes.
pub fn derive_auth_and_encryption_keys(
    password: &[u8],
    salt: &[u8],
) -> Result<AuthKeys, CryptoError> {
    let argon_output = argon2id_derive(password, salt)?;
    let auth_hash = derive_auth_hash(&argon_output)?;
    let encryption_key = derive_encryption_key(&argon_output)?;
    Ok(AuthKeys {
        auth_hash,
        encryption_key,
        argon_output,
    })
}

/// Verify a password against a stored auth hash.
pub fn verify_auth_hash(
    password: &[u8],
    salt: &[u8],
    expected: &[u8],
) -> Result<bool, CryptoError> {
    use crate::crypto::hashing::constant_time_eq;
    let argon_output = argon2id_derive(password, salt)?;
    let computed = derive_auth_hash(&argon_output)?;
    Ok(constant_time_eq(&computed, expected))
}

/// Encrypt `plaintext` under `key` with a fresh random nonce.
/// Returns an `EncryptedBlob` (iv + ciphertext+tag).
pub fn encrypt_with_key(
    plaintext: &[u8],
    key: &SymmetricKey,
) -> Result<EncryptedBlob, CryptoError> {
    let nonce = generate_nonce()?;
    let ciphertext = aes_gcm_encrypt_with_nonce(plaintext, key, &nonce)?;
    Ok(EncryptedBlob {
        iv: *nonce.as_bytes(),
        ciphertext,
    })
}

/// Decrypt an `EncryptedBlob` under `key`.
/// Returns the plaintext. Caller is responsible for zeroizing if sensitive.
pub fn decrypt_with_key(
    encrypted: &EncryptedBlob,
    key: &SymmetricKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let nonce = Nonce12::new(encrypted.iv);
    let plaintext = aes_gcm_decrypt(&encrypted.ciphertext, &nonce, key)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_salt() -> [u8; 32] {
        [0x11u8; 32]
    }

    #[test]
    fn derive_keys_is_deterministic() {
        let keys1 = derive_auth_and_encryption_keys(b"password", &test_salt()).unwrap();
        let keys2 = derive_auth_and_encryption_keys(b"password", &test_salt()).unwrap();
        assert_eq!(keys1.auth_hash, keys2.auth_hash);
        assert_eq!(
            keys1.encryption_key.as_bytes(),
            keys2.encryption_key.as_bytes()
        );
    }

    #[test]
    fn verify_auth_hash_correct() {
        let salt = test_salt();
        let keys = derive_auth_and_encryption_keys(b"mypassword", &salt).unwrap();
        assert!(verify_auth_hash(b"mypassword", &salt, &keys.auth_hash).unwrap());
    }

    #[test]
    fn verify_auth_hash_wrong_password_fails() {
        let salt = test_salt();
        let keys = derive_auth_and_encryption_keys(b"correct", &salt).unwrap();
        assert!(!verify_auth_hash(b"wrong", &salt, &keys.auth_hash).unwrap());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = crate::crypto::symmetric::generate_aes_key().unwrap();
        let plaintext = b"sensitive key material";
        let blob = encrypt_with_key(plaintext, &key).unwrap();
        let decrypted = decrypt_with_key(&blob, &key).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn encrypted_blob_to_from_bytes() {
        let key = crate::crypto::symmetric::generate_aes_key().unwrap();
        let blob = encrypt_with_key(b"data", &key).unwrap();
        let serialized = blob.to_bytes();
        let parsed = EncryptedBlob::from_bytes(&serialized).unwrap();
        let decrypted = decrypt_with_key(&parsed, &key).unwrap();
        assert_eq!(decrypted.as_slice(), b"data");
    }

    #[test]
    fn from_bytes_too_short_fails() {
        assert!(EncryptedBlob::from_bytes(&[0u8; 27]).is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = crate::crypto::symmetric::generate_aes_key().unwrap();
        let key2 = crate::crypto::symmetric::generate_aes_key().unwrap();
        let blob = encrypt_with_key(b"data", &key1).unwrap();
        assert!(decrypt_with_key(&blob, &key2).is_err());
    }
}
