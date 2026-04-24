// Key hierarchy management.
//
// Implements key version wrap/unwrap using the KEK (Key Encryption Key).
// Keys are stored as base64 in API responses; callers (sdk-wasm) decode
// to bytes before calling these functions. No base64 in sdk-core.
//
// KeyStorage trait: platform-specific secure storage for decrypted key material.
// Web implementation (WebKeyStorage) lives in sdk-wasm.

use crate::crypto::auth::{decrypt_with_key, encrypt_with_key, EncryptedBlob};
use crate::crypto::zeroize_utils::{
    MlKemPublicKey, MlKemSecretKey, SymmetricKey, X25519PublicKey, X25519SecretKey,
};
use crate::error::{CryptoError, SdkError};

/// Platform abstraction trait for secure key storage.
/// Web implementation: keys stay in Web Worker memory.
/// Android implementation: Android Keystore (Phase 7+, out of scope).
pub trait KeyStorage: Send + Sync {
    /// Store a key version's decrypted key material.
    fn store(&self, version_id: &str, key_material: &[u8]) -> Result<(), SdkError>;
    /// Retrieve key material for a version.
    fn retrieve(&self, version_id: &str) -> Result<Option<Vec<u8>>, SdkError>;
    /// Delete a stored key version.
    fn delete(&self, version_id: &str) -> Result<(), SdkError>;
    /// Check if a key version is stored.
    fn exists(&self, version_id: &str) -> Result<bool, SdkError>;
}

/// Platform abstraction trait for trusted-device key storage.
///
/// The platform (browser/mobile) holds a non-extractable hardware-bound key.
/// The SDK never sees raw device key material — only the encrypted payload that
/// the platform produces.
///
/// Web implementation:
///   - `encrypt_and_store`: generates a non-extractable AES-256-GCM CryptoKey,
///     encrypts `plaintext` (the `client_kek_half`), stores the key in IndexedDB,
///     and returns `JSON { "iv": "<base64>", "ciphertext": "<base64>" }`.
///   - `load_and_decrypt`: loads the CryptoKey from IndexedDB and decrypts.
pub trait DeviceKeyStorage: Send + Sync {
    /// Encrypt `plaintext` with the device key and store the key securely.
    /// Returns the encrypted payload bytes (format is platform-defined).
    fn encrypt_and_store(&self, plaintext: &[u8]) -> Result<Vec<u8>, SdkError>;

    /// Load the device key and decrypt `encrypted_payload`.
    fn load_and_decrypt(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>, SdkError>;

    /// Return `true` if a device key exists in local storage.
    fn has_device_key(&self) -> Result<bool, SdkError>;

    /// Delete the stored device key.
    fn delete_device_key(&self) -> Result<(), SdkError>;

    /// Retrieve the stored device ID (e.g. from localStorage / preferences).
    fn get_device_id(&self) -> Result<Option<String>, SdkError>;

    /// Persist a device ID.
    fn set_device_id(&self, id: &str) -> Result<(), SdkError>;

    /// Clear all device data: key, device ID, and any other local device state.
    fn clear_all(&self) -> Result<(), SdkError>;
}

/// All key material for a single key version, decrypted and ready for use.
/// Secret fields are zeroized on drop via their inner types.
/// Clone is intentionally not implemented.
pub struct DecryptedKeyBundle {
    pub version_id: i64,
    pub mlkem_secret_key: MlKemSecretKey,
    pub x25519_secret_key: X25519SecretKey,
    pub mlkem_public_key: MlKemPublicKey,
    pub x25519_public_key: X25519PublicKey,
}

/// Raw encrypted key fields ready for API submission.
/// Callers (sdk-wasm) base64-encode these before JSON serialization.
pub struct EncryptedKeyFields {
    /// `iv(12) || ciphertext+tag` for the ML-KEM private key.
    pub mlkem_private_key_encrypted: Vec<u8>,
    /// `iv(12) || ciphertext+tag` for the X25519 private key.
    pub x25519_private_key_encrypted: Vec<u8>,
}

/// Decrypt a key version's private keys using a KEK.
///
/// All `*_bytes` parameters are raw bytes (base64 already decoded by the caller).
/// `mlkem_priv_encrypted` and `x25519_priv_encrypted` are in `iv(12) || ciphertext+tag` format.
pub fn decrypt_key_version(
    mlkem_pub_bytes: &[u8],
    x25519_pub_bytes: &[u8],
    mlkem_priv_encrypted: &[u8],
    x25519_priv_encrypted: &[u8],
    version_id: i64,
    kek: &SymmetricKey,
) -> Result<DecryptedKeyBundle, CryptoError> {
    let mlkem_blob = EncryptedBlob::from_bytes(mlkem_priv_encrypted)?;
    let x25519_blob = EncryptedBlob::from_bytes(x25519_priv_encrypted)?;

    let mlkem_sk_bytes = decrypt_with_key(&mlkem_blob, kek)?;
    let x25519_sk_bytes = decrypt_with_key(&x25519_blob, kek)?;

    Ok(DecryptedKeyBundle {
        version_id,
        mlkem_secret_key: MlKemSecretKey::from_slice(&mlkem_sk_bytes)?,
        x25519_secret_key: X25519SecretKey::from_slice(&x25519_sk_bytes)?,
        mlkem_public_key: MlKemPublicKey::from_slice(mlkem_pub_bytes)?,
        x25519_public_key: X25519PublicKey::from_slice(x25519_pub_bytes)?,
    })
}

/// Encrypt a keypair's private keys with a KEK for storage or API submission.
pub fn encrypt_key_version(
    mlkem_sk: &MlKemSecretKey,
    x25519_sk: &X25519SecretKey,
    kek: &SymmetricKey,
) -> Result<EncryptedKeyFields, CryptoError> {
    let mlkem_blob = encrypt_with_key(mlkem_sk.as_bytes(), kek)?;
    let x25519_blob = encrypt_with_key(x25519_sk.as_bytes(), kek)?;
    Ok(EncryptedKeyFields {
        mlkem_private_key_encrypted: mlkem_blob.to_bytes(),
        x25519_private_key_encrypted: x25519_blob.to_bytes(),
    })
}

/// Encrypt a keypair's private keys with a recovery KEK.
/// Produces the `mlkem_private_key_recovery_encrypted` /
/// `x25519_private_key_recovery_encrypted` fields for API submission.
pub fn encrypt_key_version_recovery(
    mlkem_sk: &MlKemSecretKey,
    x25519_sk: &X25519SecretKey,
    recovery_kek: &SymmetricKey,
) -> Result<EncryptedKeyFields, CryptoError> {
    encrypt_key_version(mlkem_sk, x25519_sk, recovery_kek)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::pqc::generate_hybrid_keypair;
    use crate::crypto::symmetric::generate_aes_key;

    #[test]
    fn encrypt_decrypt_key_version_roundtrip() {
        let kp = generate_hybrid_keypair().unwrap();
        let kek = generate_aes_key().unwrap();

        let encrypted =
            encrypt_key_version(&kp.mlkem_secret_key, &kp.x25519_secret_key, &kek).unwrap();

        let bundle = decrypt_key_version(
            kp.mlkem_public_key.as_bytes(),
            kp.x25519_public_key.as_bytes(),
            &encrypted.mlkem_private_key_encrypted,
            &encrypted.x25519_private_key_encrypted,
            42,
            &kek,
        )
        .unwrap();

        assert_eq!(bundle.version_id, 42);
        assert_eq!(
            bundle.mlkem_secret_key.as_bytes(),
            kp.mlkem_secret_key.as_bytes()
        );
        assert_eq!(
            bundle.x25519_secret_key.as_bytes(),
            kp.x25519_secret_key.as_bytes()
        );
        assert_eq!(
            bundle.mlkem_public_key.as_bytes(),
            kp.mlkem_public_key.as_bytes()
        );
        assert_eq!(
            bundle.x25519_public_key.as_bytes(),
            kp.x25519_public_key.as_bytes()
        );
    }

    #[test]
    fn wrong_kek_fails_decryption() {
        let kp = generate_hybrid_keypair().unwrap();
        let kek = generate_aes_key().unwrap();
        let wrong_kek = generate_aes_key().unwrap();

        let encrypted =
            encrypt_key_version(&kp.mlkem_secret_key, &kp.x25519_secret_key, &kek).unwrap();

        let result = decrypt_key_version(
            kp.mlkem_public_key.as_bytes(),
            kp.x25519_public_key.as_bytes(),
            &encrypted.mlkem_private_key_encrypted,
            &encrypted.x25519_private_key_encrypted,
            1,
            &wrong_kek,
        );

        assert!(result.is_err());
    }

    #[test]
    fn recovery_encrypt_decrypt_roundtrip() {
        let kp = generate_hybrid_keypair().unwrap();
        let recovery_kek = generate_aes_key().unwrap();
        let normal_kek = generate_aes_key().unwrap();

        let recovery_encrypted = encrypt_key_version_recovery(
            &kp.mlkem_secret_key,
            &kp.x25519_secret_key,
            &recovery_kek,
        )
        .unwrap();

        // Decrypt with recovery kek succeeds
        let bundle = decrypt_key_version(
            kp.mlkem_public_key.as_bytes(),
            kp.x25519_public_key.as_bytes(),
            &recovery_encrypted.mlkem_private_key_encrypted,
            &recovery_encrypted.x25519_private_key_encrypted,
            1,
            &recovery_kek,
        )
        .unwrap();
        assert_eq!(
            bundle.mlkem_secret_key.as_bytes(),
            kp.mlkem_secret_key.as_bytes()
        );

        // Decrypt with normal kek fails
        assert!(decrypt_key_version(
            kp.mlkem_public_key.as_bytes(),
            kp.x25519_public_key.as_bytes(),
            &recovery_encrypted.mlkem_private_key_encrypted,
            &recovery_encrypted.x25519_private_key_encrypted,
            1,
            &normal_kek,
        )
        .is_err());
    }
}
