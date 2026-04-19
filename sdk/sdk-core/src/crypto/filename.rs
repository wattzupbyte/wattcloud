// Filename and folder path encryption using AES-256-GCM-SIV.
// Nonce = HMAC-SHA256(key, plaintext)[0..12] — deterministic SIV property.
// Same filename + key always produces the same ciphertext (safe, by design).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::crypto::hashing::derive_siv_nonce;
use crate::crypto::zeroize_utils::SymmetricKey;
use crate::error::CryptoError;

/// Encrypt a filename. Returns `nonce(12) || ciphertext+tag`.
/// Deterministic: same `name` + `key` → same output.
pub fn encrypt_filename(name: &str, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
    let siv = derive_siv_nonce(key.as_bytes(), name.as_bytes())?;
    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let nonce = Nonce::from_slice(siv.as_bytes());
    let encrypted = cipher
        .encrypt(nonce, name.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut result = Vec::with_capacity(12 + encrypted.len());
    result.extend_from_slice(siv.as_bytes());
    result.extend_from_slice(&encrypted);
    Ok(result)
}

/// Decrypt a filename from `nonce(12) || ciphertext+tag`.
pub fn decrypt_filename(encrypted: &[u8], key: &SymmetricKey) -> Result<String, CryptoError> {
    if encrypted.len() < 12 + 16 {
        return Err(CryptoError::InvalidFormat(
            "encrypted filename too short".to_string(),
        ));
    }
    let siv = &encrypted[..12];
    let ciphertext = &encrypted[12..];

    let cipher =
        Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let nonce = Nonce::from_slice(siv);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    String::from_utf8(plaintext)
        .map_err(|_| CryptoError::InvalidFormat("filename is not valid UTF-8".to_string()))
}

/// Encrypt a folder path by encrypting each `/`-separated component individually.
/// Empty components (e.g. leading/trailing slashes) are preserved as-is.
/// Returns the encrypted components joined with `/`, each base64-like encoded via hex
/// — actually returns raw bytes joined by '/' where each component is hex-encoded encrypted bytes.
///
/// Note: In practice, the WASM layer base64-encodes each component before joining.
/// In sdk-core we return each component's bytes separately to keep the base64 boundary.
pub fn encrypt_folder_path(path: &str, key: &SymmetricKey) -> Result<Vec<Vec<u8>>, CryptoError> {
    if path.is_empty() {
        return Err(CryptoError::InvalidFormat("path is empty".to_string()));
    }
    let components: Vec<&str> = path.split('/').collect();
    let mut result = Vec::with_capacity(components.len());
    for component in components {
        if component.is_empty() {
            result.push(Vec::new());
        } else {
            result.push(encrypt_filename(component, key)?);
        }
    }
    Ok(result)
}

/// Decrypt a folder path from a slice of encrypted component bytes.
/// Each non-empty entry is decrypted; empty entries become empty strings.
pub fn decrypt_folder_path(
    encrypted_components: &[Vec<u8>],
    key: &SymmetricKey,
) -> Result<String, CryptoError> {
    let mut parts = Vec::with_capacity(encrypted_components.len());
    for component in encrypted_components {
        if component.is_empty() {
            parts.push(String::new());
        } else {
            parts.push(decrypt_filename(component, key)?);
        }
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::symmetric::generate_aes_key;

    #[test]
    fn filename_roundtrip() {
        let key = generate_aes_key().unwrap();
        let name = "document.pdf";
        let enc = encrypt_filename(name, &key).unwrap();
        let dec = decrypt_filename(&enc, &key).unwrap();
        assert_eq!(dec, name);
    }

    #[test]
    fn filename_deterministic() {
        let key = generate_aes_key().unwrap();
        let name = "test.txt";
        let enc1 = encrypt_filename(name, &key).unwrap();
        let enc2 = encrypt_filename(name, &key).unwrap();
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn different_filenames_different_ciphertext() {
        let key = generate_aes_key().unwrap();
        let enc1 = encrypt_filename("a.txt", &key).unwrap();
        let enc2 = encrypt_filename("b.txt", &key).unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn filename_wrong_key_fails() {
        let key1 = generate_aes_key().unwrap();
        let key2 = generate_aes_key().unwrap();
        let enc = encrypt_filename("secret.pdf", &key1).unwrap();
        assert!(decrypt_filename(&enc, &key2).is_err());
    }

    #[test]
    fn filename_too_short_fails() {
        let key = generate_aes_key().unwrap();
        assert!(decrypt_filename(&[0u8; 27], &key).is_err());
    }

    #[test]
    fn folder_path_roundtrip() {
        let key = generate_aes_key().unwrap();
        let path = "photos/2024/january";
        let enc_components = encrypt_folder_path(path, &key).unwrap();
        let dec = decrypt_folder_path(&enc_components, &key).unwrap();
        assert_eq!(dec, path);
    }

    #[test]
    fn folder_path_with_empty_component() {
        let key = generate_aes_key().unwrap();
        let path = "a//b";
        let enc = encrypt_folder_path(path, &key).unwrap();
        let dec = decrypt_folder_path(&enc, &key).unwrap();
        assert_eq!(dec, path);
    }

    #[test]
    fn empty_path_fails() {
        let key = generate_aes_key().unwrap();
        assert!(encrypt_folder_path("", &key).is_err());
    }

    #[test]
    fn filename_too_short_for_nonce_fails() {
        // Encrypted filename must be at least 12 (nonce) + 16 (tag) = 28 bytes
        let key = generate_aes_key().unwrap();
        assert!(decrypt_filename(&[0u8; 10], &key).is_err());
    }

    #[test]
    fn filename_unicode_roundtrip() {
        let key = generate_aes_key().unwrap();
        let name = "résumé_2024_日本語.pdf";
        let enc = encrypt_filename(name, &key).unwrap();
        let dec = decrypt_filename(&enc, &key).unwrap();
        assert_eq!(dec, name);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proptest_tests {
    use super::*;
    use crate::crypto::symmetric::generate_aes_key;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn filename_roundtrip_arbitrary(name in "[a-zA-Z0-9._\\-]{1,100}") {
            let key = generate_aes_key().unwrap();
            let enc = encrypt_filename(&name, &key).unwrap();
            let dec = decrypt_filename(&enc, &key).unwrap();
            prop_assert_eq!(dec, name);
        }

        #[test]
        fn filename_siv_is_deterministic(name in "[a-zA-Z0-9._\\-]{1,50}") {
            let key = generate_aes_key().unwrap();
            let enc1 = encrypt_filename(&name, &key).unwrap();
            let enc2 = encrypt_filename(&name, &key).unwrap();
            // SIV property: same key+name always produces same ciphertext
            prop_assert_eq!(enc1, enc2);
        }

        #[test]
        fn different_filenames_different_ciphertext(
            a in "[a-zA-Z]{3,20}",
            b in "[a-zA-Z]{3,20}"
        ) {
            prop_assume!(a != b);
            let key = generate_aes_key().unwrap();
            let enc_a = encrypt_filename(&a, &key).unwrap();
            let enc_b = encrypt_filename(&b, &key).unwrap();
            prop_assert_ne!(enc_a, enc_b);
        }
    }
}
