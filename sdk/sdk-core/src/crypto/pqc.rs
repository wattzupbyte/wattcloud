// ML-KEM-1024 + X25519 hybrid KEM (v6 construction, reused by v7 wire format).
// No classical-only fallback: both components must succeed.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::array::Array;
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params};
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::constants::V6;
use crate::crypto::zeroize_utils::{
    HybridKeypair, MlKemPublicKey, MlKemSecretKey, SymmetricKey, X25519PublicKey, X25519SecretKey,
};
use crate::error::CryptoError;

type MlKem1024EncKey = EncapsulationKey<MlKem1024Params>;
type MlKem1024DecKey = DecapsulationKey<MlKem1024Params>;

/// Result of v6 hybrid KEM encapsulation.
pub struct HybridEncapResultV6 {
    /// Ephemeral X25519 public key (32 bytes).
    pub eph_x25519_pub: [u8; 32],
    /// ML-KEM-1024 ciphertext (1568 bytes).
    pub mlkem_ciphertext: Vec<u8>,
    /// AES-GCM encrypted content key: wrapping_iv(12) || AES-GCM(wrapping_key, content_key)(48) = 60 bytes.
    pub encrypted_file_key: Vec<u8>,
    /// Plaintext content key (32 bytes) — held in memory for immediate use, zeroized on drop.
    pub content_key: SymmetricKey,
    /// HMAC key (32 bytes) — held in memory for immediate use.
    pub hmac_key: SymmetricKey,
}

/// Generate a random ML-KEM-1024 + X25519 hybrid keypair.
pub fn generate_hybrid_keypair() -> Result<HybridKeypair, CryptoError> {
    let (mlkem_dk, mlkem_ek) = MlKem1024::generate(&mut OsRng);
    let mlkem_pub = MlKemPublicKey::new(mlkem_ek.as_bytes().to_vec());
    let mlkem_sec = MlKemSecretKey::new(mlkem_dk.as_bytes().to_vec());

    let x25519_sec = StaticSecret::random_from_rng(OsRng);
    let x25519_pub = PublicKey::from(&x25519_sec);

    Ok(HybridKeypair {
        mlkem_public_key: mlkem_pub,
        mlkem_secret_key: mlkem_sec,
        x25519_public_key: X25519PublicKey::new(*x25519_pub.as_bytes()),
        x25519_secret_key: X25519SecretKey::new(*x25519_sec.as_bytes()),
    })
}

/// Derive ML-KEM-1024 public key from a secret (decapsulation) key.
pub fn derive_mlkem_public_key(secret_key: &MlKemSecretKey) -> Result<MlKemPublicKey, CryptoError> {
    let sk_bytes: [u8; 3168] = secret_key
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let dk = MlKem1024DecKey::from_bytes(&Array::from(sk_bytes));
    let ek = dk.encapsulation_key();
    Ok(MlKemPublicKey::new(ek.as_bytes().to_vec()))
}

/// V6 hybrid KEM encapsulation.
/// Derives wrapping_key + hmac_key via HKDF(x25519_ss || mlkem_ss, info=V6, L=64).
/// Content key is random and encrypted under wrapping_key.
pub fn hybrid_encapsulate_v6(
    mlkem_pub: &MlKemPublicKey,
    x25519_pub: &X25519PublicKey,
) -> Result<HybridEncapResultV6, CryptoError> {
    // X25519 ephemeral key exchange
    let recipient_pub = PublicKey::from(*x25519_pub.as_bytes());
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let x25519_ss = Zeroizing::new(eph_secret.diffie_hellman(&recipient_pub));

    // ML-KEM-1024 encapsulation
    let pk_bytes: [u8; 1568] = mlkem_pub
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let mlkem_ek = MlKem1024EncKey::from_bytes(&Array::from(pk_bytes));
    let (mlkem_ct, mlkem_ss) = mlkem_ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CryptoError::KemEncapFailed)?;

    // Combine shared secrets: x25519_ss || mlkem_ss → HKDF-SHA256(V6, L=64)
    let mut combined_ikm = Zeroizing::new(Vec::with_capacity(64));
    combined_ikm.extend_from_slice(x25519_ss.as_bytes());
    combined_ikm.extend_from_slice(mlkem_ss.as_ref());

    // HKDF salt: RFC 5869 recommends a salt when IKM may have low entropy.
    // Here IKM = x25519_ss(32B) || mlkem_ss(32B) — both are independent high-entropy
    // KEM outputs, so omitting the salt is safe per RFC 5869 §3.1. A salt would be
    // a defense-in-depth improvement, but requires a wire-format version bump to
    // avoid breaking decryption of existing V7 ciphertexts. Deferred to V8.
    let hkdf = Hkdf::<Sha256>::new(None, &combined_ikm);
    let mut derived = Zeroizing::new([0u8; 64]);
    hkdf.expand(V6, derived.as_mut())
        .map_err(|_| CryptoError::KdfFailed)?;

    let mut wrapping_key = Zeroizing::new([0u8; 32]);
    wrapping_key.copy_from_slice(&derived[..32]);
    let mut hmac_raw = [0u8; 32];
    hmac_raw.copy_from_slice(&derived[32..64]);

    // Generate random content key
    let content_key = crate::crypto::symmetric::generate_aes_key()?;

    // Wrap content_key: wrapping_iv(12) || AES-GCM(wrapping_key, content_key)(48) = 60 bytes
    let mut wrapping_iv_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut wrapping_iv_bytes);
    let wrapping_cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let wrapping_nonce = Nonce::from_slice(&wrapping_iv_bytes);
    let wrapped = wrapping_cipher
        .encrypt(wrapping_nonce, content_key.as_bytes().as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut encrypted_file_key = Vec::with_capacity(60);
    encrypted_file_key.extend_from_slice(&wrapping_iv_bytes);
    encrypted_file_key.extend_from_slice(&wrapped);

    Ok(HybridEncapResultV6 {
        eph_x25519_pub: *eph_pub.as_bytes(),
        mlkem_ciphertext: mlkem_ct.to_vec(),
        encrypted_file_key,
        content_key,
        hmac_key: SymmetricKey::new(hmac_raw),
    })
}

/// V6 hybrid KEM decapsulation.
/// Returns `(content_key, hmac_key)`.
pub fn hybrid_decapsulate_v6(
    eph_x25519_pub: &[u8],
    mlkem_ct: &[u8],
    encrypted_file_key: &[u8],
    mlkem_sec: &MlKemSecretKey,
    x25519_sec: &X25519SecretKey,
) -> Result<(SymmetricKey, SymmetricKey), CryptoError> {
    // X25519 static key exchange
    let eph_pub_bytes: [u8; 32] = eph_x25519_pub
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let static_secret = StaticSecret::from(*x25519_sec.as_bytes());
    let eph_pub = PublicKey::from(eph_pub_bytes);
    let x25519_ss = Zeroizing::new(static_secret.diffie_hellman(&eph_pub));

    // ML-KEM-1024 decapsulation
    let sk_bytes: [u8; 3168] = mlkem_sec
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let mlkem_dk = MlKem1024DecKey::from_bytes(&Array::from(sk_bytes));
    let ct_bytes: [u8; 1568] = mlkem_ct
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat("mlkem_ct must be 1568 bytes".to_string()))?;
    let mlkem_ss = mlkem_dk
        .decapsulate(&Array::from(ct_bytes))
        .map_err(|_| CryptoError::KemDecapFailed)?;

    // Derive wrapping_key + hmac_key
    let mut combined_ikm = Zeroizing::new(Vec::with_capacity(64));
    combined_ikm.extend_from_slice(x25519_ss.as_bytes());
    combined_ikm.extend_from_slice(mlkem_ss.as_ref());

    let hkdf = Hkdf::<Sha256>::new(None, &combined_ikm);
    let mut derived = Zeroizing::new([0u8; 64]);
    hkdf.expand(V6, derived.as_mut())
        .map_err(|_| CryptoError::KdfFailed)?;

    let mut wrapping_key = Zeroizing::new([0u8; 32]);
    wrapping_key.copy_from_slice(&derived[..32]);
    let mut hmac_raw = [0u8; 32];
    hmac_raw.copy_from_slice(&derived[32..64]);

    // Unwrap content_key: efk = wrapping_iv(12) || ciphertext+tag(48)
    if encrypted_file_key.len() != 60 {
        return Err(CryptoError::InvalidFormat(
            "encrypted_file_key must be 60 bytes".to_string(),
        ));
    }
    let wrapping_iv = Nonce::from_slice(&encrypted_file_key[..12]);
    let wrapped = &encrypted_file_key[12..];
    let wrapping_cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref())
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let mut content_key_vec = wrapping_cipher
        .decrypt(wrapping_iv, wrapped)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if content_key_vec.len() != 32 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let content_key = SymmetricKey::from_slice(&content_key_vec)?;
    // Zeroize the intermediate vec
    use zeroize::Zeroize;
    content_key_vec.zeroize();

    Ok((content_key, SymmetricKey::new(hmac_raw)))
}

// re-export fill_bytes usage
use rand::RngCore;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_keypair_generation() {
        let kp = generate_hybrid_keypair().unwrap();
        assert_eq!(kp.mlkem_public_key.as_bytes().len(), 1568);
        assert_eq!(kp.mlkem_secret_key.as_bytes().len(), 3168);
        assert_eq!(kp.x25519_public_key.as_bytes().len(), 32);
        assert_eq!(kp.x25519_secret_key.as_bytes().len(), 32);
    }

    #[test]
    fn hybrid_v6_encap_decap_roundtrip() {
        let kp = generate_hybrid_keypair().unwrap();
        let result = hybrid_encapsulate_v6(&kp.mlkem_public_key, &kp.x25519_public_key).unwrap();

        let (ck2, hk2) = hybrid_decapsulate_v6(
            &result.eph_x25519_pub,
            &result.mlkem_ciphertext,
            &result.encrypted_file_key,
            &kp.mlkem_secret_key,
            &kp.x25519_secret_key,
        )
        .unwrap();

        assert_eq!(result.content_key.as_bytes(), ck2.as_bytes());
        assert_eq!(result.hmac_key.as_bytes(), hk2.as_bytes());
    }

    #[test]
    fn hybrid_v6_wrong_secret_fails() {
        let kp = generate_hybrid_keypair().unwrap();
        let kp2 = generate_hybrid_keypair().unwrap();
        let result = hybrid_encapsulate_v6(&kp.mlkem_public_key, &kp.x25519_public_key).unwrap();

        // Using wrong keypair should fail at decapsulation or produce different keys
        let res = hybrid_decapsulate_v6(
            &result.eph_x25519_pub,
            &result.mlkem_ciphertext,
            &result.encrypted_file_key,
            &kp2.mlkem_secret_key,
            &kp2.x25519_secret_key,
        );
        // Either an error or wrong keys (decryption of wrapped key should fail)
        assert!(res.is_err());
    }

    #[test]
    fn derive_mlkem_public_key_matches_original() {
        let kp = generate_hybrid_keypair().unwrap();
        let derived_pub = derive_mlkem_public_key(&kp.mlkem_secret_key).unwrap();
        assert_eq!(derived_pub.as_bytes(), kp.mlkem_public_key.as_bytes());
    }
}
