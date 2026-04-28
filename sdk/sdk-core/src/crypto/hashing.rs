// Hashing utilities: SHA-256, SHAKE-256 (XOF), BLAKE2b-256, HMAC-SHA256.
// Also: SIV nonce derivation and constant-time equality.

use blake2::digest::Digest as Blake2Digest;
use blake2::Blake2b;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use typenum::U32;

use crate::crypto::zeroize_utils::Nonce12;
use crate::error::CryptoError;

type Blake2b256 = Blake2b<U32>;
type HmacSha256 = Hmac<Sha256>;

/// SHA-256 hash of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}

/// SHAKE-256 extendable-output function producing `output_len` bytes.
pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, data);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// BLAKE2b-256 hash of `data`.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    Blake2Digest::update(&mut hasher, data);
    Blake2Digest::finalize(hasher).into()
}

/// HMAC-SHA256 of `data` using `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    Mac::update(&mut mac, data);
    Ok(mac.finalize().into_bytes().into())
}

/// Derive a deterministic 12-byte SIV nonce: HMAC-SHA256(key, plaintext)[0..12].
/// Safe for repeated encryption of the same value under the same key.
pub fn derive_siv_nonce(key: &[u8], plaintext: &[u8]) -> Result<Nonce12, CryptoError> {
    let hash = hmac_sha256(key, plaintext)?;
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&hash[..12]);
    Ok(Nonce12::new(iv))
}

/// Constant-time equality check. Prevents timing attacks during MAC verification.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).unwrap_u8() == 1
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149...
        let hash = sha256(b"");
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
    }

    #[test]
    fn blake2b_256_non_empty() {
        let hash = blake2b_256(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn hmac_sha256_roundtrip() {
        let key = [0x01u8; 32];
        let data = b"test data";
        let mac1 = hmac_sha256(&key, data).unwrap();
        let mac2 = hmac_sha256(&key, data).unwrap();
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn siv_nonce_deterministic() {
        let key = [0x42u8; 32];
        let n1 = derive_siv_nonce(&key, b"filename.txt").unwrap();
        let n2 = derive_siv_nonce(&key, b"filename.txt").unwrap();
        assert_eq!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn siv_nonce_differs_for_different_input() {
        let key = [0x42u8; 32];
        let n1 = derive_siv_nonce(&key, b"file_a.txt").unwrap();
        let n2 = derive_siv_nonce(&key, b"file_b.txt").unwrap();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    #[test]
    fn shake256_produces_correct_length() {
        let out = shake256(b"test", 64);
        assert_eq!(out.len(), 64);
    }
}
