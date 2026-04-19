// Master secret generation and verification.
// Format: [version(1)][secret(32)][checksum(4)] = 37 bytes.
// V2 (0x02) and V5 (0x05) use SHA-256(version || secret)[0..4] as checksum.

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::crypto::constants::{MASTER_SECRET_SIZE, MASTER_SECRET_V2, MASTER_SECRET_V5};
use crate::crypto::zeroize_utils::MasterSecret;
use crate::error::CryptoError;

/// Generate a V5 master secret with random entropy.
/// V5 uses SHAKE-256 for ML-KEM seed derivation (stronger than V2's SHA-256).
pub fn generate_master_secret_v5() -> Result<MasterSecret, CryptoError> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);

    let mut data = Vec::with_capacity(MASTER_SECRET_SIZE);
    data.push(MASTER_SECRET_V5);
    data.extend_from_slice(&secret);

    let checksum = compute_checksum(MASTER_SECRET_V5, &secret);
    data.extend_from_slice(&checksum);

    MasterSecret::new(data)
}

/// Verify master secret checksum and version byte.
/// Returns `true` if valid, `false` if corrupted or wrong version.
pub fn verify_master_secret(data: &[u8]) -> Result<bool, CryptoError> {
    if data.len() != MASTER_SECRET_SIZE {
        return Ok(false);
    }
    let version = data[0];
    if version != MASTER_SECRET_V2 && version != MASTER_SECRET_V5 {
        return Ok(false);
    }
    let secret = &data[1..33];
    let stored = &data[33..37];
    let computed = compute_checksum(version, secret);
    Ok(computed == stored)
}

fn compute_checksum(version: u8, secret: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update([version]);
    hasher.update(secret);
    let hash = hasher.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_v5_is_valid() {
        let ms = generate_master_secret_v5().unwrap();
        assert_eq!(ms.as_bytes().len(), MASTER_SECRET_SIZE);
        assert_eq!(ms.version(), MASTER_SECRET_V5);
        assert!(verify_master_secret(ms.as_bytes()).unwrap());
    }

    #[test]
    fn generate_v5_random() {
        let ms1 = generate_master_secret_v5().unwrap();
        let ms2 = generate_master_secret_v5().unwrap();
        assert_ne!(ms1.as_bytes(), ms2.as_bytes());
    }

    #[test]
    fn verify_rejects_wrong_length() {
        assert!(!verify_master_secret(&[0u8; 36]).unwrap());
        assert!(!verify_master_secret(&[0u8; 38]).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_version() {
        let mut data = [0u8; 37];
        data[0] = 0x99;
        assert!(!verify_master_secret(&data).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_checksum() {
        let ms = generate_master_secret_v5().unwrap();
        let mut bytes = ms.as_bytes().to_vec();
        bytes[35] ^= 0xff;
        assert!(!verify_master_secret(&bytes).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_secret() {
        let ms = generate_master_secret_v5().unwrap();
        let mut bytes = ms.as_bytes().to_vec();
        bytes[10] ^= 0xff;
        assert!(!verify_master_secret(&bytes).unwrap());
    }
}
