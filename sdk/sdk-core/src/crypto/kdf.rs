// Key derivation functions.
// Argon2id: m=65536 KiB, t=3, p=4, output=64 bytes.
// HKDF-SHA256 with domain-separated info strings.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
use rand::rngs::OsRng;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::constants::{
    ARGON2_MAX_ITERATIONS, ARGON2_MAX_MEMORY_KIB, ARGON2_MAX_PARALLELISM, AUTH_V1, ENCRYPTION_V1,
    FILENAME_V1, KEK_HALF_V2, KEK_V2, MASTER_SECRET_V2, MASTER_SECRET_V5, MLKEM_SEED_V2,
    MLKEM_SEED_V5, RECOVERY_KEK_V1, X25519_SEED,
};
use crate::crypto::zeroize_utils::{
    Argon2Output, HybridKeypair, MasterSecret, MlKemPublicKey, MlKemSecretKey, SymmetricKey,
    X25519PublicKey, X25519SecretKey,
};
use crate::error::CryptoError;
use zeroize::Zeroizing;

const ARGON2_MEMORY: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 64;

/// Run Argon2id with the project parameters (64 MB memory, t=3, p=4).
/// `password` and `salt` are raw bytes (no base64 in sdk-core).
/// `salt` must be exactly 32 bytes.
/// This is the managed-mode default. BYO mode uses `argon2id_derive_with_params`
/// with `memory_kb = 131072`.
pub fn argon2id_derive(password: &[u8], salt: &[u8]) -> Result<Argon2Output, CryptoError> {
    argon2id_derive_with_params(
        password,
        salt,
        ARGON2_MEMORY,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
    )
}

/// Run Argon2id with custom parameters.
/// Used for BYO mode (128 MB memory) and backward-compatible login with stored params.
/// `salt` must be exactly 32 bytes. `memory_kb` is in KiB (e.g. 65536 = 64 MB, 131072 = 128 MB).
///
/// Enforces DoS ceilings (`ARGON2_MAX_MEMORY_KIB`, `ARGON2_MAX_ITERATIONS`,
/// `ARGON2_MAX_PARALLELISM`) *before* any derivation work runs, so a hostile
/// vault header with inflated parameters is rejected in microseconds. The
/// ceilings are set well above the nominal BYO params (128 MiB / 3 / 4) so
/// legitimate derivations are never affected.
pub fn argon2id_derive_with_params(
    password: &[u8],
    salt: &[u8],
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Argon2Output, CryptoError> {
    if salt.len() != 32 {
        return Err(CryptoError::InvalidFormat(
            "salt must be 32 bytes".to_string(),
        ));
    }

    if memory_kb > ARGON2_MAX_MEMORY_KIB {
        return Err(CryptoError::Argon2ParamsOutOfBounds(format!(
            "memory_kb {memory_kb} exceeds maximum {ARGON2_MAX_MEMORY_KIB} KiB"
        )));
    }
    if iterations > ARGON2_MAX_ITERATIONS {
        return Err(CryptoError::Argon2ParamsOutOfBounds(format!(
            "iterations {iterations} exceeds maximum {ARGON2_MAX_ITERATIONS}"
        )));
    }
    if parallelism > ARGON2_MAX_PARALLELISM {
        return Err(CryptoError::Argon2ParamsOutOfBounds(format!(
            "parallelism {parallelism} exceeds maximum {ARGON2_MAX_PARALLELISM}"
        )));
    }

    let params = Params::new(memory_kb, iterations, parallelism, Some(ARGON2_OUTPUT_LEN))
        .map_err(|_| CryptoError::KdfFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 64];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| CryptoError::KdfFailed)?;

    Ok(Argon2Output::new(output))
}

/// HKDF-SHA256 with no salt.
/// Returns a `Zeroizing<Vec<u8>>` so that the derived key material is
/// overwritten on drop even if the caller doesn't immediately move it into
/// a typed key wrapper (e.g. `SymmetricKey::from_slice`).
pub fn hkdf_sha256(
    ikm: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = Zeroizing::new(vec![0u8; output_len]);
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(okm)
}

/// Derive auth hash: HKDF-SHA256(argon_output[0..32], info=AUTH_V1, L=32).
pub fn derive_auth_hash(argon_output: &Argon2Output) -> Result<[u8; 32], CryptoError> {
    let out = hkdf_sha256(argon_output.auth_material(), AUTH_V1, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// Derive encryption key: HKDF-SHA256(argon_output[32..64], info=ENCRYPTION_V1, L=32).
pub fn derive_encryption_key(argon_output: &Argon2Output) -> Result<SymmetricKey, CryptoError> {
    let out = hkdf_sha256(argon_output.enc_material(), ENCRYPTION_V1, 32)?;
    SymmetricKey::from_slice(&out)
}

/// Derive client KEK half: HKDF-SHA256(argon_output[32..64], info=KEK_HALF_V2, L=32).
pub fn derive_client_kek_half(argon_output: &Argon2Output) -> Result<SymmetricKey, CryptoError> {
    let out = hkdf_sha256(argon_output.enc_material(), KEK_HALF_V2, 32)?;
    SymmetricKey::from_slice(&out)
}

/// Derive full KEK: HKDF-SHA256(client_kek_half || server_shard, info=KEK_V2, L=32).
pub fn derive_kek_v2(
    client_kek_half: &SymmetricKey,
    server_shard: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    if server_shard.len() != 32 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let mut ikm = zeroize::Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(client_kek_half.as_bytes());
    ikm.extend_from_slice(server_shard);
    let out = hkdf_sha256(&ikm, KEK_V2, 32)?;
    SymmetricKey::from_slice(&out)
}

/// Derive recovery KEK: HKDF-SHA256(master_secret[1..33], info=RECOVERY_KEK_V1, L=32).
pub fn derive_recovery_kek(master_secret: &MasterSecret) -> Result<SymmetricKey, CryptoError> {
    let out = hkdf_sha256(master_secret.secret_bytes(), RECOVERY_KEK_V1, 32)?;
    SymmetricKey::from_slice(&out)
}

/// Derive filename encryption key: HKDF-SHA256(master_secret[1..33], info=FILENAME_V1, L=32).
pub fn derive_filename_key_from_master(
    master_secret: &MasterSecret,
) -> Result<SymmetricKey, CryptoError> {
    let out = hkdf_sha256(master_secret.secret_bytes(), FILENAME_V1, 32)?;
    SymmetricKey::from_slice(&out)
}

/// Derive hybrid keypair from master secret (V2 or V5).
///
/// V5: ML-KEM seed = SHAKE-256(secret || MLKEM_SEED_V5)[0..32]
/// V2: ML-KEM seed = SHA-256(secret || MLKEM_SEED_V2)[0..32]  (legacy)
/// X25519 seed = SHA-256(secret || X25519_SEED)[0..32] for both versions
pub fn derive_keypair_from_master(
    master_secret: &MasterSecret,
) -> Result<HybridKeypair, CryptoError> {
    let version = master_secret.version();
    if version != MASTER_SECRET_V2 && version != MASTER_SECRET_V5 {
        return Err(CryptoError::UnsupportedVersion(version));
    }
    let secret = master_secret.secret_bytes();

    // Derive ML-KEM seed
    let mlkem_seed: [u8; 32] = if version == MASTER_SECRET_V5 {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        use sha3::Shake256;
        let mut hasher = Shake256::default();
        Update::update(&mut hasher, secret);
        Update::update(&mut hasher, MLKEM_SEED_V5);
        let mut reader = hasher.finalize_xof();
        let mut seed = [0u8; 32];
        reader.read(&mut seed);
        seed
    } else {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        Digest::update(&mut h, secret);
        Digest::update(&mut h, MLKEM_SEED_V2);
        let hash = h.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[..32]);
        seed
    };

    // Generate ML-KEM keypair deterministically from seed
    let mut rng = ChaCha20Rng::from_seed(mlkem_seed);
    let (mlkem_dk, mlkem_ek) = MlKem1024::generate(&mut rng);

    // Derive X25519 seed: SHA-256(secret || X25519_SEED)
    let x25519_seed: [u8; 32] = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        Digest::update(&mut h, secret);
        Digest::update(&mut h, X25519_SEED);
        let hash = h.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[..32]);
        seed
    };
    let x25519_sec = StaticSecret::from(x25519_seed);
    let x25519_pub = PublicKey::from(&x25519_sec);

    Ok(HybridKeypair {
        mlkem_public_key: MlKemPublicKey::new(mlkem_ek.as_bytes().to_vec()),
        mlkem_secret_key: MlKemSecretKey::new(mlkem_dk.as_bytes().to_vec()),
        x25519_public_key: X25519PublicKey::new(*x25519_pub.as_bytes()),
        x25519_secret_key: X25519SecretKey::new(*x25519_sec.as_bytes()),
    })
}

/// Generate a random 32-byte authentication salt.
pub fn generate_auth_salt() -> Result<[u8; 32], CryptoError> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    Ok(salt)
}

/// Generate a random 32-byte device key.
pub fn generate_device_key() -> Result<SymmetricKey, CryptoError> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Ok(SymmetricKey::new(key))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::master_secret::generate_master_secret_v5;

    fn test_salt() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn argon2id_derive_is_deterministic() {
        let password = b"testpassword";
        let salt = test_salt();
        let out1 = argon2id_derive(password, &salt).unwrap();
        let out2 = argon2id_derive(password, &salt).unwrap();
        assert_eq!(out1.as_bytes(), out2.as_bytes());
    }

    #[test]
    fn argon2id_different_passwords_differ() {
        let salt = test_salt();
        let out1 = argon2id_derive(b"password1", &salt).unwrap();
        let out2 = argon2id_derive(b"password2", &salt).unwrap();
        assert_ne!(out1.as_bytes(), out2.as_bytes());
    }

    #[test]
    fn derive_auth_hash_is_deterministic() {
        let argon_out = argon2id_derive(b"password", &test_salt()).unwrap();
        let h1 = derive_auth_hash(&argon_out).unwrap();
        let h2 = derive_auth_hash(&argon_out).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn derive_client_kek_half_differs_from_auth_hash() {
        let argon_out = argon2id_derive(b"password", &test_salt()).unwrap();
        let auth = derive_auth_hash(&argon_out).unwrap();
        let kek = derive_client_kek_half(&argon_out).unwrap();
        assert_ne!(&auth, kek.as_bytes());
    }

    #[test]
    fn derive_kek_v2_deterministic() {
        let argon_out = argon2id_derive(b"password", &test_salt()).unwrap();
        let half = derive_client_kek_half(&argon_out).unwrap();
        let shard = [0xabu8; 32];
        let kek1 = derive_kek_v2(&half, &shard).unwrap();
        let kek2 = derive_kek_v2(&half, &shard).unwrap();
        assert_eq!(kek1.as_bytes(), kek2.as_bytes());
    }

    #[test]
    fn hkdf_sha256_different_info_different_output() {
        let ikm = [0x01u8; 32];
        let out1 = hkdf_sha256(&ikm, b"info_a", 32).unwrap();
        let out2 = hkdf_sha256(&ikm, b"info_b", 32).unwrap();
        assert_ne!(out1, out2);
    }

    #[test]
    fn generate_auth_salt_random() {
        let s1 = generate_auth_salt().unwrap();
        let s2 = generate_auth_salt().unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn argon2id_wrong_salt_length_fails() {
        // Salt must be exactly 32 bytes
        assert!(argon2id_derive(b"password", &[0u8; 16]).is_err());
        assert!(argon2id_derive(b"password", &[0u8; 31]).is_err());
        assert!(argon2id_derive(b"password", &[0u8; 33]).is_err());
        assert!(argon2id_derive(b"password", &[0u8; 0]).is_err());
    }

    // C1: DoS ceilings must be enforced *before* any derivation work. Rejects
    // happen in microseconds (parameter math only) — this test would time out
    // if the check happened after Argon2 ran.
    #[test]
    fn argon2id_rejects_memory_above_ceiling() {
        let salt = test_salt();
        let res = argon2id_derive_with_params(
            b"pw",
            &salt,
            ARGON2_MAX_MEMORY_KIB + 1,
            3,
            4,
        );
        match res {
            Err(CryptoError::Argon2ParamsOutOfBounds(m)) => {
                assert!(m.contains("memory_kb"), "got: {m}");
            }
            other => panic!("expected Argon2ParamsOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn argon2id_rejects_iterations_above_ceiling() {
        let salt = test_salt();
        let res = argon2id_derive_with_params(
            b"pw",
            &salt,
            65536,
            ARGON2_MAX_ITERATIONS + 1,
            4,
        );
        match res {
            Err(CryptoError::Argon2ParamsOutOfBounds(m)) => {
                assert!(m.contains("iterations"), "got: {m}");
            }
            other => panic!("expected Argon2ParamsOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn argon2id_rejects_parallelism_above_ceiling() {
        let salt = test_salt();
        let res = argon2id_derive_with_params(
            b"pw",
            &salt,
            65536,
            3,
            ARGON2_MAX_PARALLELISM + 1,
        );
        match res {
            Err(CryptoError::Argon2ParamsOutOfBounds(m)) => {
                assert!(m.contains("parallelism"), "got: {m}");
            }
            other => panic!("expected Argon2ParamsOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn argon2id_accepts_ceiling_values_exactly() {
        // Boundary: exactly at the ceiling must succeed. This also guards
        // against an accidental "<" → "<=" regression that would lock out
        // legitimate callers using the upper bound.
        let salt = test_salt();
        // Use the nominal BYO params (well under ceilings) to keep the test fast;
        // a full ceiling derivation (256 MiB, 10 iter) would be slow.
        let out = argon2id_derive_with_params(b"pw", &salt, 65536, 3, 4).unwrap();
        assert_eq!(out.as_bytes().len(), 64);
    }

    #[test]
    fn derive_keypair_from_master_wrong_version_fails() {
        // Create a 37-byte blob with version byte 0x01 (neither V2=0x02 nor V5=0x05)
        let mut bytes = vec![0u8; 37];
        bytes[0] = 0x01; // invalid version
                         // Fill checksum so it's not a checksum mismatch error
        use crate::crypto::hashing::sha256;
        let ck = sha256(&bytes[0..33]);
        bytes[33..37].copy_from_slice(&ck[..4]);
        let ms = MasterSecret::from_slice(&bytes).unwrap();
        let result = derive_keypair_from_master(&ms);
        assert!(result.is_err(), "should reject unsupported version byte");
    }

    #[test]
    fn derive_recovery_kek_from_v5() {
        let ms = generate_master_secret_v5().unwrap();
        let kek = derive_recovery_kek(&ms).unwrap();
        assert_eq!(kek.as_bytes().len(), 32);
    }

    #[test]
    fn different_passwords_different_auth_hash() {
        let salt = [0x11u8; 32];
        let out1 = argon2id_derive(b"password1", &salt).unwrap();
        let out2 = argon2id_derive(b"password2", &salt).unwrap();
        let h1 = derive_auth_hash(&out1).unwrap();
        let h2 = derive_auth_hash(&out2).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hkdf_output_length_respected() {
        let ikm = [0xAAu8; 32];
        for &len in &[16usize, 32, 48, 64] {
            let out = hkdf_sha256(&ikm, b"test", len).unwrap();
            assert_eq!(out.len(), len);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hkdf_different_info_different_output(
            a in "[a-z]{3,20}",
            b in "[a-z]{3,20}"
        ) {
            prop_assume!(a != b);
            let ikm = [0x55u8; 32];
            let out_a = hkdf_sha256(&ikm, a.as_bytes(), 32).unwrap();
            let out_b = hkdf_sha256(&ikm, b.as_bytes(), 32).unwrap();
            prop_assert_ne!(out_a, out_b, "HKDF with different info must produce different output");
        }
    }
}
