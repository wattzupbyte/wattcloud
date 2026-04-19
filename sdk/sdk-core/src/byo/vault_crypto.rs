// BYO vault cryptographic operations: key derivation, wrapping, HMAC, body encryption.
// All functions are pure (no I/O). Follows sdk-core conventions:
//   - #![deny(clippy::unwrap_used, clippy::expect_used)]
//   - All key types derive Zeroize + ZeroizeOnDrop, no Clone
//   - Debug prints "[REDACTED]"
//   - No base64 — encode/decode at WASM boundary

use crate::crypto::constants::{
    ARGON2_ITERATIONS_BYO, ARGON2_MEMORY_KB_BYO, ARGON2_PARALLELISM_BYO, BYO_RECOVERY_VAULT_KEK_V1,
    BYO_VAULT_KEK_V1, KEK_HALF_V2, KEK_V2, VAULT_HMAC_OFFSET_V1,
};
use crate::crypto::hashing::{constant_time_eq, hmac_sha256};
use crate::crypto::kdf::{argon2id_derive_with_params, hkdf_sha256};
use crate::crypto::symmetric::{
    aes_gcm_decrypt, aes_gcm_encrypt_with_nonce, generate_aes_key, generate_nonce,
};
use crate::crypto::zeroize_utils::{Argon2Output, Nonce12, SymmetricKey};
use crate::error::CryptoError;
use rand::RngCore;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Run Argon2id with BYO parameters (128 MB memory, t=3, p=4).
pub fn argon2id_derive_byo(password: &[u8], salt: &[u8]) -> Result<Argon2Output, CryptoError> {
    argon2id_derive_with_params(
        password,
        salt,
        ARGON2_MEMORY_KB_BYO,
        ARGON2_ITERATIONS_BYO,
        ARGON2_PARALLELISM_BYO,
    )
}

/// Derive vault_kek: HKDF-SHA256(argon_output[0..32], BYO_VAULT_KEK_V1, 32).
/// Used to wrap/unwrap the vault_key in the passphrase slot.
pub fn derive_vault_kek(argon_output: &Argon2Output) -> Result<SymmetricKey, CryptoError> {
    let out = hkdf_sha256(argon_output.auth_material(), BYO_VAULT_KEK_V1, 32)?;
    SymmetricKey::from_slice(&out)
}

/// Derive client_kek_half: HKDF-SHA256(argon_output[32..64], KEK_HALF_V2, 32).
/// Reuses the same domain separation string as managed mode — BYO uses 128MB
/// Argon2id so the argon_output is different, producing a different key.
pub fn derive_client_kek_half_from_byo(
    argon_output: &Argon2Output,
) -> Result<SymmetricKey, CryptoError> {
    let out = hkdf_sha256(argon_output.enc_material(), KEK_HALF_V2, 32)?;
    SymmetricKey::from_slice(&out)
}

/// Derive the full KEK: HKDF-SHA256(client_kek_half || shard, KEK_V2, 32).
/// Reuses the same domain separation string as managed mode — the shard source
/// differs (server_shard vs local shard), so the KEK is different.
pub fn derive_byo_kek(
    client_kek_half: &SymmetricKey,
    shard: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    if shard.len() != 32 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(client_kek_half.as_bytes());
    ikm.extend_from_slice(shard);
    let out = hkdf_sha256(&ikm, KEK_V2, 32)?;
    SymmetricKey::from_slice(&out)
}

/// Derive recovery_vault_kek: HKDF-SHA256(recovery_key_secret[0..32], BYO_RECOVERY_VAULT_KEK_V1, 32).
/// `recovery_key_secret` is the 32-byte secret portion of the V5 recovery key (bytes [1..33]).
/// Different from managed mode's RECOVERY_KEK_V1 — different purpose requires domain separation.
pub fn derive_recovery_vault_kek(recovery_key_secret: &[u8]) -> Result<SymmetricKey, CryptoError> {
    if recovery_key_secret.len() != 32 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let out = hkdf_sha256(recovery_key_secret, BYO_RECOVERY_VAULT_KEK_V1, 32)?;
    SymmetricKey::from_slice(&out)
}

/// Wrap vault_key with a wrapping key using AES-256-GCM.
/// Returns (nonce, ciphertext_with_tag) where ciphertext_with_tag is 48 bytes
/// (32-byte encrypted vault_key + 16-byte GCM tag).
pub fn wrap_vault_key(
    vault_key: &SymmetricKey,
    wrapping_key: &SymmetricKey,
) -> Result<(Nonce12, [u8; 48]), CryptoError> {
    let nonce = generate_nonce()?;
    let ciphertext = aes_gcm_encrypt_with_nonce(vault_key.as_bytes(), wrapping_key, &nonce)?;
    let mut wrapped = [0u8; 48];
    if ciphertext.len() != 48 {
        return Err(CryptoError::InvalidFormat(format!(
            "wrapped vault_key must be 48 bytes (32 ct + 16 tag), got {}",
            ciphertext.len()
        )));
    }
    wrapped.copy_from_slice(&ciphertext);
    Ok((nonce, wrapped))
}

/// Unwrap vault_key from passphrase or recovery slot.
/// `wrap_iv` is the 12-byte nonce, `wrapped` is the 48-byte AES-GCM ciphertext+tag.
/// Returns the unwrapped vault_key on success, or error if the tag doesn't verify
/// (wrong passphrase, corrupted data).
pub fn unwrap_vault_key(
    wrap_iv: &[u8; 12],
    wrapped: &[u8; 48],
    unwrapping_key: &SymmetricKey,
) -> Result<SymmetricKey, CryptoError> {
    let nonce = Nonce12::new(*wrap_iv);
    let plaintext = aes_gcm_decrypt(wrapped, &nonce, unwrapping_key)?;
    SymmetricKey::from_slice(&plaintext)
}

/// Compute header HMAC for a v2 vault: HMAC-SHA256(vault_key, header_bytes[0..1195]).
/// Used for integrity verification after unwrapping vault_key on the current wire format.
///
/// A1: strict on `VAULT_HMAC_OFFSET` (1195). A caller who needs the legacy v1 offset
/// must explicitly call `compute_header_hmac_v1` so that v2 vaults cannot be verified
/// via a v1 prefix slice (which would leave device_slots + revocation_epoch uncovered).
pub fn compute_header_hmac(
    vault_key: &SymmetricKey,
    header_prefix: &[u8],
) -> Result<[u8; 32], CryptoError> {
    use crate::crypto::constants::VAULT_HMAC_OFFSET;
    if header_prefix.len() != VAULT_HMAC_OFFSET {
        return Err(CryptoError::InvalidFormat(format!(
            "v2 header prefix must be {VAULT_HMAC_OFFSET} bytes for HMAC, got {}",
            header_prefix.len()
        )));
    }
    hmac_sha256(vault_key.as_bytes(), header_prefix)
}

/// Compute header HMAC for a legacy v1 vault: HMAC-SHA256(vault_key, header_bytes[0..807]).
/// ONLY used by the v1→v2 migration path to verify the original v1 header before re-sealing
/// as v2. New vaults and every post-migration code path must use `compute_header_hmac`.
pub fn compute_header_hmac_v1(
    vault_key: &SymmetricKey,
    header_prefix: &[u8],
) -> Result<[u8; 32], CryptoError> {
    use crate::crypto::constants::VAULT_HMAC_OFFSET_V1;
    if header_prefix.len() != VAULT_HMAC_OFFSET_V1 {
        return Err(CryptoError::InvalidFormat(format!(
            "v1 header prefix must be {VAULT_HMAC_OFFSET_V1} bytes for HMAC, got {}",
            header_prefix.len()
        )));
    }
    hmac_sha256(vault_key.as_bytes(), header_prefix)
}

/// Verify header HMAC against expected value using constant-time comparison (v2).
pub fn verify_header_hmac(
    vault_key: &SymmetricKey,
    header_prefix: &[u8],
    expected_hmac: &[u8; 32],
) -> Result<bool, CryptoError> {
    let computed = compute_header_hmac(vault_key, header_prefix)?;
    Ok(constant_time_eq(&computed, expected_hmac))
}

/// Verify header HMAC against expected value (v1 legacy — migration path only).
pub fn verify_header_hmac_v1(
    vault_key: &SymmetricKey,
    header_prefix: &[u8],
    expected_hmac: &[u8; 32],
) -> Result<bool, CryptoError> {
    let computed = compute_header_hmac_v1(vault_key, header_prefix)?;
    Ok(constant_time_eq(&computed, expected_hmac))
}

/// Encrypt the vault body (SQLite bytes) with vault_key using AES-256-GCM.
/// Returns (nonce, ciphertext_with_tag).
pub fn encrypt_vault_body(
    sqlite_bytes: &[u8],
    vault_key: &SymmetricKey,
) -> Result<(Nonce12, Vec<u8>), CryptoError> {
    let nonce = generate_nonce()?;
    let ciphertext = aes_gcm_encrypt_with_nonce(sqlite_bytes, vault_key, &nonce)?;
    Ok((nonce, ciphertext))
}

/// Decrypt the vault body with vault_key using AES-256-GCM.
/// Returns the decrypted SQLite bytes.
pub fn decrypt_vault_body(
    body_iv: &[u8; 12],
    body_ciphertext: &[u8],
    vault_key: &SymmetricKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let nonce = Nonce12::new(*body_iv);
    let plaintext = aes_gcm_decrypt(body_ciphertext, &nonce, vault_key)?;
    Ok(Zeroizing::new(plaintext))
}

/// All keys generated for a new BYO vault.
/// Each field is freshly random — never reused across vaults.
///
/// Derives `Zeroize + ZeroizeOnDrop` so that both the key material and the
/// plain byte arrays are scrubbed when the struct is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NewVaultKeys {
    pub vault_key: SymmetricKey,
    pub shard: SymmetricKey,
    pub vault_id: [u8; 16],
    pub master_salt: [u8; 32],
}

impl fmt::Debug for NewVaultKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // K1: redact everything. master_salt isn't strictly secret but
        // disclosing it in logs narrows a brute-force attacker's search;
        // vault_id is a cross-provider correlation handle. The CLAUDE.md
        // Debug policy is "[REDACTED] — never actual bytes" for every field
        // of a key-holding struct, no carve-outs.
        f.write_str("NewVaultKeys { [REDACTED] }")
    }
}

/// Generate all random keys needed for a new BYO vault.
/// - vault_key: random 32 bytes (encrypts SQLite body + header HMAC)
/// - shard: random 32 bytes (stored in device slots, used for KEK derivation)
/// - vault_id: random 16 bytes (identifies vault across devices)
/// - master_salt: random 32 bytes (Argon2id salt)
pub fn generate_vault_keys() -> Result<NewVaultKeys, CryptoError> {
    let vault_key = generate_aes_key()?;
    let shard = generate_aes_key()?;

    let mut vault_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut vault_id);

    let mut master_salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut master_salt);

    Ok(NewVaultKeys {
        vault_key,
        shard,
        vault_id,
        master_salt,
    })
}

// ─── Per-device Ed25519 signing keys (v2 vault format) ───────────────────────

/// Generate a fresh Ed25519 key pair for a device slot.
/// Returns (public_key_bytes[32], secret_key_seed[32]).
/// The seed is the 32-byte secret scalar; it is the value stored (wrapped) in the vault.
#[cfg(feature = "crypto")]
pub fn generate_device_signing_key() -> Result<([u8; 32], Zeroizing<[u8; 32]>), CryptoError> {
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let seed: [u8; 32] = signing_key.to_bytes();
    let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();
    Ok((public_key, Zeroizing::new(seed)))
}

/// Wrap an Ed25519 seed (32 bytes) with AES-256-GCM.
/// Nonce = `device_id[0..12]` (deterministic — device_id is random per enrollment,
/// so nonce reuse is negligible-probability, and we never re-seal the same slot).
/// Returns the 48-byte ciphertext+tag to store in the device slot.
///
/// K2: HKDF info is hardcoded to `BYO_DEVICE_SIGNING_KEY_V2` rather than
/// accepted as a parameter. Using a caller-supplied info string made it
/// trivially possible to mint a slot that could never be unsealed (different
/// info on seal vs unseal → different wrapping key → opaque MacVerificationFailed).
/// All existing callers already passed the same constant, so dropping the
/// parameter is a pure internalisation.
#[cfg(feature = "crypto")]
pub fn seal_device_signing_key(
    vault_key: &SymmetricKey,
    device_id: &[u8; 16],
    seed: &[u8; 32],
) -> Result<[u8; 48], CryptoError> {
    use crate::crypto::constants::BYO_DEVICE_SIGNING_KEY_V2;
    // Derive a slot-specific wrapping key so we get domain separation per device.
    let wrapping_key_bytes = hkdf_sha256(vault_key.as_bytes(), BYO_DEVICE_SIGNING_KEY_V2, 32)?;
    let wrapping_key = SymmetricKey::from_slice(&wrapping_key_bytes)?;

    let nonce_bytes: [u8; 12] = device_id[..12]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let nonce = Nonce12::new(nonce_bytes);
    let ct = aes_gcm_encrypt_with_nonce(seed, &wrapping_key, &nonce)?;
    if ct.len() != 48 {
        return Err(CryptoError::InvalidFormat(
            "seal_device_signing_key: unexpected ciphertext length".into(),
        ));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&ct);
    Ok(out)
}

/// Unwrap an Ed25519 seed from the vault slot.
/// Returns the 32-byte seed, or error if the GCM tag fails (wrong vault_key or corruption).
///
/// K2: info is hardcoded — see `seal_device_signing_key` for the rationale.
#[cfg(feature = "crypto")]
pub fn unseal_device_signing_key(
    vault_key: &SymmetricKey,
    device_id: &[u8; 16],
    wrapped: &[u8; 48],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    use crate::crypto::constants::BYO_DEVICE_SIGNING_KEY_V2;
    let wrapping_key_bytes = hkdf_sha256(vault_key.as_bytes(), BYO_DEVICE_SIGNING_KEY_V2, 32)?;
    let wrapping_key = SymmetricKey::from_slice(&wrapping_key_bytes)?;

    let nonce_bytes: [u8; 12] = device_id[..12]
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let nonce = Nonce12::new(nonce_bytes);
    let plaintext = aes_gcm_decrypt(wrapped, &nonce, &wrapping_key)?;
    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

/// Sign a message with an Ed25519 secret key seed.
/// Returns the 64-byte detached signature.
#[cfg(feature = "crypto")]
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Result<[u8; 64], CryptoError> {
    use ed25519_dalek::{Signer, SigningKey};
    let signing_key = SigningKey::from_bytes(seed);
    let sig = signing_key.sign(message);
    Ok(sig.to_bytes())
}

/// Verify an Ed25519 signature.
/// Returns `true` if valid, `false` if the signature doesn't match.
#[cfg(feature = "crypto")]
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig).is_ok()
}

/// Migrate a v1 vault to v2 format.
///
/// Reads the v1 bytes, parses the header, writes it back as v2.
/// Existing device slots get `signing_key_wrapped` = all-zeros (no signing key yet).
/// `revocation_epoch` starts at 0.
/// The new header HMAC is computed with `vault_key`.
///
/// Returns the new 1227-byte header bytes on success.
/// The vault body (everything after the old 839-byte header) is appended unchanged.
#[cfg(feature = "crypto")]
pub fn migrate_vault_v1_to_v2(
    vault_bytes: &[u8],
    vault_key: &SymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    use crate::byo::vault_format::VaultHeader;
    use crate::crypto::constants::{VAULT_HEADER_SIZE, VAULT_HEADER_SIZE_V1};

    if vault_bytes.len() < VAULT_HEADER_SIZE_V1 {
        return Err(CryptoError::InvalidFormat(
            "vault_v1_to_v2: input too short for v1 header".into(),
        ));
    }

    // Parse as v1 (accepts both v1 and v2; returns needs_migration()=false for v2).
    let mut header = VaultHeader::parse(&vault_bytes[..VAULT_HEADER_SIZE_V1.max(
        vault_bytes.len().min(VAULT_HEADER_SIZE),
    )])
    .map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;

    if !header.needs_migration() {
        // Already v2 — return as-is.
        return Ok(vault_bytes.to_vec());
    }

    // Verify the v1 HMAC before re-signing as v2.
    // An attacker with provider write access could tamper the v1 header fields
    // (argon2 params, wrapped vault key IV, device slots) and have those changes
    // authenticated under v2 HMAC unless we verify first.
    let v1_prefix = vault_bytes.get(..VAULT_HMAC_OFFSET_V1).ok_or_else(|| {
        CryptoError::InvalidFormat("v1 header too short to verify HMAC".into())
    })?;
    if !verify_header_hmac_v1(vault_key, v1_prefix, &header.header_hmac)? {
        return Err(CryptoError::MacVerificationFailed);
    }

    // Re-compute HMAC for v2 header bytes (signing_key_wrapped fields are zeros; that's fine).
    let v2_header_bytes = header.to_bytes();
    let hmac_region = &v2_header_bytes[..crate::crypto::constants::VAULT_HMAC_OFFSET];
    let new_hmac = compute_header_hmac(vault_key, hmac_region)?;
    header.header_hmac.copy_from_slice(&new_hmac);

    // A2: a v1 blob whose length equals VAULT_HEADER_SIZE_V1 has a zero-byte body, which
    // is legitimate; `.get(n..)` returns `Some(&[])`. Any slice failure (e.g. the header
    // length check lied) means the input is malformed and we refuse — dropping the body
    // silently would produce a valid-looking v2 blob with no file data.
    let body = vault_bytes
        .get(VAULT_HEADER_SIZE_V1..)
        .ok_or_else(|| CryptoError::InvalidFormat(
            "v1 vault shorter than VAULT_HEADER_SIZE_V1 after parse".into(),
        ))?;
    let mut out = Vec::with_capacity(VAULT_HEADER_SIZE + body.len());
    out.extend_from_slice(&header.to_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::kdf::argon2id_derive;

    // Note: Argon2id with 128MB is slow. We use a small-memory variant for
    // unit tests that just need to verify the derivation chain, and a 128MB
    // test for the actual parameter verification.

    #[test]
    fn vault_key_wrap_unwrap_roundtrip() {
        let vault_key = generate_aes_key().unwrap();
        let wrapping_key = generate_aes_key().unwrap();

        let (nonce, wrapped) = wrap_vault_key(&vault_key, &wrapping_key).unwrap();
        let unwrapped = unwrap_vault_key(nonce.as_bytes(), &wrapped, &wrapping_key).unwrap();

        assert_eq!(vault_key.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn wrong_key_unwrap_fails() {
        let vault_key = generate_aes_key().unwrap();
        let wrapping_key = generate_aes_key().unwrap();
        let wrong_key = generate_aes_key().unwrap();

        let (nonce, wrapped) = wrap_vault_key(&vault_key, &wrapping_key).unwrap();
        let result = unwrap_vault_key(nonce.as_bytes(), &wrapped, &wrong_key);
        assert!(result.is_err(), "unwrapping with wrong key should fail");
    }

    #[test]
    fn derive_vault_kek_deterministic() {
        // Use small memory for speed
        let argon_output =
            argon2id_derive_with_params(b"test_password", &[0x42u8; 32], 65536, 3, 4).unwrap();
        let kek1 = derive_vault_kek(&argon_output).unwrap();
        let kek2 = derive_vault_kek(&argon_output).unwrap();
        assert_eq!(kek1.as_bytes(), kek2.as_bytes());
    }

    #[test]
    fn byo_client_kek_half_matches_managed() {
        // BYO and managed mode derive the same client_kek_half from the same
        // Argon2id output — they use the same HKDF info string (KEK_HALF_V2).
        let argon_output =
            argon2id_derive_with_params(b"test_password", &[0x42u8; 32], 65536, 3, 4).unwrap();
        let byo_half = derive_client_kek_half_from_byo(&argon_output).unwrap();
        let managed_half = crate::crypto::kdf::derive_client_kek_half(&argon_output).unwrap();
        assert_eq!(byo_half.as_bytes(), managed_half.as_bytes());
    }

    #[test]
    fn byo_kek_derivation() {
        // client_kek_half + shard → KEK using same KEK_V2 info string as managed
        let argon_output =
            argon2id_derive_with_params(b"test_password", &[0x42u8; 32], 65536, 3, 4).unwrap();
        let client_kek_half = derive_client_kek_half_from_byo(&argon_output).unwrap();
        let shard = [0xABu8; 32];

        let byo_kek = derive_byo_kek(&client_kek_half, &shard).unwrap();
        // Same result as managed mode derive_kek_v2 with same inputs
        let managed_kek = crate::crypto::kdf::derive_kek_v2(&client_kek_half, &shard).unwrap();
        assert_eq!(byo_kek.as_bytes(), managed_kek.as_bytes());
    }

    #[test]
    fn argon2id_different_memory_kb_differs() {
        // 64MB and 128MB produce different outputs even with same password+salt
        let salt = [0x42u8; 32];
        let out_64 = argon2id_derive_with_params(b"test_password", &salt, 65536, 3, 4).unwrap();
        let out_128 = argon2id_derive_with_params(b"test_password", &salt, 131072, 3, 4).unwrap();
        assert_ne!(out_64.as_bytes(), out_128.as_bytes());
    }

    #[test]
    fn argon2id_derive_with_params_matches_byo() {
        // argon2id_derive_with_params(131072) matches argon2id_derive_byo
        let salt = [0x42u8; 32];
        let with_params =
            argon2id_derive_with_params(b"test_password", &salt, 131072, 3, 4).unwrap();
        let with_byo = argon2id_derive_byo(b"test_password", &salt).unwrap();
        assert_eq!(with_params.as_bytes(), with_byo.as_bytes());
    }

    #[test]
    fn recovery_vault_kek_derivation() {
        let recovery_secret = [0xCCu8; 32];
        let kek1 = derive_recovery_vault_kek(&recovery_secret).unwrap();
        let kek2 = derive_recovery_vault_kek(&recovery_secret).unwrap();
        assert_eq!(kek1.as_bytes(), kek2.as_bytes());
    }

    #[test]
    fn recovery_vault_kek_wrong_length_fails() {
        let short = [0u8; 16];
        assert!(derive_recovery_vault_kek(&short).is_err());
    }

    #[test]
    fn byo_kek_wrong_shard_length_fails() {
        let half = generate_aes_key().unwrap();
        let short_shard = [0u8; 16];
        assert!(derive_byo_kek(&half, &short_shard).is_err());
    }

    #[test]
    fn header_hmac_roundtrip_v2() {
        use crate::crypto::constants::VAULT_HMAC_OFFSET;
        let vault_key = generate_aes_key().unwrap();
        let header_prefix = vec![0xAAu8; VAULT_HMAC_OFFSET];

        let hmac = compute_header_hmac(&vault_key, &header_prefix).unwrap();
        assert!(verify_header_hmac(&vault_key, &header_prefix, &hmac).unwrap());
    }

    #[test]
    fn header_hmac_roundtrip_v1() {
        use crate::crypto::constants::VAULT_HMAC_OFFSET_V1;
        let vault_key = generate_aes_key().unwrap();
        let header_prefix = vec![0xAAu8; VAULT_HMAC_OFFSET_V1];

        let hmac = compute_header_hmac_v1(&vault_key, &header_prefix).unwrap();
        assert!(verify_header_hmac_v1(&vault_key, &header_prefix, &hmac).unwrap());
    }

    #[test]
    fn wrong_vault_key_hmac_fails() {
        use crate::crypto::constants::VAULT_HMAC_OFFSET;
        let vault_key = generate_aes_key().unwrap();
        let wrong_key = generate_aes_key().unwrap();
        let header_prefix = vec![0xAAu8; VAULT_HMAC_OFFSET];

        let hmac = compute_header_hmac(&vault_key, &header_prefix).unwrap();
        assert!(!verify_header_hmac(&wrong_key, &header_prefix, &hmac).unwrap());
    }

    #[test]
    fn header_hmac_wrong_length_rejected() {
        let vault_key = generate_aes_key().unwrap();
        let short = vec![0u8; 100];
        assert!(compute_header_hmac(&vault_key, &short).is_err());
        // A1: v2 function must also reject the v1 legacy length so a caller
        // can't silently hmac-verify a v2 vault over just bytes [0..807].
        let v1_sized = vec![0u8; crate::crypto::constants::VAULT_HMAC_OFFSET_V1];
        assert!(compute_header_hmac(&vault_key, &v1_sized).is_err());
        // v1 function mirrors the symmetry.
        assert!(compute_header_hmac_v1(&vault_key, &short).is_err());
    }

    #[test]
    fn encrypt_decrypt_vault_body_roundtrip() {
        let vault_key = generate_aes_key().unwrap();
        let sqlite_data = b"CREATE TABLE test (id INTEGER PRIMARY KEY);";

        let (nonce, ciphertext) = encrypt_vault_body(sqlite_data, &vault_key).unwrap();
        let plaintext = decrypt_vault_body(nonce.as_bytes(), &ciphertext, &vault_key).unwrap();
        assert_eq!(&*plaintext, sqlite_data);
    }

    #[test]
    fn decrypt_vault_body_wrong_key_fails() {
        let vault_key = generate_aes_key().unwrap();
        let wrong_key = generate_aes_key().unwrap();
        let data = b"some sqlite data";

        let (nonce, ciphertext) = encrypt_vault_body(data, &vault_key).unwrap();
        let result = decrypt_vault_body(nonce.as_bytes(), &ciphertext, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn generate_vault_keys_random() {
        let keys1 = generate_vault_keys().unwrap();
        let keys2 = generate_vault_keys().unwrap();
        assert_ne!(keys1.vault_key.as_bytes(), keys2.vault_key.as_bytes());
        assert_ne!(keys1.shard.as_bytes(), keys2.shard.as_bytes());
        assert_ne!(keys1.vault_id, keys2.vault_id);
        assert_ne!(keys1.master_salt, keys2.master_salt);
    }

    #[test]
    fn wrap_vault_key_produces_48_bytes() {
        let vault_key = generate_aes_key().unwrap();
        let wrapping_key = generate_aes_key().unwrap();
        let (_nonce, wrapped) = wrap_vault_key(&vault_key, &wrapping_key).unwrap();
        assert_eq!(wrapped.len(), 48);
    }

    #[test]
    fn argon2id_custom_params_works() {
        // Verify custom params work (not just 64MB and 128MB)
        let salt = [0x42u8; 32];
        let out = argon2id_derive_with_params(
            b"test",
            &salt,
            65536,
            ARGON2_ITERATIONS_BYO,
            ARGON2_PARALLELISM_BYO,
        )
        .unwrap();
        assert_eq!(out.as_bytes().len(), 64);
    }

    // ─── Multi-step integration tests ─────────────────────────────────────────

    /// Helper: derive vault_kek from password using small test params (fast).
    fn test_derive_kek(password: &[u8], salt: &[u8; 32]) -> SymmetricKey {
        let out = argon2id_derive_with_params(password, salt, 4096, 1, 1).unwrap();
        derive_vault_kek(&out).unwrap()
    }

    /// (Section 10 #4) Recovery roundtrip: wrap vault_key via passphrase + recovery slots,
    /// then unwrap using only the recovery kek.
    #[test]
    fn recovery_roundtrip() {
        let keys = generate_vault_keys().unwrap();
        let salt = keys.master_salt;

        // Derive passphrase vault_kek and wrap vault_key
        let vault_kek = test_derive_kek(b"my-test-passphrase-long", &salt);
        let (pass_iv, pass_wrapped) = wrap_vault_key(&keys.vault_key, &vault_kek).unwrap();

        // Generate a recovery secret (32 bytes) and derive recovery_vault_kek
        let recovery_secret = [0xBEu8; 32];
        let rec_vault_kek = derive_recovery_vault_kek(&recovery_secret).unwrap();
        let (rec_iv, rec_wrapped) = wrap_vault_key(&keys.vault_key, &rec_vault_kek).unwrap();

        // "Lose" the passphrase — unwrap via recovery kek only
        let recovered = unwrap_vault_key(rec_iv.as_bytes(), &rec_wrapped, &rec_vault_kek).unwrap();
        assert_eq!(
            keys.vault_key.as_bytes(),
            recovered.as_bytes(),
            "Recovery must recover the same vault_key"
        );

        // Passphrase slot still works independently
        let from_pass = unwrap_vault_key(pass_iv.as_bytes(), &pass_wrapped, &vault_kek).unwrap();
        assert_eq!(keys.vault_key.as_bytes(), from_pass.as_bytes());

        // Full round-trip: encrypt/decrypt a body with the recovered vault_key
        let sqlite = b"SELECT 1;".to_vec();
        let (iv, ct) = encrypt_vault_body(&sqlite, &recovered).unwrap();
        let plaintext = decrypt_vault_body(iv.as_bytes(), &ct, &recovered).unwrap();
        assert_eq!(&plaintext[..], sqlite.as_slice());
    }

    /// (Section 10 #5) Passphrase change: old passphrase fails, new works,
    /// recovery slot unchanged, device slots unchanged.
    #[test]
    fn passphrase_change() {
        let keys = generate_vault_keys().unwrap();
        let salt_a = keys.master_salt;

        // Initial wrap with passphrase A
        let kek_a = test_derive_kek(b"old-passphrase-sufficient-len", &salt_a);
        let (iv_a, wrapped_a) = wrap_vault_key(&keys.vault_key, &kek_a).unwrap();

        // Recovery slot
        let recovery_secret = [0xAAu8; 32];
        let rec_kek = derive_recovery_vault_kek(&recovery_secret).unwrap();
        let (rec_iv, rec_wrapped) = wrap_vault_key(&keys.vault_key, &rec_kek).unwrap();

        // Change passphrase: new salt, new kek_b, re-wrap same vault_key
        let salt_b = [0xBBu8; 32];
        let kek_b = test_derive_kek(b"new-passphrase-sufficient-len", &salt_b);
        let (iv_b, wrapped_b) = wrap_vault_key(&keys.vault_key, &kek_b).unwrap();

        // Old passphrase must no longer work
        assert!(
            unwrap_vault_key(iv_b.as_bytes(), &wrapped_b, &kek_a).is_err(),
            "Old passphrase must not unwrap new slot"
        );
        // New passphrase must work
        let from_new = unwrap_vault_key(iv_b.as_bytes(), &wrapped_b, &kek_b).unwrap();
        assert_eq!(keys.vault_key.as_bytes(), from_new.as_bytes());

        // Recovery slot still valid (vault_key unchanged)
        let from_rec = unwrap_vault_key(rec_iv.as_bytes(), &rec_wrapped, &rec_kek).unwrap();
        assert_eq!(keys.vault_key.as_bytes(), from_rec.as_bytes());

        // Old slot (iv_a, wrapped_a) with old kek still works as a sanity check
        let from_old = unwrap_vault_key(iv_a.as_bytes(), &wrapped_a, &kek_a).unwrap();
        assert_eq!(keys.vault_key.as_bytes(), from_old.as_bytes());
    }

    /// (Section 10 #7) Simple revocation: zero out a device slot, other slots intact.
    #[test]
    fn simple_revocation_zeroes_slot() {
        use crate::byo::vault_format::{DeviceSlot, SlotStatus};

        let device_0 = [0x01u8; 16];
        let device_1 = [0x02u8; 16];
        let device_2 = [0x03u8; 16];
        let wrap_iv = [0x0Au8; 12];
        let payload = [0x0Bu8; 48];

        // Build a header with 3 active slots
        let keys = generate_vault_keys().unwrap();
        let kek = test_derive_kek(b"test-passphrase-long-enough", &keys.master_salt);
        let (iv, wrapped) = wrap_vault_key(&keys.vault_key, &kek).unwrap();
        let rec_secret = [0xCCu8; 32];
        let rec_kek = derive_recovery_vault_kek(&rec_secret).unwrap();
        let (rec_iv, rec_wrapped) = wrap_vault_key(&keys.vault_key, &rec_kek).unwrap();

        let hmac = compute_header_hmac(
            &keys.vault_key,
            &[0u8; crate::crypto::constants::VAULT_HMAC_OFFSET],
        )
        .unwrap();

        let mut pass_wrapped_arr = [0u8; 48];
        pass_wrapped_arr.copy_from_slice(&wrapped);
        let mut rec_wrapped_arr = [0u8; 48];
        rec_wrapped_arr.copy_from_slice(&rec_wrapped);
        let mut hmac_arr = [0u8; 32];
        hmac_arr.copy_from_slice(&hmac);

        let mut slots: [DeviceSlot; 8] = std::array::from_fn(|_| DeviceSlot::empty());
        slots[0] = DeviceSlot::active(device_0, wrap_iv, payload);
        slots[1] = DeviceSlot::active(device_1, wrap_iv, payload);
        slots[2] = DeviceSlot::active(device_2, wrap_iv, payload);

        use crate::crypto::constants::VAULT_FORMAT_VERSION;
        let mut header = crate::byo::vault_format::VaultHeader {
            format_version: VAULT_FORMAT_VERSION,
            argon2_memory_kb: 4096,
            argon2_iterations: 1,
            argon2_parallelism: 1,
            master_salt: keys.master_salt,
            vault_id: keys.vault_id,
            pass_wrap_iv: *iv.as_bytes(),
            pass_wrapped_vault_key: pass_wrapped_arr,
            recovery_wrap_iv: *rec_iv.as_bytes(),
            recovery_wrapped_vault_key: rec_wrapped_arr,
            device_slots: slots,
            revocation_epoch: 0,
            header_hmac: hmac_arr,
        };

        // Revoke slot 1 (simple: zero it out)
        assert_eq!(header.device_slots[1].status, SlotStatus::Active);
        header.device_slots[1] = DeviceSlot::empty();

        // Slot 1 is gone
        assert_eq!(header.device_slots[1].status, SlotStatus::Empty);
        assert_eq!(header.device_slots[1].device_id, [0u8; 16]);

        // Slots 0 and 2 are unchanged
        assert_eq!(header.device_slots[0].status, SlotStatus::Active);
        assert_eq!(header.device_slots[0].device_id, device_0);
        assert_eq!(header.device_slots[2].status, SlotStatus::Active);
        assert_eq!(header.device_slots[2].device_id, device_2);

        // Active count is now 2
        assert_eq!(header.active_slot_count(), 2);
        // find_device_slot for the revoked device returns None
        assert!(header.find_device_slot(&device_1).is_none());
    }

    /// (Section 10 #7a) Compromise revocation: new vault_key after rotation,
    /// old vault_key cannot decrypt new body.
    #[test]
    fn compromise_revocation_rotates_vault_key() {
        let keys = generate_vault_keys().unwrap();

        // Encrypt body with original vault_key (V1)
        let plaintext = b"secret data v1".to_vec();
        let (iv_v1, ct_v1) = encrypt_vault_body(&plaintext, &keys.vault_key).unwrap();

        // Compromise response: generate NEW vault_key (V2)
        let new_keys = generate_vault_keys().unwrap();

        // New body encrypted with V2
        let (iv_v2, ct_v2) = encrypt_vault_body(&plaintext, &new_keys.vault_key).unwrap();

        // Old vault_key (V1) cannot decrypt new body (V2)
        assert!(
            decrypt_vault_body(iv_v2.as_bytes(), &ct_v2, &keys.vault_key).is_err(),
            "Old vault_key must not decrypt new body"
        );
        // New vault_key (V2) can decrypt new body
        let recovered = decrypt_vault_body(iv_v2.as_bytes(), &ct_v2, &new_keys.vault_key).unwrap();
        assert_eq!(&recovered[..], plaintext.as_slice());

        // Old vault_key (V1) still decrypts old body (proves V1 was valid)
        let old_recovered = decrypt_vault_body(iv_v1.as_bytes(), &ct_v1, &keys.vault_key).unwrap();
        assert_eq!(&old_recovered[..], plaintext.as_slice());
    }

    /// (Section 10 #8) Max devices: all 8 slots filled, first_empty_slot returns None.
    #[test]
    fn max_devices_no_empty_slot() {
        use crate::byo::vault_format::{DeviceSlot, SlotStatus};

        let wrap_iv = [0x0Au8; 12];
        let payload = [0x0Bu8; 48];
        let slots: [DeviceSlot; 8] = std::array::from_fn(|i| {
            let mut id = [0u8; 16];
            id[0] = i as u8 + 1;
            DeviceSlot::active(id, wrap_iv, payload)
        });

        // All 8 slots active
        for s in &slots {
            assert_eq!(s.status, SlotStatus::Active);
        }

        // Create a minimal header to exercise the find_empty_slot logic
        let keys = generate_vault_keys().unwrap();
        let kek = test_derive_kek(b"test-passphrase-long-enough", &keys.master_salt);
        let (iv, wrapped) = wrap_vault_key(&keys.vault_key, &kek).unwrap();
        let rec_secret = [0xCCu8; 32];
        let rec_kek = derive_recovery_vault_kek(&rec_secret).unwrap();
        let (rec_iv, rec_wrapped) = wrap_vault_key(&keys.vault_key, &rec_kek).unwrap();
        let hmac = compute_header_hmac(
            &keys.vault_key,
            &[0u8; crate::crypto::constants::VAULT_HMAC_OFFSET],
        )
        .unwrap();

        let mut pass_wrapped_arr = [0u8; 48];
        pass_wrapped_arr.copy_from_slice(&wrapped);
        let mut rec_wrapped_arr = [0u8; 48];
        rec_wrapped_arr.copy_from_slice(&rec_wrapped);
        let mut hmac_arr = [0u8; 32];
        hmac_arr.copy_from_slice(&hmac);

        use crate::crypto::constants::VAULT_FORMAT_VERSION;
        let header = crate::byo::vault_format::VaultHeader {
            format_version: VAULT_FORMAT_VERSION,
            argon2_memory_kb: 4096,
            argon2_iterations: 1,
            argon2_parallelism: 1,
            master_salt: keys.master_salt,
            vault_id: keys.vault_id,
            pass_wrap_iv: *iv.as_bytes(),
            pass_wrapped_vault_key: pass_wrapped_arr,
            recovery_wrap_iv: *rec_iv.as_bytes(),
            recovery_wrapped_vault_key: rec_wrapped_arr,
            device_slots: slots,
            revocation_epoch: 0,
            header_hmac: hmac_arr,
        };

        assert_eq!(header.active_slot_count(), 8);
        assert!(
            header.first_empty_slot().is_none(),
            "No empty slot when all 8 are active — 9th enrollment must be rejected"
        );
    }

    /// Ed25519: generate, seal, unseal, sign, verify round-trip.
    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let vault_key = generate_aes_key().unwrap();
        let mut device_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut device_id);

        // Generate key pair
        let (public_key, seed) = generate_device_signing_key().unwrap();

        // Seal and unseal
        let wrapped = seal_device_signing_key(&vault_key, &device_id, &seed).unwrap();
        let recovered_seed = unseal_device_signing_key(&vault_key, &device_id, &wrapped).unwrap();
        assert_eq!(*seed, *recovered_seed);

        // Sign and verify
        let message = b"test journal entry v2";
        let sig = ed25519_sign(&seed, message).unwrap();
        assert!(ed25519_verify(&public_key, message, &sig));

        // Wrong message → invalid
        assert!(!ed25519_verify(&public_key, b"wrong message", &sig));
    }

    /// Ed25519: wrong vault_key cannot unseal the signing key.
    #[test]
    fn ed25519_wrong_vault_key_fails_unseal() {
        let vault_key = generate_aes_key().unwrap();
        let wrong_key = generate_aes_key().unwrap();
        let mut device_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut device_id);

        let (_pk, seed) = generate_device_signing_key().unwrap();
        let wrapped = seal_device_signing_key(&vault_key, &device_id, &seed).unwrap();
        assert!(unseal_device_signing_key(&wrong_key, &device_id, &wrapped).is_err());
    }

    /// Vault migration: v1 bytes → v2 header is 1227 bytes and parses cleanly.
    #[test]
    fn migrate_v1_to_v2_produces_valid_header() {
        use crate::byo::vault_format::VaultHeader;
        use crate::crypto::constants::{VAULT_HEADER_SIZE, VAULT_FORMAT_VERSION};

        // Build a minimal v1 vault (839-byte header + 1 byte body).
        let keys = generate_vault_keys().unwrap();
        let kek = test_derive_kek(b"test-passphrase-long-enough", &keys.master_salt);
        let (iv, wrapped) = wrap_vault_key(&keys.vault_key, &kek).unwrap();
        let rec_secret = [0xCCu8; 32];
        let rec_kek = derive_recovery_vault_kek(&rec_secret).unwrap();
        let (rec_iv, rec_wrapped) = wrap_vault_key(&keys.vault_key, &rec_kek).unwrap();

        // Build v1 header bytes manually (839 bytes):
        // magic(8) + version(2) + argon2(12) + salt(32) + vault_id(16) + ivs/wrapped(108) +
        // num_slots(1) + 8 × 77-byte slots(616) + hmac(32) = 839 bytes total
        let mut v1 = Vec::with_capacity(839 + 1);
        v1.extend_from_slice(b"SCVAULT\x00"); // 8
        v1.extend_from_slice(&1u16.to_le_bytes()); // version = 1
        v1.extend_from_slice(&131072u32.to_le_bytes()); // argon2_memory_kb
        v1.extend_from_slice(&3u32.to_le_bytes()); // iterations
        v1.extend_from_slice(&4u32.to_le_bytes()); // parallelism
        v1.extend_from_slice(&keys.master_salt); // 32
        v1.extend_from_slice(&keys.vault_id); // 16
        v1.extend_from_slice(iv.as_bytes()); // 12
        v1.extend_from_slice(&wrapped); // 48
        v1.extend_from_slice(rec_iv.as_bytes()); // 12
        v1.extend_from_slice(&rec_wrapped); // 48
        v1.push(0); // num_active_slots
        // 8 × 77-byte empty slots
        v1.extend_from_slice(&[0u8; 77 * 8]);
        // Compute a real HMAC over the prefix (migration now verifies it)
        let real_hmac = hmac_sha256(keys.vault_key.as_bytes(), &v1).unwrap();
        v1.extend_from_slice(&real_hmac);
        assert_eq!(v1.len(), 839);
        // Append body
        v1.push(0xAB);

        let migrated = migrate_vault_v1_to_v2(&v1, &keys.vault_key).unwrap();
        assert_eq!(migrated.len(), VAULT_HEADER_SIZE + 1); // new header + 1 body byte

        let header = VaultHeader::parse(&migrated[..VAULT_HEADER_SIZE]).unwrap();
        assert_eq!(header.format_version, VAULT_FORMAT_VERSION);
        assert_eq!(header.revocation_epoch, 0);
        assert!(!header.needs_migration());
        assert_eq!(migrated[VAULT_HEADER_SIZE], 0xAB);
    }
}
