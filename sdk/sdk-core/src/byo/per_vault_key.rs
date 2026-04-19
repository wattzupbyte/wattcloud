// Per-vault and manifest HKDF subkey derivation for R6 multi-vault architecture.
//
// All keys are derived from `vault_key` (already inside WASM; never crosses JS).
// Per-vault keys include the `provider_id` in the HKDF `info` field to ensure
// domain separation across providers — a key for provider A cannot be used for B.
//
// Info construction: `<DOMAIN_CONST> || \x00 || provider_id.as_bytes()`.
// The `\x00` separator prevents prefix-extension collisions.
//
// Follows sdk-core conventions:
//   - #![deny(clippy::unwrap_used, clippy::expect_used)]
//   - All key types derive Zeroize + ZeroizeOnDrop, MUST NOT impl Clone
//   - No base64 — encode/decode at the WASM boundary

use crate::crypto::constants::{
    BYO_MANIFEST_AEAD_V1, BYO_PER_VAULT_AEAD_V1, BYO_PER_VAULT_JOURNAL_AEAD_V1,
    BYO_PER_VAULT_JOURNAL_HMAC_V1, BYO_PER_VAULT_WAL_V1,
};
use crate::crypto::kdf::hkdf_sha256;
use crate::crypto::zeroize_utils::SymmetricKey;
use crate::error::CryptoError;

/// Derive the AES-256-GCM AEAD key for the vault_manifest.sc body.
/// This key is shared across all providers (the manifest is identical on each).
pub fn derive_manifest_aead_key(vault_key: &SymmetricKey) -> Result<SymmetricKey, CryptoError> {
    let okm = hkdf_sha256(vault_key.as_bytes(), BYO_MANIFEST_AEAD_V1, 32)?;
    SymmetricKey::from_slice(&okm)
}

/// Derive the AES-256-GCM AEAD key for a specific provider's vault_<id>.sc body.
///
/// `provider_id` must be a non-empty UTF-8 string (typically a UUID).
/// Different `provider_id` values produce independent, domain-separated keys.
pub fn derive_per_vault_aead_key(
    vault_key: &SymmetricKey,
    provider_id: &str,
) -> Result<SymmetricKey, CryptoError> {
    if provider_id.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let info = build_info(BYO_PER_VAULT_AEAD_V1, provider_id);
    let okm = hkdf_sha256(vault_key.as_bytes(), &info, 32)?;
    SymmetricKey::from_slice(&okm)
}

/// Derive the AES-256-GCM key for a provider's IndexedDB write-ahead log.
///
/// Different from the vault body AEAD key (different HKDF domain constant)
/// to ensure WAL entries cannot be confused with vault body ciphertext.
pub fn derive_per_vault_wal_key(
    vault_key: &SymmetricKey,
    provider_id: &str,
) -> Result<SymmetricKey, CryptoError> {
    if provider_id.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let info = build_info(BYO_PER_VAULT_WAL_V1, provider_id);
    let okm = hkdf_sha256(vault_key.as_bytes(), &info, 32)?;
    SymmetricKey::from_slice(&okm)
}

/// Derive the AES-256-GCM body-encryption key for a provider's cloud journal.
pub fn derive_per_vault_journal_aead_key(
    vault_key: &SymmetricKey,
    provider_id: &str,
) -> Result<SymmetricKey, CryptoError> {
    if provider_id.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let info = build_info(BYO_PER_VAULT_JOURNAL_AEAD_V1, provider_id);
    let okm = hkdf_sha256(vault_key.as_bytes(), &info, 32)?;
    SymmetricKey::from_slice(&okm)
}

/// Derive the HMAC-SHA256 key for authenticating a provider's cloud journal entries.
pub fn derive_per_vault_journal_hmac_key(
    vault_key: &SymmetricKey,
    provider_id: &str,
) -> Result<SymmetricKey, CryptoError> {
    if provider_id.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let info = build_info(BYO_PER_VAULT_JOURNAL_HMAC_V1, provider_id);
    let okm = hkdf_sha256(vault_key.as_bytes(), &info, 32)?;
    SymmetricKey::from_slice(&okm)
}

/// Convenience struct returned by `derive_per_vault_journal_keys`.
/// Both fields are Zeroize + ZeroizeOnDrop via SymmetricKey.
pub struct JournalKeys {
    pub aead: SymmetricKey,
    pub hmac: SymmetricKey,
}

/// Derive both journal keys (AEAD + HMAC) for a provider in one call.
pub fn derive_per_vault_journal_keys(
    vault_key: &SymmetricKey,
    provider_id: &str,
) -> Result<JournalKeys, CryptoError> {
    let aead = derive_per_vault_journal_aead_key(vault_key, provider_id)?;
    let hmac = derive_per_vault_journal_hmac_key(vault_key, provider_id)?;
    Ok(JournalKeys { aead, hmac })
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Build the HKDF `info` bytes: `domain_const || \x00 || provider_id`.
///
/// The `\x00` byte prevents prefix-extension collisions when `provider_id` is
/// an arbitrary string — e.g. a provider_id that starts with "v1" cannot forge
/// an `info` value matching a different domain constant with a shorter suffix.
fn build_info(domain: &[u8], provider_id: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(domain.len() + 1 + provider_id.len());
    info.extend_from_slice(domain);
    info.push(0x00);
    info.extend_from_slice(provider_id.as_bytes());
    info
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::symmetric::generate_aes_key;

    fn test_key() -> SymmetricKey {
        generate_aes_key().unwrap()
    }

    #[test]
    fn manifest_key_deterministic() {
        let k = test_key();
        let k1 = derive_manifest_aead_key(&k).unwrap();
        let k2 = derive_manifest_aead_key(&k).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn manifest_key_different_from_per_vault() {
        let k = test_key();
        let manifest = derive_manifest_aead_key(&k).unwrap();
        let per_vault = derive_per_vault_aead_key(&k, "provider-a").unwrap();
        assert_ne!(manifest.as_bytes(), per_vault.as_bytes());
    }

    #[test]
    fn per_vault_aead_different_providers() {
        let k = test_key();
        let ka = derive_per_vault_aead_key(&k, "provider-a").unwrap();
        let kb = derive_per_vault_aead_key(&k, "provider-b").unwrap();
        assert_ne!(
            ka.as_bytes(),
            kb.as_bytes(),
            "different provider_ids must produce different keys"
        );
    }

    #[test]
    fn per_vault_aead_deterministic() {
        let k = test_key();
        let k1 = derive_per_vault_aead_key(&k, "prov-x").unwrap();
        let k2 = derive_per_vault_aead_key(&k, "prov-x").unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn per_vault_aead_different_from_wal() {
        // Same provider_id, different domain → different key (domain separation).
        let k = test_key();
        let aead = derive_per_vault_aead_key(&k, "prov-x").unwrap();
        let wal = derive_per_vault_wal_key(&k, "prov-x").unwrap();
        assert_ne!(aead.as_bytes(), wal.as_bytes());
    }

    #[test]
    fn per_vault_journal_keys_different() {
        let k = test_key();
        let keys = derive_per_vault_journal_keys(&k, "prov-x").unwrap();
        assert_ne!(keys.aead.as_bytes(), keys.hmac.as_bytes());
    }

    #[test]
    fn per_vault_aead_empty_provider_id_rejected() {
        let k = test_key();
        assert!(derive_per_vault_aead_key(&k, "").is_err());
    }

    #[test]
    fn per_vault_wal_empty_provider_id_rejected() {
        let k = test_key();
        assert!(derive_per_vault_wal_key(&k, "").is_err());
    }

    #[test]
    fn per_vault_journal_empty_provider_id_rejected() {
        let k = test_key();
        assert!(derive_per_vault_journal_keys(&k, "").is_err());
    }

    #[test]
    fn different_vault_keys_different_per_vault_keys() {
        let k1 = test_key();
        let k2 = test_key();
        let pv1 = derive_per_vault_aead_key(&k1, "same-provider").unwrap();
        let pv2 = derive_per_vault_aead_key(&k2, "same-provider").unwrap();
        assert_ne!(pv1.as_bytes(), pv2.as_bytes());
    }

    /// No-prefix-extension collision: "aead v1" + provider_id starting with next domain segment.
    /// This is the core correctness guarantee of the `\x00` separator.
    #[test]
    fn no_prefix_extension_collision() {
        // Craft provider_id so that BYO_PER_VAULT_AEAD_V1 || provider_id would naively
        // equal BYO_PER_VAULT_WAL_V1 without the separator.
        // With the separator inserted, the two info strings differ even in degenerate cases.
        let k = test_key();
        // provider_id whose bytes happen to equal the tail of the WAL constant
        let crafted_id = " v1\x00wallet-x"; // includes \x00 itself
        let aead = derive_per_vault_aead_key(&k, crafted_id).unwrap();
        let wal = derive_per_vault_wal_key(&k, "wallet-x").unwrap();
        assert_ne!(aead.as_bytes(), wal.as_bytes());
    }
}
