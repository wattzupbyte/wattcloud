//! WebAuthn PRF-derived device-key protection (BYO).
//!
//! See SECURITY.md §12 "Passkey-gated device key (BYO)" for the threat model
//! and lifecycle. This module owns the crypto layer — DOM calls to
//! `navigator.credentials.{create,get}` and credential-id storage live in
//! the frontend because WebAuthn is a browser-only API.
//!
//! Pipeline (prf mode):
//!
//! ```text
//! prf_output  (32 B from the authenticator, bound to credential + salt)
//!     │
//!     ▼
//! HKDF-SHA256(prf_output, info=DEVICE_KEY_WRAP_V1, L=32)
//!     │
//!     ▼
//! wrapping_key
//!     │  ── AES-256-GCM ──►  wrapped_device_key   (stored in IDB)
//!     │  ◄── AES-256-GCM ──  device_key            (held in WASM only)
//! ```
//!
//! Multi-credential support: the device key is random per vault and wrapped
//! once per enrolled credential (different credentials produce different PRF
//! outputs, so different wrapping keys; the same device key is stored N times
//! in N AES-GCM ciphertexts). Any enrolled credential can unwrap.
//!
//! `"Wattcloud device key v1"` and `"Wattcloud vault_key wrap v1"` are frozen
//! protocol identifiers. Changing either invalidates every wrapped row
//! written before the change.
//!
//! The vault_key wrap path is the opt-in "passkey unlocks without passphrase"
//! mode (SECURITY.md §12 "Passkey replaces passphrase"). When the user
//! enables it, the currently-open session's `vault_key` is wrapped once per
//! enrolled credential under a PRF-derived key with a *different* HKDF info
//! than the device-key wrap, so an attacker who recovers one wrap cannot
//! forge the other even if they somehow influenced the PRF output once.

use crate::crypto::kdf::hkdf_sha256;
use crate::crypto::symmetric::{aes_gcm_decrypt, aes_gcm_encrypt};
use crate::crypto::zeroize_utils::{Nonce12, SymmetricKey};
use crate::error::CryptoError;

/// HKDF info label binding the WebAuthn PRF output to the BYO device-key
/// wrapping subkey. Domain-separated from every other BYO HKDF info.
pub const DEVICE_KEY_WRAP_V1: &[u8] = b"Wattcloud device key v1";

/// HKDF info label for the opt-in vault_key-wrap under PRF (passkey unlock
/// without passphrase, SECURITY.md §12). Distinct info → distinct wrapping
/// key → guarantees no accidental crossover between the device-key wrap and
/// the vault_key wrap even though both derive from the same PRF output.
pub const VAULT_KEY_WRAP_V1: &[u8] = b"Wattcloud vault_key wrap v1";

/// Derive the 32-byte AES-GCM wrapping key from a WebAuthn PRF output.
///
/// `prf_output` is the raw bytes returned by the authenticator's PRF
/// extension (`extensions.prf.results.first` on the JS side, typically 32
/// bytes). The returned `SymmetricKey` is used only to AES-GCM-wrap or
/// unwrap the random device key; it never touches IDB or any other
/// persistent store.
pub fn derive_wrapping_key_from_prf(prf_output: &[u8]) -> Result<SymmetricKey, CryptoError> {
    if prf_output.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let bytes = hkdf_sha256(prf_output, DEVICE_KEY_WRAP_V1, 32)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(SymmetricKey::new(arr))
}

/// AES-256-GCM-wrap the raw device-key bytes under a PRF-derived
/// wrapping key. Output format is `nonce(12) || ciphertext||tag`,
/// matching every other wrap site in the codebase.
pub fn wrap_device_key(
    device_key: &[u8],
    wrapping_key: &SymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    if device_key.len() != 32 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let (ct, nonce) = aes_gcm_encrypt(device_key, wrapping_key)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Derive the AES-GCM wrapping key for the opt-in passkey-unlock (wraps
/// `vault_key` itself, not just the device key). Same PRF output shape as
/// `derive_wrapping_key_from_prf` but a different HKDF info — so the two
/// wrapping keys are guaranteed distinct.
pub fn derive_vault_key_wrapping_key_from_prf(
    prf_output: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    if prf_output.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let bytes = hkdf_sha256(prf_output, VAULT_KEY_WRAP_V1, 32)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(SymmetricKey::new(arr))
}

/// AES-256-GCM-wrap the raw 32-byte `vault_key` under a PRF-derived vault
/// wrapping key. Output format mirrors `wrap_device_key`:
/// `nonce(12) || ciphertext||tag`. Used only by the opt-in passkey-unlock
/// path (SECURITY.md §12); disabled by default. Suffix `_with_prf` keeps
/// it namespace-distinct from `sdk_core::byo::vault_crypto::wrap_vault_key`
/// which wraps under a KEK.
pub fn wrap_vault_key_with_prf(
    vault_key: &[u8],
    wrapping_key: &SymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    if vault_key.len() != 32 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let (ct, nonce) = aes_gcm_encrypt(vault_key, wrapping_key)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of `wrap_vault_key_with_prf`. Input is `nonce(12) || ct||tag`;
/// returns the 32-byte `vault_key` bytes. Callers typically feed the result
/// straight into a vault session constructor and zeroize the buffer.
pub fn unwrap_vault_key_with_prf(
    wrapped: &[u8],
    wrapping_key: &SymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    if wrapped.len() < 12 + 16 {
        return Err(CryptoError::DecryptionFailed);
    }
    let nonce_bytes: [u8; 12] = wrapped
        .get(..12)
        .ok_or(CryptoError::DecryptionFailed)?
        .try_into()
        .map_err(|_| CryptoError::InvalidNonceLength)?;
    let nonce = Nonce12::new(nonce_bytes);
    let ct = wrapped.get(12..).ok_or(CryptoError::DecryptionFailed)?;
    let plaintext = aes_gcm_decrypt(ct, &nonce, wrapping_key)?;
    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    Ok(plaintext)
}

/// Inverse of `wrap_device_key`. Input is `nonce(12) || ciphertext||tag`;
/// returns the 32-byte device key.
pub fn unwrap_device_key(
    wrapped: &[u8],
    wrapping_key: &SymmetricKey,
) -> Result<Vec<u8>, CryptoError> {
    if wrapped.len() < 12 + 16 {
        return Err(CryptoError::DecryptionFailed);
    }
    let nonce_bytes: [u8; 12] = wrapped
        .get(..12)
        .ok_or(CryptoError::DecryptionFailed)?
        .try_into()
        .map_err(|_| CryptoError::InvalidNonceLength)?;
    let nonce = Nonce12::new(nonce_bytes);
    let ct = wrapped.get(12..).ok_or(CryptoError::DecryptionFailed)?;
    let plaintext = aes_gcm_decrypt(ct, &nonce, wrapping_key)?;
    if plaintext.len() != 32 {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    Ok(plaintext)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn derive_wrapping_key_is_deterministic() {
        let prf = [0x42u8; 32];
        let a = derive_wrapping_key_from_prf(&prf).unwrap();
        let b = derive_wrapping_key_from_prf(&prf).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derive_wrapping_key_different_inputs_differ() {
        let a = derive_wrapping_key_from_prf(&[0x42u8; 32]).unwrap();
        let b = derive_wrapping_key_from_prf(&[0x43u8; 32]).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derive_wrapping_key_length_is_32() {
        let k = derive_wrapping_key_from_prf(&[0x01u8; 32]).unwrap();
        assert_eq!(k.as_bytes().len(), 32);
    }

    #[test]
    fn derive_wrapping_key_rejects_empty_prf() {
        assert!(derive_wrapping_key_from_prf(&[]).is_err());
    }

    /// Domain separation: same PRF output through different HKDF info
    /// strings MUST produce different keys. Guards against someone ever
    /// reusing another subkey's info literal here (or vice versa).
    #[test]
    fn device_key_wrap_info_is_domain_separated() {
        // Literal constants used elsewhere in the BYO crypto paths.
        let other_infos: &[&[u8]] = &[
            b"SecureCloud BYO key_versions wrap v1",
            b"SecureCloud BYO WAL v1",
            b"SecureCloud BYO manifest v1",
        ];
        let prf = [0x99u8; 32];
        let mine = derive_wrapping_key_from_prf(&prf).unwrap();
        for info in other_infos {
            let other = hkdf_sha256(&prf, info, 32).unwrap();
            assert_ne!(
                mine.as_bytes(),
                other.as_slice(),
                "HKDF info \"{}\" collides with DEVICE_KEY_WRAP_V1",
                std::str::from_utf8(info).unwrap_or("<non-utf8>"),
            );
        }
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let wrapping_key = derive_wrapping_key_from_prf(&[0x11u8; 32]).unwrap();
        let device_key = [0x77u8; 32];
        let wrapped = wrap_device_key(&device_key, &wrapping_key).unwrap();
        // nonce(12) + ct+tag(48) = 60 bytes
        assert_eq!(wrapped.len(), 60);
        let unwrapped = unwrap_device_key(&wrapped, &wrapping_key).unwrap();
        assert_eq!(unwrapped, device_key);
    }

    #[test]
    fn unwrap_with_wrong_key_fails() {
        let k1 = derive_wrapping_key_from_prf(&[0x11u8; 32]).unwrap();
        let k2 = derive_wrapping_key_from_prf(&[0x22u8; 32]).unwrap();
        let device_key = [0x77u8; 32];
        let wrapped = wrap_device_key(&device_key, &k1).unwrap();
        assert!(unwrap_device_key(&wrapped, &k2).is_err());
    }

    #[test]
    fn wrap_rejects_wrong_length_device_key() {
        let k = derive_wrapping_key_from_prf(&[0x11u8; 32]).unwrap();
        assert!(wrap_device_key(&[0u8; 31], &k).is_err());
        assert!(wrap_device_key(&[0u8; 33], &k).is_err());
    }

    #[test]
    fn unwrap_rejects_short_ciphertext() {
        let k = derive_wrapping_key_from_prf(&[0x11u8; 32]).unwrap();
        assert!(unwrap_device_key(&[0u8; 20], &k).is_err());
    }

    #[test]
    fn wrap_produces_unique_nonces() {
        // Two wraps of the same plaintext under the same key must differ
        // because the nonce is CSPRNG per call.
        let k = derive_wrapping_key_from_prf(&[0x11u8; 32]).unwrap();
        let pt = [0x55u8; 32];
        let a = wrap_device_key(&pt, &k).unwrap();
        let b = wrap_device_key(&pt, &k).unwrap();
        assert_ne!(a, b);
    }

    // ── Vault-key wrap under PRF (opt-in passkey unlock) ──────────────────

    #[test]
    fn vault_key_wrap_is_domain_separated_from_device_key_wrap() {
        // Same PRF output must produce two distinct wrapping keys — one
        // for the device-key slot, one for the vault_key slot. Otherwise a
        // compromise of either ciphertext would threaten the other.
        let prf = [0xA5u8; 32];
        let device_side = derive_wrapping_key_from_prf(&prf).unwrap();
        let vault_side = derive_vault_key_wrapping_key_from_prf(&prf).unwrap();
        assert_ne!(device_side.as_bytes(), vault_side.as_bytes());
    }

    #[test]
    fn vault_key_wrap_unwrap_roundtrip() {
        let wrapping_key = derive_vault_key_wrapping_key_from_prf(&[0x33u8; 32]).unwrap();
        let vault_key = [0x88u8; 32];
        let wrapped = wrap_vault_key_with_prf(&vault_key, &wrapping_key).unwrap();
        assert_eq!(wrapped.len(), 60); // nonce(12) + ct+tag(48)
        let unwrapped = unwrap_vault_key_with_prf(&wrapped, &wrapping_key).unwrap();
        assert_eq!(unwrapped, vault_key);
    }

    #[test]
    fn vault_key_wrap_rejects_non_32_byte_input() {
        let k = derive_vault_key_wrapping_key_from_prf(&[0x33u8; 32]).unwrap();
        assert!(wrap_vault_key_with_prf(&[0u8; 16], &k).is_err());
        assert!(wrap_vault_key_with_prf(&[0u8; 31], &k).is_err());
        assert!(wrap_vault_key_with_prf(&[0u8; 33], &k).is_err());
    }

    #[test]
    fn vault_key_unwrap_fails_with_device_key_wrapping() {
        // Ciphertext from one side must not decrypt with the other side's
        // wrapping key — proves the HKDF-info split is load-bearing, not
        // cosmetic.
        let prf = [0xCCu8; 32];
        let device_wk = derive_wrapping_key_from_prf(&prf).unwrap();
        let vault_wk = derive_vault_key_wrapping_key_from_prf(&prf).unwrap();
        let pt = [0x44u8; 32];
        let wrapped = wrap_vault_key_with_prf(&pt, &vault_wk).unwrap();
        assert!(unwrap_vault_key_with_prf(&wrapped, &device_wk).is_err());
    }

    #[test]
    fn vault_key_wrap_info_is_domain_separated_from_every_known_info() {
        // Mirror of the device-key wrap separation check — same guardrail,
        // distinct constant.
        let other_infos: &[&[u8]] = &[
            b"Wattcloud device key v1",
            b"SecureCloud BYO key_versions wrap v1",
            b"SecureCloud BYO WAL v1",
            b"SecureCloud BYO manifest v1",
        ];
        let prf = [0xDDu8; 32];
        let mine = derive_vault_key_wrapping_key_from_prf(&prf).unwrap();
        for info in other_infos {
            let other = hkdf_sha256(&prf, info, 32).unwrap();
            assert_ne!(
                mine.as_bytes(),
                other.as_slice(),
                "HKDF info \"{}\" collides with VAULT_KEY_WRAP_V1",
                std::str::from_utf8(info).unwrap_or("<non-utf8>"),
            );
        }
    }
}
