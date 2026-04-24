//! WASM bindings for the WebAuthn PRF-gated device-key protection layer.
//!
//! The browser-side WebAuthn DOM calls (`navigator.credentials.*`, PRF
//! extension negotiation, credential-id persistence) live in the frontend;
//! everything below is the crypto layer and is thin on purpose — HKDF and
//! AES-GCM over bytes, no policy.
//!
//! Pipeline:
//!   1. Frontend passes PRF output to `webauthn_derive_wrapping_key`.
//!   2. Frontend generates a fresh random 32-byte device key (via
//!      `generate_aes_key` or the existing WASM vault-session generator) and
//!      calls `webauthn_wrap_device_key` once per enrolled credential.
//!   3. On unlock, frontend receives PRF output again, derives the same
//!      wrapping key, calls `webauthn_unwrap_device_key` to recover the
//!      device key, imports it into WebCrypto as non-extractable AES-GCM.

use sdk_core::crypto::webauthn::{
    derive_vault_key_wrapping_key_from_prf, derive_wrapping_key_from_prf, unwrap_device_key,
    unwrap_vault_key_with_prf, wrap_device_key, wrap_vault_key_with_prf,
};
use sdk_core::crypto::zeroize_utils::SymmetricKey;
use wasm_bindgen::prelude::*;

use crate::util::js_error;

/// Derive the 32-byte AES-GCM wrapping key from a WebAuthn PRF output.
///
/// Returns the raw bytes so the frontend can pass them straight into
/// `webauthn_wrap_device_key` / `webauthn_unwrap_device_key`. The wrapping
/// key is not itself persisted — it is short-lived and regenerated from
/// PRF on every unlock.
#[wasm_bindgen]
pub fn webauthn_derive_wrapping_key(prf_output: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let key =
        derive_wrapping_key_from_prf(&prf_output).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(key.as_bytes().to_vec())
}

/// AES-256-GCM-wrap the raw device-key bytes under a PRF-derived
/// wrapping key. Output format is `nonce(12) || ciphertext||tag`.
#[wasm_bindgen]
pub fn webauthn_wrap_device_key(
    device_key: Vec<u8>,
    wrapping_key: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let sym = match SymmetricKey::from_slice(&wrapping_key) {
        Ok(k) => k,
        Err(_) => return Err(js_error("wrapping_key must be 32 bytes")),
    };
    wrap_device_key(&device_key, &sym).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Inverse of `webauthn_wrap_device_key`. Input is `nonce(12) || ct||tag`;
/// returns the 32-byte device key.
#[wasm_bindgen]
pub fn webauthn_unwrap_device_key(
    wrapped: Vec<u8>,
    wrapping_key: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let sym = match SymmetricKey::from_slice(&wrapping_key) {
        Ok(k) => k,
        Err(_) => return Err(js_error("wrapping_key must be 32 bytes")),
    };
    unwrap_device_key(&wrapped, &sym).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate a fresh random 32-byte device key inside WASM (OsRng via the
/// existing symmetric key generator). Exposed so the frontend never has to
/// touch raw device-key bytes before they hit `webauthn_wrap_device_key`.
#[wasm_bindgen]
pub fn webauthn_generate_device_key() -> Result<Vec<u8>, JsValue> {
    let key = sdk_core::crypto::symmetric::generate_aes_key()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(key.as_bytes().to_vec())
}

// ── Opt-in passkey-unlock: vault_key wrap under PRF (SECURITY.md §12) ─────

/// Derive the AES-GCM wrapping key used to wrap `vault_key` itself — the
/// opt-in "passkey unlocks without passphrase" mode. Uses a different HKDF
/// info than `webauthn_derive_wrapping_key` so the two derived keys are
/// guaranteed distinct for the same PRF output.
#[wasm_bindgen]
pub fn webauthn_derive_vault_key_wrapping_key(prf_output: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let key = derive_vault_key_wrapping_key_from_prf(&prf_output)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(key.as_bytes().to_vec())
}

/// AES-256-GCM-wrap a 32-byte `vault_key` under a PRF-derived vault
/// wrapping key. Output format is `nonce(12) || ciphertext||tag`.
#[wasm_bindgen]
pub fn webauthn_wrap_vault_key(
    vault_key: Vec<u8>,
    wrapping_key: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let sym = match SymmetricKey::from_slice(&wrapping_key) {
        Ok(k) => k,
        Err(_) => return Err(js_error("wrapping_key must be 32 bytes")),
    };
    wrap_vault_key_with_prf(&vault_key, &sym).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Inverse of `webauthn_wrap_vault_key`. Returns the 32-byte `vault_key`.
/// Frontend feeds the output into `byo_vault_load_from_vault_key` and then
/// zeroizes the buffer.
#[wasm_bindgen]
pub fn webauthn_unwrap_vault_key(
    wrapped: Vec<u8>,
    wrapping_key: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    let sym = match SymmetricKey::from_slice(&wrapping_key) {
        Ok(k) => k,
        Err(_) => return Err(js_error("wrapping_key must be 32 bytes")),
    };
    unwrap_vault_key_with_prf(&wrapped, &sym).map_err(|e| JsValue::from_str(&e.to_string()))
}
