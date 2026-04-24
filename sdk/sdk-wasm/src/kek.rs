// KEK derivation and re-encryption WASM bindings.
//
// Return shapes are part of the @wattcloud/wasm JS API contract — see docs below.
//   derive_client_kek_half  → { client_kek_half }
//   derive_kek_v2           → { kek }
//   derive_recovery_kek     → { recovery_kek }
//   reencrypt_private_key   → { ciphertext }
// All byte values are base64. Errors return { error }.

use sdk_core::crypto::{
    kdf::{
        derive_client_kek_half as sdk_derive_client_kek_half, derive_kek_v2 as sdk_derive_kek_v2,
        derive_recovery_kek as sdk_derive_recovery_kek,
    },
    reencrypt::reencrypt_private_key as sdk_reencrypt,
    zeroize_utils::{Argon2Output, MasterSecret, SymmetricKey},
};
use wasm_bindgen::prelude::*;

use crate::util::{b64_decode, b64_encode, js_error, js_set};

/// Derive the 32-byte client KEK half from the Argon2id output.
/// `argon_output_b64` is the base64-encoded 64-byte Argon2id output.
/// Returns `{ client_kek_half }` (base64) or `{ error }`.
#[wasm_bindgen]
pub fn derive_client_kek_half(argon_output_b64: String) -> JsValue {
    let bytes = match b64_decode(&argon_output_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 argon_output"),
    };
    let argon = match Argon2Output::from_slice(&bytes) {
        Ok(a) => a,
        Err(e) => return js_error(&e.to_string()),
    };
    match sdk_derive_client_kek_half(&argon) {
        Ok(half) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "client_kek_half",
                &JsValue::from_str(&b64_encode(half.as_bytes())),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Combine client and server KEK halves into the 32-byte master KEK.
/// Both inputs are base64-encoded 32-byte values.
/// Returns `{ kek }` (base64) or `{ error }`.
#[wasm_bindgen]
pub fn derive_kek_v2(client_kek_half_b64: String, server_shard_b64: String) -> JsValue {
    let half_bytes = match b64_decode(&client_kek_half_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 client_kek_half"),
    };
    let shard_bytes = match b64_decode(&server_shard_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 server_shard"),
    };
    let half = match SymmetricKey::from_slice(&half_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    match sdk_derive_kek_v2(&half, &shard_bytes) {
        Ok(kek) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "kek", &JsValue::from_str(&b64_encode(kek.as_bytes())));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Derive a 32-byte recovery KEK from a V5 master secret.
/// `recovery_key_b64` is the base64-encoded 37-byte master secret.
/// Returns `{ recovery_kek }` (base64) or `{ error }`.
#[wasm_bindgen]
pub fn derive_recovery_kek(recovery_key_b64: String) -> JsValue {
    let bytes = match b64_decode(&recovery_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 recovery_key"),
    };
    let ms = match MasterSecret::from_slice(&bytes) {
        Ok(m) => m,
        Err(e) => return js_error(&e.to_string()),
    };
    match sdk_derive_recovery_kek(&ms) {
        Ok(kek) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "recovery_kek",
                &JsValue::from_str(&b64_encode(kek.as_bytes())),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Re-encrypt an AES-GCM blob from one KEK to another.
/// `encrypted_blob_b64` is base64-encoded `iv(12) || ciphertext+tag`.
/// Returns `{ ciphertext }` (base64 of new blob) or `{ error }`.
#[wasm_bindgen]
pub fn reencrypt_private_key(
    encrypted_blob_b64: String,
    old_kek_b64: String,
    new_kek_b64: String,
) -> JsValue {
    let blob = match b64_decode(&encrypted_blob_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 encrypted_blob"),
    };
    let old_bytes = match b64_decode(&old_kek_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 old_kek"),
    };
    let new_bytes = match b64_decode(&new_kek_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 new_kek"),
    };
    let old_kek = match SymmetricKey::from_slice(&old_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let new_kek = match SymmetricKey::from_slice(&new_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    match sdk_reencrypt(&blob, &old_kek, &new_kek) {
        Ok(new_blob) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "ciphertext",
                &JsValue::from_str(&b64_encode(&new_blob)),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}
