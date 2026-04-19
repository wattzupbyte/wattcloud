// Key generation and master-secret WASM bindings.
//
// All outputs are base64-encoded. Return shapes match the existing secure-cloud-wasm
// crate exactly so the frontend requires no changes until Phase 6.

use js_sys::Reflect;
use sdk_core::crypto::{
    kdf::{
        derive_filename_key_from_master as sdk_derive_filename_key_from_master,
        derive_keypair_from_master as sdk_derive_keypair_from_master,
    },
    master_secret::{
        generate_master_secret_v5 as sdk_generate_master_secret_v5,
        verify_master_secret as sdk_verify_master_secret,
    },
    pqc::generate_hybrid_keypair,
    zeroize_utils::MasterSecret,
};
use wasm_bindgen::prelude::*;

use crate::util::{b64_decode, b64_encode, js_error, js_set};

/// Generate a fresh hybrid ML-KEM-1024 + X25519 keypair.
///
/// Returns `{ mlkem_public_key, mlkem_secret_key, x25519_public_key, x25519_secret_key,
///             public_key, private_key }` — `public_key`/`private_key` are legacy aliases.
#[wasm_bindgen]
pub fn generate_keypair() -> JsValue {
    match generate_hybrid_keypair() {
        Ok(kp) => {
            let mlkem_pub = b64_encode(kp.mlkem_public_key.as_bytes());
            let mlkem_sec = b64_encode(kp.mlkem_secret_key.as_bytes());
            let x25519_pub = b64_encode(kp.x25519_public_key.as_bytes());
            let x25519_sec = b64_encode(kp.x25519_secret_key.as_bytes());
            let obj = js_sys::Object::new();
            js_set(&obj, "mlkem_public_key", &JsValue::from_str(&mlkem_pub));
            js_set(&obj, "mlkem_secret_key", &JsValue::from_str(&mlkem_sec));
            js_set(&obj, "x25519_public_key", &JsValue::from_str(&x25519_pub));
            js_set(&obj, "x25519_secret_key", &JsValue::from_str(&x25519_sec));
            // Legacy aliases
            js_set(&obj, "public_key", &JsValue::from_str(&mlkem_pub));
            js_set(&obj, "private_key", &JsValue::from_str(&mlkem_sec));
            obj.into()
        }
        Err(_) => JsValue::NULL,
    }
}

/// Generate a fresh hybrid keypair (alternative field naming for some callers).
///
/// Returns `{ mlkem_public_key, mlkem_private_key, x25519_public_key, x25519_secret_key }`.
#[wasm_bindgen]
pub fn generate_random_keypair() -> JsValue {
    match generate_hybrid_keypair() {
        Ok(kp) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "mlkem_public_key",
                &JsValue::from_str(&b64_encode(kp.mlkem_public_key.as_bytes())),
            );
            // "mlkem_private_key" is the field name used by this variant (intentional)
            js_set(
                &obj,
                "mlkem_private_key",
                &JsValue::from_str(&b64_encode(kp.mlkem_secret_key.as_bytes())),
            );
            js_set(
                &obj,
                "x25519_public_key",
                &JsValue::from_str(&b64_encode(kp.x25519_public_key.as_bytes())),
            );
            js_set(
                &obj,
                "x25519_secret_key",
                &JsValue::from_str(&b64_encode(kp.x25519_secret_key.as_bytes())),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Extract public keys as a JSON string `{"mlkem_public_key":"...","x25519_public_key":"..."}`.
#[wasm_bindgen]
pub fn get_public_keys_json(keypair: JsValue) -> JsValue {
    let mlkem = Reflect::get(&keypair, &JsValue::from_str("mlkem_public_key"))
        .ok()
        .and_then(|v| v.as_string());
    let x25519 = Reflect::get(&keypair, &JsValue::from_str("x25519_public_key"))
        .ok()
        .and_then(|v| v.as_string());
    match (mlkem, x25519) {
        (Some(m), Some(x)) => JsValue::from_str(&format!(
            r#"{{"mlkem_public_key":"{m}","x25519_public_key":"{x}"}}"#
        )),
        _ => JsValue::NULL,
    }
}

/// Extract secret keys as a JSON string `{"mlkem_secret_key":"...","x25519_secret_key":"..."}`.
/// Also accepts `mlkem_private_key` field name (legacy inconsistency in some keypair objects).
#[wasm_bindgen]
pub fn get_secret_keys_json(keypair: JsValue) -> JsValue {
    let mlkem = Reflect::get(&keypair, &JsValue::from_str("mlkem_secret_key"))
        .ok()
        .and_then(|v| v.as_string())
        .or_else(|| {
            Reflect::get(&keypair, &JsValue::from_str("mlkem_private_key"))
                .ok()
                .and_then(|v| v.as_string())
        });
    let x25519 = Reflect::get(&keypair, &JsValue::from_str("x25519_secret_key"))
        .ok()
        .and_then(|v| v.as_string())
        .or_else(|| {
            Reflect::get(&keypair, &JsValue::from_str("x25519_private_key"))
                .ok()
                .and_then(|v| v.as_string())
        });
    match (mlkem, x25519) {
        (Some(m), Some(x)) => JsValue::from_str(&format!(
            r#"{{"mlkem_secret_key":"{m}","x25519_secret_key":"{x}"}}"#
        )),
        _ => JsValue::NULL,
    }
}

/// Generate a V5 master secret (37 bytes: `0x05 || SHAKE-256(32) || checksum(4)`).
/// Returns the secret as a base64 string.
#[wasm_bindgen]
pub fn generate_master_secret_v5() -> JsValue {
    match sdk_generate_master_secret_v5() {
        Ok(ms) => JsValue::from_str(&b64_encode(ms.as_bytes())),
        Err(_) => JsValue::NULL,
    }
}

/// Deterministically derive a hybrid keypair from a V2 or V5 master secret.
/// Returns `{ mlkem_private_key, mlkem_public_key, x25519_secret_key, x25519_public_key }`.
#[wasm_bindgen]
pub fn derive_keypair_from_master(master_secret_b64: String) -> JsValue {
    let bytes = match b64_decode(&master_secret_b64) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let ms = match MasterSecret::from_slice(&bytes) {
        Ok(m) => m,
        Err(e) => return JsValue::from_str(&e.to_string()),
    };
    match sdk_derive_keypair_from_master(&ms) {
        Ok(kp) => {
            let obj = js_sys::Object::new();
            // Field name matches old crate: "mlkem_private_key" (not "mlkem_secret_key")
            js_set(
                &obj,
                "mlkem_private_key",
                &JsValue::from_str(&b64_encode(kp.mlkem_secret_key.as_bytes())),
            );
            js_set(
                &obj,
                "mlkem_public_key",
                &JsValue::from_str(&b64_encode(kp.mlkem_public_key.as_bytes())),
            );
            js_set(
                &obj,
                "x25519_secret_key",
                &JsValue::from_str(&b64_encode(kp.x25519_secret_key.as_bytes())),
            );
            js_set(
                &obj,
                "x25519_public_key",
                &JsValue::from_str(&b64_encode(kp.x25519_public_key.as_bytes())),
            );
            obj.into()
        }
        Err(e) => JsValue::from_str(&e.to_string()),
    }
}

/// Verify a master secret's embedded checksum. Returns `true` if valid.
#[wasm_bindgen]
pub fn verify_master_secret(master_secret_b64: String) -> JsValue {
    let bytes = match b64_decode(&master_secret_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::from_bool(false),
    };
    match sdk_verify_master_secret(&bytes) {
        Ok(valid) => JsValue::from_bool(valid),
        Err(_) => JsValue::from_bool(false),
    }
}

/// Derive a 32-byte AES filename key from a V5 master secret.
/// Returns `{ key }` (base64) or `null` on error.
#[wasm_bindgen]
pub fn derive_filename_key_from_master(master_secret_b64: String) -> JsValue {
    let bytes = match b64_decode(&master_secret_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::NULL,
    };
    let ms = match MasterSecret::from_slice(&bytes) {
        Ok(m) => m,
        Err(_) => return JsValue::NULL,
    };
    match sdk_derive_filename_key_from_master(&ms) {
        Ok(key) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "key", &JsValue::from_str(&b64_encode(key.as_bytes())));
            obj.into()
        }
        Err(_) => JsValue::NULL,
    }
}
