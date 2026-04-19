// Filename and folder-path encryption WASM bindings.
//
// Return shapes are part of the @wattcloud/wasm JS API contract — see docs below.
//   encrypt_filename    → { encrypted_name }  (base64)
//   decrypt_filename    → { name }            (UTF-8 string)
//   encrypt_folder_path → { encrypted_path }  (base64 components joined with '/')
//   decrypt_folder_path → { path }            (decrypted path string)
// Returns null on any error.

use sdk_core::crypto::{
    filename::{
        decrypt_filename as sdk_decrypt_filename, decrypt_folder_path as sdk_decrypt_folder_path,
        encrypt_filename as sdk_encrypt_filename, encrypt_folder_path as sdk_encrypt_folder_path,
    },
    zeroize_utils::SymmetricKey,
};
use wasm_bindgen::prelude::*;

use crate::util::{b64_decode, b64_encode, js_set};

/// Encrypt a filename with a 32-byte AES filename key.
/// Returns `{ encrypted_name }` (base64) or `null` on error.
#[wasm_bindgen]
pub fn encrypt_filename(name: String, key_b64: String) -> JsValue {
    let key_bytes = match b64_decode(&key_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::NULL,
    };
    let key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(_) => return JsValue::NULL,
    };
    match sdk_encrypt_filename(&name, &key) {
        Ok(enc) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "encrypted_name",
                &JsValue::from_str(&b64_encode(&enc)),
            );
            obj.into()
        }
        Err(_) => JsValue::NULL,
    }
}

/// Decrypt a filename.
/// `encrypted_name_b64` — base64 of `nonce(12) || ciphertext+tag`.
/// Returns `{ name }` (UTF-8 string) or `null` on error.
#[wasm_bindgen]
pub fn decrypt_filename(encrypted_name_b64: String, key_b64: String) -> JsValue {
    let enc = match b64_decode(&encrypted_name_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::NULL,
    };
    let key_bytes = match b64_decode(&key_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::NULL,
    };
    let key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(_) => return JsValue::NULL,
    };
    match sdk_decrypt_filename(&enc, &key) {
        Ok(name) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "name", &JsValue::from_str(&name));
            obj.into()
        }
        Err(_) => JsValue::NULL,
    }
}

/// Encrypt each component of a `/`-delimited folder path separately.
/// Returns `{ encrypted_path }` where the value is base64 components joined with `/`.
/// Returns `null` on error.
#[wasm_bindgen]
pub fn encrypt_folder_path(path: String, key_b64: String) -> JsValue {
    let key_bytes = match b64_decode(&key_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::NULL,
    };
    let key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(_) => return JsValue::NULL,
    };
    match sdk_encrypt_folder_path(&path, &key) {
        Ok(components) => {
            let joined = components
                .iter()
                .map(|c| b64_encode(c))
                .collect::<Vec<_>>()
                .join("/");
            let obj = js_sys::Object::new();
            js_set(&obj, "encrypted_path", &JsValue::from_str(&joined));
            obj.into()
        }
        Err(_) => JsValue::NULL,
    }
}

/// Decrypt a `/`-joined base64 encrypted folder path.
/// Returns `{ path }` (decrypted path string) or `null` on error.
#[wasm_bindgen]
pub fn decrypt_folder_path(encrypted_path: String, key_b64: String) -> JsValue {
    let key_bytes = match b64_decode(&key_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::NULL,
    };
    let key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(_) => return JsValue::NULL,
    };
    // Split on '/' and decode each component
    let components: Result<Vec<Vec<u8>>, _> = encrypted_path
        .split('/')
        .map(|s| b64_decode(s).map_err(|_| ()))
        .collect();
    let components = match components {
        Ok(c) => c,
        Err(()) => return JsValue::NULL,
    };
    match sdk_decrypt_folder_path(&components, &key) {
        Ok(path) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "path", &JsValue::from_str(&path));
            obj.into()
        }
        Err(_) => JsValue::NULL,
    }
}
