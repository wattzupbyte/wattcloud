// Auth / KDF WASM bindings.
//
// Auth / KDF helpers. JS API contract is part of @wattcloud/wasm:
// - derive_auth_and_encryption_keys / derive_auth_hash_only / verify_auth_hash
// - encrypt_master_secret_with_key / decrypt_master_secret_with_key
// - generate_auth_salt / generate_device_key
//
// Return values are JSON strings (not objects) for the derive functions, matching
// the old crate's convention. Error fields are also JSON strings.

use sdk_core::crypto::{
    auth::{
        decrypt_with_key, encrypt_with_key, verify_auth_hash as sdk_verify_auth_hash, EncryptedBlob,
    },
    auth::{derive_auth_and_encryption_keys as sdk_derive_auth_keys, AuthKeys},
    kdf::{
        argon2id_derive, argon2id_derive_with_params, derive_auth_hash,
        generate_auth_salt as sdk_generate_auth_salt,
        generate_device_key as sdk_generate_device_key,
    },
    zeroize_utils::SymmetricKey,
};
use wasm_bindgen::prelude::*;

use crate::util::{b64_decode, b64_encode};

// Argon2id parameters — hardcoded here to match sdk-core's internal constants.
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_MEMORY_KB: u32 = 65536;
const ARGON2_PARALLELISM: u32 = 4;

/// Generate a random 32-byte Argon2id salt.
/// Returns a base64 string.
#[wasm_bindgen]
pub fn generate_auth_salt() -> JsValue {
    match sdk_generate_auth_salt() {
        Ok(salt) => JsValue::from_str(&b64_encode(&salt)),
        Err(_) => JsValue::NULL,
    }
}

/// Derive auth_hash and encryption_key from a password and base64-encoded salt using Argon2id.
///
/// Returns a JSON string:
/// `{ auth_hash, encryption_key, salt, algorithm, iterations, memory_kb, parallelism, argon_output }`.
/// All byte fields are base64. On error returns JSON `{ error }`.
#[wasm_bindgen]
pub fn derive_auth_and_encryption_keys(password: &str, salt_b64: &str) -> JsValue {
    let salt = match b64_decode(salt_b64) {
        Ok(s) => s,
        Err(_) => {
            return JsValue::from_str(r#"{"error":"invalid base64 salt"}"#);
        }
    };
    match sdk_derive_auth_keys(password.as_bytes(), &salt) {
        Ok(AuthKeys {
            auth_hash,
            encryption_key,
            argon_output,
        }) => {
            let json = format!(
                r#"{{"auth_hash":"{ah}","encryption_key":"{ek}","salt":"{salt}","algorithm":"argon2id","iterations":{it},"memory_kb":{mem},"parallelism":{par},"argon_output":"{ao}"}}"#,
                ah = b64_encode(&auth_hash),
                ek = b64_encode(encryption_key.as_bytes()),
                salt = salt_b64,
                it = ARGON2_ITERATIONS,
                mem = ARGON2_MEMORY_KB,
                par = ARGON2_PARALLELISM,
                ao = b64_encode(argon_output.as_bytes()),
            );
            JsValue::from_str(&json)
        }
        Err(e) => JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    }
}

/// Derive auth_hash and encryption_key with custom Argon2id memory parameter.
/// Use `memory_kb` from the init-login response (65536 for legacy, 131072 for migrated/BYO).
/// Returns a JSON string:
/// `{ auth_hash, encryption_key, salt, algorithm, iterations, memory_kb, parallelism, argon_output }`.
/// All byte fields are base64. On error returns JSON `{ error }`.
#[wasm_bindgen]
pub fn derive_auth_and_encryption_keys_with_params(
    password: &str,
    salt_b64: &str,
    memory_kb: u32,
) -> JsValue {
    let salt = match b64_decode(salt_b64) {
        Ok(s) => s,
        Err(_) => {
            return JsValue::from_str(r#"{"error":"invalid base64 salt"}"#);
        }
    };
    let argon_output = match argon2id_derive_with_params(
        password.as_bytes(),
        &salt,
        memory_kb,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
    ) {
        Ok(o) => o,
        Err(e) => return JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    };

    let auth_hash = match derive_auth_hash(&argon_output) {
        Ok(h) => h,
        Err(e) => return JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    };
    let encryption_key = match sdk_core::crypto::kdf::derive_encryption_key(&argon_output) {
        Ok(k) => k,
        Err(e) => return JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    };

    let json = format!(
        r#"{{"auth_hash":"{ah}","encryption_key":"{ek}","salt":"{salt}","algorithm":"argon2id","iterations":{it},"memory_kb":{mem},"parallelism":{par},"argon_output":"{ao}"}}"#,
        ah = b64_encode(&auth_hash),
        ek = b64_encode(encryption_key.as_bytes()),
        salt = salt_b64,
        it = ARGON2_ITERATIONS,
        mem = memory_kb,
        par = ARGON2_PARALLELISM,
        ao = b64_encode(argon_output.as_bytes()),
    );
    JsValue::from_str(&json)
}

/// Derive only the auth_hash from a password and base64 salt.
/// Returns a JSON string `{ auth_hash }` or `{ error }`.
#[wasm_bindgen]
pub fn derive_auth_hash_only(password: &str, salt_b64: &str) -> JsValue {
    let salt = match b64_decode(salt_b64) {
        Ok(s) => s,
        Err(_) => {
            return JsValue::from_str(r#"{"error":"invalid base64 salt"}"#);
        }
    };
    let output = match argon2id_derive(password.as_bytes(), &salt) {
        Ok(o) => o,
        Err(e) => return JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    };
    match derive_auth_hash(&output) {
        Ok(hash) => JsValue::from_str(&format!(r#"{{"auth_hash":"{}"}}"#, b64_encode(&hash))),
        Err(e) => JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    }
}

/// Verify a password against a stored auth_hash and salt. Returns `true` if correct.
#[wasm_bindgen]
pub fn verify_auth_hash(password: &str, salt_b64: &str, expected_hash_b64: &str) -> JsValue {
    let salt = match b64_decode(salt_b64) {
        Ok(s) => s,
        Err(_) => return JsValue::from_bool(false),
    };
    let expected = match b64_decode(expected_hash_b64) {
        Ok(h) => h,
        Err(_) => return JsValue::from_bool(false),
    };
    match sdk_verify_auth_hash(password.as_bytes(), &salt, &expected) {
        Ok(valid) => JsValue::from_bool(valid),
        Err(_) => JsValue::from_bool(false),
    }
}

/// Encrypt a master secret (or any plaintext) with an AES-256-GCM key.
/// Returns a JSON string `{ iv, ciphertext }` (both base64) or `{ error }`.
#[wasm_bindgen]
pub fn encrypt_master_secret_with_key(
    master_secret_b64: &str,
    encryption_key_b64: &str,
) -> JsValue {
    let plaintext = match b64_decode(master_secret_b64) {
        Ok(p) => p,
        Err(_) => return JsValue::from_str(r#"{"error":"invalid base64 plaintext"}"#),
    };
    let key_bytes = match b64_decode(encryption_key_b64) {
        Ok(k) => k,
        Err(_) => return JsValue::from_str(r#"{"error":"invalid base64 key"}"#),
    };
    let key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(e) => return JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    };
    match encrypt_with_key(&plaintext, &key) {
        Ok(blob) => {
            let json = format!(
                r#"{{"iv":"{}","ciphertext":"{}"}}"#,
                b64_encode(&blob.iv),
                b64_encode(&blob.ciphertext),
            );
            JsValue::from_str(&json)
        }
        Err(e) => JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    }
}

/// Decrypt a master secret encrypted with `encrypt_master_secret_with_key`.
/// `encrypted_json` must be `{ iv, ciphertext }` (both base64).
/// Returns a base64 string of the decrypted plaintext, or a JSON `{ error }` string.
#[wasm_bindgen]
pub fn decrypt_master_secret_with_key(encrypted_json: &str, encryption_key_b64: &str) -> JsValue {
    let v: serde_json::Value = match serde_json::from_str(encrypted_json) {
        Ok(v) => v,
        Err(_) => return JsValue::from_str(r#"{"error":"invalid encrypted JSON"}"#),
    };
    let iv_b64 = match v["iv"].as_str() {
        Some(s) => s,
        None => return JsValue::from_str(r#"{"error":"missing iv"}"#),
    };
    let ct_b64 = match v["ciphertext"].as_str() {
        Some(s) => s,
        None => return JsValue::from_str(r#"{"error":"missing ciphertext"}"#),
    };
    let iv_bytes = match b64_decode(iv_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::from_str(r#"{"error":"invalid base64 iv"}"#),
    };
    let ciphertext = match b64_decode(ct_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::from_str(r#"{"error":"invalid base64 ciphertext"}"#),
    };
    let iv: [u8; 12] = match iv_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return JsValue::from_str(r#"{"error":"iv must be 12 bytes"}"#),
    };
    let key_bytes = match b64_decode(encryption_key_b64) {
        Ok(k) => k,
        Err(_) => return JsValue::from_str(r#"{"error":"invalid base64 key"}"#),
    };
    let key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(e) => return JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    };
    let blob = EncryptedBlob { iv, ciphertext };
    match decrypt_with_key(&blob, &key) {
        Ok(plaintext) => JsValue::from_str(&b64_encode(&plaintext)),
        Err(e) => JsValue::from_str(&format!(r#"{{"error":"{e}"}}"#)),
    }
}

/// Generate a random 32-byte device key.
/// Returns a base64 string.
#[wasm_bindgen]
pub fn generate_device_key() -> JsValue {
    match sdk_generate_device_key() {
        Ok(key) => JsValue::from_str(&b64_encode(key.as_bytes())),
        Err(_) => JsValue::NULL,
    }
}
