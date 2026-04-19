// Utilities shared across WASM binding modules.
// base64 encode/decode, JSON key parsing, JsValue object helpers.
//
// This is the base64 boundary: sdk-core works with raw bytes; everything crossing
// the JS/Rust boundary is encoded here.

use base64::{engine::general_purpose::STANDARD, Engine};
use js_sys::Reflect;
use sdk_core::crypto::zeroize_utils::{
    MlKemPublicKey, MlKemSecretKey, X25519PublicKey, X25519SecretKey,
};
use wasm_bindgen::prelude::*;

/// Encode raw bytes as standard base64 with padding.
pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode a standard base64 string to bytes; returns a JS error string on failure.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, JsValue> {
    STANDARD
        .decode(s)
        .map_err(|e| JsValue::from_str(&format!("base64 decode error: {e}")))
}

/// Parse `{"mlkem_public_key":"...","x25519_public_key":"..."}` JSON into typed keys.
pub fn parse_public_keys(json: &str) -> Result<(MlKemPublicKey, X25519PublicKey), JsValue> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mlkem_b64 = v["mlkem_public_key"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("missing mlkem_public_key"))?;
    let x25519_b64 = v["x25519_public_key"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("missing x25519_public_key"))?;
    let mlkem = MlKemPublicKey::from_slice(&b64_decode(mlkem_b64)?)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let x25519 = X25519PublicKey::from_slice(&b64_decode(x25519_b64)?)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok((mlkem, x25519))
}

/// Parse `{"mlkem_secret_key":"...","x25519_secret_key":"..."}` JSON into typed keys.
/// Also accepts `mlkem_private_key` / `x25519_private_key` (legacy naming inconsistency).
pub fn parse_secret_keys(json: &str) -> Result<(MlKemSecretKey, X25519SecretKey), JsValue> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mlkem_b64 = v["mlkem_secret_key"]
        .as_str()
        .or_else(|| v["mlkem_private_key"].as_str())
        .ok_or_else(|| JsValue::from_str("missing mlkem_secret_key"))?;
    let x25519_b64 = v["x25519_secret_key"]
        .as_str()
        .or_else(|| v["x25519_private_key"].as_str())
        .ok_or_else(|| JsValue::from_str("missing x25519_secret_key"))?;
    let mlkem = MlKemSecretKey::from_slice(&b64_decode(mlkem_b64)?)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let x25519 = X25519SecretKey::from_slice(&b64_decode(x25519_b64)?)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok((mlkem, x25519))
}

/// Set a property on a plain JS Object.
/// Reflect::set only fails for non-extensible objects or Proxy traps — never for plain Objects.
#[allow(clippy::expect_used)]
pub fn js_set(obj: &js_sys::Object, key: &str, val: &JsValue) {
    Reflect::set(obj, &JsValue::from_str(key), val)
        .expect("js_set: plain Object is always extensible");
}

/// Build `{ error: "msg" }`.
pub fn js_error(msg: &str) -> JsValue {
    let obj = js_sys::Object::new();
    js_set(&obj, "error", &JsValue::from_str(msg));
    obj.into()
}
