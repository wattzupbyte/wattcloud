// Hashing WASM bindings.
//
// blake2b_256 matches the existing secure-cloud-wasm crate:
//   input:  base64 data
//   output: { hash } (base64 32-byte digest) or { error }

use sdk_core::crypto::hashing::blake2b_256 as sdk_blake2b_256;
use wasm_bindgen::prelude::*;

use crate::util::{b64_decode, b64_encode, js_error, js_set};

/// Compute BLAKE2b-256 over base64-encoded input data.
/// Returns `{ hash }` (base64) or `{ error }`.
#[wasm_bindgen]
pub fn blake2b_256(data_b64: String) -> JsValue {
    let data = match b64_decode(&data_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 data"),
    };
    let hash = sdk_blake2b_256(&data);
    let obj = js_sys::Object::new();
    js_set(&obj, "hash", &JsValue::from_str(&b64_encode(&hash)));
    obj.into()
}
