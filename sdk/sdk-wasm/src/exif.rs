// EXIF WASM bindings — JPEG metadata extraction + thumbnail crypto.

use sdk_core::exif::{decrypt_thumbnail, encrypt_thumbnail, extract_exif};
use wasm_bindgen::prelude::*;

use crate::util::{js_error, parse_public_keys, parse_secret_keys};

/// Extract EXIF metadata from JPEG bytes.
///
/// `data` — raw JPEG bytes (Uint8Array from JS).
///
/// Returns a JSON object:
/// `{ taken_at?, latitude?, longitude?, camera_make?, camera_model?,
///    exposure_time?, f_number?, iso? }`
///
/// All fields are optional (absent means not found). Never returns `{ error }`.
#[wasm_bindgen]
pub fn extract_exif_wasm(data: Vec<u8>) -> JsValue {
    let exif = extract_exif(&data);
    // Serialize the ExifData struct to JSON. ExifData derives Serialize and uses
    // skip_serializing_if = "Option::is_none" so absent fields are omitted.
    match serde_json::to_string(&exif) {
        Ok(json) => JsValue::from_str(&json),
        Err(e) => js_error(&e.to_string()),
    }
}

/// Encrypt thumbnail bytes for server storage (v7 wire format).
///
/// `data` — plaintext thumbnail bytes (Uint8Array).
/// `pub_keys_json` — `{ "mlkem_public_key": "...", "x25519_public_key": "..." }`.
///
/// Returns the encrypted bytes as a `Uint8Array` or `null` on error.
#[wasm_bindgen]
pub fn encrypt_thumbnail_wasm(data: Vec<u8>, pub_keys_json: String) -> Option<Vec<u8>> {
    let (mlkem_pub, x25519_pub) = parse_public_keys(&pub_keys_json).ok()?;
    encrypt_thumbnail(&data, &mlkem_pub, &x25519_pub).ok()
}

/// Decrypt thumbnail bytes from server storage.
///
/// `encrypted` — raw v7 ciphertext bytes (Uint8Array).
/// `sec_keys_json` — `{ "mlkem_secret_key": "...", "x25519_secret_key": "..." }`.
///
/// Returns the plaintext as a `Uint8Array` or `null` on error.
#[wasm_bindgen]
pub fn decrypt_thumbnail_wasm(encrypted: Vec<u8>, sec_keys_json: String) -> Option<Vec<u8>> {
    let (mlkem_sec, x25519_sec) = parse_secret_keys(&sec_keys_json).ok()?;
    decrypt_thumbnail(&encrypted, &mlkem_sec, &x25519_sec).ok()
}
