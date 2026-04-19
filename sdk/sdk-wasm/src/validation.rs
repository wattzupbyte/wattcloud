// Validation WASM bindings.
//
// These are NEW exports (no equivalent in the old wasm crate).
// All functions return plain JS objects built with js_set.
//
//   validate_password(pw, username?) → { valid, strength, errors[], warnings[] }
//   get_strength_description(n)      → { label, color }
//   validate_email(email)            → { valid, error? }
//   validate_filename(name)          → { valid, error? }
//   validate_file_size(size, max_mb) → { valid, error? }
//   validate_username(username)      → { valid, error? }

use sdk_core::validation::{
    get_strength_description as sdk_strength_description, validate_email as sdk_validate_email,
    validate_file_size as sdk_validate_file_size, validate_filename as sdk_validate_filename,
    validate_password as sdk_validate_password, validate_username as sdk_validate_username,
};
use wasm_bindgen::prelude::*;

use crate::util::js_set;

/// Validate a password against all rules.
///
/// Returns `{ valid: bool, strength: 0-4, errors: string[], warnings: string[] }`.
#[wasm_bindgen]
pub fn validate_password(password: &str, username: Option<String>) -> JsValue {
    let result = sdk_validate_password(password, username.as_deref());

    let errors = js_sys::Array::new();
    for e in &result.errors {
        errors.push(&JsValue::from_str(e));
    }
    let warnings = js_sys::Array::new();
    for w in &result.warnings {
        warnings.push(&JsValue::from_str(w));
    }

    let obj = js_sys::Object::new();
    js_set(&obj, "valid", &JsValue::from_bool(result.valid));
    js_set(&obj, "strength", &JsValue::from_f64(result.strength as f64));
    js_set(&obj, "errors", &errors.into());
    js_set(&obj, "warnings", &warnings.into());
    obj.into()
}

/// Map a strength score (0-4) to a label and color.
///
/// Returns `{ label: string, color: string }`.
#[wasm_bindgen]
pub fn get_strength_description(strength: u8) -> JsValue {
    let desc = sdk_strength_description(strength);
    let obj = js_sys::Object::new();
    js_set(&obj, "label", &JsValue::from_str(desc.label));
    js_set(&obj, "color", &JsValue::from_str(desc.color));
    obj.into()
}

/// Validate an email address (basic format check).
/// Returns `{ valid: bool, error?: string }`.
#[wasm_bindgen]
pub fn validate_email(email: &str) -> JsValue {
    let obj = js_sys::Object::new();
    match sdk_validate_email(email) {
        Ok(()) => {
            js_set(&obj, "valid", &JsValue::TRUE);
        }
        Err(e) => {
            js_set(&obj, "valid", &JsValue::FALSE);
            js_set(&obj, "error", &JsValue::from_str(&e.to_string()));
        }
    }
    obj.into()
}

/// Validate a filename (no path separators, no NUL, 1-255 bytes).
/// Returns `{ valid: bool, error?: string }`.
#[wasm_bindgen]
pub fn validate_filename(name: &str) -> JsValue {
    let obj = js_sys::Object::new();
    match sdk_validate_filename(name) {
        Ok(()) => {
            js_set(&obj, "valid", &JsValue::TRUE);
        }
        Err(e) => {
            js_set(&obj, "valid", &JsValue::FALSE);
            js_set(&obj, "error", &JsValue::from_str(&e.to_string()));
        }
    }
    obj.into()
}

/// Validate a file size against a per-user or server-wide limit in MB.
/// Returns `{ valid: bool, error?: string }`.
#[wasm_bindgen]
pub fn validate_file_size(size_bytes: f64, max_mb: f64) -> JsValue {
    let obj = js_sys::Object::new();
    match sdk_validate_file_size(size_bytes as u64, max_mb as u64) {
        Ok(()) => {
            js_set(&obj, "valid", &JsValue::TRUE);
        }
        Err(e) => {
            js_set(&obj, "valid", &JsValue::FALSE);
            js_set(&obj, "error", &JsValue::from_str(&e.to_string()));
        }
    }
    obj.into()
}

/// Validate a username (3-50 chars, ASCII letters/digits/underscore).
/// Returns `{ valid: bool, error?: string }`.
#[wasm_bindgen]
pub fn validate_username(username: &str) -> JsValue {
    let obj = js_sys::Object::new();
    match sdk_validate_username(username) {
        Ok(()) => {
            js_set(&obj, "valid", &JsValue::TRUE);
        }
        Err(e) => {
            js_set(&obj, "valid", &JsValue::FALSE);
            js_set(&obj, "error", &JsValue::from_str(&e.to_string()));
        }
    }
    obj.into()
}
