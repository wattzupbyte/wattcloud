// sdk-wasm: WASM binding layer for sdk-core (Wattcloud BYO build).
//
// This is the base64 boundary: sdk-core works with raw bytes; this crate handles
// all base64 encode/decode and builds JsValue objects.
//
// Modules:
//   util           — shared helpers (base64, JSON key parsing, JsValue builders)
//   keys           — keypair generation, master secret, key derivation
//   auth           — auth hash / symmetric encrypt-decrypt helpers
//   kek            — KEK derivation, recovery KEK, re-encryption
//   crypto         — V7 chunked file encryption/decryption
//   filename       — filename and folder-path encryption
//   hashing        — BLAKE2b-256
//   validation     — password, email, filename, file size, username
//   exif           — JPEG EXIF extraction + thumbnail crypto
//   byo*           — BYO provider, vault, streaming, SFTP, enrollment
//   oauth, provider_http, stats — BYO relay + provider plumbing

pub mod auth;
pub mod byo;
pub mod byo_providers;
pub mod byo_streaming;
pub mod byo_sftp;
pub mod byo_vault;
pub mod stats;
pub(crate) mod enrollment_session;
pub(crate) mod vault_session;
pub mod crypto;
pub mod exif;
pub mod filename;
pub mod hashing;
pub mod kek;
pub mod keys;
pub mod oauth;
mod provider_http;
mod util;
pub mod validation;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn health_check() -> String {
    sdk_core::health_check().to_string()
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_health_check() {
        let result = super::health_check();
        assert_eq!(result, "sdk-core ok");
    }
}
