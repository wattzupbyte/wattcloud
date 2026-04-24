// BYO vault operations WASM bindings.
//
// All byte values are base64-encoded (sdk-core works with raw bytes;
// this crate handles all base64 encode/decode at the boundary).
// Errors return { error: "message" }.
// Successful returns use JSON objects with base64 byte fields.

use sdk_core::byo::{
    enrollment::{
        decrypt_payload_from_transfer, decrypt_shard_from_transfer, encrypt_payload_for_transfer,
        encrypt_shard_for_transfer, enrollment_derive_session, enrollment_initiate,
        EnrollmentSession, PayloadEnvelope, ShardEnvelope,
    },
    relay_auth::{derive_enrollment_purpose, derive_sftp_purpose, solve_pow},
    share::{decode_variant_a, encode_variant_a, unwrap_key_with_password, wrap_key_with_password},
    vault_crypto::{
        argon2id_derive_byo, compute_header_hmac, compute_header_hmac_v1, decrypt_vault_body,
        derive_byo_kek, derive_client_kek_half_from_byo, derive_recovery_vault_kek,
        derive_vault_kek, ed25519_sign, ed25519_verify, encrypt_vault_body,
        generate_device_signing_key, generate_vault_keys, migrate_vault_v1_to_v2,
        seal_device_signing_key, unseal_device_signing_key, unwrap_vault_key, verify_header_hmac,
        verify_header_hmac_v1, wrap_vault_key,
    },
    vault_format::VaultHeader,
};
use sdk_core::crypto::constants::V7_HEADER_MIN;
use sdk_core::crypto::kdf::{argon2id_derive_with_params, hkdf_sha256};
use sdk_core::crypto::pqc::generate_hybrid_keypair;
use sdk_core::crypto::symmetric::{aes_gcm_decrypt, aes_gcm_encrypt, generate_aes_key};
use sdk_core::crypto::webauthn::{
    derive_vault_key_wrapping_key_from_prf, unwrap_vault_key_with_prf as unwrap_vk_prf,
    wrap_vault_key_with_prf as wrap_vk_prf,
};
use sdk_core::crypto::wire_format::{decrypt_file_v7_init, encrypt_manifest_v7, V7ShareDecryptor};
use sdk_core::crypto::zeroize_utils::{MlKemSecretKey, Nonce12, SymmetricKey, X25519SecretKey};
use wasm_bindgen::prelude::*;

use crate::enrollment_session::{
    close_enrollment_session, store_enrollment_session, with_enrollment_session_mut,
    WasmEnrollmentSession,
};
use crate::util::{
    b64_decode, b64_encode, b64url_decode_lenient, b64url_encode_nopad, js_error, js_set,
};
use crate::vault_session::{
    close_vault_session, store_vault_session, with_vault_session, with_vault_session_mut,
    VaultSession,
};

/// Parse a BYO vault header from raw bytes.
/// Returns JSON with header fields or { error }.
#[wasm_bindgen]
pub fn byo_parse_vault_header(vault_bytes: Vec<u8>) -> JsValue {
    match VaultHeader::parse(&vault_bytes) {
        Ok(header) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "format_version",
                &JsValue::from(header.format_version),
            );
            js_set(
                &obj,
                "argon2_memory_kb",
                &JsValue::from(header.argon2_memory_kb),
            );
            js_set(
                &obj,
                "argon2_iterations",
                &JsValue::from(header.argon2_iterations),
            );
            js_set(
                &obj,
                "argon2_parallelism",
                &JsValue::from(header.argon2_parallelism),
            );
            js_set(
                &obj,
                "master_salt",
                &JsValue::from_str(&b64_encode(&header.master_salt)),
            );
            js_set(
                &obj,
                "vault_id",
                &JsValue::from_str(&b64_encode(&header.vault_id)),
            );
            js_set(
                &obj,
                "pass_wrap_iv",
                &JsValue::from_str(&b64_encode(&header.pass_wrap_iv)),
            );
            js_set(
                &obj,
                "pass_wrapped_vault_key",
                &JsValue::from_str(&b64_encode(&header.pass_wrapped_vault_key)),
            );
            js_set(
                &obj,
                "recovery_wrap_iv",
                &JsValue::from_str(&b64_encode(&header.recovery_wrap_iv)),
            );
            js_set(
                &obj,
                "recovery_wrapped_vault_key",
                &JsValue::from_str(&b64_encode(&header.recovery_wrapped_vault_key)),
            );

            // Serialize device slots as JSON array
            let slots = js_sys::Array::new();
            for slot in &header.device_slots {
                let s = js_sys::Object::new();
                js_set(&s, "status", &JsValue::from(slot.status as u8));
                js_set(
                    &s,
                    "device_id",
                    &JsValue::from_str(&b64_encode(&slot.device_id)),
                );
                js_set(
                    &s,
                    "wrap_iv",
                    &JsValue::from_str(&b64_encode(&slot.wrap_iv)),
                );
                js_set(
                    &s,
                    "encrypted_payload",
                    &JsValue::from_str(&b64_encode(&slot.encrypted_payload)),
                );
                slots.push(&s);
            }
            js_set(&obj, "device_slots", &slots);
            js_set(
                &obj,
                "num_active_slots",
                &JsValue::from(header.active_slot_count()),
            );
            js_set(
                &obj,
                "header_hmac",
                &JsValue::from_str(&b64_encode(&header.header_hmac)),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Derive vault keys from passphrase using Argon2id with header-specified parameters.
/// Returns { vault_kek, client_kek_half, argon_output } (all base64) or { error }.
#[wasm_bindgen]
pub fn byo_derive_vault_keys(
    password: String,
    salt_b64: String,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> JsValue {
    let salt = match b64_decode(&salt_b64) {
        Ok(s) => s,
        Err(_) => return js_error("invalid base64 salt"),
    };
    let argon_output = match argon2id_derive_with_params(
        password.as_bytes(),
        &salt,
        memory_kb,
        iterations,
        parallelism,
    ) {
        Ok(o) => o,
        Err(e) => return js_error(&e.to_string()),
    };
    let vault_kek = match derive_vault_kek(&argon_output) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let client_kek_half = match derive_client_kek_half_from_byo(&argon_output) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let obj = js_sys::Object::new();
    js_set(
        &obj,
        "vault_kek",
        &JsValue::from_str(&b64_encode(vault_kek.as_bytes())),
    );
    js_set(
        &obj,
        "client_kek_half",
        &JsValue::from_str(&b64_encode(client_kek_half.as_bytes())),
    );
    js_set(
        &obj,
        "argon_output",
        &JsValue::from_str(&b64_encode(argon_output.as_bytes())),
    );
    obj.into()
}

/// Unwrap vault_key from passphrase or recovery slot.
/// Returns { vault_key } (base64) or { error }.
#[wasm_bindgen]
pub fn byo_unwrap_vault_key(
    wrap_iv_b64: String,
    wrapped_key_b64: String,
    unwrapping_key_b64: String,
) -> JsValue {
    let iv_bytes = match b64_decode(&wrap_iv_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 wrap_iv"),
    };
    let iv: [u8; 12] = match iv_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("wrap_iv must be 12 bytes"),
    };
    let wrapped = match b64_decode(&wrapped_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 wrapped_key"),
    };
    let wrapped_arr: [u8; 48] = match wrapped.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("wrapped_key must be 48 bytes"),
    };
    let key_bytes = match b64_decode(&unwrapping_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 unwrapping_key"),
    };
    let unwrapping_key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    match unwrap_vault_key(&iv, &wrapped_arr, &unwrapping_key) {
        Ok(vault_key) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "vault_key",
                &JsValue::from_str(&b64_encode(vault_key.as_bytes())),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Derive BYO KEK from client_kek_half and shard.
/// Reuses the same HKDF info string as managed mode (KEK_V2).
/// Returns { kek } (base64) or { error }.
#[wasm_bindgen]
pub fn byo_derive_kek(client_kek_half_b64: String, shard_b64: String) -> JsValue {
    let half_bytes = match b64_decode(&client_kek_half_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 client_kek_half"),
    };
    let shard_bytes = match b64_decode(&shard_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 shard"),
    };
    let half = match SymmetricKey::from_slice(&half_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    match derive_byo_kek(&half, &shard_bytes) {
        Ok(kek) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "kek", &JsValue::from_str(&b64_encode(kek.as_bytes())));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Derive recovery_vault_kek from the 32-byte secret portion of a recovery key.
/// `recovery_key_b64` is base64-encoded 32 bytes (recovery_key[1..33]).
/// Returns { recovery_vault_kek } (base64) or { error }.
#[wasm_bindgen]
pub fn byo_derive_recovery_vault_kek(recovery_key_b64: String) -> JsValue {
    let bytes = match b64_decode(&recovery_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 recovery_key"),
    };
    if bytes.len() != 32 {
        return js_error("recovery_key secret must be 32 bytes");
    }
    match derive_recovery_vault_kek(&bytes) {
        Ok(kek) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "recovery_vault_kek",
                &JsValue::from_str(&b64_encode(kek.as_bytes())),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Compute header HMAC: HMAC-SHA256(vault_key, header_bytes[0..807]).
/// Returns { hmac } (base64) or { error }.
#[wasm_bindgen]
pub fn byo_compute_header_hmac(vault_key_b64: String, header_prefix_b64: String) -> JsValue {
    let key_bytes = match b64_decode(&vault_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 vault_key"),
    };
    let vault_key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let header_prefix = match b64_decode(&header_prefix_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 header_prefix"),
    };
    // Route to the v1 or v2 variant based on prefix length. A1: each variant is
    // strict on its expected length so a caller can't silently compute a v1
    // HMAC over a v2 header's first 807 bytes (or vice-versa).
    let hmac_result = match header_prefix.len() {
        n if n == sdk_core::crypto::constants::VAULT_HMAC_OFFSET => {
            compute_header_hmac(&vault_key, &header_prefix)
        }
        n if n == sdk_core::crypto::constants::VAULT_HMAC_OFFSET_V1 => {
            compute_header_hmac_v1(&vault_key, &header_prefix)
        }
        _ => {
            return js_error(&format!(
                "header_prefix length {} is neither v1 ({}) nor v2 ({})",
                header_prefix.len(),
                sdk_core::crypto::constants::VAULT_HMAC_OFFSET_V1,
                sdk_core::crypto::constants::VAULT_HMAC_OFFSET,
            ));
        }
    };
    match hmac_result {
        Ok(hmac) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "hmac", &JsValue::from_str(&b64_encode(&hmac)));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Verify header HMAC using constant-time comparison.
/// Returns { valid: true/false } or { error }.
#[wasm_bindgen]
pub fn byo_verify_header_hmac(
    vault_key_b64: String,
    header_prefix_b64: String,
    expected_hmac_b64: String,
) -> JsValue {
    let key_bytes = match b64_decode(&vault_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 vault_key"),
    };
    let vault_key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let header_prefix = match b64_decode(&header_prefix_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 header_prefix"),
    };
    let hmac_bytes = match b64_decode(&expected_hmac_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 expected_hmac"),
    };
    let expected: [u8; 32] = match hmac_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("expected_hmac must be 32 bytes"),
    };
    // A1: route to v1 or v2 variant strictly on prefix length.
    let verify_result = match header_prefix.len() {
        n if n == sdk_core::crypto::constants::VAULT_HMAC_OFFSET => {
            verify_header_hmac(&vault_key, &header_prefix, &expected)
        }
        n if n == sdk_core::crypto::constants::VAULT_HMAC_OFFSET_V1 => {
            verify_header_hmac_v1(&vault_key, &header_prefix, &expected)
        }
        _ => {
            return js_error(&format!(
                "header_prefix length {} is neither v1 ({}) nor v2 ({})",
                header_prefix.len(),
                sdk_core::crypto::constants::VAULT_HMAC_OFFSET_V1,
                sdk_core::crypto::constants::VAULT_HMAC_OFFSET,
            ));
        }
    };
    match verify_result {
        Ok(valid) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "valid", &JsValue::from_bool(valid));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Wrap vault_key with a wrapping key (AES-256-GCM).
/// Returns { wrap_iv, wrapped_key } (both base64) or { error }.
#[wasm_bindgen]
pub fn byo_wrap_vault_key(vault_key_b64: String, wrapping_key_b64: String) -> JsValue {
    let vk_bytes = match b64_decode(&vault_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 vault_key"),
    };
    let vault_key = match SymmetricKey::from_slice(&vk_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let wk_bytes = match b64_decode(&wrapping_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 wrapping_key"),
    };
    let wrapping_key = match SymmetricKey::from_slice(&wk_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    match wrap_vault_key(&vault_key, &wrapping_key) {
        Ok((nonce, wrapped)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "wrap_iv",
                &JsValue::from_str(&b64_encode(nonce.as_bytes())),
            );
            js_set(
                &obj,
                "wrapped_key",
                &JsValue::from_str(&b64_encode(&wrapped)),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Encrypt vault body (SQLite bytes) with vault_key.
/// Returns `nonce(12) || ciphertext` as a `Uint8Array` or `null` on error.
/// The caller splits at byte 12 to recover body_iv and body_ciphertext separately.
#[wasm_bindgen]
pub fn byo_encrypt_vault_body(sqlite_bytes: Vec<u8>, vault_key_b64: String) -> Option<Vec<u8>> {
    let key_bytes = b64_decode(&vault_key_b64).ok()?;
    let vault_key = SymmetricKey::from_slice(&key_bytes).ok()?;
    let (nonce, ciphertext) = encrypt_vault_body(&sqlite_bytes, &vault_key).ok()?;
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(nonce.as_bytes());
    result.extend_from_slice(&ciphertext);
    Some(result)
}

/// Decrypt vault body with vault_key.
/// `nonce_and_ct` — `nonce(12) || ciphertext` bytes (matches the layout returned by `byo_encrypt_vault_body`).
/// Returns the plaintext SQLite bytes as a `Uint8Array` or `null` on error.
#[wasm_bindgen]
pub fn byo_decrypt_vault_body(nonce_and_ct: Vec<u8>, vault_key_b64: String) -> Option<Vec<u8>> {
    if nonce_and_ct.len() < 12 {
        return None;
    }
    let iv: [u8; 12] = nonce_and_ct[..12].try_into().ok()?;
    let ciphertext = &nonce_and_ct[12..];
    let key_bytes = b64_decode(&vault_key_b64).ok()?;
    let vault_key = SymmetricKey::from_slice(&key_bytes).ok()?;
    decrypt_vault_body(&iv, ciphertext, &vault_key)
        .ok()
        .map(|z| z.to_vec())
}

/// Generate random vault keys for new vault creation.
/// Returns { vault_key, shard, vault_id, master_salt } (all base64) or { error }.
#[wasm_bindgen]
pub fn byo_generate_vault_keys() -> JsValue {
    match generate_vault_keys() {
        Ok(keys) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "vault_key",
                &JsValue::from_str(&b64_encode(keys.vault_key.as_bytes())),
            );
            js_set(
                &obj,
                "shard",
                &JsValue::from_str(&b64_encode(keys.shard.as_bytes())),
            );
            js_set(
                &obj,
                "vault_id",
                &JsValue::from_str(&b64_encode(&keys.vault_id)),
            );
            js_set(
                &obj,
                "master_salt",
                &JsValue::from_str(&b64_encode(&keys.master_salt)),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Derive vault_kek using BYO default parameters (128 MB).
/// Convenience wrapper for byo_derive_vault_keys with memory_kb=131072.
/// Returns { vault_kek, client_kek_half, argon_output } or { error }.
#[wasm_bindgen]
pub fn byo_derive_vault_keys_default(password: String, salt_b64: String) -> JsValue {
    let salt = match b64_decode(&salt_b64) {
        Ok(s) => s,
        Err(_) => return js_error("invalid base64 salt"),
    };
    let argon_output = match argon2id_derive_byo(password.as_bytes(), &salt) {
        Ok(o) => o,
        Err(e) => return js_error(&e.to_string()),
    };
    let vault_kek = match derive_vault_kek(&argon_output) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let client_kek_half = match derive_client_kek_half_from_byo(&argon_output) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let obj = js_sys::Object::new();
    js_set(
        &obj,
        "vault_kek",
        &JsValue::from_str(&b64_encode(vault_kek.as_bytes())),
    );
    js_set(
        &obj,
        "client_kek_half",
        &JsValue::from_str(&b64_encode(client_kek_half.as_bytes())),
    );
    js_set(
        &obj,
        "argon_output",
        &JsValue::from_str(&b64_encode(argon_output.as_bytes())),
    );
    obj.into()
}

// ─── Enrollment protocol ──────────────────────────────────────────────────

/// Initiate device enrollment: generate ephemeral X25519 keypair + channel ID.
/// The existing device calls this and encodes the result into a QR code.
/// Returns { eph_sk, eph_pk, channel_id } (all base64) or { error }.
#[wasm_bindgen]
pub fn byo_enrollment_initiate() -> JsValue {
    match enrollment_initiate() {
        Ok((eph_sk, eph_pk, channel_id)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "eph_sk",
                &JsValue::from_str(&b64_encode(eph_sk.as_bytes())),
            );
            js_set(&obj, "eph_pk", &JsValue::from_str(&b64_encode(&eph_pk)));
            // Emit channel_id URL-safe, no padding — relay purpose validator
            // requires exactly 22 base64url-no-pad chars for `enroll:<ch>`
            // and the WS URL avoids escaping '/' and '+' from standard b64.
            js_set(
                &obj,
                "channel_id",
                &JsValue::from_str(&b64url_encode_nopad(&channel_id)),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Derive enrollment session keys from ephemeral DH.
/// Combined function: returns enc_key, mac_key, AND sas_code from a single DH
/// operation. This avoids exposing the raw shared secret to JS and prevents
/// accidental reuse (documented design decision).
/// `channel_id_b64` is the 16-byte channel ID (base64), mixed into HKDF to bind
/// the session to this specific enrollment channel.
/// Returns { enc_key, mac_key, sas_code } or { error }.
#[wasm_bindgen]
pub fn byo_enrollment_derive_session(
    eph_sk_b64: String,
    peer_pk_b64: String,
    channel_id_b64: String,
) -> JsValue {
    let sk_bytes = match b64_decode(&eph_sk_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 eph_sk"),
    };
    let eph_sk = match X25519SecretKey::from_slice(&sk_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let peer_pk = match b64_decode(&peer_pk_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 peer_pk"),
    };
    // channel_id travels through URL query params (relay purpose, WS
    // URL) — accept URL-safe-no-pad (canonical) and fall back to
    // standard base64 so legacy/QR payloads keep working.
    let ch_bytes = match b64url_decode_lenient(&channel_id_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 channel_id"),
    };
    let channel_id: [u8; 16] = match ch_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return js_error("channel_id must be 16 bytes"),
    };
    match enrollment_derive_session(&eph_sk, &peer_pk, &channel_id) {
        Ok(session) => session_to_js(&session),
        Err(e) => js_error(&e.to_string()),
    }
}

/// Encrypt a shard for transfer to a new device.
/// Returns { nonce, ciphertext, hmac } (all base64) or { error }.
#[wasm_bindgen]
pub fn byo_enrollment_encrypt_shard(
    shard_b64: String,
    enc_key_b64: String,
    mac_key_b64: String,
) -> JsValue {
    let shard_bytes = match b64_decode(&shard_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 shard"),
    };
    let shard = match SymmetricKey::from_slice(&shard_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let enc_key_bytes = match b64_decode(&enc_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 enc_key"),
    };
    let enc_key = match SymmetricKey::from_slice(&enc_key_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let mac_key_bytes = match b64_decode(&mac_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 mac_key"),
    };
    let mac_key = match SymmetricKey::from_slice(&mac_key_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    match encrypt_shard_for_transfer(&shard, &enc_key, &mac_key) {
        Ok(envelope) => envelope_to_js(&envelope),
        Err(e) => js_error(&e.to_string()),
    }
}

/// Decrypt a shard from a transfer envelope (verify HMAC, then AES-GCM decrypt).
/// Returns { shard } (base64) or { error }.
#[wasm_bindgen]
pub fn byo_enrollment_decrypt_shard(
    envelope_b64: String,
    enc_key_b64: String,
    mac_key_b64: String,
) -> JsValue {
    let envelope_bytes = match b64_decode(&envelope_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 envelope"),
    };
    let envelope = match ShardEnvelope::from_bytes(&envelope_bytes) {
        Ok(e) => e,
        Err(e) => return js_error(&e.to_string()),
    };
    let enc_key_bytes = match b64_decode(&enc_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 enc_key"),
    };
    let enc_key = match SymmetricKey::from_slice(&enc_key_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let mac_key_bytes = match b64_decode(&mac_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 mac_key"),
    };
    let mac_key = match SymmetricKey::from_slice(&mac_key_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    match decrypt_shard_from_transfer(&envelope, &enc_key, &mac_key) {
        Ok(shard) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "shard",
                &JsValue::from_str(&b64_encode(shard.as_bytes())),
            );
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

// ─── Per-device signing keys (v2 vault format) ────────────────────────────

/// Generate a fresh Ed25519 key pair.
/// Returns { public_key: b64, seed: b64 } or { error }.
#[wasm_bindgen]
pub fn byo_generate_device_signing_key() -> JsValue {
    match generate_device_signing_key() {
        Ok((pk, seed)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "public_key", &JsValue::from_str(&b64_encode(&pk)));
            js_set(&obj, "seed", &JsValue::from_str(&b64_encode(seed.as_ref())));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Seal an Ed25519 seed into a device slot.
/// `vault_key_b64`, `device_id_b64` (16 bytes), `seed_b64` (32 bytes).
/// Returns { wrapped: b64 } (48 bytes) or { error }.
#[wasm_bindgen]
pub fn byo_seal_device_signing_key(
    vault_key_b64: String,
    device_id_b64: String,
    seed_b64: String,
) -> JsValue {
    let vault_key_bytes = match b64_decode(&vault_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 vault_key"),
    };
    let vault_key = match SymmetricKey::from_slice(&vault_key_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let device_id_bytes = match b64_decode(&device_id_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 device_id"),
    };
    let device_id: [u8; 16] = match device_id_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("device_id must be 16 bytes"),
    };
    let seed_bytes = match b64_decode(&seed_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 seed"),
    };
    let seed: [u8; 32] = match seed_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("seed must be 32 bytes"),
    };
    match seal_device_signing_key(&vault_key, &device_id, &seed) {
        Ok(wrapped) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "wrapped", &JsValue::from_str(&b64_encode(&wrapped)));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Unseal an Ed25519 seed from a device slot.
/// Returns { seed: b64 } (32 bytes) or { error }.
#[wasm_bindgen]
pub fn byo_unseal_device_signing_key(
    vault_key_b64: String,
    device_id_b64: String,
    wrapped_b64: String,
) -> JsValue {
    let vault_key_bytes = match b64_decode(&vault_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 vault_key"),
    };
    let vault_key = match SymmetricKey::from_slice(&vault_key_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let device_id_bytes = match b64_decode(&device_id_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 device_id"),
    };
    let device_id: [u8; 16] = match device_id_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("device_id must be 16 bytes"),
    };
    let wrapped_bytes = match b64_decode(&wrapped_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 wrapped"),
    };
    let wrapped: [u8; 48] = match wrapped_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("wrapped must be 48 bytes"),
    };
    match unseal_device_signing_key(&vault_key, &device_id, &wrapped) {
        Ok(seed) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "seed", &JsValue::from_str(&b64_encode(seed.as_ref())));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Sign a message with an Ed25519 seed.
/// Returns { signature: b64 } (64 bytes) or { error }.
#[wasm_bindgen]
pub fn byo_ed25519_sign(seed_b64: String, message_b64: String) -> JsValue {
    let seed_bytes = match b64_decode(&seed_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 seed"),
    };
    let seed: [u8; 32] = match seed_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("seed must be 32 bytes"),
    };
    let message = match b64_decode(&message_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 message"),
    };
    match ed25519_sign(&seed, &message) {
        Ok(sig) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "signature", &JsValue::from_str(&b64_encode(&sig)));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Verify an Ed25519 signature.
/// Returns { valid: bool } or { error }.
#[wasm_bindgen]
pub fn byo_ed25519_verify(
    public_key_b64: String,
    message_b64: String,
    signature_b64: String,
) -> JsValue {
    let pk_bytes = match b64_decode(&public_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 public_key"),
    };
    let pk: [u8; 32] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("public_key must be 32 bytes"),
    };
    let message = match b64_decode(&message_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 message"),
    };
    let sig_bytes = match b64_decode(&signature_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 signature"),
    };
    let sig: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("signature must be 64 bytes"),
    };
    let obj = js_sys::Object::new();
    js_set(
        &obj,
        "valid",
        &JsValue::from_bool(ed25519_verify(&pk, &message, &sig)),
    );
    obj.into()
}

/// Migrate a v1 vault file to v2 format.
/// Takes the complete vault file bytes and the vault_key (base64).
/// Returns the migrated bytes, or the original bytes unchanged if already v2.
#[wasm_bindgen]
pub fn byo_migrate_vault_v1_to_v2(vault_bytes: Vec<u8>, vault_key_b64: String) -> Option<Vec<u8>> {
    let vault_key_bytes = b64_decode(&vault_key_b64).ok()?;
    let vault_key = SymmetricKey::from_slice(&vault_key_bytes).ok()?;
    migrate_vault_v1_to_v2(&vault_bytes, &vault_key).ok()
}

// ─── Enrollment session API (ZK-safe: eph_sk / enc_key / mac_key never cross WASM) ───

/// Open a new enrollment channel: generate ephemeral X25519 keypair + channel ID.
/// Returns `{ eph_pk, channel_id, session_id }` — eph_sk is stored in the session.
#[wasm_bindgen]
pub fn byo_enrollment_open() -> JsValue {
    match enrollment_initiate() {
        Ok((eph_sk, eph_pk, channel_id)) => {
            let session = WasmEnrollmentSession {
                eph_sk: Some(eph_sk),
                channel_id,
                enc_key: None,
                mac_key: None,
                received_shard: None,
            };
            let session_id = store_enrollment_session(session);
            let obj = js_sys::Object::new();
            js_set(&obj, "eph_pk", &JsValue::from_str(&b64_encode(&eph_pk)));
            // Emit channel_id URL-safe, no padding — relay purpose validator
            // requires exactly 22 base64url-no-pad chars for `enroll:<ch>`
            // and the WS URL avoids escaping '/' and '+' from standard b64.
            js_set(
                &obj,
                "channel_id",
                &JsValue::from_str(&b64url_encode_nopad(&channel_id)),
            );
            js_set(&obj, "session_id", &JsValue::from(session_id));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Derive session keys from the peer's public key.
/// Consumes eph_sk from the session and stores enc_key + mac_key in its place.
/// Returns `{ sas_code }` — enc_key and mac_key never leave WASM.
#[wasm_bindgen]
pub fn byo_enrollment_derive_keys(session_id: u32, peer_pk_b64: String) -> JsValue {
    let peer_pk_bytes = match b64_decode(&peer_pk_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 peer_pk"),
    };

    let result = with_enrollment_session_mut(session_id, |session| {
        let eph_sk = match session.eph_sk.take() {
            Some(k) => k,
            None => return Err("eph_sk already consumed or session not found".to_string()),
        };
        let derived = enrollment_derive_session(&eph_sk, &peer_pk_bytes, &session.channel_id)
            .map_err(|e| e.to_string())?;
        // Copy keys into session before `derived` is dropped (ZeroizeOnDrop)
        session.enc_key = Some(SymmetricKey::new(*derived.enc_key().as_bytes()));
        session.mac_key = Some(SymmetricKey::new(*derived.mac_key().as_bytes()));
        Ok(derived.sas_code().value())
    });

    match result {
        None => js_error("unknown enrollment session"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(sas_code)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "sas_code", &JsValue::from(sas_code));
            obj.into()
        }
    }
}

/// Encrypt a shard for transfer using session enc_key + mac_key.
/// `shard_b64` is the 32-byte shard (base64). Returns `{ envelope_b64 }`.
#[wasm_bindgen]
pub fn byo_enrollment_session_encrypt_shard(session_id: u32, shard_b64: String) -> JsValue {
    let shard_bytes = match b64_decode(&shard_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 shard"),
    };
    let shard = match SymmetricKey::from_slice(&shard_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };

    let result = with_enrollment_session_mut(session_id, |session| {
        let enc_key = match &session.enc_key {
            Some(k) => SymmetricKey::new(*k.as_bytes()),
            None => {
                return Err(
                    "session enc_key not set (call byo_enrollment_derive_keys first)".to_string(),
                )
            }
        };
        let mac_key = match &session.mac_key {
            Some(k) => SymmetricKey::new(*k.as_bytes()),
            None => return Err("session mac_key not set".to_string()),
        };
        encrypt_shard_for_transfer(&shard, &enc_key, &mac_key).map_err(|e| e.to_string())
    });

    match result {
        None => js_error("unknown enrollment session"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(envelope)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "envelope_b64",
                &JsValue::from_str(&b64_encode(&envelope.to_bytes())),
            );
            obj.into()
        }
    }
}

/// Decrypt a shard from a transfer envelope and store it in the session.
/// `envelope_b64` is the flat-serialized ShardEnvelope bytes (base64).
/// The shard is NOT returned — retrieve it later via `byo_enrollment_session_get_shard`.
#[wasm_bindgen]
pub fn byo_enrollment_session_decrypt_shard(session_id: u32, envelope_b64: String) -> JsValue {
    let envelope_bytes = match b64_decode(&envelope_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 envelope"),
    };
    let envelope = match ShardEnvelope::from_bytes(&envelope_bytes) {
        Ok(e) => e,
        Err(e) => return js_error(&e.to_string()),
    };

    let result = with_enrollment_session_mut(session_id, |session| {
        let enc_key = match &session.enc_key {
            Some(k) => SymmetricKey::new(*k.as_bytes()),
            None => return Err("session enc_key not set".to_string()),
        };
        let mac_key = match &session.mac_key {
            Some(k) => SymmetricKey::new(*k.as_bytes()),
            None => return Err("session mac_key not set".to_string()),
        };
        let shard = decrypt_shard_from_transfer(&envelope, &enc_key, &mac_key)
            .map_err(|e| e.to_string())?;
        session.received_shard = Some(shard.as_bytes().to_vec());
        Ok(())
    });

    match result {
        None => js_error("unknown enrollment session"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(())) => js_sys::Object::new().into(),
    }
}

/// Consume and return the shard stored by `byo_enrollment_session_decrypt_shard`.
/// The shard bytes are zeroed in the session after this call.
/// Returns `{ shard_b64 }` — the shard briefly appears in JS for the WebCrypto
/// device-slot encryption step (accepted exception: non-extractable CryptoKey).
#[wasm_bindgen]
pub fn byo_enrollment_session_get_shard(session_id: u32) -> JsValue {
    let result = with_enrollment_session_mut(session_id, |session| session.received_shard.take());

    match result {
        None => js_error("unknown enrollment session"),
        Some(None) => js_error("no shard stored in session"),
        Some(Some(shard_bytes)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "shard_b64",
                &JsValue::from_str(&b64_encode(&shard_bytes)),
            );
            obj.into()
        }
    }
}

/// Close and zeroize an enrollment session.
#[wasm_bindgen]
pub fn byo_enrollment_close(session_id: u32) {
    close_enrollment_session(session_id);
}

/// Encrypt an arbitrary-length payload (e.g. a ProviderConfig JSON) using the
/// session enc_key + mac_key. Returns `{ envelope_b64 }`.
///
/// Used by the source device of an enrollment to ship the primary
/// `ProviderConfig` to the receiver alongside the shard, so the receiver does
/// not have to re-type provider credentials from scratch.
#[wasm_bindgen]
pub fn byo_enrollment_session_encrypt_payload(session_id: u32, payload_b64: String) -> JsValue {
    let payload_bytes = match b64_decode(&payload_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 payload"),
    };

    let result = with_enrollment_session_mut(session_id, |session| {
        let enc_key = match &session.enc_key {
            Some(k) => SymmetricKey::new(*k.as_bytes()),
            None => {
                return Err(
                    "session enc_key not set (call byo_enrollment_derive_keys first)".to_string(),
                )
            }
        };
        let mac_key = match &session.mac_key {
            Some(k) => SymmetricKey::new(*k.as_bytes()),
            None => return Err("session mac_key not set".to_string()),
        };
        encrypt_payload_for_transfer(&payload_bytes, &enc_key, &mac_key).map_err(|e| e.to_string())
    });

    match result {
        None => js_error("unknown enrollment session"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(envelope)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "envelope_b64",
                &JsValue::from_str(&b64_encode(&envelope.to_bytes())),
            );
            obj.into()
        }
    }
}

/// Decrypt a payload envelope using the session enc_key + mac_key. Returns
/// `{ payload_b64 }`. The caller handles zeroization of the decoded bytes on
/// the JS side (they are JSON config blobs, not long-lived key material).
#[wasm_bindgen]
pub fn byo_enrollment_session_decrypt_payload(session_id: u32, envelope_b64: String) -> JsValue {
    let envelope_bytes = match b64_decode(&envelope_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 envelope"),
    };
    let envelope = match PayloadEnvelope::from_bytes(&envelope_bytes) {
        Ok(e) => e,
        Err(e) => return js_error(&e.to_string()),
    };

    let result = with_enrollment_session_mut(session_id, |session| {
        let enc_key = match &session.enc_key {
            Some(k) => SymmetricKey::new(*k.as_bytes()),
            None => return Err("session enc_key not set".to_string()),
        };
        let mac_key = match &session.mac_key {
            Some(k) => SymmetricKey::new(*k.as_bytes()),
            None => return Err("session mac_key not set".to_string()),
        };
        decrypt_payload_from_transfer(&envelope, &enc_key, &mac_key).map_err(|e| e.to_string())
    });

    match result {
        None => js_error("unknown enrollment session"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(payload)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "payload_b64",
                &JsValue::from_str(&b64_encode(&payload)),
            );
            obj.into()
        }
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn session_to_js(session: &EnrollmentSession) -> JsValue {
    let obj = js_sys::Object::new();
    js_set(
        &obj,
        "enc_key",
        &JsValue::from_str(&b64_encode(session.enc_key().as_bytes())),
    );
    js_set(
        &obj,
        "mac_key",
        &JsValue::from_str(&b64_encode(session.mac_key().as_bytes())),
    );
    js_set(&obj, "sas_code", &JsValue::from(session.sas_code().value()));
    obj.into()
}

fn envelope_to_js(envelope: &ShardEnvelope) -> JsValue {
    let obj = js_sys::Object::new();
    js_set(
        &obj,
        "nonce",
        &JsValue::from_str(&b64_encode(envelope.nonce.as_bytes())),
    );
    js_set(
        &obj,
        "ciphertext",
        &JsValue::from_str(&b64_encode(&envelope.ciphertext)),
    );
    js_set(
        &obj,
        "hmac",
        &JsValue::from_str(&b64_encode(&envelope.hmac)),
    );
    obj.into()
}

// ── Relay auth / PoW ─────────────────────────────────────────────────────────

/// Derive the SFTP relay cookie purpose for the given host and port.
/// Returns "sftp:<32 lowercase hex chars>".
#[wasm_bindgen]
pub fn byo_derive_sftp_purpose(host: &str, port: u16) -> String {
    derive_sftp_purpose(host, port)
}

/// Derive the enrollment relay cookie purpose for the given channel ID.
/// Returns "enroll:<channel_id>".
#[wasm_bindgen]
pub fn byo_derive_enrollment_purpose(channel_id: &str) -> String {
    derive_enrollment_purpose(channel_id)
}

/// Solve the PoW challenge. Runs synchronously — call from a Web Worker.
///
/// Returns `{ answer: number }` on success or `{ error: string }` on failure.
/// `answer` is a safe JS Number (f64) — for difficulty <= 32 this is always exact.
#[wasm_bindgen]
pub fn byo_solve_relay_pow(nonce_hex: String, purpose: String, difficulty: u32) -> JsValue {
    match solve_pow(&nonce_hex, &purpose, difficulty) {
        Ok(answer) => {
            let obj = js_sys::Object::new();
            // answer fits in f64 for any realistic difficulty (18 bits ≈ 131K expected iterations).
            js_set(&obj, "answer", &JsValue::from_f64(answer as f64));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

// ─── Vault session API (ZK-safe: vault_key/kek never cross WASM boundary) ──

/// Open a vault session: run Argon2id on `password`, derive vault_kek and
/// client_kek_half, unwrap vault_key, and store all three in the WASM session
/// registry.  Only an opaque u32 session ID is returned to JS.
///
/// Replaces the `byoDeriveVaultKeys` + `byoUnwrapVaultKey` pair.
/// Returns `{ session_id }` or `{ error: "Argon2ParamsOutOfBounds: ..." }`.
///
/// Argon2 DoS ceilings are enforced inside `argon2id_derive_with_params` and
/// surface here as the `Argon2ParamsOutOfBounds` variant of `CryptoError`.
#[wasm_bindgen]
pub fn byo_vault_open(
    password: String,
    salt_b64: String,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
    wrap_iv_b64: String,
    wrapped_vault_key_b64: String,
) -> JsValue {
    let salt = match b64_decode(&salt_b64) {
        Ok(s) => s,
        Err(_) => return js_error("invalid base64 salt"),
    };
    let argon_output = match argon2id_derive_with_params(
        password.as_bytes(),
        &salt,
        memory_kb,
        iterations,
        parallelism,
    ) {
        Ok(o) => o,
        Err(e) => return js_error(&e.to_string()),
    };
    let vault_kek = match derive_vault_kek(&argon_output) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let client_kek_half = match derive_client_kek_half_from_byo(&argon_output) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let iv_bytes = match b64_decode(&wrap_iv_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 wrap_iv"),
    };
    let iv: [u8; 12] = match iv_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("wrap_iv must be 12 bytes"),
    };
    let wrapped = match b64_decode(&wrapped_vault_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 wrapped_vault_key"),
    };
    let wrapped_arr: [u8; 48] = match wrapped.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("wrapped_vault_key must be 48 bytes"),
    };
    let vault_key = match unwrap_vault_key(&iv, &wrapped_arr, &vault_kek) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let session = VaultSession {
        vault_key,
        client_kek_half,
        kek: None,
    };
    let session_id = store_vault_session(session);
    let obj = js_sys::Object::new();
    js_set(&obj, "session_id", &JsValue::from(session_id));
    obj.into()
}

/// Close the vault session and zeroize all key material (vault_key, kek, …).
/// Idempotent — calling with an unknown ID is a no-op.
#[wasm_bindgen]
pub fn byo_vault_close(session_id: u32) {
    close_vault_session(session_id);
}

/// Wrap the session's `vault_key` under a PRF-derived wrapping key and
/// return the wrapped bytes as base64. Used by the opt-in passkey-unlock
/// flow (SECURITY.md §12) to emit one wrapped copy per enrolled credential.
///
/// The raw `vault_key` bytes never leave WASM memory — the JS side only
/// ever sees the wrapped ciphertext. PRF output, on the other hand, is a
/// short-lived intermediate already visible to JS via the WebAuthn API, so
/// taking it in here is no worse than the existing `webauthn_*` entry points.
///
/// Returns `{ wrapped_b64 }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_wrap_session_vault_key_with_prf(
    session_id: u32,
    prf_output_b64: String,
) -> JsValue {
    let prf_bytes = match b64_decode(&prf_output_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 prf_output"),
    };
    let wrapping_key = match derive_vault_key_wrapping_key_from_prf(&prf_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let result = with_vault_session(session_id, |sess| {
        wrap_vk_prf(sess.vault_key.as_bytes(), &wrapping_key).map_err(|e| e.to_string())
    });
    match result {
        Some(Ok(wrapped)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "wrapped_b64",
                &JsValue::from_str(&b64_encode(&wrapped)),
            );
            obj.into()
        }
        Some(Err(msg)) => js_error(&msg),
        None => js_error("unknown session_id"),
    }
}

/// Unwrap a PRF-wrapped `vault_key` and open a fresh vault session with it.
/// Used on the opt-in passkey-unlock path — the caller has just held their
/// passkey to the authenticator, obtained a fresh PRF output, and pulled
/// the wrapped vault_key from the `device_webauthn` IDB row.
///
/// `client_kek_half` is populated with an all-zero placeholder — nothing
/// downstream uses it once the session is loaded from an existing vault_key
/// (body encrypt/decrypt, manifest AEAD, HMAC, subkey derivation all key
/// off `vault_key` only). `kek` is left `None` for the same reason.
///
/// Returns `{ session_id }` or `{ error }`. The raw `vault_key` bytes are
/// zeroized inside this function as soon as they land in the session.
#[wasm_bindgen]
pub fn byo_vault_load_session_from_wrapped_vault_key(
    wrapped_b64: String,
    prf_output_b64: String,
) -> JsValue {
    let wrapped = match b64_decode(&wrapped_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 wrapped_vault_key"),
    };
    let prf_bytes = match b64_decode(&prf_output_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 prf_output"),
    };
    let wrapping_key = match derive_vault_key_wrapping_key_from_prf(&prf_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let mut vk_bytes = match unwrap_vk_prf(&wrapped, &wrapping_key) {
        Ok(v) => v,
        Err(e) => return js_error(&e.to_string()),
    };
    let vk_arr: [u8; 32] = match (&vk_bytes[..]).try_into() {
        Ok(a) => a,
        Err(_) => {
            vk_bytes.fill(0);
            return js_error("unwrapped vault_key is not 32 bytes");
        }
    };
    vk_bytes.fill(0);

    // Placeholder: zeros for client_kek_half, since nothing in the vault
    // operations used via this session path consumes it. See function doc.
    let placeholder_half = SymmetricKey::new([0u8; 32]);
    let session = VaultSession {
        vault_key: SymmetricKey::new(vk_arr),
        client_kek_half: placeholder_half,
        kek: None,
    };
    let session_id = store_vault_session(session);
    let obj = js_sys::Object::new();
    js_set(&obj, "session_id", &JsValue::from(session_id));
    obj.into()
}

/// Verify the vault header HMAC using the session vault_key.
/// Returns `{ valid: bool }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_verify_header_hmac(
    session_id: u32,
    header_prefix_b64: String,
    expected_hmac_b64: String,
) -> JsValue {
    let result = with_vault_session(session_id, |sess| {
        let header_prefix = b64_decode(&header_prefix_b64)
            .map_err(|_| "invalid base64 header_prefix".to_string())?;
        let hmac_bytes = b64_decode(&expected_hmac_b64)
            .map_err(|_| "invalid base64 expected_hmac".to_string())?;
        let expected: [u8; 32] = hmac_bytes
            .try_into()
            .map_err(|_| "expected_hmac must be 32 bytes".to_string())?;
        match header_prefix.len() {
            n if n == sdk_core::crypto::constants::VAULT_HMAC_OFFSET => {
                verify_header_hmac(&sess.vault_key, &header_prefix, &expected)
                    .map_err(|e| e.to_string())
            }
            n if n == sdk_core::crypto::constants::VAULT_HMAC_OFFSET_V1 => {
                verify_header_hmac_v1(&sess.vault_key, &header_prefix, &expected)
                    .map_err(|e| e.to_string())
            }
            n => Err(format!(
                "header_prefix length {n} is neither v1 ({}) nor v2 ({})",
                sdk_core::crypto::constants::VAULT_HMAC_OFFSET_V1,
                sdk_core::crypto::constants::VAULT_HMAC_OFFSET,
            )),
        }
    });
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(valid)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "valid", &JsValue::from_bool(valid));
            obj.into()
        }
    }
}

/// Decrypt the vault body using the session vault_key.
/// `nonce_and_ct` — `nonce(12) || ciphertext` (identical layout to `byo_decrypt_vault_body`).
/// Returns plaintext SQLite bytes or `null` on error.
#[wasm_bindgen]
pub fn byo_vault_decrypt_body(session_id: u32, nonce_and_ct: Vec<u8>) -> Option<Vec<u8>> {
    if nonce_and_ct.len() < 12 {
        return None;
    }
    let iv: [u8; 12] = nonce_and_ct.get(..12)?.try_into().ok()?;
    let ciphertext = nonce_and_ct.get(12..)?;
    with_vault_session(session_id, |sess| {
        decrypt_vault_body(&iv, ciphertext, &sess.vault_key)
            .ok()
            .map(|z| z.to_vec())
    })
    .flatten()
}

/// Encrypt the vault body using the session vault_key.
/// Returns `nonce(12) || ciphertext` or `null` on error.
#[wasm_bindgen]
pub fn byo_vault_encrypt_body(session_id: u32, sqlite_bytes: Vec<u8>) -> Option<Vec<u8>> {
    with_vault_session(session_id, |sess| {
        encrypt_vault_body(&sqlite_bytes, &sess.vault_key)
            .ok()
            .map(|(nonce, ct)| {
                let mut result = Vec::with_capacity(12 + ct.len());
                result.extend_from_slice(nonce.as_bytes());
                result.extend_from_slice(&ct);
                result
            })
    })
    .flatten()
}

/// Compute the vault header HMAC using the session vault_key.
/// Returns `{ hmac_b64 }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_compute_header_hmac(session_id: u32, header_prefix_b64: String) -> JsValue {
    let result = with_vault_session(session_id, |sess| {
        let header_prefix = b64_decode(&header_prefix_b64)
            .map_err(|_| "invalid base64 header_prefix".to_string())?;
        match header_prefix.len() {
            n if n == sdk_core::crypto::constants::VAULT_HMAC_OFFSET => {
                compute_header_hmac(&sess.vault_key, &header_prefix).map_err(|e| e.to_string())
            }
            n if n == sdk_core::crypto::constants::VAULT_HMAC_OFFSET_V1 => {
                compute_header_hmac_v1(&sess.vault_key, &header_prefix).map_err(|e| e.to_string())
            }
            n => Err(format!(
                "header_prefix length {n} is neither v1 ({}) nor v2 ({})",
                sdk_core::crypto::constants::VAULT_HMAC_OFFSET_V1,
                sdk_core::crypto::constants::VAULT_HMAC_OFFSET,
            )),
        }
    });
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(hmac)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "hmac_b64", &JsValue::from_str(&b64_encode(&hmac)));
            obj.into()
        }
    }
}

/// Derive the BYO KEK from the session `client_kek_half` and the device shard,
/// and store the result in the session.  Must be called once before
/// `byo_vault_load_keys`.
///
/// Returns `{}` on success or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_derive_kek(session_id: u32, shard_b64: String) -> JsValue {
    let result = with_vault_session_mut(session_id, |sess| {
        let shard_bytes = b64_decode(&shard_b64).map_err(|_| "invalid base64 shard".to_string())?;
        let kek = derive_byo_kek(&sess.client_kek_half, &shard_bytes).map_err(|e| e.to_string())?;
        sess.kek = Some(kek);
        Ok::<_, String>(())
    });
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(())) => js_sys::Object::new().into(),
    }
}

/// Frozen HKDF info label for the subkey that AES-GCM-wraps `key_versions`
/// private-key rows. Must not be renamed — changing it would break every
/// vault whose `key_versions` rows were written with the old label.
const KEY_VERSIONS_WRAP_INFO: &[u8] = b"SecureCloud BYO key_versions wrap v1";

/// Decrypt the ML-KEM and X25519 private keys stored in `key_versions`.
///
/// The row ciphertext format is `nonce(12) || AES-256-GCM(K_wrap, nonce, sk)`
/// where `K_wrap = HKDF-SHA256(vault_key, info=KEY_VERSIONS_WRAP_INFO, L=32)`.
/// Using a subkey of `vault_key` (which is stable across recovery re-key and
/// shared across all enrolled devices) is what lets every device decrypt the
/// same row — an earlier managed-mode scheme used the per-device KEK, which
/// is not portable across devices in BYO mode.
///
/// Returns `{ mlkem_sk_b64, x25519_sk_b64 }` or `{ error }`.
/// The returned bytes are passed directly to the worker key registry;
/// they never reach the main thread.
#[wasm_bindgen]
pub fn byo_vault_load_keys(
    session_id: u32,
    mlkem_sk_encrypted: Vec<u8>,
    x25519_sk_encrypted: Vec<u8>,
) -> JsValue {
    let result = with_vault_session(session_id, |sess| -> Result<(Vec<u8>, Vec<u8>), String> {
        let k_wrap = derive_key_versions_wrap_key(sess)?;
        let mlkem_sk = vault_aes_decrypt(&mlkem_sk_encrypted, &k_wrap)?;
        let x25519_sk = vault_aes_decrypt(&x25519_sk_encrypted, &k_wrap)?;
        Ok((mlkem_sk, x25519_sk))
    });
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok((mlkem, x25519))) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "mlkem_sk_b64",
                &JsValue::from_str(&b64_encode(&mlkem)),
            );
            js_set(
                &obj,
                "x25519_sk_b64",
                &JsValue::from_str(&b64_encode(&x25519)),
            );
            obj.into()
        }
    }
}

/// Derive a 32-byte subkey from the session vault_key using HKDF-SHA256.
///
/// `purpose` is used as the HKDF `info` string and must match the string used
/// by the caller (e.g. "SecureCloud BYO WAL v1").  The returned bytes are
/// imported by the caller as a non-extractable AES-256-GCM `CryptoKey` for
/// WAL or journal encryption — vault_key itself never leaves WASM.
///
/// Returns 32 bytes or `null` on error.
#[wasm_bindgen]
pub fn byo_vault_derive_subkey(session_id: u32, purpose: String) -> Option<Vec<u8>> {
    with_vault_session(session_id, |sess| {
        hkdf_sha256(sess.vault_key.as_bytes(), purpose.as_bytes(), 32)
            .ok()
            .map(|z| z.to_vec())
    })
    .flatten()
}

/// Generate a fresh hybrid ML-KEM-1024 + X25519 keypair and return the public
/// halves alongside the AES-GCM-wrapped private halves. The private key bytes
/// are wrapped under `K_wrap = HKDF(vault_key, KEY_VERSIONS_WRAP_INFO)` and
/// never cross the JS boundary in plaintext.
///
/// Caller stores the returned values in the vault's `key_versions` table:
///   mlkem_public_key, mlkem_private_key_encrypted,
///   x25519_public_key, x25519_private_key_encrypted.
/// A later `byo_vault_load_keys` call unwraps the same rows.
///
/// Returns `{ mlkem_public_key_b64, mlkem_private_key_encrypted,
///            x25519_public_key_b64, x25519_private_key_encrypted }`
/// (the two `_encrypted` fields are raw bytes: `nonce(12) || ct||tag`), or
/// `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_generate_keypair_wrapped(session_id: u32) -> JsValue {
    let result = with_vault_session(
        session_id,
        |sess| -> Result<(String, Vec<u8>, String, Vec<u8>), String> {
            let k_wrap = derive_key_versions_wrap_key(sess)?;
            let keypair = generate_hybrid_keypair().map_err(|e| e.to_string())?;
            let mlkem_sk_wrapped =
                vault_aes_encrypt_with_subkey(keypair.mlkem_secret_key.as_bytes(), &k_wrap)?;
            let x25519_sk_wrapped =
                vault_aes_encrypt_with_subkey(keypair.x25519_secret_key.as_bytes(), &k_wrap)?;
            Ok((
                b64_encode(keypair.mlkem_public_key.as_bytes()),
                mlkem_sk_wrapped,
                b64_encode(keypair.x25519_public_key.as_bytes()),
                x25519_sk_wrapped,
            ))
        },
    );
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok((mlkem_pk_b64, mlkem_sk_ct, x25519_pk_b64, x25519_sk_ct))) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "mlkem_public_key_b64",
                &JsValue::from_str(&mlkem_pk_b64),
            );
            js_set(
                &obj,
                "mlkem_private_key_encrypted",
                &js_sys::Uint8Array::from(mlkem_sk_ct.as_slice()).into(),
            );
            js_set(
                &obj,
                "x25519_public_key_b64",
                &JsValue::from_str(&x25519_pk_b64),
            );
            js_set(
                &obj,
                "x25519_private_key_encrypted",
                &js_sys::Uint8Array::from(x25519_sk_ct.as_slice()).into(),
            );
            obj.into()
        }
    }
}

/// Session-based variant of `byo_seal_device_signing_key`.
/// Uses the session vault_key — the key never appears in JS.
/// Returns `{ wrapped: b64 }` (48 bytes) or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_seal_device_signing_key(
    session_id: u32,
    device_id_b64: String,
    seed_b64: String,
) -> JsValue {
    let result = with_vault_session(session_id, |sess| {
        let device_id_bytes =
            b64_decode(&device_id_b64).map_err(|_| "invalid base64 device_id".to_string())?;
        let device_id: [u8; 16] = device_id_bytes
            .try_into()
            .map_err(|_| "device_id must be 16 bytes".to_string())?;
        let seed_bytes = b64_decode(&seed_b64).map_err(|_| "invalid base64 seed".to_string())?;
        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| "seed must be 32 bytes".to_string())?;
        seal_device_signing_key(&sess.vault_key, &device_id, &seed).map_err(|e| e.to_string())
    });
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(wrapped)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "wrapped", &JsValue::from_str(&b64_encode(&wrapped)));
            obj.into()
        }
    }
}

/// Session-based variant of `byo_unseal_device_signing_key`.
/// Uses the session vault_key — the key never appears in JS.
/// Returns `{ seed: b64 }` (32 bytes) or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_unseal_device_signing_key(
    session_id: u32,
    device_id_b64: String,
    wrapped_b64: String,
) -> JsValue {
    let result = with_vault_session(session_id, |sess| {
        let device_id_bytes =
            b64_decode(&device_id_b64).map_err(|_| "invalid base64 device_id".to_string())?;
        let device_id: [u8; 16] = device_id_bytes
            .try_into()
            .map_err(|_| "device_id must be 16 bytes".to_string())?;
        let wrapped_bytes =
            b64_decode(&wrapped_b64).map_err(|_| "invalid base64 wrapped".to_string())?;
        let wrapped: [u8; 48] = wrapped_bytes
            .try_into()
            .map_err(|_| "wrapped must be 48 bytes".to_string())?;
        unseal_device_signing_key(&sess.vault_key, &device_id, &wrapped).map_err(|e| e.to_string())
    });
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok(seed)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "seed", &JsValue::from_str(&b64_encode(seed.as_ref())));
            obj.into()
        }
    }
}

/// Session-based variant of `byo_migrate_vault_v1_to_v2`.
/// Uses the session vault_key — vault_key never appears in JS.
/// Returns migrated bytes or `null` on error.
#[wasm_bindgen]
pub fn byo_vault_migrate_v1_to_v2(session_id: u32, vault_bytes: Vec<u8>) -> Option<Vec<u8>> {
    with_vault_session(session_id, |sess| {
        migrate_vault_v1_to_v2(&vault_bytes, &sess.vault_key).ok()
    })
    .flatten()
}

/// Re-wrap the session vault_key with a new wrapping key (e.g. for passphrase change).
///
/// `new_wrapping_key_b64` is the new vault_kek derived from the new passphrase via Argon2id.
/// vault_key never leaves WASM — only the new wrapped form is returned.
/// Returns `{ wrap_iv_b64, wrapped_key_b64 }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_rewrap(session_id: u32, new_wrapping_key_b64: String) -> JsValue {
    let result = with_vault_session(session_id, |sess| {
        let wk_bytes = b64_decode(&new_wrapping_key_b64)
            .map_err(|_| "invalid base64 new_wrapping_key".to_string())?;
        let wrapping_key = SymmetricKey::from_slice(&wk_bytes).map_err(|e| e.to_string())?;
        wrap_vault_key(&sess.vault_key, &wrapping_key).map_err(|e| e.to_string())
    });
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok((nonce, wrapped))) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "wrap_iv_b64",
                &JsValue::from_str(&b64_encode(nonce.as_bytes())),
            );
            js_set(
                &obj,
                "wrapped_key_b64",
                &JsValue::from_str(&b64_encode(&wrapped)),
            );
            obj.into()
        }
    }
}

/// Create a new vault and open a session in one call.
///
/// Generates vault_key, shard, vault_id, master_salt; runs Argon2id on
/// `password` to derive vault_kek; wraps vault_key with vault_kek.
///
/// Returns `{ session_id, shard_b64, vault_id_b64, master_salt_b64,
/// pass_wrap_iv_b64, pass_wrapped_key_b64 }` or `{ error }`.
/// `shard_b64` is returned so JS can encrypt it with the non-extractable
/// device CryptoKey (unavoidable: WebCrypto non-extractable keys cannot be
/// used from WASM).
#[wasm_bindgen]
pub fn byo_vault_create(
    password: String,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> JsValue {
    let keys = match generate_vault_keys() {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let salt = keys.master_salt;
    let argon_output = match argon2id_derive_with_params(
        password.as_bytes(),
        &salt,
        memory_kb,
        iterations,
        parallelism,
    ) {
        Ok(o) => o,
        Err(e) => return js_error(&e.to_string()),
    };
    let vault_kek = match derive_vault_kek(&argon_output) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let client_kek_half = match derive_client_kek_half_from_byo(&argon_output) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let (pass_nonce, pass_wrapped) = match wrap_vault_key(&keys.vault_key, &vault_kek) {
        Ok(r) => r,
        Err(e) => return js_error(&e.to_string()),
    };
    let shard_b64 = b64_encode(keys.shard.as_bytes());
    let vault_id_b64 = b64_encode(&keys.vault_id);
    let master_salt_b64 = b64_encode(&keys.master_salt);
    let pass_wrap_iv_b64 = b64_encode(pass_nonce.as_bytes());
    let pass_wrapped_key_b64 = b64_encode(&pass_wrapped);
    // Copy vault_key bytes before `keys` is dropped (ZeroizeOnDrop prevents field moves)
    let vault_key = SymmetricKey::new(*keys.vault_key.as_bytes());
    drop(keys);
    let session = VaultSession {
        vault_key,
        client_kek_half,
        kek: None,
    };
    let session_id = store_vault_session(session);
    let obj = js_sys::Object::new();
    js_set(&obj, "session_id", &JsValue::from(session_id));
    js_set(&obj, "shard_b64", &JsValue::from_str(&shard_b64));
    js_set(&obj, "vault_id_b64", &JsValue::from_str(&vault_id_b64));
    js_set(
        &obj,
        "master_salt_b64",
        &JsValue::from_str(&master_salt_b64),
    );
    js_set(
        &obj,
        "pass_wrap_iv_b64",
        &JsValue::from_str(&pass_wrap_iv_b64),
    );
    js_set(
        &obj,
        "pass_wrapped_key_b64",
        &JsValue::from_str(&pass_wrapped_key_b64),
    );
    obj.into()
}

/// Open a vault session using the recovery slot.
///
/// Derives recovery_vault_kek from `recovery_key_b64` (raw key bytes, base64-encoded)
/// and unwraps vault_key.  Only an opaque session ID is returned to JS.
///
/// Returns `{ session_id }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_open_recovery(
    recovery_key_b64: String,
    wrap_iv_b64: String,
    wrapped_key_b64: String,
) -> JsValue {
    let rec_key_bytes = match b64_decode(&recovery_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 recovery_key"),
    };
    // recovery_key is the full 37-byte key; secret portion is bytes [1..33]
    let secret = if rec_key_bytes.len() >= 33 {
        rec_key_bytes.get(1..33).map(|s| s.to_vec())
    } else if rec_key_bytes.len() == 32 {
        Some(rec_key_bytes.clone())
    } else {
        None
    };
    let secret = match secret {
        Some(s) => s,
        None => return js_error("recovery_key must be 32 or 37 bytes"),
    };
    let recovery_kek = match derive_recovery_vault_kek(&secret) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let iv_bytes = match b64_decode(&wrap_iv_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 wrap_iv"),
    };
    let iv: [u8; 12] = match iv_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("wrap_iv must be 12 bytes"),
    };
    let wrapped = match b64_decode(&wrapped_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 wrapped_key"),
    };
    let wrapped_arr: [u8; 48] = match wrapped.try_into() {
        Ok(a) => a,
        Err(_) => return js_error("wrapped_key must be 48 bytes"),
    };
    let vault_key = match unwrap_vault_key(&iv, &wrapped_arr, &recovery_kek) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    // client_kek_half is unknown in recovery context; use a random placeholder
    // (recovery sessions only re-wrap keys, never derive KEK for relay auth)
    let placeholder_kek_half = match generate_aes_key() {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let session = VaultSession {
        vault_key,
        client_kek_half: placeholder_kek_half,
        kek: None,
    };
    let session_id = store_vault_session(session);
    let obj = js_sys::Object::new();
    js_set(&obj, "session_id", &JsValue::from(session_id));
    obj.into()
}

/// Wrap the session vault_key using a recovery key.
///
/// Derives recovery_vault_kek from `recovery_key_b64` inside WASM and wraps
/// vault_key.  Returns `{ rec_wrap_iv_b64, rec_wrapped_key_b64 }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_wrap_recovery(session_id: u32, recovery_key_b64: String) -> JsValue {
    let rec_key_bytes = match b64_decode(&recovery_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 recovery_key"),
    };
    let secret = if rec_key_bytes.len() >= 33 {
        rec_key_bytes.get(1..33).map(|s| s.to_vec())
    } else if rec_key_bytes.len() == 32 {
        Some(rec_key_bytes.clone())
    } else {
        None
    };
    let secret = match secret {
        Some(s) => s,
        None => return js_error("recovery_key must be 32 or 37 bytes"),
    };
    let result = with_vault_session(session_id, |sess| {
        let recovery_kek = derive_recovery_vault_kek(&secret).map_err(|e| e.to_string())?;
        wrap_vault_key(&sess.vault_key, &recovery_kek).map_err(|e| e.to_string())
    });
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok((nonce, wrapped))) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "rec_wrap_iv_b64",
                &JsValue::from_str(&b64_encode(nonce.as_bytes())),
            );
            js_set(
                &obj,
                "rec_wrapped_key_b64",
                &JsValue::from_str(&b64_encode(&wrapped)),
            );
            obj.into()
        }
    }
}

/// Re-wrap the session vault_key under a new passphrase without exposing
/// vault_key or the new vault_kek to JS.
///
/// Generates a fresh `master_salt`, runs Argon2id, derives the new vault_kek,
/// and wraps vault_key.
///
/// Returns `{ wrap_iv_b64, wrapped_key_b64, master_salt_b64 }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_rewrap_with_passphrase(
    session_id: u32,
    new_password: String,
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
) -> JsValue {
    let mut new_salt = [0u8; 32];
    if getrandom::getrandom(&mut new_salt).is_err() {
        return js_error("failed to generate random salt");
    }
    let argon_output = match argon2id_derive_with_params(
        new_password.as_bytes(),
        &new_salt,
        memory_kb,
        iterations,
        parallelism,
    ) {
        Ok(o) => o,
        Err(e) => return js_error(&e.to_string()),
    };
    let new_vault_kek = match derive_vault_kek(&argon_output) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    let result = with_vault_session(session_id, |sess| {
        wrap_vault_key(&sess.vault_key, &new_vault_kek).map_err(|e| e.to_string())
    });
    match result {
        None => js_error("vault session not found"),
        Some(Err(e)) => js_error(&e),
        Some(Ok((nonce, wrapped))) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "wrap_iv_b64",
                &JsValue::from_str(&b64_encode(nonce.as_bytes())),
            );
            js_set(
                &obj,
                "wrapped_key_b64",
                &JsValue::from_str(&b64_encode(&wrapped)),
            );
            js_set(
                &obj,
                "master_salt_b64",
                &JsValue::from_str(&b64_encode(&new_salt)),
            );
            obj.into()
        }
    }
}

// ─── Share link crypto (P10) ─────────────────────────────────────────────────

/// Extract the content_key from a V7 file header and encode it as a share fragment.
///
/// This function keeps the content_key entirely inside WASM — it never crosses the
/// WASM/JS boundary. Only the fragment string (suitable for a URL #hash) is returned.
///
/// ZK invariant: content_key is created and destroyed in a single stack frame.
///
/// mlkem_sec_b64:  base64-encoded ML-KEM-1024 secret key
/// x25519_sec_b64: base64-encoded X25519 secret key (32 bytes)
/// header_b64:     base64-encoded V7 file header bytes (≥ V7_HEADER_MIN = 1709 bytes)
/// variant:        "A" or "A+"
/// password:       required when variant == "A+", ignored otherwise
///
/// Returns: fragment string (e.g. "k=..." or "s=...&e=..."), or { error }.
#[wasm_bindgen]
pub fn byo_create_share_fragment(
    mlkem_sec_b64: &str,
    x25519_sec_b64: &str,
    header_b64: &str,
    variant: &str,
    password: Option<String>,
) -> JsValue {
    // Decode private keys.
    let mlkem_bytes = match b64_decode(mlkem_sec_b64) {
        Ok(b) => b,
        Err(_) => return js_error("mlkem decode: invalid base64"),
    };
    let mlkem_sec = match MlKemSecretKey::from_slice(&mlkem_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };

    let x25519_bytes = match b64_decode(x25519_sec_b64) {
        Ok(b) => b,
        Err(_) => return js_error("x25519 decode: invalid base64"),
    };
    let x25519_sec = match X25519SecretKey::from_slice(&x25519_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };

    // Decode header.
    let header_bytes = match b64_decode(header_b64) {
        Ok(b) => b,
        Err(_) => return js_error("header decode: invalid base64"),
    };

    // Decapsulate: extracts content_key into V7DecryptInit.
    let init = match decrypt_file_v7_init(&header_bytes, &mlkem_sec, &x25519_sec) {
        Ok(i) => i,
        Err(e) => return js_error(&e.to_string()),
    };

    let ck: &[u8; 32] = init.content_key.as_bytes();

    // Encode fragment — content_key never leaves this scope as raw bytes.
    let fragment = match variant {
        "A" => {
            use sdk_core::byo::share::encode_variant_a;
            encode_variant_a(ck)
        }
        "A+" => {
            use sdk_core::byo::share::wrap_key_with_password;
            let pwd = match password {
                Some(p) => p,
                None => return js_error("password required for variant A+"),
            };
            match wrap_key_with_password(ck, &pwd) {
                Ok((salt_b64, enc_b64)) => format!("s={salt_b64}&e={enc_b64}"),
                Err(e) => return js_error(&e.to_string()),
            }
        }
        other => return js_error(&format!("unknown variant: {other}; use 'A' or 'A+'")),
    };

    JsValue::from_str(&fragment)
}

/// Extract the per-file content_key from a V7 header, base64-encoded.
///
/// This is the bundle-share analog of `byo_create_share_fragment`: it uses
/// the vault's private keys to decapsulate the V7 KEM and returns the
/// content_key so the caller can embed it in a bundle manifest (which is
/// then re-encrypted under the bundle_key before upload). The per-file key
/// still never reaches the relay — it only round-trips through the worker
/// on the way into `byo_encrypt_manifest_v7`.
///
/// Returns: base64-encoded 32-byte content_key, or `{ error }`.
#[wasm_bindgen]
pub fn byo_bundle_extract_file_key(
    mlkem_sec_b64: &str,
    x25519_sec_b64: &str,
    header_b64: &str,
) -> JsValue {
    let mlkem_bytes = match b64_decode(mlkem_sec_b64) {
        Ok(b) => b,
        Err(_) => return js_error("mlkem decode: invalid base64"),
    };
    let mlkem_sec = match MlKemSecretKey::from_slice(&mlkem_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };

    let x25519_bytes = match b64_decode(x25519_sec_b64) {
        Ok(b) => b,
        Err(_) => return js_error("x25519 decode: invalid base64"),
    };
    let x25519_sec = match X25519SecretKey::from_slice(&x25519_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };

    let header_bytes = match b64_decode(header_b64) {
        Ok(b) => b,
        Err(_) => return js_error("header decode: invalid base64"),
    };

    let init = match decrypt_file_v7_init(&header_bytes, &mlkem_sec, &x25519_sec) {
        Ok(i) => i,
        Err(e) => return js_error(&e.to_string()),
    };

    // content_key is a zeroize-on-drop SymmetricKey — its bytes live for the
    // duration of this stack frame only. We copy the 32 raw bytes into a
    // base64 string and return; the SymmetricKey drops at end of scope.
    JsValue::from_str(&b64_encode(init.content_key.as_bytes()))
}

/// Encode a 32-byte content_key (base64url input) as a Variant A fragment "k=<b64url>".
/// Input: base64-encoded content_key (32 bytes).
/// Returns: fragment string, or { error }.
#[wasm_bindgen]
pub fn byo_share_encode_variant_a(content_key_b64: &str) -> JsValue {
    let ck_bytes = match b64_decode(content_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("b64 decode failed: invalid base64"),
    };
    let ck: [u8; 32] = match ck_bytes.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => return js_error("content_key must be 32 bytes"),
    };
    JsValue::from_str(&encode_variant_a(&ck))
}

/// Decode a Variant A fragment "k=<b64url>" and return the base64-encoded content_key.
/// Returns: base64-encoded content_key string, or { error }.
#[wasm_bindgen]
pub fn byo_share_decode_variant_a(fragment: &str) -> JsValue {
    match decode_variant_a(fragment) {
        Ok(ck) => JsValue::from_str(&b64_encode(&ck)),
        Err(e) => js_error(&e.to_string()),
    }
}

/// Wrap a content_key with password (Variant A+).
/// content_key_b64: base64-encoded 32-byte content_key.
/// password: plaintext password string.
/// Returns: { salt_b64url, encrypted_ck_b64url } or { error }.
#[wasm_bindgen]
pub fn byo_share_wrap_key(content_key_b64: &str, password: &str) -> JsValue {
    let ck_bytes = match b64_decode(content_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("b64 decode failed: invalid base64"),
    };
    let ck: [u8; 32] = match ck_bytes.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => return js_error("content_key must be 32 bytes"),
    };
    match wrap_key_with_password(&ck, password) {
        Ok((salt_b64, enc_b64)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "salt_b64url", &JsValue::from_str(&salt_b64));
            js_set(&obj, "encrypted_ck_b64url", &JsValue::from_str(&enc_b64));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Unwrap a password-protected content_key (Variant A+).
/// Returns base64-encoded content_key or { error }.
#[wasm_bindgen]
pub fn byo_share_unwrap_key(
    salt_b64url: &str,
    encrypted_ck_b64url: &str,
    password: &str,
) -> JsValue {
    match unwrap_key_with_password(salt_b64url, encrypted_ck_b64url, password) {
        Ok(ck) => JsValue::from_str(&b64_encode(&ck)),
        Err(e) => js_error(&e.to_string()),
    }
}

// ─── Streaming share decryption ───────────────────────────────────────────
//
// Three-function flow used by the /s/:share_id recipient page. Unlike the
// single-shot `byo_v7_share_decrypt` below, this keeps the V7ShareDecryptor
// alive across chunks so we never materialise the full plaintext in RAM —
// the page can save arbitrarily large shares to disk via streamToDisk.
//
// Session map lives thread-local. Each entry holds a live V7ShareDecryptor;
// dropping the session zeroizes the content_key + HMAC state.

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static SHARE_DECRYPT_SESSIONS: RefCell<HashMap<String, V7ShareDecryptor>> =
        RefCell::new(HashMap::new());
}

fn share_session_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        return "csprng-unavailable".to_string();
    }
    let mut s = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Initialise a streaming share decryptor from the V7 header and a known
/// content_key. The header (bytes 0..1709 of the ciphertext) must be fully
/// buffered before this call; everything after that is fed via
/// `byoShareStreamPush`. Returns `{ sessionId }` on success.
#[wasm_bindgen(js_name = byoShareStreamInit)]
pub fn byo_share_stream_init(header_bytes: &[u8], content_key_b64: &str) -> JsValue {
    let ck = match b64_decode(content_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("content_key: invalid base64"),
    };
    if ck.len() != 32 {
        return js_error("content_key must be 32 bytes");
    }
    let (dec, _header_end) = match V7ShareDecryptor::new(header_bytes, &ck) {
        Ok(v) => v,
        Err(e) => return js_error(&e.to_string()),
    };
    let id = share_session_id();
    SHARE_DECRYPT_SESSIONS.with(|s| s.borrow_mut().insert(id.clone(), dec));
    let obj = js_sys::Object::new();
    js_set(&obj, "sessionId", &JsValue::from_str(&id));
    obj.into()
}

/// Feed ciphertext bytes into an open session. Returns plaintext that has
/// become available (may be empty if the bytes didn't complete a frame).
/// Callers MUST NOT pass the trailing 32-byte HMAC footer here — hand it
/// to `byoShareStreamClose` instead.
#[wasm_bindgen(js_name = byoShareStreamPush)]
pub fn byo_share_stream_push(session_id: &str, chunk: &[u8]) -> JsValue {
    let result = SHARE_DECRYPT_SESSIONS.with(|s| {
        let mut sessions = s.borrow_mut();
        match sessions.get_mut(session_id) {
            Some(dec) => dec.push(chunk).map_err(|e| e.to_string()),
            None => Err("unknown share session".to_string()),
        }
    });
    match result {
        Ok(pt) => js_sys::Uint8Array::from(pt.as_slice()).into(),
        Err(e) => js_error(&e),
    }
}

/// Finalise the session. `footer` must be the trailing 32-byte HMAC bytes
/// from the ciphertext stream. Returns `{ ok: true }` on match, `{ error }`
/// on HMAC mismatch / truncation / unknown session. Drops the decryptor
/// (zeroize on drop) regardless of verification outcome.
#[wasm_bindgen(js_name = byoShareStreamClose)]
pub fn byo_share_stream_close(session_id: &str, footer: &[u8]) -> JsValue {
    let dec = SHARE_DECRYPT_SESSIONS.with(|s| s.borrow_mut().remove(session_id));
    let Some(dec) = dec else {
        return js_error("unknown share session");
    };
    match dec.finalize(footer) {
        Ok(()) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "ok", &JsValue::from_bool(true));
            obj.into()
        }
        Err(e) => js_error(&e.to_string()),
    }
}

/// Encrypt a bundle manifest (JSON bytes) under a known bundle content_key.
///
/// Returns the V7-formatted ciphertext bytes ready to upload as the
/// `_manifest` blob of a bundle share. The recipient decrypts it with
/// `V7ShareDecryptor` using the same content_key carried in the URL
/// fragment — same protocol as any other share.
///
/// `content_key_b64`: base64-encoded 32-byte bundle_key.
#[wasm_bindgen(js_name = byoEncryptManifestV7)]
pub fn byo_encrypt_manifest_v7(manifest_bytes: &[u8], content_key_b64: &str) -> JsValue {
    let ck_bytes = match b64_decode(content_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("content_key: invalid base64"),
    };
    if ck_bytes.len() != 32 {
        return js_error("content_key must be 32 bytes");
    }
    let content_key = match SymmetricKey::from_slice(&ck_bytes) {
        Ok(k) => k,
        Err(e) => return js_error(&e.to_string()),
    };
    match encrypt_manifest_v7(manifest_bytes, &content_key) {
        Ok(bytes) => js_sys::Uint8Array::from(bytes.as_slice()).into(),
        Err(e) => js_error(&e.to_string()),
    }
}

/// Decrypt a complete V7 share ciphertext using a known content_key.
///
/// This is the recipient-side decryption for share links (variants A / A+).
/// The content_key is the fragment-transported key — it never crossed the network.
///
/// `ciphertext`: complete V7 file bytes (header + chunks + 32-byte HMAC footer).
/// `content_key_b64`: base64url-encoded 32-byte content key.
///
/// Returns the decrypted plaintext as a `Uint8Array`, or `{ error }` on failure.
#[wasm_bindgen]
pub fn byo_v7_share_decrypt(ciphertext: Vec<u8>, content_key_b64: &str) -> JsValue {
    let ck_bytes = match b64_decode(content_key_b64) {
        Ok(b) => b,
        Err(_) => return js_error("content_key: invalid base64"),
    };
    if ck_bytes.len() != 32 {
        return js_error("content_key must be 32 bytes");
    }
    if ciphertext.len() < V7_HEADER_MIN + 32 {
        return js_error("ciphertext too short to be valid V7");
    }

    // Pass only the header to `new()` — extra bytes become leftover and would
    // double-feed if we also called push(body).
    let (mut dec, _) = match V7ShareDecryptor::new(&ciphertext[..V7_HEADER_MIN], &ck_bytes) {
        Ok(v) => v,
        Err(e) => return js_error(&e.to_string()),
    };

    // Feed the body (everything after the header, before the footer).
    let body = &ciphertext[V7_HEADER_MIN..ciphertext.len() - 32];
    let plaintext = match dec.push(body) {
        Ok(p) => p,
        Err(e) => return js_error(&e.to_string()),
    };

    // Verify the trailing HMAC footer.
    let footer = &ciphertext[ciphertext.len() - 32..];
    if let Err(e) = dec.finalize(footer) {
        return js_error(&e.to_string());
    }

    js_sys::Uint8Array::from(plaintext.as_slice()).into()
}

// ─── Private helpers ────────────────────────────────────────────────────────

/// Derive the 32-byte AES-GCM key that wraps `key_versions` private-key rows,
/// using HKDF-SHA256 with `KEY_VERSIONS_WRAP_INFO` over the session vault_key.
fn derive_key_versions_wrap_key(sess: &VaultSession) -> Result<SymmetricKey, String> {
    let bytes = hkdf_sha256(sess.vault_key.as_bytes(), KEY_VERSIONS_WRAP_INFO, 32)
        .map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "hkdf output length mismatch".to_string())?;
    Ok(SymmetricKey::new(arr))
}

/// AES-256-GCM encrypt with a freshly-drawn CSPRNG nonce; result format is
/// `nonce(12) || ciphertext||tag` — symmetric with `vault_aes_decrypt`.
fn vault_aes_encrypt_with_subkey(plaintext: &[u8], key: &SymmetricKey) -> Result<Vec<u8>, String> {
    let (ct, nonce) = aes_gcm_encrypt(plaintext, key).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM decrypt with the format `nonce(12) || ciphertext`.
fn vault_aes_decrypt(encrypted: &[u8], key: &SymmetricKey) -> Result<Vec<u8>, String> {
    if encrypted.len() < 12 {
        return Err("encrypted key too short".into());
    }
    let nonce_arr: [u8; 12] = encrypted
        .get(..12)
        .ok_or("slice error")?
        .try_into()
        .map_err(|_| "nonce length mismatch")?;
    let nonce = Nonce12::new(nonce_arr);
    let ct = encrypted.get(12..).ok_or("empty ciphertext")?;
    aes_gcm_decrypt(ct, &nonce, key).map_err(|e| e.to_string())
}
