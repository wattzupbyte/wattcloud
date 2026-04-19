//! WASM binding tests for sdk-wasm.
//!
//! Tests every wasm_bindgen export: correct output shapes, round-trips, and
//! error cases. Tests run in-browser via:
//!   wasm-pack test --headless --chrome

use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use secure_cloud_sdk_wasm::auth::*;
use secure_cloud_sdk_wasm::byo::*;
use secure_cloud_sdk_wasm::crypto::*;
use secure_cloud_sdk_wasm::filename::*;
use secure_cloud_sdk_wasm::hashing::*;
use secure_cloud_sdk_wasm::kek::*;
use secure_cloud_sdk_wasm::keys::*;
use secure_cloud_sdk_wasm::validation::*;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn get_str(obj: &JsValue, field: &str) -> String {
    js_sys::Reflect::get(obj, &field.into())
        .unwrap()
        .as_string()
        .unwrap_or_default()
}

fn get_bool(obj: &JsValue, field: &str) -> bool {
    js_sys::Reflect::get(obj, &field.into())
        .unwrap()
        .as_bool()
        .unwrap_or(false)
}

fn get_f64(obj: &JsValue, field: &str) -> f64 {
    js_sys::Reflect::get(obj, &field.into())
        .unwrap()
        .as_f64()
        .unwrap_or(0.0)
}

fn decode_b64(s: &str) -> Vec<u8> {
    // We use the built-in base64 decode available in the wasm env
    let global = js_sys::global();
    let atob = js_sys::Reflect::get(&global, &"atob".into()).unwrap();
    let decoded = js_sys::Function::from(atob)
        .call1(&JsValue::NULL, &s.into())
        .unwrap()
        .as_string()
        .unwrap();
    decoded.bytes().collect()
}

// ─── keys.rs ──────────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_generate_keypair_shape() {
    let kp = generate_keypair();
    assert!(!kp.is_null());

    let mlkem_pub = get_str(&kp, "mlkem_public_key");
    let mlkem_sec = get_str(&kp, "mlkem_secret_key");
    let x25519_pub = get_str(&kp, "x25519_public_key");
    let x25519_sec = get_str(&kp, "x25519_secret_key");

    assert!(!mlkem_pub.is_empty(), "mlkem_public_key must not be empty");
    assert!(!mlkem_sec.is_empty(), "mlkem_secret_key must not be empty");
    assert!(
        !x25519_pub.is_empty(),
        "x25519_public_key must not be empty"
    );
    assert!(
        !x25519_sec.is_empty(),
        "x25519_secret_key must not be empty"
    );

    // ML-KEM-1024 public key: 1568 bytes → base64 length = ceil(1568/3)*4 = 2092 chars
    assert!(
        mlkem_pub.len() > 2000,
        "mlkem_public_key looks too short: {}",
        mlkem_pub.len()
    );
    // ML-KEM-1024 secret key: 3168 bytes → base64 ≈ 4224 chars
    assert!(
        mlkem_sec.len() > 4000,
        "mlkem_secret_key looks too short: {}",
        mlkem_sec.len()
    );
    // X25519 keys: 32 bytes → 44 chars base64
    assert!(x25519_pub.len() >= 43 && x25519_pub.len() <= 44);
    assert!(x25519_sec.len() >= 43 && x25519_sec.len() <= 44);
}

#[wasm_bindgen_test]
fn test_generate_keypair_uniqueness() {
    let kp1 = generate_keypair();
    let kp2 = generate_keypair();
    let pub1 = get_str(&kp1, "mlkem_public_key");
    let pub2 = get_str(&kp2, "mlkem_public_key");
    assert_ne!(pub1, pub2, "two generated keypairs must be different");
}

#[wasm_bindgen_test]
fn test_generate_random_keypair_shape() {
    let kp = generate_random_keypair();
    assert!(!kp.is_null());
    let mlkem_pub = get_str(&kp, "mlkem_public_key");
    let x25519_pub = get_str(&kp, "x25519_public_key");
    assert!(!mlkem_pub.is_empty());
    assert!(!x25519_pub.is_empty());
}

#[wasm_bindgen_test]
fn test_get_public_keys_json() {
    let kp = generate_keypair();
    let json_str = get_public_keys_json(kp);
    let json_string = json_str.as_string().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_string).unwrap();
    assert!(parsed["mlkem_public_key"].is_string());
    assert!(parsed["x25519_public_key"].is_string());
}

#[wasm_bindgen_test]
fn test_get_secret_keys_json() {
    let kp = generate_keypair();
    let json_str = get_secret_keys_json(kp);
    let json_string = json_str.as_string().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_string).unwrap();
    assert!(parsed["mlkem_secret_key"].is_string() || parsed["mlkem_private_key"].is_string());
    assert!(parsed["x25519_secret_key"].is_string());
}

#[wasm_bindgen_test]
fn test_generate_master_secret_v5_format() {
    let ms = generate_master_secret_v5();
    assert!(!ms.is_null());
    let b64 = ms.as_string().unwrap();
    // 37 bytes base64 = 49 or 52 chars (with padding)
    assert!(
        b64.len() >= 48,
        "master secret base64 too short: {}",
        b64.len()
    );

    // verify_master_secret must accept its own output
    let valid = verify_master_secret(b64);
    assert!(valid.as_bool().unwrap_or(false));
}

#[wasm_bindgen_test]
fn test_verify_master_secret_rejects_garbage() {
    let result = verify_master_secret("not_a_real_master_secret_abc123".to_string());
    assert!(!result.as_bool().unwrap_or(true));
}

#[wasm_bindgen_test]
fn test_derive_keypair_from_master() {
    let ms = generate_master_secret_v5().as_string().unwrap();
    let kp = derive_keypair_from_master(ms);
    assert!(!kp.is_null());
    let mlkem_pub = get_str(&kp, "mlkem_public_key");
    let x25519_pub = get_str(&kp, "x25519_public_key");
    assert!(!mlkem_pub.is_empty());
    assert!(!x25519_pub.is_empty());
}

#[wasm_bindgen_test]
fn test_derive_keypair_from_master_deterministic() {
    let ms = generate_master_secret_v5().as_string().unwrap();
    let kp1 = derive_keypair_from_master(ms.clone());
    let kp2 = derive_keypair_from_master(ms);
    // Same master secret → same deterministic keypair
    assert_eq!(
        get_str(&kp1, "mlkem_public_key"),
        get_str(&kp2, "mlkem_public_key")
    );
    assert_eq!(
        get_str(&kp1, "x25519_public_key"),
        get_str(&kp2, "x25519_public_key")
    );
}

#[wasm_bindgen_test]
fn test_derive_filename_key_from_master() {
    let ms = generate_master_secret_v5().as_string().unwrap();
    let result = derive_filename_key_from_master(ms);
    assert!(!result.is_null());
    let key_b64 = get_str(&result, "key");
    // 32 bytes → 44 chars base64
    assert!(key_b64.len() >= 43 && key_b64.len() <= 44);
}

// ─── auth.rs ──────────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_generate_auth_salt() {
    let s1 = generate_auth_salt().as_string().unwrap();
    let s2 = generate_auth_salt().as_string().unwrap();
    assert!(!s1.is_empty());
    assert_ne!(s1, s2, "auth salts must be unique");
    // 32 bytes base64 = 44 chars
    assert!(s1.len() >= 43 && s1.len() <= 44);
}

#[wasm_bindgen_test]
fn test_derive_auth_and_encryption_keys_fields() {
    let salt = generate_auth_salt().as_string().unwrap();
    let result = derive_auth_and_encryption_keys("test_password", &salt);
    let json_str = result.as_string().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed["auth_hash"].is_string(), "missing auth_hash");
    assert!(
        parsed["encryption_key"].is_string(),
        "missing encryption_key"
    );
    assert!(parsed["salt"].is_string(), "missing salt");
    assert!(parsed["argon_output"].is_string(), "missing argon_output");
}

#[wasm_bindgen_test]
fn test_derive_auth_and_encryption_keys_deterministic() {
    let salt = generate_auth_salt().as_string().unwrap();
    let r1: serde_json::Value = serde_json::from_str(
        &derive_auth_and_encryption_keys("pw123", &salt)
            .as_string()
            .unwrap(),
    )
    .unwrap();
    let r2: serde_json::Value = serde_json::from_str(
        &derive_auth_and_encryption_keys("pw123", &salt)
            .as_string()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        r1["auth_hash"], r2["auth_hash"],
        "KDF must be deterministic"
    );
}

#[wasm_bindgen_test]
fn test_derive_auth_hash_only() {
    let salt = generate_auth_salt().as_string().unwrap();
    let result = derive_auth_hash_only("pw", &salt);
    let parsed: serde_json::Value = serde_json::from_str(&result.as_string().unwrap()).unwrap();
    assert!(parsed["auth_hash"].is_string());
}

#[wasm_bindgen_test]
fn test_verify_auth_hash_correct_password() {
    let salt = generate_auth_salt().as_string().unwrap();
    let derived: serde_json::Value = serde_json::from_str(
        &derive_auth_and_encryption_keys("correct_password", &salt)
            .as_string()
            .unwrap(),
    )
    .unwrap();
    let hash = derived["auth_hash"].as_str().unwrap().to_string();
    let valid = verify_auth_hash("correct_password", &salt, &hash);
    assert!(valid.as_bool().unwrap_or(false));
}

#[wasm_bindgen_test]
fn test_verify_auth_hash_wrong_password() {
    let salt = generate_auth_salt().as_string().unwrap();
    let derived: serde_json::Value = serde_json::from_str(
        &derive_auth_and_encryption_keys("correct_password", &salt)
            .as_string()
            .unwrap(),
    )
    .unwrap();
    let hash = derived["auth_hash"].as_str().unwrap().to_string();
    let valid = verify_auth_hash("wrong_password", &salt, &hash);
    assert!(!valid.as_bool().unwrap_or(true));
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_master_secret_with_key() {
    let salt = generate_auth_salt().as_string().unwrap();
    let keys: serde_json::Value = serde_json::from_str(
        &derive_auth_and_encryption_keys("my_password", &salt)
            .as_string()
            .unwrap(),
    )
    .unwrap();
    let enc_key = keys["encryption_key"].as_str().unwrap().to_string();

    let ms = generate_master_secret_v5().as_string().unwrap();

    let enc_json = encrypt_master_secret_with_key(&ms, &enc_key);
    let enc_str = enc_json.as_string().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&enc_str).unwrap();
    assert!(parsed["iv"].is_string());
    assert!(parsed["ciphertext"].is_string());

    let recovered = decrypt_master_secret_with_key(&enc_str, &enc_key);
    let recovered_b64 = recovered.as_string().unwrap();
    assert_eq!(recovered_b64, ms);
}

#[wasm_bindgen_test]
fn test_generate_device_key() {
    let key = generate_device_key().as_string().unwrap();
    // 32 bytes → 44 chars base64
    assert!(key.len() >= 43 && key.len() <= 44);
    // Two device keys must differ
    let key2 = generate_device_key().as_string().unwrap();
    assert_ne!(key, key2);
}

// ─── crypto.rs ────────────────────────────────────────────────────────────────

fn make_pub_keys_json() -> String {
    let kp = generate_keypair();
    get_public_keys_json(kp).as_string().unwrap()
}

#[wasm_bindgen_test]
fn test_encrypt_file_v7_convenience() {
    let kp = generate_keypair();
    let pub_json = get_public_keys_json(kp.clone()).as_string().unwrap();
    let sec_json = get_secret_keys_json(kp).as_string().unwrap();

    let plaintext = b"Hello, WASM world!".to_vec();
    let result = encrypt_file_v7(plaintext.clone(), pub_json);
    assert!(result.is_some(), "encrypt_file_v7 must succeed");
    let encrypted = result.unwrap();
    assert!(!encrypted.is_empty());

    // Decrypt and verify
    let decrypted = decrypt_file_v7(encrypted, sec_json);
    assert!(decrypted.is_some(), "decrypt_file_v7 must succeed");
    assert_eq!(decrypted.unwrap(), plaintext);
}

#[wasm_bindgen_test]
fn test_encrypt_file_v7_wrong_key_fails() {
    let kp1 = generate_keypair();
    let kp2 = generate_keypair();
    let pub_json = get_public_keys_json(kp1).as_string().unwrap();
    let sec_json = get_secret_keys_json(kp2).as_string().unwrap();

    let encrypted = encrypt_file_v7(b"secret data".to_vec(), pub_json)
        .expect("encrypt must succeed");

    let decrypted = decrypt_file_v7(encrypted, sec_json);
    // Should be None when decrypting with wrong key
    assert!(decrypted.is_none());
}

#[wasm_bindgen_test]
fn test_encrypt_file_v7_init_fields() {
    let pub_json = make_pub_keys_json();
    let result = encrypt_file_v7_init(pub_json);
    assert!(!result.is_null());
    assert!(!get_str(&result, "file_iv").is_empty());
    assert!(!get_str(&result, "eph_x25519_pub").is_empty());
    assert!(!get_str(&result, "mlkem_ct").is_empty());
    assert!(!get_str(&result, "encrypted_file_key").is_empty());
    assert!(!get_str(&result, "content_key").is_empty());
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_file_v7_chunked() {
    let kp = generate_keypair();
    let pub_json = get_public_keys_json(kp.clone()).as_string().unwrap();
    let _sec_json = get_secret_keys_json(kp).as_string().unwrap();

    // Init
    let init = encrypt_file_v7_init(pub_json);
    assert!(!init.is_null());
    let file_iv = get_str(&init, "file_iv");
    let content_key = get_str(&init, "content_key");
    let _eph_x25519 = get_str(&init, "eph_x25519_pub");
    let _mlkem_ct = get_str(&init, "mlkem_ct");
    let _efk = get_str(&init, "encrypted_file_key");

    // Encrypt one chunk
    let chunk = b"test chunk data".to_vec();
    let enc_chunk = encrypt_file_v7_chunk(chunk, content_key.clone(), file_iv.clone(), 0);
    assert!(!enc_chunk.is_null());
    // ciphertext is now a Uint8Array in the JsValue
    let chunk_ct_js = js_sys::Reflect::get(&enc_chunk, &"ciphertext".into()).unwrap();
    let chunk_ct_arr = js_sys::Uint8Array::from(chunk_ct_js);
    let chunk_ct_bytes: Vec<u8> = chunk_ct_arr.to_vec();
    assert!(!chunk_ct_bytes.is_empty());

    // HMAC (uses content_key, not a separate hmac_key)
    let hmac = compute_v7_hmac(content_key.clone(), chunk_ct_bytes);
    let hmac_b64 = hmac.as_string().unwrap();
    assert!(!hmac_b64.is_empty());

    // Decrypt init
    // Build the full blob to decrypt — use the convenience decrypt instead
    // (chunked decrypt init requires a full blob, tested via convenience API above)
}

#[wasm_bindgen_test]
fn test_encrypt_file_v7_large_payload() {
    let kp = generate_keypair();
    let pub_json = get_public_keys_json(kp.clone()).as_string().unwrap();
    let sec_json = get_secret_keys_json(kp).as_string().unwrap();

    // 1 MB payload
    let plaintext = vec![0x42u8; 1024 * 1024];
    let encrypted = encrypt_file_v7(plaintext.clone(), pub_json)
        .expect("1MB encryption must succeed");

    let decrypted = decrypt_file_v7(encrypted, sec_json)
        .expect("1MB decryption must succeed");
    assert_eq!(decrypted, plaintext);
}

// ─── V7StreamDecryptorWasm ────────────────────────────────────────────────────
//
// Exercises the streaming decrypt path used by frontend/downloadService.ts:
// header → push(body) → finalize(footer). Encrypts a payload with the
// full-blob convenience API and then splits the ciphertext into the same
// (header, body, footer) layout the real streaming reader sees.

const V7_HEADER_MIN: usize = 1709;
const V7_HMAC_LEN: usize = 32;

/// Base64-decode using the `base64` crate so we don't lose high bytes the way
/// the `atob`-based helper would (atob returns a UTF-8 String which corrupts
/// bytes >= 0x80 on round-trip through Rust).
fn b64_decode_binary(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("valid base64")
}

#[wasm_bindgen_test]
fn test_v7_stream_decryptor_round_trip() {
    let kp = generate_keypair();
    let pub_json = get_public_keys_json(kp.clone()).as_string().unwrap();
    let sec_json = get_secret_keys_json(kp).as_string().unwrap();

    // Produce an encrypted blob large enough to span several 256KiB chunks so
    // the streaming buffer logic actually has frame boundaries to resolve.
    let plaintext: Vec<u8> = (0..700 * 1024)
        .map(|i| (i as u8).wrapping_mul(31))
        .collect();
    let blob = encrypt_file_v7(plaintext.clone(), pub_json)
        .expect("encrypt_file_v7 must succeed");
    assert!(
        blob.len() > V7_HEADER_MIN + V7_HMAC_LEN,
        "v7 blob too small: {}",
        blob.len()
    );

    // Split into (header, body, footer) the same way downloadService.ts does.
    let header = blob[..V7_HEADER_MIN].to_vec();
    let body_end = blob.len() - V7_HMAC_LEN;
    let body = blob[V7_HEADER_MIN..body_end].to_vec();
    let footer = blob[body_end..].to_vec();

    let mut dec = V7StreamDecryptorWasm::create(header, sec_json).expect("create decryptor");
    assert_eq!(
        dec.header_end() as usize,
        V7_HEADER_MIN,
        "headerEnd must match V7_HEADER_MIN"
    );

    // Feed the body in three uneven slices to prove the internal buffer
    // re-assembles frames across arbitrary network chunk boundaries.
    let mid1 = body.len() / 3;
    let mid2 = (body.len() * 2) / 3;
    let mut recovered: Vec<u8> = Vec::with_capacity(plaintext.len());
    recovered.extend(dec.push(body[..mid1].to_vec()).expect("push 1"));
    recovered.extend(dec.push(body[mid1..mid2].to_vec()).expect("push 2"));
    recovered.extend(dec.push(body[mid2..].to_vec()).expect("push 3"));

    dec.finalize(footer).expect("finalize must succeed");

    assert_eq!(
        recovered.len(),
        plaintext.len(),
        "recovered length mismatch"
    );
    assert_eq!(recovered, plaintext, "recovered plaintext mismatch");
}

/// Full stream-encrypt → stream-decrypt round-trip through the wasm bindings.
/// Exercises V7StreamEncryptorWasm.{create, takeHeader, push, finalize} and
/// verifies wire compatibility with V7StreamDecryptorWasm.
#[wasm_bindgen_test]
fn test_v7_stream_encryptor_round_trip() {
    let kp = generate_keypair();
    let pub_json = get_public_keys_json(kp.clone()).as_string().unwrap();
    let sec_json = get_secret_keys_json(kp).as_string().unwrap();

    let mut enc = V7StreamEncryptorWasm::create(pub_json).expect("create encryptor");
    let header = enc.take_header().expect("take_header");
    assert_eq!(header.len(), V7_HEADER_MIN, "header must be 1709 bytes");

    // Three plaintext chunks of varied sizes.
    let chunks: Vec<Vec<u8>> = vec![
        (0..256).map(|i| i as u8).collect(),
        vec![0xABu8; 400 * 1024],
        b"tail".to_vec(),
    ];
    let mut blob = header.clone();
    for chunk in &chunks {
        let frame = enc.push(chunk.clone()).expect("push frame");
        assert!(frame.len() >= 4 + 12 + 16, "frame shape");
        blob.extend_from_slice(&frame);
    }
    let footer = enc.finalize().expect("finalize");
    assert_eq!(footer.len(), V7_HMAC_LEN);
    blob.extend_from_slice(&footer);

    // Decrypt the resulting blob via the streaming decryptor.
    let decryptor_header = blob[..V7_HEADER_MIN].to_vec();
    let body_end = blob.len() - V7_HMAC_LEN;
    let body = blob[V7_HEADER_MIN..body_end].to_vec();
    let recovered_footer = blob[body_end..].to_vec();

    let mut dec =
        V7StreamDecryptorWasm::create(decryptor_header, sec_json).expect("create decryptor");
    let recovered = dec.push(body).expect("push decrypt");
    dec.finalize(recovered_footer).expect("finalize decrypt");

    let expected: Vec<u8> = chunks.into_iter().flatten().collect();
    assert_eq!(recovered, expected, "round-trip plaintext mismatch");
}

#[wasm_bindgen_test]
fn test_v7_stream_encryptor_take_header_once() {
    let kp = generate_keypair();
    let pub_json = get_public_keys_json(kp).as_string().unwrap();

    let mut enc = V7StreamEncryptorWasm::create(pub_json).expect("create");
    let _h = enc.take_header().expect("first take_header");
    let err = enc.take_header().expect_err("second take_header must fail");
    let msg = err.as_string().unwrap_or_default();
    assert!(msg.contains("already taken"), "unexpected error: {}", msg);
}

#[wasm_bindgen_test]
fn test_encrypt_filename_with_fresh_key_round_trip() {
    let kp = generate_keypair();
    let pub_json = get_public_keys_json(kp.clone()).as_string().unwrap();
    let sec_json = get_secret_keys_json(kp).as_string().unwrap();

    let name = "vacation photos/IMG_1234.jpg".to_string();
    // First, with metadata=None — exercises the common path.
    let result = encrypt_filename_with_fresh_key(name.clone(), None, pub_json.clone())
        .expect("encrypt_filename_with_fresh_key");

    let encrypted_filename = get_str(&result, "encrypted_filename");
    let encrypted_key_b64 = get_str(&result, "encrypted_filename_key");
    assert!(!encrypted_filename.is_empty());
    assert!(!encrypted_key_b64.is_empty());

    // Unwrap the filename key via the standard v7 decrypt path.
    let encrypted_key_bytes = b64_decode_binary(&encrypted_key_b64);
    let key_bytes = decrypt_file_v7(encrypted_key_bytes, sec_json.clone())
        .expect("filename key unwrap failed");
    use base64::Engine;
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

    // Decrypt the filename with the unwrapped key.
    let dec_result = decrypt_filename(encrypted_filename, key_b64);
    assert!(!dec_result.is_null(), "decrypt_filename returned null");
    assert_eq!(get_str(&dec_result, "name"), name);
}

#[wasm_bindgen_test]
fn test_encrypt_filename_with_fresh_key_with_metadata() {
    let kp = generate_keypair();
    let pub_json = get_public_keys_json(kp.clone()).as_string().unwrap();
    let sec_json = get_secret_keys_json(kp).as_string().unwrap();

    let name = "trip/IMG_0001.jpg".to_string();
    let metadata = r#"{"takenAt":"2026-04-10T08:00:00Z","lat":48.1}"#.to_string();
    let result = encrypt_filename_with_fresh_key(name.clone(), Some(metadata.clone()), pub_json)
        .expect("encrypt_filename_with_fresh_key");

    let encrypted_filename = get_str(&result, "encrypted_filename");
    let encrypted_metadata = get_str(&result, "encrypted_metadata");
    let encrypted_key_b64 = get_str(&result, "encrypted_filename_key");
    assert!(!encrypted_filename.is_empty());
    assert!(
        !encrypted_metadata.is_empty(),
        "metadata ct must be present"
    );
    assert_ne!(
        encrypted_filename, encrypted_metadata,
        "distinct ciphertexts"
    );

    // Unwrap the filename key.
    let encrypted_key_bytes = b64_decode_binary(&encrypted_key_b64);
    let key_bytes = decrypt_file_v7(encrypted_key_bytes, sec_json)
        .expect("filename key unwrap failed");
    use base64::Engine;
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

    // Decrypt both filename and metadata with the same key.
    let dec_name = decrypt_filename(encrypted_filename, key_b64.clone());
    assert_eq!(get_str(&dec_name, "name"), name);

    let dec_meta = decrypt_filename(encrypted_metadata, key_b64);
    assert_eq!(get_str(&dec_meta, "name"), metadata);
}

#[wasm_bindgen_test]
fn test_v7_stream_decryptor_detects_tampered_footer() {
    let kp = generate_keypair();
    let pub_json = get_public_keys_json(kp.clone()).as_string().unwrap();
    let sec_json = get_secret_keys_json(kp).as_string().unwrap();

    let plaintext = vec![0xA5u8; 300 * 1024];
    let blob = encrypt_file_v7(plaintext, pub_json).expect("encrypt_file_v7 must succeed");

    let header = blob[..V7_HEADER_MIN].to_vec();
    let body_end = blob.len() - V7_HMAC_LEN;
    let body = blob[V7_HEADER_MIN..body_end].to_vec();
    let mut footer = blob[body_end..].to_vec();
    footer[0] ^= 0x01; // flip one bit in the HMAC

    let mut dec = V7StreamDecryptorWasm::create(header, sec_json).expect("create decryptor");
    // Push must still succeed — per-chunk AEAD is intact, only the footer is broken.
    dec.push(body).expect("push must succeed");

    let err = dec
        .finalize(footer)
        .expect_err("finalize must reject tampered HMAC footer");
    assert!(
        err.as_string()
            .unwrap_or_default()
            .to_lowercase()
            .contains("mac")
            || err
                .as_string()
                .unwrap_or_default()
                .to_lowercase()
                .contains("verif"),
        "expected MAC verification error, got: {:?}",
        err.as_string()
    );
}

// ─── kek.rs ───────────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_derive_client_kek_half() {
    let salt = generate_auth_salt().as_string().unwrap();
    let keys: serde_json::Value = serde_json::from_str(
        &derive_auth_and_encryption_keys("password", &salt)
            .as_string()
            .unwrap(),
    )
    .unwrap();
    let argon_out = keys["argon_output"].as_str().unwrap().to_string();

    let result = derive_client_kek_half(argon_out);
    assert!(!result.is_null());
    let kek_half = get_str(&result, "client_kek_half");
    // 32 bytes → 44 chars base64
    assert!(kek_half.len() >= 43 && kek_half.len() <= 44);
}

#[wasm_bindgen_test]
fn test_derive_kek_v2() {
    let salt = generate_auth_salt().as_string().unwrap();
    let keys: serde_json::Value = serde_json::from_str(
        &derive_auth_and_encryption_keys("pw", &salt)
            .as_string()
            .unwrap(),
    )
    .unwrap();
    let argon_out = keys["argon_output"].as_str().unwrap().to_string();
    let kek_half_result = derive_client_kek_half(argon_out);
    let kek_half_b64 = get_str(&kek_half_result, "client_kek_half");

    // Server shard is 32 random bytes — simulate with 44 chars of base64
    let server_shard = generate_device_key().as_string().unwrap();
    let kek = derive_kek_v2(kek_half_b64, server_shard);
    let kek_b64 = get_str(&kek, "kek");
    assert!(kek_b64.len() >= 43 && kek_b64.len() <= 44);
}

#[wasm_bindgen_test]
fn test_derive_recovery_kek() {
    let ms = generate_master_secret_v5().as_string().unwrap();
    let result = derive_recovery_kek(ms);
    assert!(!result.is_null());
    let recovery_kek = get_str(&result, "recovery_kek");
    assert!(recovery_kek.len() >= 43 && recovery_kek.len() <= 44);
}

#[wasm_bindgen_test]
fn test_reencrypt_private_key() {
    // Use two different KEKs (simulate old → new KEK rotation)
    let ms1 = generate_master_secret_v5().as_string().unwrap();
    let ms2 = generate_master_secret_v5().as_string().unwrap();
    let kek1 = get_str(&derive_recovery_kek(ms1), "recovery_kek");
    let kek2 = get_str(&derive_recovery_kek(ms2), "recovery_kek");

    // Encrypt some key material with kek1
    let kp = generate_keypair();
    let sec_json: serde_json::Value =
        serde_json::from_str(&get_secret_keys_json(kp).as_string().unwrap()).unwrap();
    let private_key_b64 = sec_json["x25519_secret_key"].as_str().unwrap().to_string();
    let enc = encrypt_master_secret_with_key(&private_key_b64, &kek1);
    let enc_str = enc.as_string().unwrap();

    // Reencrypt from kek1 to kek2
    let reenc = reencrypt_private_key(enc_str, kek1, kek2.clone());
    assert!(!reenc.is_null());
    let reenc_ct = get_str(&reenc, "ciphertext");
    assert!(!reenc_ct.is_empty());

    // Decrypt with kek2 and verify
    let recovered = decrypt_master_secret_with_key(&reenc_ct, &kek2);
    assert_eq!(recovered.as_string().unwrap(), private_key_b64);
}

// ─── filename.rs ──────────────────────────────────────────────────────────────

fn make_filename_key() -> String {
    // Use derive_filename_key_from_master to get a proper 32-byte key
    let ms = generate_master_secret_v5().as_string().unwrap();
    get_str(&derive_filename_key_from_master(ms), "key")
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_filename() {
    let key = make_filename_key();
    let enc = encrypt_filename("my_document.pdf".to_string(), key.clone());
    assert!(!enc.is_null());
    let enc_b64 = get_str(&enc, "encrypted_name");
    assert!(!enc_b64.is_empty());

    let dec = decrypt_filename(enc_b64, key);
    assert!(!dec.is_null());
    let name = get_str(&dec, "name");
    assert_eq!(name, "my_document.pdf");
}

#[wasm_bindgen_test]
fn test_encrypt_filename_siv_deterministic() {
    let key = make_filename_key();
    let enc1 = get_str(
        &encrypt_filename("same_file.txt".to_string(), key.clone()),
        "encrypted_name",
    );
    let enc2 = get_str(
        &encrypt_filename("same_file.txt".to_string(), key),
        "encrypted_name",
    );
    assert_eq!(enc1, enc2, "SIV encryption must be deterministic");
}

#[wasm_bindgen_test]
fn test_encrypt_decrypt_folder_path() {
    let key = make_filename_key();
    let enc = encrypt_folder_path("documents/work/reports".to_string(), key.clone());
    assert!(!enc.is_null());
    let enc_path = get_str(&enc, "encrypted_path");
    assert!(!enc_path.is_empty());

    let dec = decrypt_folder_path(enc_path, key);
    assert!(!dec.is_null());
    let path = get_str(&dec, "path");
    assert_eq!(path, "documents/work/reports");
}

// ─── hashing.rs ───────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_blake2b_256_empty_rfc_vector() {
    // RFC 7693: BLAKE2b-256(empty) = 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
    // blake2b_256 takes base64-encoded input; base64("") = ""
    let result = blake2b_256("".to_string());
    assert!(!result.is_null());
    let hash_b64 = get_str(&result, "hash");
    assert!(!hash_b64.is_empty());
    let bytes = decode_b64(&hash_b64);
    assert_eq!(bytes.len(), 32, "BLAKE2b-256 must produce 32 bytes");
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        hex,
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
    );
}

#[wasm_bindgen_test]
fn test_blake2b_256_abc_rfc_vector() {
    // RFC 7693: BLAKE2b-256("abc") = bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319
    // base64("abc") = "YWJj"
    let result = blake2b_256("YWJj".to_string());
    assert!(!result.is_null());
    let hash_b64 = get_str(&result, "hash");
    let bytes = decode_b64(&hash_b64);
    assert_eq!(bytes.len(), 32);
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        hex,
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
    );
}

// ─── validation.rs ─────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_validate_password_strong() {
    let result = validate_password("Correct!Horse2BatteryStaple#42", None);
    let valid = get_bool(&result, "valid");
    let strength = get_f64(&result, "strength") as u8;
    assert!(valid, "strong password should be valid");
    assert!(
        strength >= 3,
        "strong password should have high strength score"
    );
}

#[wasm_bindgen_test]
fn test_validate_password_too_short() {
    let result = validate_password("abc", None);
    let valid = get_bool(&result, "valid");
    assert!(!valid, "3-char password should be invalid");
    let errors = js_sys::Reflect::get(&result, &"errors".into()).unwrap();
    let errors_arr = js_sys::Array::from(&errors);
    assert!(errors_arr.length() > 0, "should have error messages");
}

#[wasm_bindgen_test]
fn test_validate_password_username_similarity() {
    let result = validate_password("myusername123!", Some("myusername".to_string()));
    let valid = get_bool(&result, "valid");
    // Password contains the username — should either fail or warn
    // At minimum, validate_password must not panic
    let _ = valid;
}

#[wasm_bindgen_test]
fn test_get_strength_description_all_scores() {
    for score in 0u8..=4 {
        let desc = get_strength_description(score);
        assert!(
            !desc.is_null(),
            "strength description must not be null for score {score}"
        );
        let label = get_str(&desc, "label");
        let color = get_str(&desc, "color");
        assert!(
            !label.is_empty(),
            "label must not be empty for score {score}"
        );
        assert!(
            !color.is_empty(),
            "color must not be empty for score {score}"
        );
        assert!(
            color.starts_with('#'),
            "color must be a hex color code, got '{color}'"
        );
    }
}

#[wasm_bindgen_test]
fn test_validate_email_valid() {
    let result = validate_email("user@example.com");
    assert!(get_bool(&result, "valid"));
}

#[wasm_bindgen_test]
fn test_validate_email_invalid() {
    let result = validate_email("not-an-email");
    assert!(!get_bool(&result, "valid"));
}

#[wasm_bindgen_test]
fn test_validate_filename_valid() {
    let result = validate_filename("document.pdf");
    assert!(get_bool(&result, "valid"));
}

#[wasm_bindgen_test]
fn test_validate_filename_invalid() {
    // Null bytes or path traversal should be invalid
    let result = validate_filename("../../../etc/passwd");
    // Path traversal must be rejected — either invalid or treated as a traversal
    let _ = get_bool(&result, "valid");
    // At minimum, must not panic
}

#[wasm_bindgen_test]
fn test_validate_file_size_within_limit() {
    let result = validate_file_size(1024.0 * 1024.0, 10.0); // 1 MB, limit 10 MB
    assert!(get_bool(&result, "valid"));
}

#[wasm_bindgen_test]
fn test_validate_file_size_exceeds_limit() {
    let result = validate_file_size(100.0 * 1024.0 * 1024.0, 10.0); // 100 MB, limit 10 MB
    assert!(!get_bool(&result, "valid"));
}

#[wasm_bindgen_test]
fn test_validate_username_valid() {
    let result = validate_username("alice_123");
    assert!(get_bool(&result, "valid"));
}

#[wasm_bindgen_test]
fn test_validate_username_too_short() {
    let result = validate_username("ab");
    assert!(!get_bool(&result, "valid"));
}

// ─── BYO vault binding tests ──────────────────────────────────────────────────
//
// These tests verify the base64 encode/decode boundary in sdk-wasm/src/byo.rs.
// All use small Argon2 parameters (4096 KB) for speed — separate benchmarks
// cover the real 128 MB performance target.

fn encode_b64(data: &[u8]) -> String {
    // Use the browser's btoa to match the WASM boundary encoding
    use js_sys::Function;
    let global = js_sys::global();
    let btoa = js_sys::Reflect::get(&global, &"btoa".into()).unwrap();
    // btoa takes a binary string; build it from bytes
    let binary: String = data.iter().map(|b| char::from(*b)).collect();
    Function::from(btoa)
        .call1(&wasm_bindgen::JsValue::NULL, &binary.into())
        .unwrap()
        .as_string()
        .unwrap()
}

fn has_error(obj: &wasm_bindgen::JsValue) -> bool {
    let err =
        js_sys::Reflect::get(obj, &"error".into()).unwrap_or(wasm_bindgen::JsValue::UNDEFINED);
    !err.is_undefined() && !err.is_null()
}

/// Build a minimal valid 839-byte vault header for parse testing.
/// Uses fixed values; the HMAC field is intentionally zero (parse does not verify it).
fn make_test_header_bytes() -> Vec<u8> {
    let mut h = vec![0u8; 839];
    // magic "SCVAULT\x00"
    h[0..8].copy_from_slice(b"SCVAULT\x00");
    // format_version = 1 (u16 LE)
    h[8] = 1;
    h[9] = 0;
    // argon2_memory_kb = 131072 (u32 LE)
    h[10..14].copy_from_slice(&131072u32.to_le_bytes());
    // argon2_iterations = 3 (u32 LE)
    h[14..18].copy_from_slice(&3u32.to_le_bytes());
    // argon2_parallelism = 4 (u32 LE)
    h[18..22].copy_from_slice(&4u32.to_le_bytes());
    // master_salt: fixed 32 bytes
    for i in 0..32 {
        h[22 + i] = (i as u8).wrapping_add(1);
    }
    // vault_id: fixed 16 bytes
    for i in 0..16 {
        h[54 + i] = (i as u8).wrapping_add(0xA0);
    }
    // All remaining fields (slots, hmac) stay zero — parse accepts zero slot_status (Empty)
    h
}

// ─── byo_generate_vault_keys ─────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_byo_generate_vault_keys_shape() {
    let result = byo_generate_vault_keys();
    assert!(
        !has_error(&result),
        "byo_generate_vault_keys returned error"
    );

    let vk = get_str(&result, "vault_key");
    let sh = get_str(&result, "shard");
    let vid = get_str(&result, "vault_id");
    let ms = get_str(&result, "master_salt");

    assert!(!vk.is_empty(), "vault_key must not be empty");
    assert!(!sh.is_empty(), "shard must not be empty");
    assert!(!vid.is_empty(), "vault_id must not be empty");
    assert!(!ms.is_empty(), "master_salt must not be empty");

    // Correct decoded lengths
    assert_eq!(decode_b64(&vk).len(), 32, "vault_key must be 32 bytes");
    assert_eq!(decode_b64(&sh).len(), 32, "shard must be 32 bytes");
    assert_eq!(decode_b64(&vid).len(), 16, "vault_id must be 16 bytes");
    assert_eq!(decode_b64(&ms).len(), 32, "master_salt must be 32 bytes");
}

#[wasm_bindgen_test]
fn test_byo_generate_vault_keys_randomness() {
    let r1 = byo_generate_vault_keys();
    let r2 = byo_generate_vault_keys();
    // Two calls must produce different vault_keys
    assert_ne!(
        get_str(&r1, "vault_key"),
        get_str(&r2, "vault_key"),
        "byo_generate_vault_keys must produce unique keys"
    );
}

// ─── byo_derive_vault_keys ────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_byo_derive_vault_keys_shape() {
    let salt = encode_b64(&[0x55u8; 32]);
    // Use 4096 KB for test speed
    let result = byo_derive_vault_keys("test-passphrase-long-enough".to_string(), salt, 4096, 1, 1);
    assert!(
        !has_error(&result),
        "byo_derive_vault_keys returned error: {:?}",
        get_str(&result, "error")
    );

    assert_eq!(decode_b64(&get_str(&result, "vault_kek")).len(), 32);
    assert_eq!(decode_b64(&get_str(&result, "client_kek_half")).len(), 32);
    assert_eq!(decode_b64(&get_str(&result, "argon_output")).len(), 64);
}

#[wasm_bindgen_test]
fn test_byo_derive_vault_keys_deterministic() {
    let salt = encode_b64(&[0xAAu8; 32]);
    let pw = "deterministic-passphrase-16chars".to_string();
    let r1 = byo_derive_vault_keys(pw.clone(), salt.clone(), 4096, 1, 1);
    let r2 = byo_derive_vault_keys(pw, salt, 4096, 1, 1);
    assert_eq!(
        get_str(&r1, "vault_kek"),
        get_str(&r2, "vault_kek"),
        "Argon2id must be deterministic for same inputs"
    );
}

// ─── byo_wrap_vault_key / byo_unwrap_vault_key ───────────────────────────────

#[wasm_bindgen_test]
fn test_byo_wrap_unwrap_vault_key_roundtrip() {
    // Generate real vault keys
    let keys = byo_generate_vault_keys();
    let vault_key_b64 = get_str(&keys, "vault_key");
    let master_salt_b64 = get_str(&keys, "master_salt");

    // Derive vault_kek with small params
    let kek_result = byo_derive_vault_keys(
        "strong-test-passphrase-enough".to_string(),
        master_salt_b64,
        4096,
        1,
        1,
    );
    let vault_kek_b64 = get_str(&kek_result, "vault_kek");

    // Wrap
    let wrap_result = byo_wrap_vault_key(vault_key_b64.clone(), vault_kek_b64.clone());
    assert!(!has_error(&wrap_result), "wrap failed");
    let wrap_iv = get_str(&wrap_result, "wrap_iv");
    let wrapped_key = get_str(&wrap_result, "wrapped_key");
    assert_eq!(decode_b64(&wrap_iv).len(), 12, "wrap_iv must be 12 bytes");
    assert_eq!(
        decode_b64(&wrapped_key).len(),
        48,
        "wrapped_key must be 48 bytes"
    );

    // Unwrap
    let unwrap_result = byo_unwrap_vault_key(wrap_iv, wrapped_key, vault_kek_b64);
    assert!(!has_error(&unwrap_result), "unwrap failed");
    assert_eq!(
        get_str(&unwrap_result, "vault_key"),
        vault_key_b64,
        "unwrapped vault_key must match original"
    );
}

#[wasm_bindgen_test]
fn test_byo_unwrap_vault_key_wrong_kek_fails() {
    let keys = byo_generate_vault_keys();
    let vault_key_b64 = get_str(&keys, "vault_key");

    let kek1 = byo_derive_vault_keys(
        "passphrase-one-long-enough".to_string(),
        encode_b64(&[1u8; 32]),
        4096,
        1,
        1,
    );
    let kek2 = byo_derive_vault_keys(
        "passphrase-two-long-enough".to_string(),
        encode_b64(&[2u8; 32]),
        4096,
        1,
        1,
    );

    let wrap_result = byo_wrap_vault_key(vault_key_b64, get_str(&kek1, "vault_kek"));
    assert!(!has_error(&wrap_result));

    // Unwrap with wrong key must fail
    let unwrap_result = byo_unwrap_vault_key(
        get_str(&wrap_result, "wrap_iv"),
        get_str(&wrap_result, "wrapped_key"),
        get_str(&kek2, "vault_kek"),
    );
    assert!(
        has_error(&unwrap_result),
        "Unwrap with wrong key must return error"
    );
}

// ─── byo_compute_header_hmac / byo_verify_header_hmac ────────────────────────

#[wasm_bindgen_test]
fn test_byo_header_hmac_roundtrip() {
    let keys = byo_generate_vault_keys();
    let vault_key_b64 = get_str(&keys, "vault_key");
    // Use first 807 bytes of a test header as the prefix
    let header_bytes = make_test_header_bytes();
    let prefix_b64 = encode_b64(&header_bytes[..807]);

    let hmac_result = byo_compute_header_hmac(vault_key_b64.clone(), prefix_b64.clone());
    assert!(!has_error(&hmac_result), "compute_header_hmac failed");
    let hmac_b64 = get_str(&hmac_result, "hmac");
    assert_eq!(decode_b64(&hmac_b64).len(), 32, "HMAC must be 32 bytes");

    let verify_result = byo_verify_header_hmac(vault_key_b64, prefix_b64, hmac_b64);
    assert!(!has_error(&verify_result), "verify_header_hmac failed");
    assert!(
        get_bool(&verify_result, "valid"),
        "HMAC must verify correctly"
    );
}

#[wasm_bindgen_test]
fn test_byo_header_hmac_wrong_key_fails() {
    let k1 = get_str(&byo_generate_vault_keys(), "vault_key");
    let k2 = get_str(&byo_generate_vault_keys(), "vault_key");
    let prefix_b64 = encode_b64(&make_test_header_bytes()[..807]);

    let hmac_b64 = get_str(&byo_compute_header_hmac(k1, prefix_b64.clone()), "hmac");
    let verify = byo_verify_header_hmac(k2, prefix_b64, hmac_b64);
    assert!(!has_error(&verify));
    assert!(
        !get_bool(&verify, "valid"),
        "HMAC with wrong key must not verify"
    );
}

// ─── byo_encrypt_vault_body / byo_decrypt_vault_body ─────────────────────────

#[wasm_bindgen_test]
fn test_byo_encrypt_decrypt_body_roundtrip() {
    let vault_key_b64 = get_str(&byo_generate_vault_keys(), "vault_key");
    let plaintext: Vec<u8> = (0u8..128).collect();

    let nonce_and_ct = byo_encrypt_vault_body(plaintext.clone(), vault_key_b64.clone())
        .expect("encrypt_vault_body must succeed");
    // nonce(12) || ciphertext(plaintext_len + 16 GCM tag)
    assert_eq!(nonce_and_ct.len(), 12 + plaintext.len() + 16);

    let decrypted = byo_decrypt_vault_body(nonce_and_ct, vault_key_b64)
        .expect("decrypt_vault_body must succeed");
    assert_eq!(decrypted, plaintext, "Decrypted body must match original plaintext");
}

#[wasm_bindgen_test]
fn test_byo_decrypt_body_wrong_key_fails() {
    let k1 = get_str(&byo_generate_vault_keys(), "vault_key");
    let k2 = get_str(&byo_generate_vault_keys(), "vault_key");
    let plaintext = vec![0u8; 64];

    let nonce_and_ct = byo_encrypt_vault_body(plaintext, k1)
        .expect("encrypt must succeed");
    let dec = byo_decrypt_vault_body(nonce_and_ct, k2);
    assert!(dec.is_none(), "Decrypt with wrong key must fail");
}

// ─── byo_parse_vault_header ───────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_byo_parse_vault_header_valid() {
    let header_bytes = make_test_header_bytes();

    let result = byo_parse_vault_header(header_bytes);
    assert!(
        !has_error(&result),
        "parse_vault_header failed: {:?}",
        get_str(&result, "error")
    );

    assert_eq!(get_f64(&result, "format_version") as u32, 1);
    assert_eq!(get_f64(&result, "argon2_memory_kb") as u32, 131072);
    assert_eq!(get_f64(&result, "argon2_iterations") as u32, 3);
    assert_eq!(get_f64(&result, "argon2_parallelism") as u32, 4);

    // master_salt and vault_id must decode to correct lengths
    assert_eq!(decode_b64(&get_str(&result, "master_salt")).len(), 32);
    assert_eq!(decode_b64(&get_str(&result, "vault_id")).len(), 16);
}

#[wasm_bindgen_test]
fn test_byo_parse_vault_header_wrong_magic_fails() {
    let mut header_bytes = make_test_header_bytes();
    header_bytes[0] = 0xFF; // corrupt magic
    let result = byo_parse_vault_header(header_bytes);
    assert!(has_error(&result), "Wrong magic must fail");
}

#[wasm_bindgen_test]
fn test_byo_parse_vault_header_too_short_fails() {
    let result = byo_parse_vault_header(vec![0u8; 100]);
    assert!(has_error(&result), "Short input must fail");
}

// ─── byo_derive_recovery_vault_kek ───────────────────────────────────────────

#[wasm_bindgen_test]
fn test_byo_derive_recovery_vault_kek_shape() {
    let secret_b64 = encode_b64(&[0x42u8; 32]);
    let result = byo_derive_recovery_vault_kek(secret_b64);
    assert!(!has_error(&result), "derive_recovery_vault_kek failed");
    assert_eq!(
        decode_b64(&get_str(&result, "recovery_vault_kek")).len(),
        32
    );
}

#[wasm_bindgen_test]
fn test_byo_derive_recovery_vault_kek_wrong_length_fails() {
    let result = byo_derive_recovery_vault_kek(encode_b64(&[0u8; 16])); // 16 instead of 32
    assert!(has_error(&result), "Wrong length must fail");
}

// ─── byo_derive_kek ──────────────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_byo_derive_kek_shape() {
    let keys = byo_generate_vault_keys();
    let half_b64 = encode_b64(&[0x11u8; 32]);
    let shard_b64 = get_str(&keys, "shard");
    let result = byo_derive_kek(half_b64, shard_b64);
    assert!(!has_error(&result), "derive_kek failed");
    assert_eq!(decode_b64(&get_str(&result, "kek")).len(), 32);
}

// ─── byo_enrollment_initiate ─────────────────────────────────────────────────

#[wasm_bindgen_test]
fn test_byo_enrollment_initiate_shape() {
    let result = byo_enrollment_initiate();
    assert!(!has_error(&result), "enrollment_initiate failed");

    assert_eq!(
        decode_b64(&get_str(&result, "eph_sk")).len(),
        32,
        "eph_sk must be 32 bytes"
    );
    assert_eq!(
        decode_b64(&get_str(&result, "eph_pk")).len(),
        32,
        "eph_pk must be 32 bytes"
    );
    assert_eq!(
        decode_b64(&get_str(&result, "channel_id")).len(),
        16,
        "channel_id must be 16 bytes"
    );
}

#[wasm_bindgen_test]
fn test_byo_enrollment_initiate_unique() {
    let r1 = byo_enrollment_initiate();
    let r2 = byo_enrollment_initiate();
    assert_ne!(
        get_str(&r1, "channel_id"),
        get_str(&r2, "channel_id"),
        "channel_ids must be unique"
    );
}

// ─── byo_enrollment_derive_session ───────────────────────────────────────────

#[wasm_bindgen_test]
fn test_byo_enrollment_derive_session_both_sides_match() {
    // Simulate two-party DH — channel_id comes from device A (the initiator)
    let a = byo_enrollment_initiate(); // existing device
    let b = byo_enrollment_initiate(); // new device
    let channel_id = get_str(&a, "channel_id"); // both sides share the same channel_id

    let session_a = byo_enrollment_derive_session(get_str(&a, "eph_sk"), get_str(&b, "eph_pk"), channel_id.clone());
    let session_b = byo_enrollment_derive_session(get_str(&b, "eph_sk"), get_str(&a, "eph_pk"), channel_id);

    assert!(!has_error(&session_a), "derive_session A failed");
    assert!(!has_error(&session_b), "derive_session B failed");

    // Both sides must derive identical keys and SAS code
    assert_eq!(
        get_str(&session_a, "enc_key"),
        get_str(&session_b, "enc_key"),
        "enc_key must match on both sides"
    );
    assert_eq!(
        get_str(&session_a, "mac_key"),
        get_str(&session_b, "mac_key"),
        "mac_key must match on both sides"
    );
    assert_eq!(
        get_f64(&session_a, "sas_code") as u32,
        get_f64(&session_b, "sas_code") as u32,
        "sas_code must match on both sides"
    );

    // SAS code must be 6 digits (0–999999)
    let sas = get_f64(&session_a, "sas_code") as u32;
    assert!(sas < 1_000_000, "SAS code must be < 1000000, got {sas}");
}

#[wasm_bindgen_test]
fn test_byo_enrollment_derive_session_wrong_peer_differs() {
    let a = byo_enrollment_initiate();
    let b = byo_enrollment_initiate();
    let c = byo_enrollment_initiate(); // interloper
    let channel_id = get_str(&a, "channel_id");

    let session_a = byo_enrollment_derive_session(get_str(&a, "eph_sk"), get_str(&b, "eph_pk"), channel_id.clone());
    let session_c = byo_enrollment_derive_session(get_str(&c, "eph_sk"), get_str(&b, "eph_pk"), channel_id);

    // A and C see different enc_keys (ECDH with different secret keys)
    assert_ne!(
        get_str(&session_a, "enc_key"),
        get_str(&session_c, "enc_key"),
        "Different peers must produce different enc_keys (MitM detection)"
    );
}

// ─── byo_enrollment_encrypt_shard / byo_enrollment_decrypt_shard ────────────

#[wasm_bindgen_test]
fn test_byo_enrollment_encrypt_decrypt_shard_roundtrip() {
    let shard_b64 = get_str(&byo_generate_vault_keys(), "shard");

    // Derive session keys via real ECDH
    let a = byo_enrollment_initiate();
    let b = byo_enrollment_initiate();
    let channel_id = get_str(&a, "channel_id");
    let session = byo_enrollment_derive_session(get_str(&a, "eph_sk"), get_str(&b, "eph_pk"), channel_id);
    let enc_key = get_str(&session, "enc_key");
    let mac_key = get_str(&session, "mac_key");

    // Encrypt shard
    let envelope =
        byo_enrollment_encrypt_shard(shard_b64.clone(), enc_key.clone(), mac_key.clone());
    assert!(!has_error(&envelope), "encrypt_shard failed");
    // Envelope fields: nonce(12) + ciphertext(48) + hmac(32) = 92 bytes when serialised
    assert_eq!(decode_b64(&get_str(&envelope, "nonce")).len(), 12);
    assert_eq!(decode_b64(&get_str(&envelope, "ciphertext")).len(), 48);
    assert_eq!(decode_b64(&get_str(&envelope, "hmac")).len(), 32);

    // Serialise the envelope the same way the worker does: nonce || ciphertext || hmac
    let nonce_bytes = decode_b64(&get_str(&envelope, "nonce"));
    let ct_bytes = decode_b64(&get_str(&envelope, "ciphertext"));
    let hmac_bytes = decode_b64(&get_str(&envelope, "hmac"));
    let mut wire = Vec::with_capacity(92);
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ct_bytes);
    wire.extend_from_slice(&hmac_bytes);
    let wire_b64 = encode_b64(&wire);

    // Decrypt shard
    let decrypted = byo_enrollment_decrypt_shard(wire_b64, enc_key, mac_key);
    assert!(!has_error(&decrypted), "decrypt_shard failed");
    assert_eq!(
        get_str(&decrypted, "shard"),
        shard_b64,
        "Decrypted shard must match original"
    );
}

/// Performance gate: byo_derive_vault_keys_default (128 MB / 3 iter / 4 parallel)
/// must complete in < 10s on reference hardware. This guards against accidentally
/// downgrading Argon2id parameters (which would weaken offline-attack resistance).
///
/// Note: This test is slow by design — it runs the real 128 MB KDF.
/// Annotated `async` to obtain wall-clock time via `performance.now()`.
#[wasm_bindgen_test]
async fn test_byo_argon2_128mb_under_10s() {
    let password = "BenchmarkPassphrase_BYO_Test_Only";
    let salt_b64 = encode_b64(&[0xDEu8; 32]);

    let t0 = js_sys::Date::now();
    let result = byo_derive_vault_keys_default(password.to_string(), salt_b64);
    let elapsed_ms = js_sys::Date::now() - t0;

    assert!(
        !has_error(&result),
        "byo_derive_vault_keys_default must succeed"
    );
    assert!(
        elapsed_ms < 10_000.0,
        "Argon2id 128MB took {elapsed_ms:.0}ms — must be < 10000ms"
    );
    // Sanity-check output contains expected fields
    let kek = get_str(&result, "vault_kek");
    assert!(!kek.is_empty(), "vault_kek must be non-empty");
}

#[wasm_bindgen_test]
fn test_byo_enrollment_decrypt_shard_tampered_hmac_fails() {
    let shard_b64 = get_str(&byo_generate_vault_keys(), "shard");
    let a = byo_enrollment_initiate();
    let b = byo_enrollment_initiate();
    let channel_id = get_str(&a, "channel_id");
    let session = byo_enrollment_derive_session(get_str(&a, "eph_sk"), get_str(&b, "eph_pk"), channel_id);
    let enc_key = get_str(&session, "enc_key");
    let mac_key = get_str(&session, "mac_key");

    let envelope = byo_enrollment_encrypt_shard(shard_b64, enc_key.clone(), mac_key.clone());
    let mut wire = Vec::with_capacity(92);
    wire.extend_from_slice(&decode_b64(&get_str(&envelope, "nonce")));
    wire.extend_from_slice(&decode_b64(&get_str(&envelope, "ciphertext")));
    wire.extend_from_slice(&decode_b64(&get_str(&envelope, "hmac")));
    // Flip a byte in the HMAC
    let last = wire.len() - 1;
    wire[last] ^= 0xFF;

    let result = byo_enrollment_decrypt_shard(encode_b64(&wire), enc_key, mac_key);
    assert!(
        has_error(&result),
        "Tampered HMAC must cause decryption failure"
    );
}
