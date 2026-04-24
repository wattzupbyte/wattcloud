//! Generate deterministic test vectors for compatibility_vectors.rs.
//! Run once with: cargo run --example gen_vectors
//! Copy the output into compatibility_vectors.rs as `const` values.
//!
//! This is a one-shot generator binary — unwrap() is appropriate because
//! any error invalidates the entire output batch; there is no graceful path.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sdk_core::crypto::filename::{decrypt_filename, encrypt_filename};
use sdk_core::crypto::hashing::{blake2b_256, hmac_sha256, sha256};
use sdk_core::crypto::kdf::{argon2id_derive, derive_auth_hash, derive_client_kek_half};
use sdk_core::crypto::symmetric::{aes_gcm_decrypt, aes_gcm_encrypt_with_nonce};
use sdk_core::crypto::zeroize_utils::{Nonce12, SymmetricKey};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    // ── SHA-256 ──────────────────────────────────────────────────────────────
    let sha_out = sha256(b"abc");
    println!("SHA256_ABC = \"{}\"", hex(&sha_out));

    // ── BLAKE2b-256 ──────────────────────────────────────────────────────────
    let b2_empty = blake2b_256(b"");
    println!("BLAKE2B_256_EMPTY = \"{}\"", hex(&b2_empty));

    let b2_abc = blake2b_256(b"abc");
    println!("BLAKE2B_256_ABC = \"{}\"", hex(&b2_abc));

    // ── HMAC-SHA256 ──────────────────────────────────────────────────────────
    // RFC 4231 Test Case 1: key = 0x0b*20, data = "Hi There"
    let key_tc1 = [0x0bu8; 20];
    let data_tc1 = b"Hi There";
    let hmac_out = hmac_sha256(&key_tc1, data_tc1).unwrap();
    println!("HMAC_SHA256_RFC4231_TC1 = \"{}\"", hex(&hmac_out));

    // ── AES-256-GCM ──────────────────────────────────────────────────────────
    // Fixed key, nonce, plaintext
    let aes_key = SymmetricKey::new([0x42u8; 32]);
    let aes_nonce = Nonce12::new([0x24u8; 12]);
    let plaintext = b"test plaintext for aes-gcm";
    let ct = aes_gcm_encrypt_with_nonce(plaintext, &aes_key, &aes_nonce).unwrap();
    println!("AES_GCM_KEY = \"{}\"", hex(&[0x42u8; 32]));
    println!("AES_GCM_NONCE = \"{}\"", hex(&[0x24u8; 12]));
    println!("AES_GCM_PLAINTEXT = \"{}\"", hex(plaintext));
    println!("AES_GCM_CIPHERTEXT = \"{}\"", hex(&ct));

    // Verify roundtrip
    let pt = aes_gcm_decrypt(&ct, &aes_nonce, &aes_key).unwrap();
    assert_eq!(pt, plaintext);
    println!("AES_GCM_ROUNDTRIP_OK = true");

    // ── Argon2id ─────────────────────────────────────────────────────────────
    // Fixed password + salt (32 bytes)
    let password = b"test_password";
    let salt = [0x42u8; 32];
    let argon_out = argon2id_derive(password, &salt).unwrap();
    println!("ARGON2ID_PASSWORD = \"test_password\"");
    println!("ARGON2ID_SALT = \"{}\"", hex(&salt));
    println!("ARGON2ID_OUTPUT = \"{}\"", hex(argon_out.as_bytes()));

    // ── HKDF ─────────────────────────────────────────────────────────────────
    let auth_hash = derive_auth_hash(&argon_out).unwrap();
    println!("AUTH_HASH = \"{}\"", hex(&auth_hash));

    let kek_half = derive_client_kek_half(&argon_out).unwrap();
    println!("CLIENT_KEK_HALF = \"{}\"", hex(kek_half.as_bytes()));

    // ── Filename encryption (SIV — deterministic) ─────────────────────────────
    let fname_key = SymmetricKey::new([0xABu8; 32]);
    let enc = encrypt_filename("test_file.txt", &fname_key).unwrap();
    println!("FILENAME_KEY = \"{}\"", hex(&[0xABu8; 32]));
    println!("FILENAME_PLAINTEXT = \"test_file.txt\"");
    println!("FILENAME_CIPHERTEXT = \"{}\"", hex(&enc));

    // Verify roundtrip
    let dec = decrypt_filename(&enc, &fname_key).unwrap();
    assert_eq!(dec, "test_file.txt");
    println!("FILENAME_ROUNDTRIP_OK = true");

    println!("\nAll vectors generated successfully.");
}
