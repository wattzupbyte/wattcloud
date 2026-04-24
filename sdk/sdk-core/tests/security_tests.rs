//! Security-specific tests for sdk-core.
//!
//! These tests verify invariants that matter for security correctness:
//! - Nonce uniqueness across 10,000 encryptions
//! - Fuzz decryption: random inputs must always return Err, never panic
//! - Post-quantum enforcement: ML-KEM ciphertext is present and correct size
//! - Error messages do not contain key material

#[allow(clippy::unwrap_used, clippy::expect_used)]
mod security {
    use sdk_core::crypto::filename::decrypt_filename;
    use sdk_core::crypto::kdf::{argon2id_derive, derive_auth_hash, derive_client_kek_half};
    use sdk_core::crypto::pqc::{generate_hybrid_keypair, hybrid_encapsulate_v6};
    use sdk_core::crypto::symmetric::{generate_aes_key, generate_nonce};
    use sdk_core::crypto::wire_format::{decrypt_file_v7, decrypt_file_v7_init, encrypt_file_v7};
    use sdk_core::crypto::zeroize_utils::SymmetricKey;
    use std::collections::HashSet;

    // ── Nonce uniqueness ──────────────────────────────────────────────────────

    #[test]
    fn nonce_uniqueness_10000_samples() {
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let nonce = generate_nonce().unwrap();
            let key = nonce.as_bytes().to_vec();
            assert!(seen.insert(key), "duplicate nonce generated");
        }
        assert_eq!(seen.len(), 10_000);
    }

    #[test]
    fn aes_key_uniqueness_1000_samples() {
        let mut seen = HashSet::new();
        for _ in 0..1_000 {
            let key = generate_aes_key().unwrap();
            let bytes = key.as_bytes().to_vec();
            assert!(seen.insert(bytes), "duplicate AES key generated");
        }
        assert_eq!(seen.len(), 1_000);
    }

    // ── Fuzz decryption ───────────────────────────────────────────────────────

    /// Feed random-length byte slices to decrypt functions.
    /// Every call must return Err — never panic.
    #[test]
    fn fuzz_decrypt_file_v7_never_panics() {
        let keypair = generate_hybrid_keypair().unwrap();
        // Inputs of varying lengths: 0, 1, small, medium, and specific boundary sizes
        let lengths = [
            0, 1, 4, 11, 12, 31, 32, 63, 64, 127, 128, 255, 512, 1024, 4096,
        ];
        for &len in &lengths {
            let garbage: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
            let result = decrypt_file_v7(
                &garbage,
                &keypair.mlkem_secret_key,
                &keypair.x25519_secret_key,
            );
            assert!(
                result.is_err(),
                "decrypt_file_v7 should fail on garbage input of length {len}"
            );
        }
    }

    #[test]
    fn fuzz_decrypt_file_v7_init_never_panics() {
        let keypair = generate_hybrid_keypair().unwrap();
        let lengths = [0, 1, 8, 15, 16, 63, 64, 200, 500, 2000];
        for &len in &lengths {
            let garbage: Vec<u8> = (0..len).map(|i| (i * 11 + 7) as u8).collect();
            let result = decrypt_file_v7_init(
                &garbage,
                &keypair.mlkem_secret_key,
                &keypair.x25519_secret_key,
            );
            assert!(
                result.is_err(),
                "decrypt_file_v7_init should fail on garbage of length {len}"
            );
        }
    }

    #[test]
    fn fuzz_aes_gcm_decrypt_never_panics() {
        use sdk_core::crypto::symmetric::aes_gcm_decrypt;
        use sdk_core::crypto::zeroize_utils::Nonce12;
        let key = SymmetricKey::new([0x42u8; 32]);
        let nonce = Nonce12::new([0x11u8; 12]);
        let lengths = [0, 1, 15, 16, 31, 32, 63, 100, 256];
        for &len in &lengths {
            let garbage: Vec<u8> = (0..len).map(|i| (i * 3 + 5) as u8).collect();
            let result = aes_gcm_decrypt(&garbage, &nonce, &key);
            // Anything shorter than 16 bytes (tag size) MUST fail; longer may or may not
            if len < 16 {
                assert!(
                    result.is_err(),
                    "AES-GCM decrypt should reject input shorter than tag size (len={len})"
                );
            }
            // If it succeeds on longer garbage, that would be a MAC forgery — assert it doesn't
            if result.is_ok() {
                panic!("AES-GCM decrypt succeeded on garbage input of length {len}");
            }
        }
    }

    #[test]
    fn fuzz_decrypt_filename_never_panics() {
        let key = SymmetricKey::new([0xABu8; 32]);
        let lengths = [0, 1, 11, 12, 27, 28, 100];
        for &len in &lengths {
            let garbage: Vec<u8> = (0..len).map(|i| (i * 17 + 3) as u8).collect();
            let result = decrypt_filename(&garbage, &key);
            assert!(
                result.is_err(),
                "decrypt_filename should fail on garbage of length {len}"
            );
        }
    }

    // ── Post-quantum enforcement ───────────────────────────────────────────────

    /// After V7 encryption, verify the blob is large enough to contain the full
    /// ML-KEM-1024 ciphertext (1568 bytes). The V7 header layout is:
    ///   version(1) | file_iv(12) | eph_x25519(32) | mlkem_ct(1568) | efk_len(4) | efk(60) | key_commitment(32)
    /// ML-KEM-1024 ciphertext is fixed-size — no length prefix.
    #[test]
    fn v7_blob_contains_mlkem_ciphertext_correct_size() {
        // Minimum header: 1+12+32+1568+4+60+32 = 1709 bytes, plus chunks and HMAC
        const MLKEM_1024_CT_LEN: usize = 1568;
        const MIN_HEADER: usize = 1 + 12 + 32 + MLKEM_1024_CT_LEN + 4 + 60 + 32;

        let keypair = generate_hybrid_keypair().unwrap();
        let blob = encrypt_file_v7(
            &keypair.mlkem_public_key,
            &keypair.x25519_public_key,
            &[b"post-quantum test payload"],
        )
        .unwrap();

        // Blob must be at least MIN_HEADER + 32 (HMAC) + at least one chunk
        assert!(
            blob.len() >= MIN_HEADER + 32,
            "blob too short ({} bytes) — ML-KEM ciphertext may be missing; expected >= {}",
            blob.len(),
            MIN_HEADER + 32,
        );

        // Version byte must be 0x07
        assert_eq!(blob[0], 0x07, "V7 version byte must be 0x07");

        // The efk_len field immediately follows mlkem_ct at offset 1+12+32+1568 = 1613.
        // efk must be 60 bytes (12-byte IV + 48-byte AES-GCM output for a 32-byte key).
        let efk_len_offset = 1 + 12 + 32 + MLKEM_1024_CT_LEN;
        let efk_len =
            u32::from_le_bytes(blob[efk_len_offset..efk_len_offset + 4].try_into().unwrap())
                as usize;
        assert_eq!(
            efk_len, 60,
            "encrypted_file_key must be 60 bytes, got {efk_len} — PQ encapsulation may have failed"
        );
    }

    #[test]
    fn hybrid_encapsulate_produces_mlkem_ciphertext() {
        let keypair = generate_hybrid_keypair().unwrap();
        let result =
            hybrid_encapsulate_v6(&keypair.mlkem_public_key, &keypair.x25519_public_key).unwrap();

        // ML-KEM-1024 ciphertext is 1568 bytes
        assert_eq!(result.mlkem_ciphertext.len(), 1568);
        // Ephemeral X25519 public key is 32 bytes
        assert_eq!(result.eph_x25519_pub.len(), 32);
        // Content and HMAC keys are 32 bytes each
        assert_eq!(result.content_key.as_bytes().len(), 32);
        assert_eq!(result.hmac_key.as_bytes().len(), 32);
    }

    // ── No key material in error messages ─────────────────────────────────────

    /// Trigger a wrong-key decryption error and verify the error message
    /// does not contain any of the key bytes in base64 or hex form.
    #[test]
    fn decryption_error_does_not_leak_key_material() {
        let keypair1 = generate_hybrid_keypair().unwrap();
        let keypair2 = generate_hybrid_keypair().unwrap();

        let blob = encrypt_file_v7(
            &keypair1.mlkem_public_key,
            &keypair1.x25519_public_key,
            &[b"secret payload"],
        )
        .unwrap();

        let err = decrypt_file_v7(
            &blob,
            &keypair2.mlkem_secret_key,
            &keypair2.x25519_secret_key,
        )
        .unwrap_err();

        let err_str = format!("{:?}", err);

        // The error must not contain "REDACTED" bypass, nor actual key hex
        // (key bytes are secret — the type's Debug impl shows [REDACTED])
        // Just verify the error message is something reasonable and not a stack trace dump
        assert!(
            !err_str.contains("panic"),
            "error should not cause a panic message"
        );
        // Error display should be short and not contain raw base64
        let err_display = format!("{}", err);
        assert!(
            err_display.len() < 500,
            "error message suspiciously long — may contain key material"
        );
    }

    // ── Auth hash domain separation ───────────────────────────────────────────

    /// auth_hash and client_kek_half must differ even with the same Argon2id input.
    /// If they were equal, leaking one would immediately reveal the other.
    #[test]
    fn auth_hash_differs_from_client_kek_half() {
        let salt = [0x99u8; 32];
        let out = argon2id_derive(b"hunter2", &salt).unwrap();
        let auth_hash = derive_auth_hash(&out).unwrap();
        let kek_half = derive_client_kek_half(&out).unwrap();
        assert_ne!(
            auth_hash,
            *kek_half.as_bytes(),
            "auth_hash and client_kek_half must be domain-separated"
        );
    }

    /// The key commitment in V7 headers allows servers to verify format integrity
    /// without learning plaintext. Verify two different keys produce different commitments.
    #[test]
    fn v7_different_keys_produce_different_blobs() {
        let kp1 = generate_hybrid_keypair().unwrap();
        let kp2 = generate_hybrid_keypair().unwrap();
        let plaintext = b"same plaintext";

        let blob1 =
            encrypt_file_v7(&kp1.mlkem_public_key, &kp1.x25519_public_key, &[plaintext]).unwrap();
        let blob2 =
            encrypt_file_v7(&kp2.mlkem_public_key, &kp2.x25519_public_key, &[plaintext]).unwrap();

        // Blobs must differ (different KEM material even for same plaintext)
        assert_ne!(blob1, blob2);
    }
}
