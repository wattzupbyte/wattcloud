//! Cross-implementation compatibility vectors for sdk-core.
//!
//! These test vectors were generated from sdk-core with fixed inputs and
//! serve as regression baselines. Any change to the output of a core crypto
//! function MUST be a conscious, documented decision — not an accidental
//! implementation change.
//!
//! Vectors for standardized algorithms (BLAKE2b-256, HMAC-SHA256) are also
//! checked against their respective RFCs.

#[allow(clippy::unwrap_used, clippy::expect_used)]
mod vectors {
    use sdk_core::crypto::filename::{decrypt_filename, encrypt_filename};
    use sdk_core::crypto::hashing::{blake2b_256, hmac_sha256, sha256};
    use sdk_core::crypto::kdf::{argon2id_derive, derive_auth_hash, derive_client_kek_half};
    use sdk_core::crypto::master_secret::{generate_master_secret_v5, verify_master_secret};
    use sdk_core::crypto::pqc::generate_hybrid_keypair;
    use sdk_core::crypto::symmetric::{aes_gcm_decrypt, aes_gcm_encrypt_with_nonce};
    use sdk_core::crypto::wire_format::{decrypt_file_v7, encrypt_file_v7};
    use sdk_core::crypto::zeroize_utils::{Nonce12, SymmetricKey};

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── SHA-256 ───────────────────────────────────────────────────────────────

    /// SHA-256 of the empty string — NIST FIPS 180-4 known vector.
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// SHA-256 of "abc" — regression vector generated from sdk-core sha2 crate.
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn sha256_empty_nist_vector() {
        let hash = sha256(b"");
        assert_eq!(hash.to_vec(), from_hex(SHA256_EMPTY));
    }

    #[test]
    fn sha256_abc_regression() {
        let hash = sha256(b"abc");
        assert_eq!(hash.to_vec(), from_hex(SHA256_ABC));
    }

    // ── BLAKE2b-256 ───────────────────────────────────────────────────────────

    /// BLAKE2b-256("") — RFC 7693 known vector.
    const BLAKE2B_256_EMPTY: &str =
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

    /// BLAKE2b-256("abc") — RFC 7693 known vector.
    const BLAKE2B_256_ABC: &str =
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319";

    #[test]
    fn blake2b_256_empty_rfc7693_vector() {
        let hash = blake2b_256(b"");
        assert_eq!(hash.to_vec(), from_hex(BLAKE2B_256_EMPTY));
    }

    #[test]
    fn blake2b_256_abc_rfc7693_vector() {
        let hash = blake2b_256(b"abc");
        assert_eq!(hash.to_vec(), from_hex(BLAKE2B_256_ABC));
    }

    // ── HMAC-SHA256 ───────────────────────────────────────────────────────────

    /// HMAC-SHA256 RFC 4231 Test Case 1.
    /// Key: 0x0b × 20, Data: "Hi There"
    /// Expected: b0344c61...
    const HMAC_RFC4231_TC1: &str =
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

    #[test]
    fn hmac_sha256_rfc4231_tc1() {
        let key = [0x0bu8; 20];
        let result = hmac_sha256(&key, b"Hi There").unwrap();
        assert_eq!(result.to_vec(), from_hex(HMAC_RFC4231_TC1));
    }

    // ── AES-256-GCM ───────────────────────────────────────────────────────────

    /// Fixed key (all 0x42), fixed nonce (all 0x24), plaintext "test plaintext for aes-gcm".
    /// Ciphertext is a regression vector; any change indicates a crypto change.
    const AES_GCM_CIPHERTEXT: &str =
        "61f4b735c9b6aa5f4f8656cfc546b3c003891311d3d87d0ad3c9c5d78cd22e21d26f6f54f45f24755ebf";

    #[test]
    fn aes_gcm_regression_vector() {
        let key = SymmetricKey::new([0x42u8; 32]);
        let nonce = Nonce12::new([0x24u8; 12]);
        let plaintext = b"test plaintext for aes-gcm";

        let ct = aes_gcm_encrypt_with_nonce(plaintext, &key, &nonce).unwrap();
        assert_eq!(ct, from_hex(AES_GCM_CIPHERTEXT));

        let pt = aes_gcm_decrypt(&ct, &nonce, &key).unwrap();
        assert_eq!(pt, plaintext);
    }

    // ── Argon2id ─────────────────────────────────────────────────────────────

    /// Argon2id with params m=65536 KiB, t=3, p=4.
    /// Input: "test_password", salt = 0x42 × 32.
    /// Any change here means the KDF parameters or implementation changed —
    /// existing users' derived keys would break.
    const ARGON2ID_OUTPUT: &str = concat!(
        "ed61e6768009314abe7a3a95d7cef58f",
        "aea7497889ffb744a80e712a90b79f16",
        "9c33d95545e9fd0dce914cffe5a5f678",
        "15f1842454bb9fbfd7c0a5fd91907688",
    );

    const AUTH_HASH: &str = "35436809e6eb3fd3099bcad13c38c81d11046899251d82dee931405df26f7815";
    const CLIENT_KEK_HALF: &str =
        "dbb322b5536ae4b12881497908c37875c290e249d5a60da218d06cecedb9948b";

    #[test]
    fn argon2id_regression_vector() {
        let salt = [0x42u8; 32];
        let out = argon2id_derive(b"test_password", &salt).unwrap();
        assert_eq!(out.as_bytes().to_vec(), from_hex(ARGON2ID_OUTPUT));
    }

    #[test]
    fn auth_hash_regression_vector() {
        let salt = [0x42u8; 32];
        let out = argon2id_derive(b"test_password", &salt).unwrap();
        let hash = derive_auth_hash(&out).unwrap();
        assert_eq!(hash.to_vec(), from_hex(AUTH_HASH));
    }

    #[test]
    fn client_kek_half_regression_vector() {
        let salt = [0x42u8; 32];
        let out = argon2id_derive(b"test_password", &salt).unwrap();
        let kek = derive_client_kek_half(&out).unwrap();
        assert_eq!(kek.as_bytes().to_vec(), from_hex(CLIENT_KEK_HALF));
    }

    // ── Filename encryption (SIV — deterministic) ────────────────────────────

    /// Filename "test_file.txt" encrypted with key = 0xAB × 32.
    /// SIV property: same input always produces same ciphertext.
    const FILENAME_CIPHERTEXT: &str =
        "8a900f1a204372b34ef38dfa3d6fc6ecf876ddedffd53895ad0db4d6d6cc696b79770fa9fb87d32497";

    #[test]
    fn filename_encryption_regression_vector() {
        let key = SymmetricKey::new([0xABu8; 32]);
        let enc = encrypt_filename("test_file.txt", &key).unwrap();
        assert_eq!(enc, from_hex(FILENAME_CIPHERTEXT));
    }

    #[test]
    fn filename_decryption_regression_vector() {
        let key = SymmetricKey::new([0xABu8; 32]);
        let enc = from_hex(FILENAME_CIPHERTEXT);
        let dec = decrypt_filename(&enc, &key).unwrap();
        assert_eq!(dec, "test_file.txt");
    }

    // ── V7 file format — roundtrip with fresh keypair ─────────────────────────

    /// Full V7 encrypt→decrypt roundtrip. Cannot hardcode a fixed ciphertext here
    /// because V7 uses ephemeral keys. Instead we verify:
    ///   1. encrypt_file_v7 succeeds
    ///   2. decrypt_file_v7 with the same keypair recovers plaintext
    ///   3. decrypt_file_v7 with a different keypair fails
    #[test]
    fn v7_format_roundtrip_with_known_plaintext() {
        let keypair = generate_hybrid_keypair().unwrap();
        let plaintext = b"The quick brown fox jumps over the lazy dog";

        let blob = encrypt_file_v7(
            &keypair.mlkem_public_key,
            &keypair.x25519_public_key,
            &[plaintext.as_ref()],
        )
        .unwrap();

        // Must be substantially larger than plaintext (header + KEM material + tag)
        assert!(blob.len() > plaintext.len() + 100);

        let recovered =
            decrypt_file_v7(&blob, &keypair.mlkem_secret_key, &keypair.x25519_secret_key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn v7_wrong_keypair_decryption_fails() {
        let keypair1 = generate_hybrid_keypair().unwrap();
        let keypair2 = generate_hybrid_keypair().unwrap();

        let blob = encrypt_file_v7(
            &keypair1.mlkem_public_key,
            &keypair1.x25519_public_key,
            &[b"secret data"],
        )
        .unwrap();

        let result = decrypt_file_v7(
            &blob,
            &keypair2.mlkem_secret_key,
            &keypair2.x25519_secret_key,
        );
        assert!(result.is_err());
    }

    // ── Master secret V5 ─────────────────────────────────────────────────────

    #[test]
    fn master_secret_v5_format() {
        let ms = generate_master_secret_v5().unwrap();
        // 37 bytes: version(1) + secret(32) + checksum(4)
        assert_eq!(ms.as_bytes().len(), 37);
        // Version byte must be 0x05
        assert_eq!(ms.as_bytes()[0], 0x05);
        // verify_master_secret must accept its own output
        let valid = verify_master_secret(ms.as_bytes()).unwrap();
        assert!(valid);
    }

    #[test]
    fn master_secret_tampered_checksum_rejected() {
        let ms = generate_master_secret_v5().unwrap();
        let mut bytes = ms.as_bytes().to_vec();
        // Corrupt the checksum (last 4 bytes)
        bytes[33] ^= 0xFF;
        let valid = verify_master_secret(&bytes).unwrap();
        assert!(!valid);
    }
}
