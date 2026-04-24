// Domain separation strings and format constants for all cryptographic operations.
// All info strings must be byte literals so they can be used with HKDF expand.

pub const V6: &[u8] = b"SecureCloud v6";
pub const MLKEM_SEED_V5: &[u8] = b"SecureCloud ML-KEM-1024 Seed v2";
pub const MLKEM_SEED_V2: &[u8] = b"SecureCloud ML-KEM-1024 Seed";
pub const X25519_SEED: &[u8] = b"SecureCloud X25519 Seed";
pub const FILENAME_V1: &[u8] = b"SecureCloud Filename v1";
pub const AUTH_V1: &[u8] = b"SecureCloud Auth v1";
pub const ENCRYPTION_V1: &[u8] = b"SecureCloud Encryption v1";
pub const KEK_HALF_V2: &[u8] = b"SecureCloud KEKHalf v2";
pub const KEK_V2: &[u8] = b"SecureCloud KEKv2";
pub const RECOVERY_KEK_V1: &[u8] = b"SecureCloud RecoveryKEK v1";
pub const CHUNK_HMAC_V1: &[u8] = b"chunk-hmac-v1";

pub const MASTER_SECRET_V2: u8 = 0x02;
pub const MASTER_SECRET_V5: u8 = 0x05;
pub const MASTER_SECRET_SIZE: usize = 37;

pub const FILE_FORMAT_V7: u8 = 0x07;
// 1(ver)+12(iv)+32(eph_x25519)+1568(mlkem_ct)+4(efk_len)+60(efk)+32(commitment)
pub const V7_HEADER_MIN: usize = 1709;
/// Per-frame wire overhead: 4 (chunk_len LE u32) + 12 (nonce) + 16 (GCM tag).
pub const V7_FRAME_OVERHEAD: usize = 32;
/// HMAC footer appended after the last chunk (32-byte HMAC-SHA256 output).
pub const V7_FOOTER_LEN: usize = 32;
/// Recommended plaintext chunk size for V7 streaming encryption (512 KiB).
pub const V7_ENCRYPT_CHUNK_SIZE: usize = 512 * 1024;

// ─── BYO vault format ────────────────────────────────────────────────────────
// Domain separation strings for BYO-specific key derivation.
// KEK_HALF_V2 and KEK_V2 are reused from managed mode — same derivation purpose,
// different IKM (BYO uses 128MB Argon2id, managed uses 64MB; plus different shard source).
pub const BYO_VAULT_KEK_V1: &[u8] = b"SecureCloud BYO VaultKEK v1";
pub const BYO_RECOVERY_VAULT_KEK_V1: &[u8] = b"SecureCloud BYO RecoveryVaultKEK v1";

// Vault file format constants.
//
// Format v2 layout (1227 bytes fixed header):
//   [0..8]     magic "SCVAULT\x00"
//   [8..10]    format_version (u16 LE) = 2
//   [10..14]   argon2_memory_kb (u32 LE)
//   [14..18]   argon2_iterations (u32 LE)
//   [18..22]   argon2_parallelism (u32 LE)
//   [22..54]   master_salt (32 bytes)
//   [54..70]   vault_id (16 bytes)
//   [70..82]   pass_wrap_iv (12 bytes)
//   [82..130]  pass_wrapped_vault_key (48 bytes)
//   [130..142] recovery_wrap_iv (12 bytes)
//   [142..190] recovery_wrapped_vault_key (48 bytes)
//   [190]      num_active_slots (u8)
//   [191..1191] device_slots (8 × 125 bytes)
//   [1191..1195] revocation_epoch (u32 LE)
//   [1195..1227] header_hmac (32 bytes, covers bytes[0..1195])
//
// Device slot v2 layout (125 bytes):
//   [0]     status (u8): 0x00=Empty, 0x01=Active
//   [1..17]  device_id (16 bytes, random per device)
//   [17..29] wrap_iv (12 bytes, AES-GCM nonce for encrypted shard)
//   [29..77] encrypted_payload (48 bytes, AES-GCM(device_crypto_key, shard))
//   [77..125] signing_key_wrapped (48 bytes, AES-GCM(vault_key, device_id[0:12], ed25519_seed))
//             nonce = device_id[0:12] (deterministic, not stored separately)
//             all-zeros when no signing key has been generated yet
//
// Format v1 (839 bytes) is accepted for reading only; migrated to v2 on next write.
pub const VAULT_MAGIC: &[u8; 8] = b"SCVAULT\x00";
pub const VAULT_FORMAT_VERSION: u16 = 2;
pub const VAULT_FORMAT_VERSION_V1: u16 = 1;
pub const VAULT_HEADER_SIZE: usize = 1227; // v2: 1195 + 32 HMAC
pub const VAULT_HEADER_SIZE_V1: usize = 839; // v1 (read-only)
pub const VAULT_DEVICE_SLOT_SIZE: usize = 125; // v2: 77 + 48 signing key
pub const VAULT_DEVICE_SLOT_SIZE_V1: usize = 77; // v1 (read-only)
pub const VAULT_MAX_DEVICES: usize = 8;
pub const VAULT_HMAC_OFFSET: usize = 1195; // v2 HMAC field starts here
pub const VAULT_HMAC_OFFSET_V1: usize = 807; // v1 HMAC field start (read-only)
pub const VAULT_REVOCATION_EPOCH_OFFSET: usize = 1191; // v2 revocation_epoch field

// HKDF label for device signing-key wrapping (v2+).
pub const BYO_DEVICE_SIGNING_KEY_V2: &[u8] = b"SecureCloud BYO DeviceSigningKey v2";

// BYO Argon2id parameters (128 MB, per BYO_PLAN §1.4).
pub const ARGON2_MEMORY_KB_BYO: u32 = 131072;
pub const ARGON2_ITERATIONS_BYO: u32 = 3;
pub const ARGON2_PARALLELISM_BYO: u32 = 4;

// Argon2id DoS ceilings (C1). Enforced inside `argon2id_derive_with_params`
// so every entry point — vault open, vault create, passphrase change, legacy
// derive — is protected uniformly. Nominal BYO params (128 MiB / 3 / 4) are
// well within all three ceilings; a hostile vault header that inflated any
// parameter is rejected in microseconds, before any Argon2 work runs.
pub const ARGON2_MAX_MEMORY_KIB: u32 = 256 * 1024; // 256 MiB
pub const ARGON2_MAX_ITERATIONS: u32 = 10;
pub const ARGON2_MAX_PARALLELISM: u32 = 8;

// ─── BYO enrollment protocol ──────────────────────────────────────────────
// Domain separation strings for QR enrollment key derivation (BYO_PLAN §2.3).
// The enrollment protocol uses ephemeral X25519 ECDH → three derived keys:
//   enc_key: AES-256-GCM key for encrypting the shard during transfer
//   mac_key: HMAC-SHA256 key for authenticating the encrypted shard
//   sas_code: 6-digit Short Authentication String for visual verification
pub const BYO_ENROLL_ENC_V1: &[u8] = b"SCEnroll Enc v1";
pub const BYO_ENROLL_MAC_V1: &[u8] = b"SCEnroll MAC v1";
pub const BYO_ENROLL_SAS_V1: &[u8] = b"SCEnroll SAS v1";

// ─── R6 per-vault and manifest HKDF domain separators ────────────────────────
// All per-vault separators are used as `info = <CONST> || \x00 || provider_id.as_bytes()`.
// The \x00 separator prevents prefix-extension collisions across info strings of
// different lengths (e.g. provider_id "abc" cannot collide with "aead v1abc").

/// AEAD key for encrypting vault_manifest.sc body.
pub const BYO_MANIFEST_AEAD_V1: &[u8] = b"SecureCloud BYO manifest-aead v1";

/// AEAD key prefix for encrypting vault_<provider_id>.sc body.
/// Concatenate with `\x00` and `provider_id` bytes before calling HKDF.
pub const BYO_PER_VAULT_AEAD_V1: &[u8] = b"SecureCloud BYO per-vault-aead v1";

/// WAL key prefix for per-provider IndexedDB write-ahead log.
/// Concatenate with `\x00` and `provider_id` bytes before calling HKDF.
pub const BYO_PER_VAULT_WAL_V1: &[u8] = b"SecureCloud BYO per-vault-wal v1";

/// Journal AEAD key prefix for per-provider cloud journal body encryption.
/// Concatenate with `\x00` and `provider_id` bytes before calling HKDF.
pub const BYO_PER_VAULT_JOURNAL_AEAD_V1: &[u8] = b"SecureCloud BYO per-vault-journal-aead v1";

/// Journal HMAC key prefix for per-provider cloud journal entry authentication.
/// Concatenate with `\x00` and `provider_id` bytes before calling HKDF.
pub const BYO_PER_VAULT_JOURNAL_HMAC_V1: &[u8] = b"SecureCloud BYO per-vault-journal-hmac v1";
