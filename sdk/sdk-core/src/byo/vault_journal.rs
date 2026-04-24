// BYO vault mutation journal codec.
//
// Wire format:
//   Journal file = MAGIC(8) || entry*
//   Entry        = type(1) | table_len(1) | table | row_id(4 LE)
//                  | iv_len(1=12) | iv(12) | data_len(4 LE) | enc_data | hmac(32)
//
// HMAC covers everything in the entry EXCEPT the trailing hmac bytes themselves.
// Encrypt-then-MAC guarantees integrity and confidentiality.

use crate::byo::per_vault_key::JournalKeys;
use crate::crypto::hashing::{constant_time_eq, hmac_sha256};
use crate::crypto::symmetric::{aes_gcm_decrypt, aes_gcm_encrypt_with_nonce, generate_nonce};
use crate::crypto::zeroize_utils::Nonce12;
use zeroize::Zeroizing;

pub const JOURNAL_MAGIC: [u8; 8] = [0x53, 0x43, 0x4a, 0x4e, 0x52, 0x4c, 0x00, 0x01];
pub const ENTRY_TYPE_INSERT: u8 = 0x01;
pub const ENTRY_TYPE_UPDATE: u8 = 0x02;
pub const ENTRY_TYPE_DELETE: u8 = 0x03;

/// A4: journal replay only targets the vault schema tables listed in SPEC.md
/// §Per-provider SQLite Schema. A forged (or corrupted-pre-HMAC) table name is
/// rejected by the codec itself — callers no longer carry the burden of
/// enforcing this at replay time.
///
/// Extending this list is additive: older journals don't include entries for
/// new tables, so backward compatibility is preserved. New entries will be
/// rejected by older clients that haven't been rebuilt.
pub const ALLOWED_JOURNAL_TABLES: &[&str] = &[
    "files",
    "folders",
    "favorites",
    "trash",
    "share_tokens",
    "vault_meta",
    "key_versions",
    "collections",
    "collection_files",
];

#[derive(Debug)]
pub enum JournalError {
    TooShort,
    BadMagic,
    TableTooLong,
    BadTableName(String),
    BadEntryType(u8),
    BadIvLen(u8),
    HmacMismatch,
    Crypto(crate::error::CryptoError),
    Truncated,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "journal too short"),
            Self::BadMagic => write!(f, "invalid journal magic"),
            Self::TableTooLong => write!(f, "table name exceeds 255 bytes"),
            Self::BadTableName(t) => write!(f, "table name not in allowlist: {t}"),
            Self::BadEntryType(t) => write!(f, "unknown entry type: {t:#x}"),
            Self::BadIvLen(l) => write!(f, "unexpected iv_len: {l}"),
            Self::HmacMismatch => write!(f, "HMAC mismatch — journal discarded"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::Truncated => write!(f, "journal truncated"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<crate::error::CryptoError> for JournalError {
    fn from(e: crate::error::CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// A decoded, decrypted journal entry.
#[derive(Debug)]
pub struct JournalEntry {
    pub entry_type: u8, // ENTRY_TYPE_INSERT / UPDATE / DELETE
    pub table: String,
    pub row_id: u32,
    pub data: Zeroizing<Vec<u8>>, // plaintext JSON bytes
}

/// Serialize + encrypt + HMAC one journal entry.
///
/// Returns the complete entry bytes (including trailing HMAC).
/// Caller appends these bytes to the journal buffer.
pub fn serialize_entry(
    keys: &JournalKeys,
    entry_type: u8,
    table: &str,
    row_id: u32,
    plaintext_data: &[u8],
) -> Result<Vec<u8>, JournalError> {
    let table_bytes = table.as_bytes();
    if table_bytes.len() > 255 {
        return Err(JournalError::TableTooLong);
    }
    // A4: refuse to encode anything outside the vault schema allowlist. This
    // catches a caller bug at serialize time rather than relying on the decoder
    // or a downstream replayer to notice.
    if !ALLOWED_JOURNAL_TABLES.contains(&table) {
        return Err(JournalError::BadTableName(table.to_string()));
    }

    // Encrypt data with AES-256-GCM.
    let nonce = generate_nonce()?;
    let ciphertext = aes_gcm_encrypt_with_nonce(plaintext_data, &keys.aead, &nonce)?;

    // Serialize entry body (everything before the HMAC).
    let mut entry =
        Vec::with_capacity(1 + 1 + table_bytes.len() + 4 + 1 + 12 + 4 + ciphertext.len());
    entry.push(entry_type);
    entry.push(table_bytes.len() as u8);
    entry.extend_from_slice(table_bytes);
    entry.extend_from_slice(&row_id.to_le_bytes());
    entry.push(12u8); // iv_len
    entry.extend_from_slice(nonce.as_bytes());
    entry.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    entry.extend_from_slice(&ciphertext);

    // Append HMAC-SHA256 over entry body (Encrypt-then-MAC).
    let hmac = hmac_sha256(keys.hmac.as_bytes(), &entry)?;
    entry.extend_from_slice(&hmac);

    Ok(entry)
}

/// Parse and verify a complete journal file (magic + entries).
///
/// Returns all decoded entries on success.
/// On the first HMAC failure, returns `Err(JournalError::HmacMismatch)` (fail-closed).
pub fn parse_journal(keys: &JournalKeys, data: &[u8]) -> Result<Vec<JournalEntry>, JournalError> {
    if data.len() < JOURNAL_MAGIC.len() {
        return Err(JournalError::TooShort);
    }
    if !constant_time_eq(&data[..JOURNAL_MAGIC.len()], &JOURNAL_MAGIC) {
        return Err(JournalError::BadMagic);
    }

    let mut entries = Vec::new();
    let mut offset = JOURNAL_MAGIC.len();

    while offset < data.len() {
        let entry_start = offset;

        // type (1)
        let entry_type = *data.get(offset).ok_or(JournalError::Truncated)?;
        if ![ENTRY_TYPE_INSERT, ENTRY_TYPE_UPDATE, ENTRY_TYPE_DELETE].contains(&entry_type) {
            return Err(JournalError::BadEntryType(entry_type));
        }
        offset += 1;

        // table_len (1) + table
        let table_len = *data.get(offset).ok_or(JournalError::Truncated)? as usize;
        offset += 1;
        if offset + table_len > data.len() {
            return Err(JournalError::Truncated);
        }
        // A4: reject non-UTF-8 or out-of-allowlist table names. Using
        // `from_utf8_lossy` here would silently substitute U+FFFD for invalid
        // bytes, potentially producing a valid-looking allowlist string from
        // corrupt input; HMAC authenticates the raw bytes but doesn't protect
        // against a replay target swap if the target itself is attacker-chosen.
        let table_slice = data
            .get(offset..offset + table_len)
            .ok_or(JournalError::Truncated)?;
        let table = std::str::from_utf8(table_slice)
            .map_err(|_| JournalError::BadTableName("<non-utf8>".to_string()))?
            .to_string();
        if !ALLOWED_JOURNAL_TABLES.contains(&table.as_str()) {
            return Err(JournalError::BadTableName(table));
        }
        offset += table_len;

        // row_id (4 LE)
        if offset + 4 > data.len() {
            return Err(JournalError::Truncated);
        }
        let row_id = u32::from_le_bytes(
            data.get(offset..offset + 4)
                .ok_or(JournalError::Truncated)?
                .try_into()
                .map_err(|_| JournalError::Truncated)?,
        );
        offset += 4;

        // iv_len (1) + iv (12)
        let iv_len = *data.get(offset).ok_or(JournalError::Truncated)?;
        if iv_len != 12 {
            return Err(JournalError::BadIvLen(iv_len));
        }
        offset += 1;
        if offset + 12 > data.len() {
            return Err(JournalError::Truncated);
        }
        let iv_bytes: [u8; 12] = data
            .get(offset..offset + 12)
            .ok_or(JournalError::Truncated)?
            .try_into()
            .map_err(|_| JournalError::Truncated)?;
        let nonce = Nonce12::new(iv_bytes);
        offset += 12;

        // data_len (4 LE) + enc_data
        if offset + 4 > data.len() {
            return Err(JournalError::Truncated);
        }
        let data_len = u32::from_le_bytes(
            data.get(offset..offset + 4)
                .ok_or(JournalError::Truncated)?
                .try_into()
                .map_err(|_| JournalError::Truncated)?,
        ) as usize;
        // J1: defence-in-depth cap on per-entry size. HMAC rejects a forged
        // huge entry before we'd decrypt, so external forgery is blocked,
        // but a legitimately-encrypted oversized entry (e.g. a preserved
        // attacker-controlled past journal) shouldn't still force a
        // multi-GB allocation. 16 MiB is far above any realistic row blob.
        const MAX_ENTRY_DATA_LEN: usize = 16 * 1024 * 1024;
        if data_len > MAX_ENTRY_DATA_LEN {
            return Err(JournalError::Truncated);
        }
        offset += 4;
        if offset + data_len + 32 > data.len() {
            return Err(JournalError::Truncated);
        }
        let enc_data = data
            .get(offset..offset + data_len)
            .ok_or(JournalError::Truncated)?;
        offset += data_len;

        // HMAC (32) — verify before decrypting (fail-closed on mismatch)
        let entry_bytes = data
            .get(entry_start..offset)
            .ok_or(JournalError::Truncated)?;
        let stored_hmac = data
            .get(offset..offset + 32)
            .ok_or(JournalError::Truncated)?;
        offset += 32;

        let expected_hmac = hmac_sha256(keys.hmac.as_bytes(), entry_bytes)?;
        if !constant_time_eq(&expected_hmac, stored_hmac) {
            return Err(JournalError::HmacMismatch);
        }

        // Decrypt data
        let plaintext = aes_gcm_decrypt(enc_data, &nonce, &keys.aead)?;

        entries.push(JournalEntry {
            entry_type,
            table,
            row_id,
            data: Zeroizing::new(plaintext),
        });
    }

    Ok(entries)
}

/// Build a journal file from pre-serialized entry bytes.
/// Each entry in `entries` is already the output of `serialize_entry`.
pub fn build_journal_file(entries: &[Vec<u8>]) -> Vec<u8> {
    let total = JOURNAL_MAGIC.len() + entries.iter().map(|e| e.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&JOURNAL_MAGIC);
    for e in entries {
        out.extend_from_slice(e);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::byo::per_vault_key::derive_per_vault_journal_keys;
    use crate::crypto::symmetric::generate_aes_key;

    fn test_keys() -> JournalKeys {
        let vault_key = generate_aes_key().unwrap();
        derive_per_vault_journal_keys(&vault_key, "test-provider").unwrap()
    }

    #[test]
    fn insert_roundtrip() {
        let keys = test_keys();
        let data = br#"{"id":1,"name":"test"}"#;
        let entry_bytes = serialize_entry(&keys, ENTRY_TYPE_INSERT, "files", 42, data).unwrap();
        let file = build_journal_file(&[entry_bytes]);
        let entries = parse_journal(&keys, &file).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_type, ENTRY_TYPE_INSERT);
        assert_eq!(entries[0].table, "files");
        assert_eq!(entries[0].row_id, 42);
        assert_eq!(&*entries[0].data, data);
    }

    #[test]
    fn multi_entry_roundtrip() {
        let keys = test_keys();
        let e1 = serialize_entry(&keys, ENTRY_TYPE_INSERT, "files", 1, b"data1").unwrap();
        let e2 = serialize_entry(&keys, ENTRY_TYPE_UPDATE, "folders", 2, b"data2").unwrap();
        let e3 = serialize_entry(&keys, ENTRY_TYPE_DELETE, "trash", 3, b"data3").unwrap();
        let file = build_journal_file(&[e1, e2, e3]);
        let entries = parse_journal(&keys, &file).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].entry_type, ENTRY_TYPE_UPDATE);
        assert_eq!(entries[2].table, "trash");
    }

    #[test]
    fn wrong_key_fails_hmac() {
        let keys = test_keys();
        let e = serialize_entry(&keys, ENTRY_TYPE_INSERT, "files", 1, b"secret").unwrap();
        let file = build_journal_file(&[e]);
        let wrong_keys = test_keys(); // different random keys
        let result = parse_journal(&wrong_keys, &file);
        assert!(matches!(result, Err(JournalError::HmacMismatch)));
    }

    #[test]
    fn tampered_entry_fails_hmac() {
        let keys = test_keys();
        let e = serialize_entry(&keys, ENTRY_TYPE_INSERT, "files", 1, b"data").unwrap();
        let mut file = build_journal_file(&[e]);
        // Flip a bit in the encrypted data region (after magic + header)
        if let Some(b) = file.get_mut(20) {
            *b ^= 0xFF;
        }
        let result = parse_journal(&keys, &file);
        assert!(matches!(result, Err(JournalError::HmacMismatch)));
    }

    #[test]
    fn bad_magic_rejected() {
        let keys = test_keys();
        let file = b"BADMAGIC extra bytes";
        assert!(matches!(
            parse_journal(&keys, file),
            Err(JournalError::BadMagic)
        ));
    }

    #[test]
    fn empty_journal_ok() {
        let keys = test_keys();
        let file = build_journal_file(&[]);
        let entries = parse_journal(&keys, &file).unwrap();
        assert!(entries.is_empty());
    }

    // A4: table allowlist + strict UTF-8 enforcement.
    #[test]
    fn serialize_rejects_unknown_table() {
        let keys = test_keys();
        let result = serialize_entry(&keys, ENTRY_TYPE_INSERT, "sqlite_master", 1, b"data");
        assert!(matches!(result, Err(JournalError::BadTableName(_))));
    }

    #[test]
    fn parse_rejects_non_utf8_table_name() {
        // Hand-craft a journal with a valid HMAC but invalid UTF-8 in the table
        // field. We can't use serialize_entry (it enforces allowlist), so build
        // the entry directly with a locally generated HMAC.
        let keys = test_keys();
        let nonce = generate_nonce().unwrap();
        let ct = aes_gcm_encrypt_with_nonce(b"payload", &keys.aead, &nonce).unwrap();

        let mut entry: Vec<u8> = Vec::new();
        entry.push(ENTRY_TYPE_INSERT);
        entry.push(5); // table_len
        entry.extend_from_slice(&[0xff, b'i', b'l', b'e', b's']); // invalid UTF-8
        entry.extend_from_slice(&1u32.to_le_bytes()); // row_id
        entry.push(12); // iv_len
        entry.extend_from_slice(nonce.as_bytes());
        entry.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        entry.extend_from_slice(&ct);
        let hmac = hmac_sha256(keys.hmac.as_bytes(), &entry).unwrap();
        entry.extend_from_slice(&hmac);

        let file = build_journal_file(&[entry]);
        assert!(matches!(
            parse_journal(&keys, &file),
            Err(JournalError::BadTableName(_))
        ));
    }

    #[test]
    fn parse_rejects_out_of_allowlist_table_name() {
        // Same trick but with a valid-UTF-8 name outside the allowlist.
        let keys = test_keys();
        let nonce = generate_nonce().unwrap();
        let ct = aes_gcm_encrypt_with_nonce(b"payload", &keys.aead, &nonce).unwrap();

        let name = b"sqlite_master";
        let mut entry: Vec<u8> = Vec::new();
        entry.push(ENTRY_TYPE_INSERT);
        entry.push(name.len() as u8);
        entry.extend_from_slice(name);
        entry.extend_from_slice(&1u32.to_le_bytes());
        entry.push(12);
        entry.extend_from_slice(nonce.as_bytes());
        entry.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        entry.extend_from_slice(&ct);
        let hmac = hmac_sha256(keys.hmac.as_bytes(), &entry).unwrap();
        entry.extend_from_slice(&hmac);

        let file = build_journal_file(&[entry]);
        assert!(matches!(
            parse_journal(&keys, &file),
            Err(JournalError::BadTableName(_))
        ));
    }
}
