// V7 chunked file format: encrypt/decrypt, header serialize/parse.
//
// Wire format:
//   [0x07(1)][file_iv(12)][eph_x25519_pub(32)][mlkem_ct(1568)][efk_len(4LE)][efk(60)]
//   [key_commitment(32)]
//   [chunk_len(4LE)][chunk_nonce(12)][chunk_ct+tag(N)] ...
//   [hmac(32)]
//
// Key commitment: BLAKE2b-256(content_key || file_iv)
// Chunk nonce:    file_iv XOR LE96(chunk_index) (only lower 4 bytes XORed)
// HMAC:           HMAC-SHA256(hmac_key, concat(chunk_index_le32 || ciphertext) for each chunk)
// HMAC key:       HKDF-SHA256(content_key, info=CHUNK_HMAC_V1, L=32)

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::constants::{
    CHUNK_HMAC_V1, FILE_FORMAT_V7, V7_FOOTER_LEN, V7_FRAME_OVERHEAD, V7_HEADER_MIN,
};
use crate::crypto::hashing::{blake2b_256, constant_time_eq};
use crate::crypto::kdf::hkdf_sha256;
use crate::crypto::pqc::{hybrid_decapsulate_v6, hybrid_encapsulate_v6};
use crate::crypto::symmetric::{
    aes_gcm_decrypt, aes_gcm_encrypt_with_nonce, generate_nonce, v7_chunk_nonce,
};
use crate::crypto::zeroize_utils::{
    MlKemPublicKey, MlKemSecretKey, Nonce12, SymmetricKey, X25519PublicKey, X25519SecretKey,
};
use crate::error::CryptoError;

type HmacSha256 = Hmac<Sha256>;

/// Output of `encrypt_file_v7_init`.
pub struct V7EncryptInit {
    /// Random 12-byte per-file IV for chunk nonce construction.
    pub file_iv: Nonce12,
    /// Ephemeral X25519 public key (32 bytes).
    pub eph_x25519_pub: [u8; 32],
    /// ML-KEM-1024 ciphertext (1568 bytes).
    pub mlkem_ct: Vec<u8>,
    /// Encrypted file key: wrapping_iv(12) || AES-GCM(wrapping_key, content_key)(48) = 60 bytes.
    pub encrypted_file_key: Vec<u8>,
    /// BLAKE2b-256(content_key || file_iv) — stored in header after efk.
    pub key_commitment: [u8; 32],
    /// Content key for chunk encryption and HMAC derivation. Zeroized on drop.
    pub content_key: SymmetricKey,
}

/// Output of `decrypt_file_v7_init`.
pub struct V7DecryptInit {
    /// Per-file IV parsed from header.
    pub file_iv: Nonce12,
    /// Content key decapsulated from header; also used for HMAC key derivation.
    pub content_key: SymmetricKey,
    /// Byte offset where chunks begin (after the fixed header).
    pub header_end: usize,
}

/// Initialize v7 encryption: run KEM encapsulation, generate file_iv, compute key commitment.
pub fn encrypt_file_v7_init(
    mlkem_pub: &MlKemPublicKey,
    x25519_pub: &X25519PublicKey,
) -> Result<V7EncryptInit, CryptoError> {
    let kem_result = hybrid_encapsulate_v6(mlkem_pub, x25519_pub)?;

    // Generate random file_iv
    let file_iv = generate_nonce()?;

    // Key commitment: BLAKE2b-256(content_key || file_iv)
    let mut kc_input = Vec::with_capacity(44);
    kc_input.extend_from_slice(kem_result.content_key.as_bytes());
    kc_input.extend_from_slice(file_iv.as_bytes());
    let key_commitment = blake2b_256(&kc_input);

    Ok(V7EncryptInit {
        file_iv,
        eph_x25519_pub: kem_result.eph_x25519_pub,
        mlkem_ct: kem_result.mlkem_ciphertext,
        encrypted_file_key: kem_result.encrypted_file_key,
        key_commitment,
        content_key: kem_result.content_key,
    })
}

/// Encrypt a single v7 chunk.
/// Returns the encrypted chunk bytes (ciphertext+tag); caller prepends chunk_len and nonce for wire format.
pub fn encrypt_file_v7_chunk(
    chunk_data: &[u8],
    content_key: &SymmetricKey,
    file_iv: &Nonce12,
    chunk_index: u32,
) -> Result<Vec<u8>, CryptoError> {
    let nonce = v7_chunk_nonce(file_iv, chunk_index);
    aes_gcm_encrypt_with_nonce(chunk_data, content_key, &nonce)
}

/// Compute HMAC-SHA256 over accumulated chunk data.
/// `chunks_data` = concatenation of `(chunk_index_le32 || ciphertext)` for each chunk, in order.
/// HMAC key is derived: HKDF-SHA256(content_key, info=CHUNK_HMAC_V1, L=32).
pub fn compute_v7_hmac(
    content_key: &SymmetricKey,
    chunks_data: &[u8],
) -> Result<[u8; 32], CryptoError> {
    // Derive HMAC key from content_key
    let hmac_key_bytes = hkdf_sha256(content_key.as_bytes(), CHUNK_HMAC_V1, 32)?;
    let mut mac =
        HmacSha256::new_from_slice(&hmac_key_bytes).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    mac.update(chunks_data);
    Ok(mac.finalize().into_bytes().into())
}

// ─── Streaming decrypt ─────────────────────────────────────────────────────
//
// Incremental V7 decryptor for true streaming downloads.
//
// Usage:
//   1. Caller reads the first V7_HEADER_MIN bytes from the ciphertext stream.
//   2. `V7StreamDecryptor::new(header_bytes, sec_keys)` — decapsulates, verifies
//      key commitment, initialises HMAC state. Returns the decryptor and the
//      header end offset (always V7_HEADER_MIN for the current format).
//   3. For each network chunk received *after* the header and *before* the
//      trailing 32-byte footer: `push(bytes)` → plaintext bytes for any
//      complete frames now available. Incomplete frames remain buffered.
//   4. `finalize(stored_hmac)` — constant-time compare against the expected
//      footer. Returns `()` on success, `MacVerificationFailed` otherwise.
//
// Per-chunk AEAD already prevents reordering/tampering (nonce encodes the
// chunk index); the footer HMAC is belt-and-suspenders against truncation
// and is verified before the pipeline is considered successful.

/// Incremental V7 file decryptor. Keeps the content key + HMAC state in one
/// place so the caller only deals with opaque byte buffers.
pub struct V7StreamDecryptor {
    file_iv: Nonce12,
    content_key: SymmetricKey,
    hmac: HmacSha256,
    chunk_index: u32,
    /// Bytes not yet consumed by frame parsing (leftover from a partial frame).
    buf: Vec<u8>,
}

impl V7StreamDecryptor {
    /// Create a new streaming decryptor from the V7 header prefix.
    ///
    /// `header_bytes` must contain at least `V7_HEADER_MIN` bytes. Extra bytes
    /// beyond the header are retained in the internal buffer and will be
    /// processed by subsequent `push` calls.
    pub fn new(
        header_bytes: &[u8],
        mlkem_sec: &MlKemSecretKey,
        x25519_sec: &X25519SecretKey,
    ) -> Result<(Self, usize), CryptoError> {
        if header_bytes.len() < V7_HEADER_MIN {
            return Err(CryptoError::InvalidFormat(
                "v7 header prefix too short".to_string(),
            ));
        }
        let init = decrypt_file_v7_init(&header_bytes[..V7_HEADER_MIN], mlkem_sec, x25519_sec)?;

        let hmac_key_bytes = hkdf_sha256(init.content_key.as_bytes(), CHUNK_HMAC_V1, 32)?;
        let hmac = HmacSha256::new_from_slice(&hmac_key_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        // Any bytes beyond the fixed header are early chunk data — keep them.
        let leftover = header_bytes[V7_HEADER_MIN..].to_vec();

        let header_end = init.header_end;
        Ok((
            Self {
                file_iv: init.file_iv,
                content_key: init.content_key,
                hmac,
                chunk_index: 0,
                buf: leftover,
            },
            header_end,
        ))
    }

    /// Append ciphertext bytes and return any plaintext that is now complete.
    ///
    /// Processes as many full frames as the internal buffer allows and leaves
    /// any trailing partial frame buffered for the next call. The caller must
    /// NOT include the trailing 32-byte footer in the bytes passed here — hand
    /// the footer to `finalize` instead.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.buf.extend_from_slice(data);
        let mut plaintext = Vec::new();
        let mut pos = 0usize;

        loop {
            if self.buf.len() - pos < 4 {
                break;
            }
            let chunk_len = u32::from_le_bytes([
                self.buf[pos],
                self.buf[pos + 1],
                self.buf[pos + 2],
                self.buf[pos + 3],
            ]) as usize;
            if chunk_len < 12 {
                return Err(CryptoError::InvalidFormat(
                    "v7 chunk_len too small".to_string(),
                ));
            }
            if self.buf.len() - pos < 4 + chunk_len {
                break; // not enough bytes for this frame yet
            }

            let frame_start = pos + 4;
            let ct_start = frame_start + 12; // skip 12-byte nonce (re-derived)
            let ct_end = frame_start + chunk_len;
            let ct = &self.buf[ct_start..ct_end];

            // HMAC input: chunk_index_le32 || ciphertext
            self.hmac.update(&self.chunk_index.to_le_bytes());
            self.hmac.update(ct);

            let chunk_pt = aes_gcm_decrypt(
                ct,
                &v7_chunk_nonce(&self.file_iv, self.chunk_index),
                &self.content_key,
            )?;
            plaintext.extend_from_slice(&chunk_pt);
            // S6: hard-fail on chunk_index overflow. Previously `wrapping_add`
            // would silently wrap at u32::MAX, reusing nonce 0 with the same
            // content_key on chunk 2^32 — a catastrophic AEAD nonce reuse.
            // At 512 KiB chunks that's 2 PiB, impractical today, but we
            // refuse to continue rather than ever produce an ambiguous result.
            self.chunk_index = self.chunk_index
                .checked_add(1)
                .ok_or_else(|| CryptoError::InvalidFormat(
                    "V7 decrypt: chunk_index overflow (>2^32 chunks)".into(),
                ))?;
            pos = ct_end;
        }

        // Discard consumed bytes.
        if pos > 0 {
            self.buf.drain(..pos);
        }
        Ok(plaintext)
    }

    /// Consume the decryptor and verify the trailing HMAC footer.
    ///
    /// Returns `Err(InvalidFormat)` if an incomplete chunk remains in the
    /// internal buffer, or `Err(MacVerificationFailed)` on HMAC mismatch.
    pub fn finalize(self, stored_hmac: &[u8]) -> Result<(), CryptoError> {
        if !self.buf.is_empty() {
            return Err(CryptoError::InvalidFormat(
                "v7 stream ended mid-frame".to_string(),
            ));
        }
        if stored_hmac.len() != V7_FOOTER_LEN {
            return Err(CryptoError::InvalidFormat(
                "v7 footer wrong length".to_string(),
            ));
        }
        let computed: [u8; 32] = self.hmac.finalize().into_bytes().into();
        if constant_time_eq(&computed, stored_hmac) {
            Ok(())
        } else {
            Err(CryptoError::MacVerificationFailed)
        }
    }
}

// ─── Share-link decrypt ────────────────────────────────────────────────────
//
// Variant of V7StreamDecryptor that takes the content_key directly instead of
// decapsulating it from KEM keys. Used for P10 share links where the recipient
// receives the content_key in the URL fragment.

/// V7 file decryptor for share links. Identical streaming interface to
/// `V7StreamDecryptor` but constructed from a raw `content_key` rather than
/// KEM private keys. Verifies the key commitment before accepting the key.
pub struct V7ShareDecryptor {
    file_iv: Nonce12,
    content_key: SymmetricKey,
    hmac: HmacSha256,
    chunk_index: u32,
    buf: Vec<u8>,
}

impl V7ShareDecryptor {
    /// Create a share decryptor from the V7 header and a known content_key.
    ///
    /// Parses the header, reads the stored key_commitment, and verifies it
    /// equals `BLAKE2b-256(content_key || file_iv)` in constant time.
    /// Returns `CryptoError::KeyCommitmentFailed` if the check fails.
    ///
    /// Returns `(Self, header_end_offset)`. `header_end_offset` is always
    /// `V7_HEADER_MIN` (1709) for the current format.
    pub fn new(
        header_bytes: &[u8],
        content_key_bytes: &[u8],
    ) -> Result<(Self, usize), CryptoError> {
        if header_bytes.len() < V7_HEADER_MIN {
            return Err(CryptoError::InvalidFormat(
                "v7 header prefix too short".to_string(),
            ));
        }

        // Parse version byte.
        let version = header_bytes[0];
        if version != FILE_FORMAT_V7 {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        // Parse file_iv (bytes 1..13).
        let file_iv = Nonce12::from_slice(
            header_bytes.get(1..13).ok_or_else(|| {
                CryptoError::InvalidFormat("header too short for file_iv".to_string())
            })?,
        )?;

        // Skip eph_x25519(32) + mlkem_ct(1568) + efk_len(4) + efk(60) = 1664 bytes at offset 13.
        // key_commitment is at bytes 1677..1709 (= 13 + 1664 = 1677).
        let commitment_offset = 1 + 12 + 32 + 1568 + 4 + 60; // = 1677
        let stored_commitment = header_bytes
            .get(commitment_offset..commitment_offset + 32)
            .ok_or_else(|| {
                CryptoError::InvalidFormat("header too short for key_commitment".to_string())
            })?;

        // Build SymmetricKey from the provided bytes.
        let content_key = SymmetricKey::from_slice(content_key_bytes)?;

        // Verify key commitment = BLAKE2b-256(content_key || file_iv).
        let mut kc_input = Vec::with_capacity(44);
        kc_input.extend_from_slice(content_key.as_bytes());
        kc_input.extend_from_slice(file_iv.as_bytes());
        let computed = blake2b_256(&kc_input);

        if !constant_time_eq(&computed, stored_commitment) {
            return Err(CryptoError::KeyCommitmentFailed);
        }

        // Derive HMAC key: HKDF-SHA256(content_key, CHUNK_HMAC_V1, 32).
        let hmac_key_bytes = hkdf_sha256(content_key.as_bytes(), CHUNK_HMAC_V1, 32)?;
        let hmac = HmacSha256::new_from_slice(&hmac_key_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        // Any bytes beyond the fixed header are early chunk data — keep them.
        let leftover = header_bytes[V7_HEADER_MIN..].to_vec();

        Ok((
            Self {
                file_iv,
                content_key,
                hmac,
                chunk_index: 0,
                buf: leftover,
            },
            V7_HEADER_MIN,
        ))
    }

    /// Append ciphertext bytes and return any plaintext now available.
    /// Same semantics as `V7StreamDecryptor::push`.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.buf.extend_from_slice(data);
        let mut plaintext = Vec::new();
        let mut pos = 0usize;

        loop {
            if self.buf.len() - pos < 4 {
                break;
            }
            let chunk_len = u32::from_le_bytes([
                self.buf[pos],
                self.buf[pos + 1],
                self.buf[pos + 2],
                self.buf[pos + 3],
            ]) as usize;
            if chunk_len < 12 {
                return Err(CryptoError::InvalidFormat(
                    "v7 chunk_len too small".to_string(),
                ));
            }
            if self.buf.len() - pos < 4 + chunk_len {
                break;
            }

            let frame_start = pos + 4;
            let ct_start = frame_start + 12;
            let ct_end = frame_start + chunk_len;
            let ct = &self.buf[ct_start..ct_end];

            self.hmac.update(&self.chunk_index.to_le_bytes());
            self.hmac.update(ct);

            let chunk_pt = aes_gcm_decrypt(
                ct,
                &v7_chunk_nonce(&self.file_iv, self.chunk_index),
                &self.content_key,
            )?;
            plaintext.extend_from_slice(&chunk_pt);
            // S6: hard-fail on chunk_index overflow. Previously `wrapping_add`
            // would silently wrap at u32::MAX, reusing nonce 0 with the same
            // content_key on chunk 2^32 — a catastrophic AEAD nonce reuse.
            // At 512 KiB chunks that's 2 PiB, impractical today, but we
            // refuse to continue rather than ever produce an ambiguous result.
            self.chunk_index = self.chunk_index
                .checked_add(1)
                .ok_or_else(|| CryptoError::InvalidFormat(
                    "V7 decrypt: chunk_index overflow (>2^32 chunks)".into(),
                ))?;
            pos = ct_end;
        }

        if pos > 0 {
            self.buf.drain(..pos);
        }
        Ok(plaintext)
    }

    /// Consume the decryptor and verify the trailing HMAC footer.
    /// Same semantics as `V7StreamDecryptor::finalize`.
    pub fn finalize(self, stored_hmac: &[u8]) -> Result<(), CryptoError> {
        if !self.buf.is_empty() {
            return Err(CryptoError::InvalidFormat(
                "v7 stream ended mid-frame".to_string(),
            ));
        }
        if stored_hmac.len() != V7_FOOTER_LEN {
            return Err(CryptoError::InvalidFormat(
                "v7 footer wrong length".to_string(),
            ));
        }
        let computed: [u8; 32] = self.hmac.finalize().into_bytes().into();
        if constant_time_eq(&computed, stored_hmac) {
            Ok(())
        } else {
            Err(CryptoError::MacVerificationFailed)
        }
    }
}

// ─── Streaming encrypt ─────────────────────────────────────────────────────
//
// Incremental V7 encryptor for true streaming uploads. Mirror of
// `V7StreamDecryptor`: keeps the content key and HMAC state inside the
// struct so the caller only ever sees output byte frames.
//
// Usage:
//   1. `V7StreamEncryptor::new(pub_keys)` — runs KEM encapsulation, generates
//      `file_iv`, builds the 1709-byte v7 header. Returns the encryptor and
//      the header bytes (which the caller must upload as the first bytes of
//      the file).
//   2. For each plaintext chunk from the upload source:
//      `push(plaintext)` → one complete wire frame
//      `[chunk_len_le32(4) || nonce(12) || ct+tag]`. The frame also feeds
//      `(chunk_index_le32 || ciphertext)` into the running HMAC.
//   3. `finalize()` — consumes the encryptor and returns the 32-byte HMAC
//      footer. The content key is zeroized when `self` drops.
//
// Unlike the decryptor, the encryptor does not buffer across `push` calls:
// each call is exactly one plaintext chunk, and the caller is responsible
// for chunking the input to the desired size (typically the upload
// system's chunk size, e.g. 256 KiB of plaintext). This keeps the state
// machine trivial and matches how the existing upload loop already works.

/// Incremental V7 file encryptor. Keeps the content key, file IV, and
/// HMAC state in one place so the caller only deals with opaque byte frames.
///
/// # Non-exportability invariant
///
/// This type MUST NOT gain `Clone`, `Serialize`, or any `snapshot` / `restore`
/// method. Zero-knowledge invariants require `content_key` to be
/// `ZeroizeOnDrop` and never persisted to host storage (IndexedDB, disk, etc.).
/// Cross-process resume of an upload requires re-running `new` and
/// re-encrypting from byte 0 with a fresh header — not replaying a snapshot.
pub struct V7StreamEncryptor {
    file_iv: Nonce12,
    content_key: SymmetricKey,
    hmac: HmacSha256,
    chunk_index: u32,
}

impl V7StreamEncryptor {
    /// Create a new streaming encryptor and build the V7 header.
    ///
    /// Runs hybrid KEM encapsulation, generates a random `file_iv`, computes
    /// the key commitment, and returns both the encryptor and the serialized
    /// 1709-byte header that must be uploaded as the first bytes of the file.
    pub fn new(
        mlkem_pub: &MlKemPublicKey,
        x25519_pub: &X25519PublicKey,
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let init = encrypt_file_v7_init(mlkem_pub, x25519_pub)?;

        // Derive the HMAC key the same way the full-blob path does.
        let hmac_key_bytes = hkdf_sha256(init.content_key.as_bytes(), CHUNK_HMAC_V1, 32)?;
        let hmac = HmacSha256::new_from_slice(&hmac_key_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        // Serialize the header (byte-identical layout to `encrypt_file_v7`).
        let mut header = Vec::with_capacity(V7_HEADER_MIN);
        header.push(FILE_FORMAT_V7);
        header.extend_from_slice(init.file_iv.as_bytes());
        header.extend_from_slice(&init.eph_x25519_pub);
        header.extend_from_slice(&init.mlkem_ct);
        let efk_len = init.encrypted_file_key.len() as u32;
        header.extend_from_slice(&efk_len.to_le_bytes());
        header.extend_from_slice(&init.encrypted_file_key);
        header.extend_from_slice(&init.key_commitment);
        debug_assert_eq!(header.len(), V7_HEADER_MIN);

        Ok((
            Self {
                file_iv: init.file_iv,
                content_key: init.content_key,
                hmac,
                chunk_index: 0,
            },
            header,
        ))
    }

    /// Encrypt one plaintext chunk and return the complete wire frame.
    ///
    /// Output: `[chunk_len_le32(4) || nonce(12) || ciphertext+tag]` where
    /// `chunk_len = 12 + ciphertext_len`. Feeds
    /// `(chunk_index_le32 || ciphertext)` into the running HMAC so the
    /// eventual footer catches truncation.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ct = encrypt_file_v7_chunk(
            plaintext,
            &self.content_key,
            &self.file_iv,
            self.chunk_index,
        )?;
        let nonce = v7_chunk_nonce(&self.file_iv, self.chunk_index);

        self.hmac.update(&self.chunk_index.to_le_bytes());
        self.hmac.update(&ct);

        let chunk_len = (12 + ct.len()) as u32;
        let mut frame = Vec::with_capacity(4 + 12 + ct.len());
        frame.extend_from_slice(&chunk_len.to_le_bytes());
        frame.extend_from_slice(nonce.as_bytes());
        frame.extend_from_slice(&ct);

        // S6: same overflow guard as the decryptor. An upload that wraps
        // past u32::MAX chunks (2 PiB at 512 KiB/chunk) would produce a
        // duplicated nonce on the next chunk; better to error out.
        self.chunk_index = self.chunk_index
            .checked_add(1)
            .ok_or_else(|| CryptoError::InvalidFormat(
                "V7 encrypt: chunk_index overflow (>2^32 chunks)".into(),
            ))?;
        Ok(frame)
    }

    /// Current chunk index (number of chunks pushed so far).
    ///
    /// Read-only; does not expose any key material. Callers can use this to
    /// report accurate per-chunk progress ("chunk N of M") instead of
    /// approximating from byte count.
    pub fn position(&self) -> u32 {
        self.chunk_index
    }

    /// Consume the encryptor and return the 32-byte HMAC footer.
    /// The content key is zeroized on drop.
    pub fn finalize(self) -> [u8; 32] {
        self.hmac.finalize().into_bytes().into()
    }
}

/// Initialize v7 decryption: parse header, decapsulate keys, verify key commitment.
pub fn decrypt_file_v7_init(
    encrypted: &[u8],
    mlkem_sec: &MlKemSecretKey,
    x25519_sec: &X25519SecretKey,
) -> Result<V7DecryptInit, CryptoError> {
    if encrypted.len() < V7_HEADER_MIN {
        return Err(CryptoError::InvalidFormat("v7 data too short".to_string()));
    }

    let version = encrypted[0];
    if version != FILE_FORMAT_V7 {
        return Err(CryptoError::UnsupportedVersion(version));
    }

    // Parse header fields
    let file_iv = Nonce12::from_slice(&encrypted[1..13])?;
    let eph_x25519_pub = &encrypted[13..45];
    let mlkem_ct = &encrypted[45..1613];
    let efk_len = u32::from_le_bytes([
        encrypted[1613],
        encrypted[1614],
        encrypted[1615],
        encrypted[1616],
    ]) as usize;
    if efk_len != 60 {
        return Err(CryptoError::InvalidFormat(
            "unexpected efk_len (expected 60)".to_string(),
        ));
    }
    let efk_end = 1617 + efk_len;
    if encrypted.len() < efk_end + 32 {
        return Err(CryptoError::InvalidFormat(
            "v7 header truncated".to_string(),
        ));
    }
    let encrypted_file_key = &encrypted[1617..efk_end];
    let stored_commitment = &encrypted[efk_end..efk_end + 32];

    // Decapsulate to get content_key (hmac_key from KEM is unused; HMAC uses HKDF(content_key))
    let (content_key, _) = hybrid_decapsulate_v6(
        eph_x25519_pub,
        mlkem_ct,
        encrypted_file_key,
        mlkem_sec,
        x25519_sec,
    )?;

    // Verify key commitment: BLAKE2b-256(content_key || file_iv)
    let mut kc_input = Vec::with_capacity(44);
    kc_input.extend_from_slice(content_key.as_bytes());
    kc_input.extend_from_slice(file_iv.as_bytes());
    let computed_commitment = blake2b_256(&kc_input);

    if !constant_time_eq(&computed_commitment, stored_commitment) {
        return Err(CryptoError::MacVerificationFailed);
    }

    Ok(V7DecryptInit {
        file_iv,
        content_key,
        header_end: efk_end + 32,
    })
}

/// Decrypt a single v7 chunk.
pub fn decrypt_file_v7_chunk(
    ciphertext: &[u8],
    content_key: &SymmetricKey,
    file_iv: &Nonce12,
    chunk_index: u32,
) -> Result<Vec<u8>, CryptoError> {
    let nonce = v7_chunk_nonce(file_iv, chunk_index);
    aes_gcm_decrypt(ciphertext, &nonce, content_key)
}

/// Serialize a complete v7 file into a `Vec<u8>`.
/// `plaintext_chunks` are the raw chunk data in order.
/// This is a convenience function for testing; production code may stream chunks.
pub fn encrypt_file_v7(
    mlkem_pub: &MlKemPublicKey,
    x25519_pub: &X25519PublicKey,
    plaintext_chunks: &[&[u8]],
) -> Result<Vec<u8>, CryptoError> {
    let init = encrypt_file_v7_init(mlkem_pub, x25519_pub)?;

    // Build header
    let mut out = Vec::new();
    out.push(FILE_FORMAT_V7);
    out.extend_from_slice(init.file_iv.as_bytes());
    out.extend_from_slice(&init.eph_x25519_pub);
    out.extend_from_slice(&init.mlkem_ct);
    let efk_len = init.encrypted_file_key.len() as u32;
    out.extend_from_slice(&efk_len.to_le_bytes());
    out.extend_from_slice(&init.encrypted_file_key);
    out.extend_from_slice(&init.key_commitment);

    // Encrypt chunks and accumulate HMAC input
    let mut hmac_input = Vec::new();

    for (i, chunk) in plaintext_chunks.iter().enumerate() {
        let chunk_index = i as u32;
        let ct = encrypt_file_v7_chunk(chunk, &init.content_key, &init.file_iv, chunk_index)?;
        let nonce = v7_chunk_nonce(&init.file_iv, chunk_index);

        // HMAC input: chunk_index_le32 || ciphertext
        hmac_input.extend_from_slice(&chunk_index.to_le_bytes());
        hmac_input.extend_from_slice(&ct);

        // Wire: chunk_len(4) || nonce(12) || ct+tag
        let chunk_len = (12 + ct.len()) as u32;
        out.extend_from_slice(&chunk_len.to_le_bytes());
        out.extend_from_slice(nonce.as_bytes());
        out.extend_from_slice(&ct);
    }

    // HMAC
    let hmac = compute_v7_hmac(&init.content_key, &hmac_input)?;
    out.extend_from_slice(&hmac);

    Ok(out)
}

/// Decrypt a complete v7 file from a `&[u8]`.
/// Returns the concatenated plaintext of all chunks.
pub fn decrypt_file_v7(
    encrypted: &[u8],
    mlkem_sec: &MlKemSecretKey,
    x25519_sec: &X25519SecretKey,
) -> Result<Vec<u8>, CryptoError> {
    let init = decrypt_file_v7_init(encrypted, mlkem_sec, x25519_sec)?;
    let mut pos = init.header_end;
    let mut plaintext = Vec::new();
    let mut hmac_input = Vec::new();
    let mut chunk_index: u32 = 0;

    // Parse chunks until V7_FOOTER_LEN bytes remain (the HMAC)
    while pos + V7_FOOTER_LEN < encrypted.len() {
        if pos + 4 > encrypted.len() {
            return Err(CryptoError::InvalidFormat(
                "truncated chunk_len".to_string(),
            ));
        }
        let chunk_len = u32::from_le_bytes([
            encrypted[pos],
            encrypted[pos + 1],
            encrypted[pos + 2],
            encrypted[pos + 3],
        ]) as usize;
        pos += 4;

        if pos + chunk_len > encrypted.len() {
            return Err(CryptoError::InvalidFormat("truncated chunk".to_string()));
        }
        let nonce_bytes = &encrypted[pos..pos + 12];
        let ct = &encrypted[pos + 12..pos + chunk_len];
        pos += chunk_len;

        // Accumulate HMAC input
        hmac_input.extend_from_slice(&chunk_index.to_le_bytes());
        hmac_input.extend_from_slice(ct);

        // Decrypt chunk
        let nonce = Nonce12::from_slice(nonce_bytes)?;
        let chunk_pt = aes_gcm_decrypt(ct, &nonce, &init.content_key)?;
        plaintext.extend_from_slice(&chunk_pt);
        chunk_index += 1;
    }

    // Verify HMAC
    if pos + V7_FOOTER_LEN != encrypted.len() {
        return Err(CryptoError::InvalidFormat(
            "unexpected trailing bytes".to_string(),
        ));
    }
    let stored_hmac = &encrypted[pos..pos + V7_FOOTER_LEN];
    let computed_hmac = compute_v7_hmac(&init.content_key, &hmac_input)?;
    if !constant_time_eq(&computed_hmac, stored_hmac) {
        return Err(CryptoError::MacVerificationFailed);
    }

    Ok(plaintext)
}

// ─── V7 sizing helper ──────────────────────────────────────────────────────

/// Compute the total V7 ciphertext size for a given plaintext length and chunk size.
///
/// Formula: `V7_HEADER_MIN + ceil(plaintext_len / chunk_size) * V7_FRAME_OVERHEAD
///          + plaintext_len + V7_FOOTER_LEN`
///
/// For `plaintext_len == 0` there are no chunks, so: `V7_HEADER_MIN + V7_FOOTER_LEN`.
///
/// Mirrors `v7CipherSize()` in `byo/src/streaming/UploadStream.ts`.
pub fn v7_cipher_size(plaintext_len: u64, chunk_size: u32) -> u64 {
    if plaintext_len == 0 {
        return (V7_HEADER_MIN + V7_FOOTER_LEN) as u64;
    }
    let cs = chunk_size as u64;
    let n = plaintext_len.div_ceil(cs);
    (V7_HEADER_MIN as u64) + n * (V7_FRAME_OVERHEAD as u64) + plaintext_len + (V7_FOOTER_LEN as u64)
}

// ─── Footer trimmer ────────────────────────────────────────────────────────

/// Buffers the trailing N bytes of a ciphertext stream, releasing earlier bytes
/// for decryption. On finalize, returns `(remaining_body, footer)` where
/// `footer.len() == keep`.
///
/// Used by streaming downloaders to separate V7's 32-byte HMAC footer from
/// the chunk body without requiring the full file in memory.
pub struct FooterTrimmer {
    trailing: Vec<u8>,
    keep: usize,
}

impl FooterTrimmer {
    /// Create a new trimmer that retains the last `keep` bytes.
    pub fn new(keep: usize) -> Self {
        Self {
            trailing: Vec::new(),
            keep,
        }
    }

    /// Push new ciphertext bytes. Returns bytes that are safe to feed to the
    /// V7 decryptor (all bytes that are definitely NOT the footer).
    pub fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.trailing.extend_from_slice(bytes);
        if self.trailing.len() > self.keep {
            let release_len = self.trailing.len() - self.keep;
            let released = self.trailing[..release_len].to_vec();
            self.trailing.drain(..release_len);
            released
        } else {
            Vec::new()
        }
    }

    /// Signal end of stream. Returns `(remaining_body, footer)`.
    ///
    /// `remaining_body` holds any body bytes before the footer that had not
    /// yet been released by `push` (non-empty only when total input < 2×keep).
    ///
    /// Returns `Err(InvalidFormat)` if fewer than `keep` total bytes were pushed.
    pub fn finalize(mut self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if self.trailing.len() < self.keep {
            return Err(CryptoError::InvalidFormat(format!(
                "stream too short for footer: got {} bytes, need {}",
                self.trailing.len(),
                self.keep
            )));
        }
        let split = self.trailing.len() - self.keep;
        let footer = self.trailing.split_off(split);
        Ok((self.trailing, footer))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::pqc::generate_hybrid_keypair;

    #[test]
    fn v7_roundtrip_single_chunk() {
        let kp = generate_hybrid_keypair().unwrap();
        let data = b"hello, v7 world!";
        let encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[data]).unwrap();
        let decrypted =
            decrypt_file_v7(&encrypted, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn v7_roundtrip_multiple_chunks() {
        let kp = generate_hybrid_keypair().unwrap();
        let chunks: &[&[u8]] = &[b"chunk_0_data", b"chunk_1_data", b"chunk_2_data"];
        let encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, chunks).unwrap();
        let decrypted =
            decrypt_file_v7(&encrypted, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(decrypted, expected);
    }

    #[test]
    fn v7_roundtrip_empty_plaintext() {
        let kp = generate_hybrid_keypair().unwrap();
        let encrypted = encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[]).unwrap();
        let decrypted =
            decrypt_file_v7(&encrypted, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn v7_wrong_key_fails() {
        let kp = generate_hybrid_keypair().unwrap();
        let kp2 = generate_hybrid_keypair().unwrap();
        let encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[b"data"]).unwrap();
        assert!(
            decrypt_file_v7(&encrypted, &kp2.mlkem_secret_key, &kp2.x25519_secret_key).is_err()
        );
    }

    #[test]
    fn v7_tampered_ciphertext_fails() {
        let kp = generate_hybrid_keypair().unwrap();
        let mut encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[b"sensitive"]).unwrap();
        // Flip a byte in the chunk area (well past the header)
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0xff;
        assert!(decrypt_file_v7(&encrypted, &kp.mlkem_secret_key, &kp.x25519_secret_key).is_err());
    }

    #[test]
    fn v7_wrong_version_fails() {
        let kp = generate_hybrid_keypair().unwrap();
        let mut encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[b"data"]).unwrap();
        encrypted[0] = 0x06;
        assert!(decrypt_file_v7(&encrypted, &kp.mlkem_secret_key, &kp.x25519_secret_key).is_err());
    }

    #[test]
    fn v7_too_short_fails() {
        let kp = generate_hybrid_keypair().unwrap();
        assert!(decrypt_file_v7(&[0u8; 100], &kp.mlkem_secret_key, &kp.x25519_secret_key).is_err());
    }

    #[test]
    fn v7_stream_decryptor_matches_full_blob() {
        let kp = generate_hybrid_keypair().unwrap();
        let chunks: &[&[u8]] = &[b"first_chunk", b"second_chunk", b"third_chunk"];
        let encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, chunks).unwrap();

        // Split into: header(1709) | body | footer(32)
        let body_end = encrypted.len() - V7_FOOTER_LEN;
        let header = &encrypted[..V7_HEADER_MIN];
        let body = &encrypted[V7_HEADER_MIN..body_end];
        let footer = &encrypted[body_end..];

        let (mut dec, header_end) =
            V7StreamDecryptor::new(header, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(header_end, V7_HEADER_MIN);

        // Feed body one byte at a time to exercise partial-frame buffering.
        let mut plaintext = Vec::new();
        for b in body {
            plaintext.extend_from_slice(&dec.push(&[*b]).unwrap());
        }
        dec.finalize(footer).unwrap();

        let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn v7_stream_decryptor_detects_tampered_hmac() {
        let kp = generate_hybrid_keypair().unwrap();
        let encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[b"sensitive"]).unwrap();

        let body_end = encrypted.len() - V7_FOOTER_LEN;
        let header = &encrypted[..V7_HEADER_MIN];
        let body = &encrypted[V7_HEADER_MIN..body_end];
        let mut footer = encrypted[body_end..].to_vec();
        footer[0] ^= 0xff;

        let (mut dec, _) =
            V7StreamDecryptor::new(header, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        dec.push(body).unwrap();
        assert!(matches!(
            dec.finalize(&footer),
            Err(CryptoError::MacVerificationFailed)
        ));
    }

    #[test]
    fn v7_stream_decryptor_detects_truncated_body() {
        let kp = generate_hybrid_keypair().unwrap();
        let encrypted = encrypt_file_v7(
            &kp.mlkem_public_key,
            &kp.x25519_public_key,
            &[b"aaaaaaaaaa", b"bbbbbbbbbb"],
        )
        .unwrap();

        let body_end = encrypted.len() - V7_FOOTER_LEN;
        let header = &encrypted[..V7_HEADER_MIN];
        // Drop the last 10 bytes of the body — leaves an incomplete frame.
        let body = &encrypted[V7_HEADER_MIN..body_end - 10];
        let footer = &encrypted[body_end..];

        let (mut dec, _) =
            V7StreamDecryptor::new(header, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        dec.push(body).unwrap();
        assert!(matches!(
            dec.finalize(footer),
            Err(CryptoError::InvalidFormat(_))
        ));
    }

    #[test]
    fn v7_large_single_chunk() {
        let kp = generate_hybrid_keypair().unwrap();
        let data = vec![0xCCu8; 1024 * 1024]; // 1 MB
        let encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[&data]).unwrap();
        let decrypted =
            decrypt_file_v7(&encrypted, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(decrypted, data);
    }

    // ─── V7StreamEncryptor ────────────────────────────────────────────────

    /// Build a blob via the streaming encryptor and verify the full-blob
    /// decrypt accepts it byte-for-byte. Covers header layout, frame
    /// framing, and footer HMAC alignment with `encrypt_file_v7`.
    #[test]
    fn v7_stream_encryptor_output_decrypts_with_full_blob_decrypt() {
        let kp = generate_hybrid_keypair().unwrap();
        let chunks: [&[u8]; 4] = [
            b"chunk_alpha_____",
            b"chunk_beta______",
            b"chunk_gamma_____",
            b"chunk_delta_____",
        ];

        let (mut enc, header) =
            V7StreamEncryptor::new(&kp.mlkem_public_key, &kp.x25519_public_key).unwrap();
        assert_eq!(header.len(), V7_HEADER_MIN);

        let mut blob = header;
        for chunk in &chunks {
            let frame = enc.push(chunk).unwrap();
            // Frame structure: [len_le32(4) || nonce(12) || ct+tag(N+16)]
            assert!(frame.len() >= 4 + 12 + 16);
            blob.extend_from_slice(&frame);
        }
        let footer = enc.finalize();
        blob.extend_from_slice(&footer);

        // Round-trip via the full-blob decrypt — proves wire compatibility.
        let decrypted =
            decrypt_file_v7(&blob, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
        assert_eq!(decrypted, expected);
    }

    /// Stream-encrypt then stream-decrypt end-to-end without touching the
    /// full-blob convenience path. Verifies both streaming sides agree on
    /// framing, HMAC derivation, and nonce construction.
    #[test]
    fn v7_stream_encryptor_interop_with_stream_decryptor() {
        let kp = generate_hybrid_keypair().unwrap();

        let plaintext_chunks: Vec<Vec<u8>> = (0..8)
            .map(|i| (0..512).map(|j| (i * 7 + j) as u8).collect())
            .collect();

        // Encrypt
        let (mut enc, header) =
            V7StreamEncryptor::new(&kp.mlkem_public_key, &kp.x25519_public_key).unwrap();
        let mut blob = header.clone();
        for chunk in &plaintext_chunks {
            blob.extend_from_slice(&enc.push(chunk).unwrap());
        }
        let footer = enc.finalize();

        // Decrypt via the streaming decryptor: header → push(body) → finalize(footer)
        let body = blob[V7_HEADER_MIN..].to_vec();
        let (mut dec, _) =
            V7StreamDecryptor::new(&header, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        let plaintext = dec.push(&body).unwrap();
        dec.finalize(&footer).unwrap();

        let expected: Vec<u8> = plaintext_chunks.iter().flatten().copied().collect();
        assert_eq!(plaintext, expected);
    }

    // ─── v7_cipher_size ───────────────────────────────────────────────────────

    #[test]
    fn v7_cipher_size_empty() {
        // 0 bytes → no chunks; just header + footer
        assert_eq!(
            v7_cipher_size(0, 512 * 1024),
            (V7_HEADER_MIN + V7_FOOTER_LEN) as u64
        );
    }

    #[test]
    fn v7_cipher_size_single_chunk_1kib() {
        // 1 KiB fits in one chunk: header + 1*(32) + 1024 + footer
        let expected = V7_HEADER_MIN as u64 + 32 + 1024 + V7_FOOTER_LEN as u64;
        assert_eq!(v7_cipher_size(1024, 512 * 1024), expected);
    }

    #[test]
    fn v7_cipher_size_1mib_two_chunks() {
        // 1 MiB with 512 KiB chunk size = 2 chunks
        let plaintext = 1024u64 * 1024;
        let expected = V7_HEADER_MIN as u64 + 2 * 32 + plaintext + V7_FOOTER_LEN as u64;
        assert_eq!(v7_cipher_size(plaintext, 512 * 1024), expected);
    }

    #[test]
    fn v7_cipher_size_exact_chunk_boundary() {
        let chunk = 512u64 * 1024;
        // Exactly one chunk
        let one = v7_cipher_size(chunk, chunk as u32);
        // One byte more = two chunks
        let two = v7_cipher_size(chunk + 1, chunk as u32);
        assert_eq!(
            one,
            V7_HEADER_MIN as u64 + 32 + chunk + V7_FOOTER_LEN as u64
        );
        assert_eq!(
            two,
            V7_HEADER_MIN as u64 + 2 * 32 + (chunk + 1) + V7_FOOTER_LEN as u64
        );
    }

    /// Verify v7_cipher_size predicts the actual output of the full-blob encryptor.
    ///
    /// We use `encrypt_file_v7` as the reference because it is what clients call for
    /// pre-sized blobs. The streaming encryptor emits an extra frame when `push(&[])`
    /// is called, which is not the normal 0-byte usage pattern.
    #[test]
    fn v7_cipher_size_matches_actual_output() {
        let kp = generate_hybrid_keypair().unwrap();
        let chunk_size: u32 = 512 * 1024;

        // 0 bytes: no chunks in the blob
        let blob0 = encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[]).unwrap();
        assert_eq!(blob0.len() as u64, v7_cipher_size(0, chunk_size));

        // Single chunk ≤ chunk_size
        for &len in &[1usize, 1024, 512 * 1024] {
            let data = vec![0xBBu8; len];
            let blob =
                encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[&data]).unwrap();
            assert_eq!(
                blob.len() as u64,
                v7_cipher_size(len as u64, chunk_size),
                "mismatch for plaintext_len={len}"
            );
        }

        // Two chunks
        let len = 512 * 1024 + 1;
        let data = vec![0xBBu8; len];
        let chunk1 = &data[..512 * 1024];
        let chunk2 = &data[512 * 1024..];
        let blob2 = encrypt_file_v7(
            &kp.mlkem_public_key,
            &kp.x25519_public_key,
            &[chunk1, chunk2],
        )
        .unwrap();
        assert_eq!(
            blob2.len() as u64,
            v7_cipher_size(len as u64, chunk_size),
            "mismatch for plaintext_len={len}"
        );
    }

    // ─── FooterTrimmer ───────────────────────────────────────────────────────

    #[test]
    fn footer_trimmer_single_push_exactly_keep() {
        let mut ft = FooterTrimmer::new(32);
        let out = ft.push(&[0u8; 32]);
        assert!(out.is_empty());
        let (body, footer) = ft.finalize().unwrap();
        assert!(body.is_empty());
        assert_eq!(footer.len(), 32);
    }

    #[test]
    fn footer_trimmer_push_more_than_keep() {
        let mut ft = FooterTrimmer::new(32);
        let out = ft.push(&[0xAAu8; 50]);
        assert_eq!(out.len(), 18); // 50 - 32
        let (body, footer) = ft.finalize().unwrap();
        assert!(body.is_empty());
        assert_eq!(footer.len(), 32);
    }

    #[test]
    fn footer_trimmer_multi_push_boundary() {
        // Push 40 then 40 with keep=32; total=80; release=48
        let mut ft = FooterTrimmer::new(32);
        let r1 = ft.push(&[0x01u8; 40]);
        assert_eq!(r1.len(), 8); // 40 - 32
        let r2 = ft.push(&[0x02u8; 40]);
        assert_eq!(r2.len(), 40); // 80 - 32 - 8 already released
        let (body, footer) = ft.finalize().unwrap();
        assert!(body.is_empty());
        assert_eq!(footer.len(), 32);
    }

    #[test]
    fn footer_trimmer_insufficient_bytes_errors() {
        let mut ft = FooterTrimmer::new(32);
        ft.push(&[0u8; 10]);
        assert!(ft.finalize().is_err());
    }

    #[test]
    fn footer_trimmer_separates_footer_correctly() {
        let keep = V7_FOOTER_LEN;
        let mut ft = FooterTrimmer::new(keep);
        let body_bytes = vec![0xBBu8; 64];
        let footer_bytes = vec![0xFFu8; keep];
        let combined = [body_bytes.as_slice(), footer_bytes.as_slice()].concat();
        let released = ft.push(&combined);
        assert_eq!(released, body_bytes);
        let (remaining_body, footer) = ft.finalize().unwrap();
        assert!(remaining_body.is_empty());
        assert_eq!(footer, footer_bytes);
    }

    /// A single 1 MB chunk through the streaming encryptor produces a blob
    /// that the full-blob decrypt accepts. Mirror of `v7_large_single_chunk`
    /// but via the streaming encrypt path.
    #[test]
    fn v7_stream_encryptor_large_chunk_round_trip() {
        let kp = generate_hybrid_keypair().unwrap();
        let data = vec![0xA7u8; 1024 * 1024];

        let (mut enc, header) =
            V7StreamEncryptor::new(&kp.mlkem_public_key, &kp.x25519_public_key).unwrap();
        let mut blob = header;
        blob.extend_from_slice(&enc.push(&data).unwrap());
        blob.extend_from_slice(&enc.finalize());

        let decrypted =
            decrypt_file_v7(&blob, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(decrypted, data);
    }

    // ── V7ShareDecryptor tests ─────────────────────────────────────────────

    /// Helper: encrypt data with full KEM, then extract the content_key by decapsulating.
    fn encrypt_and_extract_key(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use crate::crypto::pqc::generate_hybrid_keypair;
        let kp = generate_hybrid_keypair().unwrap();
        let encrypted =
            encrypt_file_v7(&kp.mlkem_public_key, &kp.x25519_public_key, &[data]).unwrap();
        let init = decrypt_file_v7_init(
            &encrypted[..V7_HEADER_MIN],
            &kp.mlkem_secret_key,
            &kp.x25519_secret_key,
        )
        .unwrap();
        let ck_bytes = init.content_key.as_bytes().to_vec();
        (encrypted, ck_bytes)
    }

    #[test]
    fn share_decryptor_happy_path() {
        let data = b"share decryption roundtrip";
        let (encrypted, ck_bytes) = encrypt_and_extract_key(data);
        // Pass only the header — passing the full blob would put body+footer in leftover,
        // causing double-feed when we subsequently call push(body).
        let (mut dec, offset) = V7ShareDecryptor::new(&encrypted[..V7_HEADER_MIN], &ck_bytes).unwrap();
        assert_eq!(offset, V7_HEADER_MIN);
        let body = &encrypted[V7_HEADER_MIN..encrypted.len() - 32];
        let plaintext = dec.push(body).unwrap();
        let footer = &encrypted[encrypted.len() - 32..];
        dec.finalize(footer).unwrap();
        assert_eq!(plaintext, data);
    }

    #[test]
    fn share_decryptor_wrong_key_rejected() {
        let data = b"sensitive content";
        let (encrypted, _) = encrypt_and_extract_key(data);
        // Use a zero key — commitment check must fail.
        let wrong_key = vec![0u8; 32];
        let result = V7ShareDecryptor::new(&encrypted[..V7_HEADER_MIN], &wrong_key);
        assert!(result.is_err(), "expected error with wrong key");
        let err = result.err().unwrap();
        assert!(
            matches!(err, crate::error::CryptoError::KeyCommitmentFailed),
            "expected KeyCommitmentFailed"
        );
    }

    #[test]
    fn share_decryptor_tampered_commitment_rejected() {
        let data = b"must not decrypt";
        let (mut encrypted, ck_bytes) = encrypt_and_extract_key(data);
        // Flip a byte in the key_commitment field (offset 1677, length 32).
        encrypted[1677] ^= 0xFF;
        let result = V7ShareDecryptor::new(&encrypted[..V7_HEADER_MIN], &ck_bytes);
        assert!(result.is_err(), "expected error after commitment tampering");
        let err = result.err().unwrap();
        assert!(
            matches!(err, crate::error::CryptoError::KeyCommitmentFailed),
            "expected KeyCommitmentFailed after tampering"
        );
    }

    #[test]
    fn share_decryptor_truncated_ciphertext_fails_finalize() {
        let data = b"another secret";
        let (encrypted, ck_bytes) = encrypt_and_extract_key(data);
        let (mut dec, _) = V7ShareDecryptor::new(&encrypted[..V7_HEADER_MIN], &ck_bytes).unwrap();
        // Push only half the body (truncated).
        let half = (encrypted.len() - V7_HEADER_MIN - 32) / 2;
        let partial = &encrypted[V7_HEADER_MIN..V7_HEADER_MIN + half];
        let _ = dec.push(partial).unwrap();
        // finalize with wrong/empty HMAC must fail.
        let fake_footer = vec![0u8; 32];
        let result = dec.finalize(&fake_footer);
        assert!(result.is_err(), "finalize must fail with truncated/wrong HMAC");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod proptest_tests {
    use super::*;
    use crate::crypto::pqc::generate_hybrid_keypair;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(20))]

        #[test]
        fn v7_roundtrip_arbitrary_single_chunk(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
            let kp = generate_hybrid_keypair().unwrap();
            let encrypted = encrypt_file_v7(
                &kp.mlkem_public_key,
                &kp.x25519_public_key,
                &[&data],
            ).unwrap();
            let decrypted = decrypt_file_v7(
                &encrypted,
                &kp.mlkem_secret_key,
                &kp.x25519_secret_key,
            ).unwrap();
            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn v7_decryption_fails_on_truncated_blob(data in proptest::collection::vec(any::<u8>(), 100..1000)) {
            let kp = generate_hybrid_keypair().unwrap();
            let encrypted = encrypt_file_v7(
                &kp.mlkem_public_key,
                &kp.x25519_public_key,
                &[&data],
            ).unwrap();
            // Truncate to various lengths — all must fail decryption
            let truncated = &encrypted[..encrypted.len() / 2];
            let result = decrypt_file_v7(truncated, &kp.mlkem_secret_key, &kp.x25519_secret_key);
            prop_assert!(result.is_err());
        }
    }
}
