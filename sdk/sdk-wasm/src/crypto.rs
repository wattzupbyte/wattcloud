// V7 chunked file encryption/decryption WASM bindings.
//
// Large binary data is passed as Vec<u8> (auto-converted to/from Uint8Array by wasm-bindgen).
// Small key material (32–64 byte keys, nonces) stays as base64 strings in JSON objects.
//
//   encrypt_file_v7_init    → { file_iv, eph_x25519_pub, mlkem_ct, encrypted_file_key,
//                                key_commitment, content_key }  (all base64 — small key material)
//   encrypt_file_v7_chunk   → { ciphertext: Uint8Array, nonce: base64, chunk_index }
//   compute_v7_hmac         → base64 string (plain, not an object)
//   decrypt_file_v7_init    → { file_iv, content_key, header_end }  (all base64 — small)
//   decrypt_file_v7_chunk   → Uint8Array plaintext
//   encrypt_file_v7         → Uint8Array  (convenience, full blob)
//   decrypt_file_v7         → Uint8Array  (convenience, full blob)
//
// Both streaming and full-blob paths use the same HMAC key derivation:
//   HKDF-SHA256(content_key, info=CHUNK_HMAC_V1, L=32)
// Pass content_key (not hmac_key — that field no longer exists) to compute_v7_hmac /
// verify_v7_hmac. The HMAC key is always derived internally: HKDF(content_key, CHUNK_HMAC_V1).

use sdk_core::byo::streaming::{
    ByoDownloadFlow as CoreByoDownloadFlow, ByoUploadFlow as CoreByoUploadFlow,
};
use sdk_core::crypto::{
    constants::{V7_ENCRYPT_CHUNK_SIZE, V7_FOOTER_LEN},
    filename::encrypt_filename as sdk_encrypt_filename,
    hashing::constant_time_eq,
    symmetric::v7_chunk_nonce,
    wire_format::{
        compute_v7_hmac as sdk_compute_v7_hmac, decrypt_file_v7 as sdk_decrypt_v7,
        decrypt_file_v7_chunk as sdk_decrypt_chunk, decrypt_file_v7_init as sdk_decrypt_init,
        encrypt_file_v7 as sdk_encrypt_v7, encrypt_file_v7_chunk as sdk_encrypt_chunk,
        encrypt_file_v7_init as sdk_encrypt_init, v7_cipher_size as sdk_v7_cipher_size,
        FooterTrimmer as CoreFooterTrimmer, V7StreamDecryptor as CoreV7StreamDecryptor,
        V7StreamEncryptor as CoreV7StreamEncryptor,
    },
    zeroize_utils::{Nonce12, SymmetricKey},
};
use wasm_bindgen::prelude::*;

use crate::util::{b64_decode, b64_encode, js_set, parse_public_keys, parse_secret_keys};

/// Initialize v7 encryption: KEM encapsulation + key commitment.
///
/// `pub_keys_json` — `{"mlkem_public_key":"...","x25519_public_key":"..."}`.
///
/// Returns `{ file_iv, eph_x25519_pub, mlkem_ct, encrypted_file_key, key_commitment,
///             content_key }` (all base64) or `null` on error.
#[wasm_bindgen]
pub fn encrypt_file_v7_init(pub_keys_json: String) -> JsValue {
    let (mlkem_pub, x25519_pub) = match parse_public_keys(&pub_keys_json) {
        Ok(keys) => keys,
        Err(_) => return JsValue::NULL,
    };
    match sdk_encrypt_init(&mlkem_pub, &x25519_pub) {
        Ok(init) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "file_iv",
                &JsValue::from_str(&b64_encode(init.file_iv.as_bytes())),
            );
            js_set(
                &obj,
                "eph_x25519_pub",
                &JsValue::from_str(&b64_encode(&init.eph_x25519_pub)),
            );
            js_set(
                &obj,
                "mlkem_ct",
                &JsValue::from_str(&b64_encode(&init.mlkem_ct)),
            );
            js_set(
                &obj,
                "encrypted_file_key",
                &JsValue::from_str(&b64_encode(&init.encrypted_file_key)),
            );
            js_set(
                &obj,
                "key_commitment",
                &JsValue::from_str(&b64_encode(&init.key_commitment)),
            );
            js_set(
                &obj,
                "content_key",
                &JsValue::from_str(&b64_encode(init.content_key.as_bytes())),
            );
            obj.into()
        }
        Err(_) => JsValue::NULL,
    }
}

/// Encrypt a single v7 chunk.
///
/// Returns `{ ciphertext: Uint8Array, nonce: base64, chunk_index }` or `null`.
/// `ciphertext` is returned as a `Uint8Array` to avoid base64 overhead on large chunks.
/// `nonce` (12 bytes) stays as base64 — it is small key material.
#[wasm_bindgen]
pub fn encrypt_file_v7_chunk(
    chunk_data: Vec<u8>,
    content_key_b64: String,
    file_iv_b64: String,
    chunk_index: u32,
) -> JsValue {
    let key_bytes = match b64_decode(&content_key_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::NULL,
    };
    let iv_bytes = match b64_decode(&file_iv_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::NULL,
    };
    let key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(_) => return JsValue::NULL,
    };
    let file_iv = match Nonce12::from_slice(&iv_bytes) {
        Ok(n) => n,
        Err(_) => return JsValue::NULL,
    };
    let nonce = v7_chunk_nonce(&file_iv, chunk_index);
    match sdk_encrypt_chunk(&chunk_data, &key, &file_iv, chunk_index) {
        Ok(ciphertext) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "ciphertext",
                &js_sys::Uint8Array::from(ciphertext.as_slice()).into(),
            );
            js_set(
                &obj,
                "nonce",
                &JsValue::from_str(&b64_encode(nonce.as_bytes())),
            );
            js_set(&obj, "chunk_index", &JsValue::from_f64(chunk_index as f64));
            obj.into()
        }
        Err(_) => JsValue::NULL,
    }
}

/// Compute HMAC-SHA256 over accumulated chunk data for streaming encryption.
///
/// `content_key_b64` — the `content_key` field from `encrypt_file_v7_init`.
/// `chunks_data` — raw bytes of concatenated `(chunk_index_le32 || ciphertext)` for each chunk.
///
/// Derives the HMAC key internally: HKDF-SHA256(content_key, CHUNK_HMAC_V1, L=32).
/// This matches the full-blob `encrypt_file_v7` / `decrypt_file_v7` path exactly.
///
/// Returns a base64 string (not an object) or `null` on error.
#[wasm_bindgen]
pub fn compute_v7_hmac(content_key_b64: String, chunks_data: Vec<u8>) -> JsValue {
    let key_bytes = match b64_decode(&content_key_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::NULL,
    };
    let key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(_) => return JsValue::NULL,
    };
    match sdk_compute_v7_hmac(&key, &chunks_data) {
        Ok(mac) => JsValue::from_str(&b64_encode(&mac)),
        Err(_) => JsValue::NULL,
    }
}

/// Verify the v7 HMAC during streaming decryption (constant-time).
///
/// `content_key_b64` — the `content_key` field from `decrypt_file_v7_init`.
/// `chunks_data` — raw bytes of concatenated `(chunk_index_le32 || ciphertext)` for each chunk.
/// `stored_hmac` — the 32-byte HMAC at the end of the v7 blob.
///
/// Returns `true` if the HMAC matches, `false` on mismatch or any parse error.
#[wasm_bindgen]
pub fn verify_v7_hmac(
    content_key_b64: String,
    chunks_data: Vec<u8>,
    stored_hmac: Vec<u8>,
) -> JsValue {
    let key_bytes = match b64_decode(&content_key_b64) {
        Ok(b) => b,
        Err(_) => return JsValue::from_bool(false),
    };
    let key = match SymmetricKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(_) => return JsValue::from_bool(false),
    };
    match sdk_compute_v7_hmac(&key, &chunks_data) {
        Ok(computed) => JsValue::from_bool(constant_time_eq(&computed, &stored_hmac)),
        Err(_) => JsValue::from_bool(false),
    }
}

/// Initialize v7 decryption: parse header, decapsulate keys, verify key commitment.
///
/// `encrypted_data` — raw bytes of the full v7 blob.
/// `sec_keys_json` — `{"mlkem_secret_key":"...","x25519_secret_key":"..."}`.
///
/// Returns `{ file_iv, content_key, header_end }` or `null`.
#[wasm_bindgen]
pub fn decrypt_file_v7_init(encrypted_data: Vec<u8>, sec_keys_json: String) -> JsValue {
    let (mlkem_sec, x25519_sec) = match parse_secret_keys(&sec_keys_json) {
        Ok(keys) => keys,
        Err(_) => return JsValue::NULL,
    };
    match sdk_decrypt_init(&encrypted_data, &mlkem_sec, &x25519_sec) {
        Ok(init) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "file_iv",
                &JsValue::from_str(&b64_encode(init.file_iv.as_bytes())),
            );
            js_set(
                &obj,
                "content_key",
                &JsValue::from_str(&b64_encode(init.content_key.as_bytes())),
            );
            js_set(
                &obj,
                "header_end",
                &JsValue::from_f64(init.header_end as f64),
            );
            obj.into()
        }
        Err(_) => JsValue::NULL,
    }
}

/// Decrypt a single v7 chunk.
///
/// Returns the plaintext as a `Uint8Array` or `null` on error.
#[wasm_bindgen]
pub fn decrypt_file_v7_chunk(
    ciphertext: Vec<u8>,
    content_key_b64: String,
    file_iv_b64: String,
    chunk_index: u32,
) -> Option<Vec<u8>> {
    let key_bytes = b64_decode(&content_key_b64).ok()?;
    let iv_bytes = b64_decode(&file_iv_b64).ok()?;
    let key = SymmetricKey::from_slice(&key_bytes).ok()?;
    let file_iv = Nonce12::from_slice(&iv_bytes).ok()?;
    sdk_decrypt_chunk(&ciphertext, &key, &file_iv, chunk_index).ok()
}

/// Encrypt a complete file as a single v7 blob (convenience — loads entire file into memory).
///
/// Returns the encrypted bytes as a `Uint8Array` or `null` on error.
#[wasm_bindgen]
pub fn encrypt_file_v7(file_data: Vec<u8>, pub_keys_json: String) -> Option<Vec<u8>> {
    let (mlkem_pub, x25519_pub) = parse_public_keys(&pub_keys_json).ok()?;
    sdk_encrypt_v7(&mlkem_pub, &x25519_pub, &[&file_data]).ok()
}

// ─── Streaming decrypt ─────────────────────────────────────────────────────
//
// Stateful incremental V7 decryptor. Wraps sdk-core's `V7StreamDecryptor` so
// the content key and HMAC state live entirely inside the WASM context — the
// JS side only ever sees opaque plaintext byte buffers.

/// Incremental V7 decryptor for streaming downloads.
///
/// Typical lifecycle:
///   const dec = V7StreamDecryptorWasm.create(headerBytes, secKeysJson);
///   for await (const chunk of stream) { plaintext = dec.push(chunk); ... }
///   dec.finalize(footerBytes);
///
/// Both `push` and `finalize` throw a string on error. `finalize` takes
/// `self` by value (consuming the decryptor) and zeroises the content key.
#[wasm_bindgen]
pub struct V7StreamDecryptorWasm {
    inner: Option<CoreV7StreamDecryptor>,
    header_end: usize,
}

#[wasm_bindgen]
impl V7StreamDecryptorWasm {
    /// Parse the V7 header and initialise a streaming decryptor.
    ///
    /// `header_bytes` must contain at least 1709 bytes (V7_HEADER_MIN). Any
    /// extra bytes beyond the header are retained and will be parsed as
    /// chunk data on the first `push` call.
    #[wasm_bindgen(js_name = create)]
    pub fn create(
        header_bytes: Vec<u8>,
        sec_keys_json: String,
    ) -> Result<V7StreamDecryptorWasm, JsValue> {
        let (mlkem_sec, x25519_sec) = parse_secret_keys(&sec_keys_json)?;
        let (inner, header_end) =
            CoreV7StreamDecryptor::new(&header_bytes, &mlkem_sec, &x25519_sec)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(Self {
            inner: Some(inner),
            header_end,
        })
    }

    /// Byte offset where v7 chunk data begins (always 1709 for current format).
    #[wasm_bindgen(getter, js_name = headerEnd)]
    pub fn header_end(&self) -> usize {
        self.header_end
    }

    /// Feed more ciphertext bytes. Returns any plaintext now available.
    ///
    /// IMPORTANT: the caller must NOT pass the trailing 32-byte HMAC footer
    /// here — strip it off and pass it to `finalize` separately.
    pub fn push(&mut self, data: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("decryptor already finalized"))?;
        inner
            .push(&data)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Verify the trailing 32-byte HMAC footer and release the content key.
    ///
    /// Takes `&mut self` rather than `self` because wasm_bindgen does not
    /// support by-value consumption; the inner state is moved out so further
    /// calls fail cleanly.
    pub fn finalize(&mut self, stored_hmac: Vec<u8>) -> Result<(), JsValue> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("decryptor already finalized"))?;
        inner
            .finalize(&stored_hmac)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// Decrypt a complete v7 blob (convenience — loads entire blob into memory).
///
/// Returns the plaintext as a `Uint8Array` or `null` on error.
#[wasm_bindgen]
pub fn decrypt_file_v7(encrypted_data: Vec<u8>, sec_keys_json: String) -> Option<Vec<u8>> {
    let (mlkem_sec, x25519_sec) = parse_secret_keys(&sec_keys_json).ok()?;
    sdk_decrypt_v7(&encrypted_data, &mlkem_sec, &x25519_sec).ok()
}

// ─── Streaming encrypt ─────────────────────────────────────────────────────
//
// Stateful incremental V7 encryptor. Wraps sdk-core's `V7StreamEncryptor`
// so the content key, file IV, and HMAC state live entirely inside the
// WASM context — the JS side only ever sees opaque ciphertext frame bytes.

/// Incremental V7 encryptor for streaming uploads.
///
/// Typical lifecycle:
///   const enc = V7StreamEncryptorWasm.create(pubKeysJson);
///   const header = enc.takeHeader();          // 1709 bytes, upload first
///   for await (const plaintextChunk of file) {
///     const frame = enc.push(plaintextChunk); // [len || nonce || ct+tag]
///     upload(frame);
///   }
///   const footer = enc.finalize();            // 32-byte HMAC footer, upload last
///
/// `push` and `finalize` throw a string on error. `takeHeader` can only be
/// called once — the second call throws. `finalize` uses the same
/// `Option::take()` pattern as the decryptor because wasm_bindgen does not
/// support by-value consumption.
#[wasm_bindgen]
pub struct V7StreamEncryptorWasm {
    inner: Option<CoreV7StreamEncryptor>,
    header: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl V7StreamEncryptorWasm {
    /// Run KEM encapsulation and initialise a streaming encryptor.
    ///
    /// `pub_keys_json` — `{"mlkem_public_key":"...","x25519_public_key":"..."}`.
    #[wasm_bindgen(js_name = create)]
    pub fn create(pub_keys_json: String) -> Result<V7StreamEncryptorWasm, JsValue> {
        let (mlkem_pub, x25519_pub) = parse_public_keys(&pub_keys_json)
            .map_err(|e| JsValue::from_str(&format!("invalid public keys: {:?}", e)))?;
        let (inner, header) = CoreV7StreamEncryptor::new(&mlkem_pub, &x25519_pub)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(Self {
            inner: Some(inner),
            header: Some(header),
        })
    }

    /// Consume and return the 1709-byte V7 header.
    ///
    /// Must be called exactly once per encryptor, before the first `push`
    /// (or at any point before `finalize`). Subsequent calls throw.
    #[wasm_bindgen(js_name = takeHeader)]
    pub fn take_header(&mut self) -> Result<Vec<u8>, JsValue> {
        self.header
            .take()
            .ok_or_else(|| JsValue::from_str("v7 stream header already taken"))
    }

    /// Encrypt one plaintext chunk and return the complete wire frame.
    ///
    /// The frame is `[chunk_len_le32(4) || nonce(12) || ciphertext+gcm_tag]`
    /// and is ready to be uploaded verbatim. Each call consumes one chunk —
    /// the encryptor does not buffer plaintext across calls.
    pub fn push(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("encryptor already finalized"))?;
        inner
            .push(&plaintext)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Return the 32-byte HMAC footer and release the content key.
    ///
    /// Takes `&mut self` because wasm_bindgen does not support by-value
    /// consumption; the inner state is moved out so further calls fail
    /// cleanly.
    pub fn finalize(&mut self) -> Result<Vec<u8>, JsValue> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("encryptor already finalized"))?;
        Ok(inner.finalize().to_vec())
    }
}

// ─── Atomic filename encryption ────────────────────────────────────────────
//
// Collapses the three-step main-thread dance (generate filename key,
// encrypt filename, wrap filename key with user's hybrid KEM) into a
// single atomic WASM call so the filename key is never exposed to JS.

/// Encrypt a filename with a fresh random key, wrap that key for the
/// recipient's hybrid KEM, and return both in one call.
///
/// The 32-byte filename key is generated inside WASM via the platform
/// CSPRNG (`OsRng` → `crypto.getRandomValues`), used exactly once, and
/// dropped when this function returns — it never touches JS memory.
///
/// `metadata` is an optional second plaintext (typically a JSON blob of
/// EXIF fields) that is encrypted with the SAME filename key. The upload
/// pipeline reuses the wrapped key to decrypt both filename and metadata,
/// so encrypting them together saves one KEM wrap and keeps the key
/// usage atomic.
///
/// `pub_keys_json` — `{"mlkem_public_key":"...","x25519_public_key":"..."}`
///
/// Returns:
///   { encrypted_filename: base64,         // nonce(12) || ct+tag for the filename
///     encrypted_metadata: base64 | null,  // same layout, present iff `metadata` was Some
///     encrypted_filename_key: base64 }    // full v7 blob wrapping the 32-byte key
#[wasm_bindgen]
pub fn encrypt_filename_with_fresh_key(
    filename: String,
    metadata: Option<String>,
    pub_keys_json: String,
) -> Result<JsValue, JsValue> {
    use sdk_core::crypto::symmetric::generate_aes_key;

    let (mlkem_pub, x25519_pub) = parse_public_keys(&pub_keys_json)
        .map_err(|e| JsValue::from_str(&format!("invalid public keys: {:?}", e)))?;

    // 1. Generate the filename key inside WASM. SymmetricKey is Zeroize.
    let filename_key = generate_aes_key()
        .map_err(|e| JsValue::from_str(&format!("filename key generation failed: {}", e)))?;

    // 2. Encrypt the filename with AES-GCM-SIV (deterministic nonce).
    let encrypted_filename = sdk_encrypt_filename(&filename, &filename_key)
        .map_err(|e| JsValue::from_str(&format!("filename encryption failed: {}", e)))?;

    // 2b. Optional metadata — encrypted with the same symmetric key.
    let encrypted_metadata = if let Some(meta) = metadata {
        Some(
            sdk_encrypt_filename(&meta, &filename_key)
                .map_err(|e| JsValue::from_str(&format!("metadata encryption failed: {}", e)))?,
        )
    } else {
        None
    };

    // 3. Wrap the filename key using the same v7 blob format used by
    //    the existing `encrypt_file_v7` path, so the server-side verification
    //    and the unwrap path are unchanged.
    let wrapped_key = sdk_encrypt_v7(&mlkem_pub, &x25519_pub, &[filename_key.as_bytes()])
        .map_err(|e| JsValue::from_str(&format!("filename key wrap failed: {}", e)))?;

    // Zeroize drop of `filename_key` happens here.

    let obj = js_sys::Object::new();
    js_set(
        &obj,
        "encrypted_filename",
        &JsValue::from_str(&b64_encode(&encrypted_filename)),
    );
    match encrypted_metadata {
        Some(meta_bytes) => js_set(
            &obj,
            "encrypted_metadata",
            &JsValue::from_str(&b64_encode(&meta_bytes)),
        ),
        None => js_set(&obj, "encrypted_metadata", &JsValue::NULL),
    }
    js_set(
        &obj,
        "encrypted_filename_key",
        &JsValue::from_str(&b64_encode(&wrapped_key)),
    );
    Ok(obj.into())
}

// ─── V7 sizing helpers ────────────────────────────────────────────────────────

/// Compute the encrypted byte length of a V7 file given `plaintext_len` bytes and
/// a `chunk_size` (recommend `v7EncryptChunkSize()`).
///
/// Both arguments are `f64` to avoid JS BigInt — they must be finite, ≥ 0, and
/// < 2^53. Returns an f64 (exact for file sizes within that range).
#[wasm_bindgen(js_name = v7CipherSize)]
pub fn v7_cipher_size(plaintext_len: f64, chunk_size: f64) -> Result<f64, JsValue> {
    if !plaintext_len.is_finite() || !(0.0..=9007199254740992.0).contains(&plaintext_len) {
        return Err(JsValue::from_str(
            "v7CipherSize: plaintext_len out of range",
        ));
    }
    if !chunk_size.is_finite() || !(1.0..=9007199254740992.0).contains(&chunk_size) {
        return Err(JsValue::from_str("v7CipherSize: chunk_size must be ≥ 1"));
    }
    let result = sdk_v7_cipher_size(plaintext_len as u64, chunk_size as u32);
    Ok(result as f64)
}

/// The recommended plaintext chunk size for V7 streaming encryption (512 KiB).
///
/// Returns `f64` (exact: 524288.0) — use this value when calling `v7CipherSize`.
#[wasm_bindgen(js_name = v7EncryptChunkSize)]
pub fn v7_encrypt_chunk_size() -> f64 {
    V7_ENCRYPT_CHUNK_SIZE as f64
}

// ─── FooterTrimmer ─────────────────────────────────────────────────────────────

/// Streaming footer separator for V7 downloads.
///
/// Buffers the trailing `keep` bytes of a ciphertext stream and releases earlier
/// bytes for decryption. `finalize()` returns `{ body: Uint8Array, footer: Uint8Array }`.
///
/// Typical use: `new FooterTrimmer(32)` (V7_FOOTER_LEN).
#[wasm_bindgen(js_name = FooterTrimmer)]
pub struct FooterTrimmerWasm {
    inner: Option<CoreFooterTrimmer>,
}

#[wasm_bindgen(js_class = FooterTrimmer)]
impl FooterTrimmerWasm {
    #[wasm_bindgen(constructor)]
    pub fn new(keep: u32) -> Self {
        Self {
            inner: Some(CoreFooterTrimmer::new(keep as usize)),
        }
    }

    /// Push ciphertext bytes. Returns bytes that are safe to pass to the V7 decryptor.
    pub fn push(&mut self, bytes: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        let ft = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("FooterTrimmer: already finalized"))?;
        Ok(ft.push(&bytes))
    }

    /// Signal end of stream. Returns `{ body: Uint8Array, footer: Uint8Array }`.
    /// The instance must not be used after calling this.
    pub fn finalize(&mut self) -> Result<JsValue, JsValue> {
        let ft = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("FooterTrimmer: already finalized"))?;
        let (body, footer) = ft
            .finalize()
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let obj = js_sys::Object::new();
        js_set(
            &obj,
            "body",
            &js_sys::Uint8Array::from(body.as_slice()).into(),
        );
        js_set(
            &obj,
            "footer",
            &js_sys::Uint8Array::from(footer.as_slice()).into(),
        );
        Ok(obj.into())
    }

    /// Returns the V7 footer length (32 bytes) as a convenience constant.
    #[wasm_bindgen(js_name = footerLen, getter)]
    pub fn footer_len() -> u32 {
        V7_FOOTER_LEN as u32
    }
}

// ─── ByoDownloadFlow ───────────────────────────────────────────────────────
//
// Single-object replacement for the V7StreamDecryptorWasm + FooterTrimmerWasm
// combination used in DownloadStream.ts.  The caller simply feeds raw provider
// bytes; header buffering, footer trimming, and HMAC verification are all
// internal.
//
// Lifecycle:
//   const flow = ByoDownloadFlowWasm.create(secKeysJson);
//   while (bytes = await provider.readChunk()) {
//     const plaintext = flow.push(bytes);          // may return empty Uint8Array
//     if (plaintext.length) sink.write(plaintext);
//   }
//   flow.finalize();   // throws on HMAC failure — discard prior plaintext if so

/// Streaming V7 download flow (header buffering + footer trimming + HMAC verification).
///
/// `sec_keys_json` — `{"mlkem_secret_key":"...","x25519_secret_key":"..."}` (base64).
///
/// `push` returns whatever plaintext is available (may be empty).
/// `finalize` consumes the flow and verifies the HMAC footer; throws on mismatch.
#[wasm_bindgen(js_name = ByoDownloadFlow)]
pub struct ByoDownloadFlowWasm {
    inner: Option<CoreByoDownloadFlow>,
}

#[wasm_bindgen(js_class = ByoDownloadFlow)]
impl ByoDownloadFlowWasm {
    /// Initialise a download flow with the recipient's private keys.
    #[wasm_bindgen(js_name = create)]
    pub fn create(sec_keys_json: String) -> Result<ByoDownloadFlowWasm, JsValue> {
        let (mlkem_sec, x25519_sec) = parse_secret_keys(&sec_keys_json)?;
        Ok(Self {
            inner: Some(CoreByoDownloadFlow::new(mlkem_sec, x25519_sec)),
        })
    }

    /// Feed raw ciphertext bytes. Returns any plaintext now available (may be empty).
    ///
    /// Buffers internally until the 1709-byte V7 header has been received,
    /// then streams plaintext for each complete AES-GCM frame.
    pub fn push(&mut self, data: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("ByoDownloadFlow: already finalized"))?;
        inner
            .push(&data)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Verify the trailing 32-byte HMAC footer.
    ///
    /// Must be called once after all ciphertext has been fed via `push`.
    /// Throws on HMAC mismatch — any plaintext emitted by `push` MUST be
    /// discarded if this throws.
    pub fn finalize(&mut self) -> Result<(), JsValue> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("ByoDownloadFlow: already finalized"))?;
        inner.finalize().map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

// ─── ByoUploadFlow ─────────────────────────────────────────────────────────
//
// Single-object replacement for V7StreamEncryptorWasm that also pre-computes
// the total ciphertext size (for provider `Content-Length` headers).
//
// Lifecycle:
//   const flow = ByoUploadFlowWasm.create(pubKeysJson, plaintextLen);
//   const header = flow.takeHeader();              // upload first
//   provider.openStream(flow.totalSize);
//   while (chunk = file.readChunk()) {
//     const isLast = file.eof();
//     const frame = flow.pushChunk(chunk, isLast); // ciphertext frame
//     provider.write(frame);
//   }
//   const footer = flow.finalize();                // 32-byte HMAC, upload last
//   provider.close();

/// Streaming V7 upload flow with pre-declared total ciphertext size.
///
/// `pub_keys_json` — `{"mlkem_public_key":"...","x25519_public_key":"..."}` (base64).
/// `plaintext_len` — exact number of plaintext bytes that will be pushed (f64 to avoid BigInt).
#[wasm_bindgen(js_name = ByoUploadFlow)]
pub struct ByoUploadFlowWasm {
    inner: Option<CoreByoUploadFlow>,
    header: Option<Vec<u8>>,
    total_size: u64,
}

#[wasm_bindgen(js_class = ByoUploadFlow)]
impl ByoUploadFlowWasm {
    /// Run KEM encapsulation and initialise an upload flow.
    #[wasm_bindgen(js_name = create)]
    pub fn create(pub_keys_json: String, plaintext_len: f64) -> Result<ByoUploadFlowWasm, JsValue> {
        let (mlkem_pub, x25519_pub) = parse_public_keys(&pub_keys_json)
            .map_err(|e| JsValue::from_str(&format!("invalid public keys: {:?}", e)))?;
        let len = plaintext_len as u64;
        let (flow, header, total_size) = CoreByoUploadFlow::new(&mlkem_pub, &x25519_pub, len)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(Self {
            inner: Some(flow),
            header: Some(header),
            total_size,
        })
    }

    /// Total ciphertext size in bytes (header + frames + footer).
    ///
    /// Pass this to the provider's upload-stream open call to set
    /// `Content-Length`.  Returns `f64` to avoid JS BigInt.
    #[wasm_bindgen(getter, js_name = totalSize)]
    pub fn total_size(&self) -> f64 {
        self.total_size as f64
    }

    /// Consume and return the 1709-byte V7 header.
    ///
    /// Must be called exactly once per flow, before the first `pushChunk`.
    /// Subsequent calls throw.
    #[wasm_bindgen(js_name = takeHeader)]
    pub fn take_header(&mut self) -> Result<Vec<u8>, JsValue> {
        self.header
            .take()
            .ok_or_else(|| JsValue::from_str("ByoUploadFlow: header already taken"))
    }

    /// Encrypt one plaintext chunk and return the V7 wire frame to upload.
    ///
    /// Non-final chunks must be exactly `V7_ENCRYPT_CHUNK_SIZE` (512 KiB).
    /// The final chunk (`is_last = true`) may be any length including zero.
    /// Throws on wrong chunk size or after the last chunk has already been supplied.
    #[wasm_bindgen(js_name = pushChunk)]
    pub fn push_chunk(&mut self, plaintext: Vec<u8>, is_last: bool) -> Result<Vec<u8>, JsValue> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| JsValue::from_str("ByoUploadFlow: already finalized"))?;
        inner
            .push_chunk(&plaintext, is_last)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Number of chunks pushed so far. Exposes no key material.
    ///
    /// Use for "chunk N of M" progress reporting instead of approximating bytes.
    pub fn position(&self) -> u32 {
        self.inner.as_ref().map(|f| f.position()).unwrap_or(0)
    }

    /// Return the 32-byte HMAC footer and release the content key.
    ///
    /// Write the returned bytes to the upload stream as the very last bytes,
    /// then close the stream.
    pub fn finalize(&mut self) -> Result<Vec<u8>, JsValue> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("ByoUploadFlow: already finalized"))?;
        inner.finalize()
            .map(|footer| footer.to_vec())
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
