// BYO upload flow: V7 streaming encryption state machine.
//
// Ports the sequencing logic from `/byo/src/streaming/UploadStream.ts`:
//   1. KEM encapsulation → header bytes + total ciphertext size
//   2. Per-chunk: plaintext → V7 wire frame (encrypt + frame)
//   3. Finalise → 32-byte HMAC footer
//
// I/O stays entirely in the platform layer (sdk-wasm WritableStream /
// Android OutputStream). sdk-core holds the cryptographic state only.
//
// # Memory invariant
//
// At any instant the struct holds: V7StreamEncryptor state (fixed-size key
// material + HMAC context) + zero plaintext buffering. Total heap allocation
// is bounded by the encryptor's internal state regardless of `plaintext_len`.
//
// # Usage
//
// ```rust,ignore
// use sdk_core::byo::streaming::ByoUploadFlow;
//
// // Step 1: initialise — get header bytes and pre-declared total size.
// let (mut flow, header, total_size) =
//     ByoUploadFlow::new(&mlkem_pub, &x25519_pub, plaintext_len)?;
//
// provider.open_upload_stream(file_name, total_size).await?;
// provider.write(&header).await?;
//
// // Step 2: supply plaintext chunks one at a time.
// let chunk_sz = ByoUploadFlow::chunk_size();
// let mut offset = 0u64;
// while offset < plaintext_len {
//     let end = (offset + chunk_sz as u64).min(plaintext_len);
//     let chunk = &plaintext[offset as usize..end as usize];
//     let is_last = end == plaintext_len;
//     let frame = flow.push_chunk(chunk, is_last)?;
//     provider.write(&frame).await?;
//     offset = end;
// }
//
// // Step 3: finalise — upload the HMAC footer.
// let footer = flow.finalize()?;
// provider.write(&footer).await?;
// provider.close().await?;
// ```

use crate::byo::streaming::constants::V7_ENCRYPT_CHUNK_SIZE;
use crate::crypto::wire_format::{v7_cipher_size, V7StreamEncryptor};
use crate::crypto::zeroize_utils::{MlKemPublicKey, X25519PublicKey};
use crate::error::{CryptoError, SdkError, ValidationError};

/// V7 streaming upload flow.
///
/// Owns the `V7StreamEncryptor` so the content key and HMAC state never leave
/// this struct. The caller is responsible for all I/O and chunk sourcing.
pub struct ByoUploadFlow {
    encryptor: V7StreamEncryptor,
    /// True once `push_chunk(_, is_last=true)` has been called.
    last_pushed: bool,
}

impl ByoUploadFlow {
    /// Begin a new upload.
    ///
    /// Returns `(flow, header_bytes, total_ciphertext_size)`.
    ///
    /// - `header_bytes` (1709 bytes) must be written to the upload stream as
    ///   the very first bytes, before any calls to `push_chunk`.
    /// - `total_ciphertext_size` is the exact number of bytes the full V7 blob
    ///   will occupy (header + frames + footer). Providers use this to
    ///   pre-declare the upload size.
    ///
    /// `plaintext_len` must be the exact number of plaintext bytes that will be
    /// supplied across all `push_chunk` calls. Passing a wrong value does not
    /// cause a security failure but will cause `total_ciphertext_size` to be
    /// wrong, which may cause provider upload errors.
    pub fn new(
        mlkem_pub: &MlKemPublicKey,
        x25519_pub: &X25519PublicKey,
        plaintext_len: u64,
    ) -> Result<(Self, Vec<u8>, u64), SdkError> {
        let (encryptor, header) = V7StreamEncryptor::new(mlkem_pub, x25519_pub)?;
        let total_size = v7_cipher_size(plaintext_len, V7_ENCRYPT_CHUNK_SIZE as u32);
        Ok((
            // For an empty file (plaintext_len == 0) the caller may skip
            // push_chunk entirely and go straight to finalize(), so treat the
            // "last chunk" as already logically supplied.
            Self { encryptor, last_pushed: plaintext_len == 0 },
            header,
            total_size,
        ))
    }

    /// Encrypt one plaintext chunk and return the V7 wire frame to upload.
    ///
    /// # Chunk size contract
    ///
    /// - For all **non-final** chunks (`is_last = false`): `plaintext` must be
    ///   exactly [`ByoUploadFlow::chunk_size()`] bytes. Passing a shorter or
    ///   longer slice is a logic error and returns
    ///   [`SdkError::Validation`] without advancing internal state.
    /// - The **final** chunk (`is_last = true`): `plaintext` may be any
    ///   length, including zero (for an empty file).
    /// - `push_chunk` must not be called again after `is_last = true`.
    ///
    /// After the last push, call [`finalize`][Self::finalize] to obtain the
    /// footer.
    ///
    /// # Errors
    ///
    /// - [`SdkError::Validation`] — wrong chunk size for a non-final chunk.
    /// - [`SdkError::Crypto`] — AES-GCM encryption failed (non-recoverable).
    pub fn push_chunk(&mut self, plaintext: &[u8], is_last: bool) -> Result<Vec<u8>, SdkError> {
        if !is_last && plaintext.len() != V7_ENCRYPT_CHUNK_SIZE {
            return Err(SdkError::Validation(ValidationError::new(
                "invalid_byo_chunk_size",
                format!(
                    "non-final upload chunk must be exactly {} bytes, got {}",
                    V7_ENCRYPT_CHUNK_SIZE,
                    plaintext.len()
                ),
            )));
        }
        if self.last_pushed {
            return Err(SdkError::Validation(ValidationError::new(
                "upload_already_finalized",
                "push_chunk called after the final chunk was already supplied",
            )));
        }
        if is_last {
            self.last_pushed = true;
        }
        let frame = self.encryptor.push(plaintext)?;
        Ok(frame)
    }

    /// Consume the encryptor and return the 32-byte HMAC footer.
    ///
    /// Write the returned bytes to the upload stream as the very last bytes,
    /// then close the stream.
    ///
    /// Returns `Err` if `push_chunk` was never called with `is_last = true`.
    /// This guards against callers that forget to mark the last chunk, which
    /// would otherwise produce a valid-looking footer for an incomplete upload.
    pub fn finalize(self) -> Result<[u8; 32], SdkError> {
        if !self.last_pushed {
            return Err(SdkError::Crypto(CryptoError::InvalidFormat(
                "ByoUploadFlow::finalize called before push_chunk(_, is_last=true)".into(),
            )));
        }
        Ok(self.encryptor.finalize())
    }

    /// The expected plaintext chunk size for all non-final chunks (512 KiB).
    ///
    /// Use this to slice the plaintext source when iterating. The final chunk
    /// may be shorter.
    pub const fn chunk_size() -> usize {
        V7_ENCRYPT_CHUNK_SIZE
    }

    /// Number of chunks pushed so far. Read-only; exposes no key material.
    ///
    /// Callers can use this to report accurate per-chunk progress ("chunk N of M")
    /// instead of approximating from byte count.
    pub fn position(&self) -> u32 {
        self.encryptor.position()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::pqc::generate_hybrid_keypair;
    use crate::crypto::wire_format::decrypt_file_v7;

    fn fresh_kp() -> crate::crypto::zeroize_utils::HybridKeypair {
        generate_hybrid_keypair().unwrap()
    }

    // ─── Happy-path round-trip ────────────────────────────────────────────────

    #[test]
    fn empty_file_round_trips() {
        let kp = fresh_kp();
        let (flow, header, total_size) =
            ByoUploadFlow::new(&kp.mlkem_public_key, &kp.x25519_public_key, 0).unwrap();

        // No chunks for an empty file.
        let footer = flow.finalize().unwrap();

        let mut blob = header;
        blob.extend_from_slice(&footer);

        // total_size should equal header+footer only (no chunks).
        assert_eq!(blob.len() as u64, total_size);

        let pt = decrypt_file_v7(&blob, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn single_small_chunk_round_trips() {
        let kp = fresh_kp();
        let plaintext = b"hello byo streaming";
        let (mut flow, header, total_size) = ByoUploadFlow::new(
            &kp.mlkem_public_key,
            &kp.x25519_public_key,
            plaintext.len() as u64,
        )
        .unwrap();

        let frame = flow.push_chunk(plaintext, true).unwrap();
        let footer = flow.finalize().unwrap();

        let mut blob = header;
        blob.extend_from_slice(&frame);
        blob.extend_from_slice(&footer);

        assert_eq!(blob.len() as u64, total_size);

        let pt = decrypt_file_v7(&blob, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn multiple_chunks_round_trips() {
        let kp = fresh_kp();
        let chunk_sz = ByoUploadFlow::chunk_size();

        // 2 full chunks + 1 partial final chunk
        let plaintext: Vec<u8> = (0..2 * chunk_sz + 1337)
            .map(|i| (i % 251) as u8)
            .collect();
        let (mut flow, header, total_size) = ByoUploadFlow::new(
            &kp.mlkem_public_key,
            &kp.x25519_public_key,
            plaintext.len() as u64,
        )
        .unwrap();

        let mut blob = header;
        let mut offset = 0;
        while offset < plaintext.len() {
            let end = (offset + chunk_sz).min(plaintext.len());
            let is_last = end == plaintext.len();
            let chunk = &plaintext[offset..end];
            let frame = flow.push_chunk(chunk, is_last).unwrap();
            blob.extend_from_slice(&frame);
            offset = end;
        }
        let footer = flow.finalize().unwrap();
        blob.extend_from_slice(&footer);

        assert_eq!(blob.len() as u64, total_size);

        let pt = decrypt_file_v7(&blob, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn exactly_one_full_chunk_round_trips() {
        let kp = fresh_kp();
        let chunk_sz = ByoUploadFlow::chunk_size();
        let plaintext = vec![0xABu8; chunk_sz];
        let (mut flow, header, total_size) = ByoUploadFlow::new(
            &kp.mlkem_public_key,
            &kp.x25519_public_key,
            chunk_sz as u64,
        )
        .unwrap();

        let frame = flow.push_chunk(&plaintext, true).unwrap();
        let footer = flow.finalize().unwrap();

        let mut blob = header;
        blob.extend_from_slice(&frame);
        blob.extend_from_slice(&footer);

        assert_eq!(blob.len() as u64, total_size);

        let pt = decrypt_file_v7(&blob, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(pt, plaintext);
    }

    // ─── Chunk size enforcement ───────────────────────────────────────────────

    #[test]
    fn non_final_short_chunk_returns_error() {
        let kp = fresh_kp();
        let (mut flow, _header, _) =
            ByoUploadFlow::new(&kp.mlkem_public_key, &kp.x25519_public_key, 1024).unwrap();

        let result = flow.push_chunk(&[0u8; 100], false); // non-final, wrong size
        assert!(
            matches!(result, Err(SdkError::Validation(_))),
            "expected Validation error, got {:?}",
            result
        );
    }

    #[test]
    fn non_final_oversized_chunk_returns_error() {
        let kp = fresh_kp();
        let chunk_sz = ByoUploadFlow::chunk_size();
        let (mut flow, _header, _) = ByoUploadFlow::new(
            &kp.mlkem_public_key,
            &kp.x25519_public_key,
            chunk_sz as u64 + 1,
        )
        .unwrap();

        let result = flow.push_chunk(&vec![0u8; chunk_sz + 1], false);
        assert!(matches!(result, Err(SdkError::Validation(_))));
    }

    #[test]
    fn push_after_last_returns_error() {
        let kp = fresh_kp();
        let (mut flow, _header, _) =
            ByoUploadFlow::new(&kp.mlkem_public_key, &kp.x25519_public_key, 4).unwrap();

        flow.push_chunk(b"data", true).unwrap();
        let result = flow.push_chunk(b"more", false);
        assert!(matches!(result, Err(SdkError::Validation(_))));
    }

    // ─── Memory / size invariant ──────────────────────────────────────────────

    #[test]
    fn struct_size_is_bounded() {
        // ByoUploadFlow must not grow with plaintext_len — the state is fixed-
        // size key material only.
        use std::mem::size_of;
        // ByoUploadFlow contains V7StreamEncryptor (fixed-size) + bool.
        // There is no Vec<plaintext> or similar. Confirm the type is smaller
        // than 4 KiB regardless of declared upload size.
        assert!(
            size_of::<ByoUploadFlow>() < 4 * 1024,
            "ByoUploadFlow is unexpectedly large: {} bytes",
            size_of::<ByoUploadFlow>()
        );
    }

    // ─── Contract parity with raw V7StreamEncryptor ───────────────────────────

    /// ByoUploadFlow must produce byte-for-byte identical output to the underlying
    /// V7StreamEncryptor when driven with the same key material.  We cannot test
    /// byte-for-byte equality across two independent encryptors (KEM uses fresh
    /// randomness each time), so instead we verify that the blob from ByoUploadFlow
    /// decrypts correctly with the matching key pair — same invariant as the
    /// encryptor's own tests.
    #[test]
    fn parity_with_v7_stream_encryptor() {
        let kp = fresh_kp();
        let data = b"parity test plaintext";
        let (mut flow, header, _) = ByoUploadFlow::new(
            &kp.mlkem_public_key,
            &kp.x25519_public_key,
            data.len() as u64,
        )
        .unwrap();
        let frame = flow.push_chunk(data, true).unwrap();
        let footer = flow.finalize().unwrap();

        let mut blob = header;
        blob.extend_from_slice(&frame);
        blob.extend_from_slice(&footer);

        let pt = decrypt_file_v7(&blob, &kp.mlkem_secret_key, &kp.x25519_secret_key).unwrap();
        assert_eq!(pt, data);
    }

    // ─── Regression guards ────────────────────────────────────────────────────

    #[test]
    fn finalize_without_last_chunk_returns_err_for_non_empty_file() {
        // M3 regression: finalize() used to be a debug_assert in release builds,
        // silently producing a valid-looking footer for an incomplete upload.
        // Now it returns Err in all build profiles.
        let kp = fresh_kp();
        let (mut flow, _, _) =
            ByoUploadFlow::new(&kp.mlkem_public_key, &kp.x25519_public_key, 100).unwrap();

        // Push a non-final chunk (is_last = false).
        let plaintext = vec![0u8; V7_ENCRYPT_CHUNK_SIZE];
        flow.push_chunk(&plaintext, false).unwrap();

        // finalize() without is_last=true must fail, not silently succeed.
        let result = flow.finalize();
        assert!(
            result.is_err(),
            "finalize() must return Err when last chunk was not marked is_last=true"
        );
    }

    #[test]
    fn finalize_without_any_push_returns_ok_for_empty_file() {
        // Empty files (plaintext_len == 0) skip push_chunk entirely; finalize must succeed.
        let kp = fresh_kp();
        let (flow, _, _) =
            ByoUploadFlow::new(&kp.mlkem_public_key, &kp.x25519_public_key, 0).unwrap();
        assert!(flow.finalize().is_ok(), "finalize() must succeed for empty files");
    }

    #[test]
    fn chunk_writer_new_zero_flush_at_returns_err() {
        // H1 regression: ChunkWriter::new previously used assert!(flush_at > 0)
        // which would panic. Now it returns Err.
        let result = crate::byo::streaming::ChunkWriter::new(0);
        assert!(result.is_err(), "flush_at=0 must return Err, not panic");
    }
}
