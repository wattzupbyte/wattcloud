// BYO download flow: V7 streaming decryption state machine.
//
// Ports the sequencing logic from `/byo/src/streaming/DownloadStream.ts`.
//
// The decryption pipeline has three stages:
//   1. Header buffering — collect the first 1709 bytes to initialise the
//      KEM-decapsulation-based `V7StreamDecryptor`.
//   2. Body decryption — feed ciphertext through `FooterTrimmer` (which holds
//      the last 32 bytes as a potential footer) and then `V7StreamDecryptor`
//      (which yields plaintext frames).
//   3. Finalisation — the retained 32 bytes are the HMAC footer; `finalize`
//      checks them and returns `MacVerificationFailed` on mismatch.
//
// Security: the caller MUST check `finalize()` and discard any plaintext
// emitted by `push` if `finalize` returns an error.  Per-chunk AES-GCM
// already prevents frame-level tampering; the footer HMAC catches truncation.
//
// # Usage
//
// ```rust,ignore
// let mut flow = ByoDownloadFlow::new(mlkem_sec, x25519_sec);
// while let Some(bytes) = provider.read_chunk().await? {
//     let plaintext = flow.push(&bytes)?;
//     if !plaintext.is_empty() { sink.write(&plaintext); }
// }
// flow.finalize()?; // verify HMAC — discard output if this errors
// ```

use crate::byo::streaming::constants::{V7_FOOTER_LEN, V7_HEADER_MIN};
use crate::crypto::wire_format::{FooterTrimmer, V7StreamDecryptor};
use crate::crypto::zeroize_utils::{MlKemSecretKey, X25519SecretKey};
use crate::error::{CryptoError, SdkError};

/// Internal state of the download pipeline.
enum DownloadState {
    /// Buffering raw ciphertext until we have the full V7 header.
    Header {
        buf: Vec<u8>,
        mlkem_sec: MlKemSecretKey,
        x25519_sec: X25519SecretKey,
    },
    /// Header consumed; decrypting frames; footer held in trimmer.
    Body {
        trimmer: FooterTrimmer,
        decryptor: V7StreamDecryptor,
    },
    /// `finalize()` has been called (or construction failed).
    Done,
}

/// V7 streaming download flow.
///
/// Feed raw provider bytes into [`push`][Self::push] and collect plaintext.
/// After the provider stream ends, call [`finalize`][Self::finalize] to verify
/// the trailing HMAC.
pub struct ByoDownloadFlow {
    state: DownloadState,
}

impl ByoDownloadFlow {
    /// Begin a new download flow.
    ///
    /// `mlkem_sec` and `x25519_sec` are the private keys that were used to
    /// encrypt the file. They are held until the first successful header
    /// completion.
    pub fn new(mlkem_sec: MlKemSecretKey, x25519_sec: X25519SecretKey) -> Self {
        Self {
            state: DownloadState::Header {
                buf: Vec::new(),
                mlkem_sec,
                x25519_sec,
            },
        }
    }

    /// Append ciphertext bytes and return any plaintext now available.
    ///
    /// Internally buffers until the V7 header (1709 bytes) has been received,
    /// then transitions to the decrypting state and returns plaintext for each
    /// complete V7 frame.
    ///
    /// The 32-byte HMAC footer is retained by the internal `FooterTrimmer` and
    /// is NOT returned as plaintext. It is checked by [`finalize`][Self::finalize].
    ///
    /// Returns an empty `Vec` when no complete frames are available yet.
    ///
    /// # Errors
    ///
    /// - [`SdkError::Crypto`] — header parse / KEM decapsulation / AES-GCM
    ///   decryption error. The flow is in an undefined state; abort.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, SdkError> {
        // ── Stage 1: still buffering the header ──────────────────────────────
        if let DownloadState::Header { ref mut buf, .. } = self.state {
            buf.extend_from_slice(data);
            if buf.len() < V7_HEADER_MIN {
                return Ok(Vec::new());
            }
            // Enough bytes to initialise the decryptor — fall through to transition.
        }

        // ── Stage 1→2 transition ─────────────────────────────────────────────
        // `data` has already been appended to `buf` above; we must NOT feed it
        // again into the body pipeline. Replace self.state with a sentinel so
        // we can move out of the Header variant.
        if matches!(self.state, DownloadState::Header { .. }) {
            match std::mem::replace(&mut self.state, DownloadState::Done) {
                DownloadState::Header {
                    buf,
                    mlkem_sec,
                    x25519_sec,
                } => {
                    // Pass only the fixed header slice — the decryptor would
                    // otherwise internalise the post-header bytes as "leftover",
                    // which would double-feed them when we push through the
                    // trimmer below.
                    let (mut decryptor, _header_end) =
                        V7StreamDecryptor::new(&buf[..V7_HEADER_MIN], &mlkem_sec, &x25519_sec)
                            .map_err(SdkError::Crypto)?;

                    let mut trimmer = FooterTrimmer::new(V7_FOOTER_LEN);
                    // Any bytes beyond the header in `buf` are the start of the body.
                    let post_header = &buf[V7_HEADER_MIN..];
                    let released = trimmer.push(post_header);
                    let initial_plaintext = decryptor.push(&released).map_err(SdkError::Crypto)?;

                    self.state = DownloadState::Body { trimmer, decryptor };
                    return Ok(initial_plaintext);
                }
                _ => {
                    return Err(SdkError::Crypto(CryptoError::InvalidFormat(
                        "ByoDownloadFlow: state invariant violated after header transition".into(),
                    )))
                }
            }
        }

        // ── Stage 2: body decryption ──────────────────────────────────────────
        match &mut self.state {
            DownloadState::Body { trimmer, decryptor } => {
                let body_bytes = trimmer.push(data);
                Ok(decryptor.push(&body_bytes).map_err(SdkError::Crypto)?)
            }
            DownloadState::Done => Err(SdkError::Crypto(CryptoError::InvalidFormat(
                "push called after finalize".to_string(),
            ))),
            DownloadState::Header { .. } => Err(SdkError::Crypto(CryptoError::InvalidFormat(
                "ByoDownloadFlow: still in header state after transition".into(),
            ))),
        }
    }

    /// Consume the flow and verify the trailing HMAC footer.
    ///
    /// Must be called once, after all ciphertext has been fed via `push`.
    ///
    /// Returns `Ok(())` if the HMAC matches. Returns
    /// [`SdkError::Crypto(MacVerificationFailed)`][crate::error::CryptoError::MacVerificationFailed]
    /// if it does not. Any plaintext emitted by prior `push` calls MUST be
    /// discarded if this returns an error.
    ///
    /// # Errors
    ///
    /// - [`SdkError::Crypto`] — HMAC mismatch (truncation or tampering), or
    ///   the stream ended before the V7 header was complete.
    pub fn finalize(mut self) -> Result<(), SdkError> {
        match std::mem::replace(&mut self.state, DownloadState::Done) {
            DownloadState::Body {
                trimmer,
                mut decryptor,
            } => {
                let (remaining_body, footer) = trimmer.finalize().map_err(SdkError::Crypto)?;
                // If any body bytes were retained by the trimmer (only possible
                // when total body < 2 × V7_FOOTER_LEN = 64 bytes), push them now
                // to update the HMAC state. The plaintext is discarded — the
                // caller has already consumed all push() output.
                if !remaining_body.is_empty() {
                    decryptor.push(&remaining_body).map_err(SdkError::Crypto)?;
                }
                decryptor.finalize(&footer).map_err(SdkError::Crypto)
            }
            DownloadState::Header { .. } => Err(SdkError::Crypto(CryptoError::InvalidFormat(
                "stream too short: V7 header was never complete".to_string(),
            ))),
            DownloadState::Done => Err(SdkError::Crypto(CryptoError::InvalidFormat(
                "finalize called twice".to_string(),
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::pqc::generate_hybrid_keypair;
    use crate::crypto::wire_format::encrypt_file_v7;

    fn make_v7_blob(
        plaintext_chunks: &[&[u8]],
    ) -> (Vec<u8>, crate::crypto::zeroize_utils::HybridKeypair) {
        let kp = generate_hybrid_keypair().unwrap();
        let blob = encrypt_file_v7(
            &kp.mlkem_public_key,
            &kp.x25519_public_key,
            plaintext_chunks,
        )
        .unwrap();
        (blob, kp)
    }

    // ─── Round-trip tests ─────────────────────────────────────────────────────

    #[test]
    fn empty_file_round_trips() {
        let (blob, kp) = make_v7_blob(&[]);
        let mut flow = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        let pt = flow.push(&blob).unwrap();
        flow.finalize().unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn single_chunk_round_trips() {
        let plaintext = b"hello byo download";
        let (blob, kp) = make_v7_blob(&[plaintext]);
        let mut flow = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        let pt = flow.push(&blob).unwrap();
        flow.finalize().unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn multi_chunk_round_trips() {
        let c1 = vec![0xAAu8; 1024];
        let c2 = vec![0xBBu8; 2048];
        let c3 = vec![0xCCu8; 512];
        let (blob, kp) = make_v7_blob(&[&c1, &c2, &c3]);
        let mut flow = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        let pt = flow.push(&blob).unwrap();
        flow.finalize().unwrap();

        let expected: Vec<u8> = [c1, c2, c3].concat();
        assert_eq!(pt, expected);
    }

    // ─── Incremental / byte-at-a-time feeding ─────────────────────────────────

    #[test]
    fn byte_at_a_time_round_trips() {
        let plaintext = b"incremental decryption";
        let (blob, kp) = make_v7_blob(&[plaintext]);
        let mut flow = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        let mut combined = Vec::new();
        for byte in &blob {
            combined.extend_from_slice(&flow.push(&[*byte]).unwrap());
        }
        flow.finalize().unwrap();
        assert_eq!(combined, plaintext);
    }

    #[test]
    fn arbitrary_chunk_sizes_round_trip() {
        let plaintext: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        let (blob, kp) = make_v7_blob(&[&plaintext]);
        let mut flow = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        let mut combined = Vec::new();
        // Feed in 300-byte chunks
        for chunk in blob.chunks(300) {
            combined.extend_from_slice(&flow.push(chunk).unwrap());
        }
        flow.finalize().unwrap();
        assert_eq!(combined, plaintext);
    }

    // ─── Error cases ──────────────────────────────────────────────────────────

    #[test]
    fn tampered_hmac_detected_at_finalize() {
        let plaintext = b"tamper test";
        let (mut blob, kp) = make_v7_blob(&[plaintext]);
        // Flip a byte in the 32-byte footer
        let footer_start = blob.len() - V7_FOOTER_LEN;
        blob[footer_start] ^= 0xFF;

        let mut flow = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        flow.push(&blob).unwrap(); // per-chunk AES-GCM still passes
        let result = flow.finalize();
        assert!(
            matches!(
                result,
                Err(SdkError::Crypto(CryptoError::MacVerificationFailed))
            ),
            "expected MacVerificationFailed, got {:?}",
            result
        );
    }

    #[test]
    fn truncated_stream_detected_at_finalize() {
        let plaintext = b"truncation test";
        let (blob, kp) = make_v7_blob(&[plaintext]);
        // Drop the last 10 bytes — leaves an incomplete footer in the trimmer
        let truncated = &blob[..blob.len() - 10];

        let mut flow = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        let _ = flow.push(truncated).unwrap();
        let result = flow.finalize();
        assert!(result.is_err(), "expected error for truncated stream");
    }

    #[test]
    fn stream_too_short_for_header_errors_on_finalize() {
        let kp = generate_hybrid_keypair().unwrap();
        let mut flow = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        // Push 100 bytes — not enough for the V7 header (needs 1709)
        flow.push(&[0u8; 100]).unwrap();
        let result = flow.finalize();
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_returns_crypto_error() {
        let plaintext = b"wrong key";
        let (blob, _kp) = make_v7_blob(&[plaintext]);
        let wrong_kp = generate_hybrid_keypair().unwrap();
        let mut flow = ByoDownloadFlow::new(wrong_kp.mlkem_secret_key, wrong_kp.x25519_secret_key);
        // Header decapsulation should fail
        let result = flow.push(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn push_after_finalize_errors() {
        let (blob, kp) = make_v7_blob(&[b"test" as &[u8]]);
        let mut flow = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        flow.push(&blob).unwrap();
        flow.finalize().unwrap();
        // flow is consumed by finalize() — no way to call push() after; this is
        // enforced at the type level since finalize() takes self by value.
    }

    // ─── Upload+download round-trip via ByoUploadFlow ─────────────────────────

    #[test]
    fn upload_then_download_flow_parity() {
        use crate::byo::streaming::ByoUploadFlow;

        let kp = generate_hybrid_keypair().unwrap();
        let chunk_sz = ByoUploadFlow::chunk_size();
        let plaintext: Vec<u8> = (0..(chunk_sz + 500)).map(|i| (i % 199) as u8).collect();

        // Upload via ByoUploadFlow
        let (mut upload, header, _total_size) = ByoUploadFlow::new(
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
            blob.extend_from_slice(&upload.push_chunk(&plaintext[offset..end], is_last).unwrap());
            offset = end;
        }
        blob.extend_from_slice(&upload.finalize().unwrap());

        // Download via ByoDownloadFlow, fed in 1-KiB increments
        let mut download = ByoDownloadFlow::new(kp.mlkem_secret_key, kp.x25519_secret_key);
        let mut recovered = Vec::new();
        for chunk in blob.chunks(1024) {
            recovered.extend_from_slice(&download.push(chunk).unwrap());
        }
        download.finalize().unwrap();

        assert_eq!(recovered, plaintext);
    }
}
