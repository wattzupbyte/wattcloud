// PKCE (Proof Key for Code Exchange) — RFC 7636.
//
// Generates cryptographically random code verifiers and SHA-256 challenges
// for browser-based and native OAuth2 flows. No client secrets needed.
//
// Android and browser share this implementation via sdk-ffi / sdk-wasm.
// All randomness uses OsRng (the only approved entropy source per CLAUDE.md).

use crate::error::CryptoError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// A PKCE code verifier + challenge pair (RFC 7636 §4.1).
pub struct PkcePair {
    /// URL-safe base64 (no padding) code verifier — 43 chars from 32 random bytes.
    pub code_verifier: String,
    /// URL-safe base64 (no padding) SHA-256 digest of the verifier.
    pub code_challenge: String,
}

impl std::fmt::Debug for PkcePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkcePair")
            .field("code_verifier", &"[REDACTED]")
            .field("code_challenge", &self.code_challenge)
            .finish()
    }
}

/// Generate a PKCE code verifier and its SHA-256 challenge.
///
/// Entropy source: `rand::rngs::OsRng` (the only approved entropy source in this codebase).
/// Algorithm: 32 random bytes → base64url(bytes) as verifier;
///            base64url(SHA-256(verifier)) as challenge.
pub fn generate_pkce() -> Result<PkcePair, CryptoError> {
    let mut random_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);

    let code_verifier = base64url_encode_no_pad(&random_bytes);

    // code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let digest = hasher.finalize();
    let code_challenge = base64url_encode_no_pad(&digest);

    Ok(PkcePair {
        code_verifier,
        code_challenge,
    })
}

/// Base64url-encode bytes with no padding (RFC 7636 §Appendix B alphabet).
pub fn base64url_encode_no_pad(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn verifier_length_is_43() {
        let pair = generate_pkce().unwrap();
        assert_eq!(pair.code_verifier.len(), 43);
    }

    #[test]
    fn verifier_is_base64url_alphabet() {
        let pair = generate_pkce().unwrap();
        for ch in pair.code_verifier.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "unexpected char in code_verifier: {ch:?}"
            );
        }
        assert!(
            !pair.code_verifier.contains('+'),
            "code_verifier contains '+'"
        );
        assert!(
            !pair.code_verifier.contains('/'),
            "code_verifier contains '/'"
        );
        assert!(
            !pair.code_verifier.contains('='),
            "code_verifier contains '='"
        );
    }

    #[test]
    fn challenge_is_sha256_of_verifier() {
        let pair = generate_pkce().unwrap();

        // Re-derive the expected challenge from the verifier
        let mut hasher = Sha256::new();
        hasher.update(pair.code_verifier.as_bytes());
        let digest = hasher.finalize();
        let expected = URL_SAFE_NO_PAD.encode(digest);

        assert_eq!(pair.code_challenge, expected);
    }

    #[test]
    fn fixed_verifier_gives_deterministic_challenge() {
        // Verifier: 43 base64url chars → challenge must be reproducible
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let digest = hasher.finalize();
        let expected_challenge = URL_SAFE_NO_PAD.encode(digest);

        // Known-answer: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
        // (from RFC 7636 Appendix B, adjusted for no-padding variant)
        assert_eq!(
            expected_challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn two_generations_produce_different_verifiers() {
        let a = generate_pkce().unwrap();
        let b = generate_pkce().unwrap();
        assert_ne!(a.code_verifier, b.code_verifier);
        assert_ne!(a.code_challenge, b.code_challenge);
    }

    #[test]
    fn base64url_encode_no_pad_produces_no_padding() {
        let encoded = base64url_encode_no_pad(&[0u8; 32]);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }
}
