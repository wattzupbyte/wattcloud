// X25519 key generation and Diffie-Hellman key exchange.

use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::zeroize_utils::{X25519PublicKey, X25519SecretKey};
use crate::error::CryptoError;

/// Generate a random X25519 static keypair using the OS CSPRNG.
pub fn generate_x25519_keypair() -> Result<(X25519PublicKey, X25519SecretKey), CryptoError> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    Ok((
        X25519PublicKey::new(*public.as_bytes()),
        X25519SecretKey::new(*secret.as_bytes()),
    ))
}

/// X25519 Diffie-Hellman: compute shared secret from our static secret and their public key.
/// Returns the shared secret bytes. Caller is responsible for further key derivation.
pub fn x25519_dh(
    own_secret: &X25519SecretKey,
    their_pub: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let pub_bytes: [u8; 32] = their_pub
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let static_secret = StaticSecret::from(*own_secret.as_bytes());
    let their_public = PublicKey::from(pub_bytes);
    let shared = static_secret.diffie_hellman(&their_public);
    Ok(Zeroizing::new(*shared.as_bytes()))
}

/// X25519 Diffie-Hellman using an ephemeral secret.
/// Returns `(ephemeral_public_key_bytes, shared_secret)`.
pub fn x25519_ecdh_ephemeral(
    their_pub: &[u8],
) -> Result<([u8; 32], Zeroizing<[u8; 32]>), CryptoError> {
    let pub_bytes: [u8; 32] = their_pub
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let recipient_pub = PublicKey::from(pub_bytes);
    let shared = eph_secret.diffie_hellman(&recipient_pub);
    Ok((*eph_pub.as_bytes(), Zeroizing::new(*shared.as_bytes())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keypair_generation() {
        let (pub1, _sec1) = generate_x25519_keypair().unwrap();
        let (pub2, _sec2) = generate_x25519_keypair().unwrap();
        // Two random keys should be different
        assert_ne!(pub1.as_bytes(), pub2.as_bytes());
    }

    #[test]
    fn x25519_dh_produces_shared_secret() {
        let (pub1, sec1) = generate_x25519_keypair().unwrap();
        let (pub2, sec2) = generate_x25519_keypair().unwrap();
        let ss1 = x25519_dh(&sec1, pub2.as_bytes()).unwrap();
        let ss2 = x25519_dh(&sec2, pub1.as_bytes()).unwrap();
        assert_eq!(ss1.as_slice(), ss2.as_slice());
    }

    #[test]
    fn x25519_invalid_pub_key_length_fails() {
        let (_pub, sec) = generate_x25519_keypair().unwrap();
        assert!(x25519_dh(&sec, &[0u8; 31]).is_err());
        assert!(x25519_dh(&sec, &[0u8; 33]).is_err());
    }
}
