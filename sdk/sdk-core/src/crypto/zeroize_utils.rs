// Key material wrapper types.
// All types containing secret key material:
//   - Derive Zeroize + ZeroizeOnDrop
//   - Do NOT implement Clone (prevents silent duplication)
//   - Implement Debug as "[REDACTED]"
//
// Public-key types (non-secret) implement Clone and normal Debug.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

// ─── Secret types ───────────────────────────────────────────────────────────

/// 256-bit symmetric key (AES-256-GCM key, HMAC key, KEK, etc.)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; 32] = s.try_into().map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// ML-KEM-1024 secret (decapsulation) key — 3168 bytes
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKemSecretKey(Vec<u8>);

impl MlKemSecretKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, CryptoError> {
        if s.len() != 3168 {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        Ok(Self(s.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MlKemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// X25519 static secret key — 32 bytes
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey([u8; 32]);

impl X25519SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; 32] = s.try_into().map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// 64-byte output of Argon2id — the raw KDF output before HKDF derivation.
/// auth_material() → bytes [0..32] → input for derive_auth_hash / derive_encryption_key
/// enc_material()  → bytes [32..64] → input for derive_client_kek_half
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Argon2Output([u8; 64]);

impl Argon2Output {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; 64] = s.try_into().map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// First 32 bytes — IKM for auth_hash and encryption_key derivation.
    pub fn auth_material(&self) -> &[u8] {
        &self.0[0..32]
    }

    /// Last 32 bytes — IKM for client_kek_half derivation.
    pub fn enc_material(&self) -> &[u8] {
        &self.0[32..64]
    }
}

impl fmt::Debug for Argon2Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Master secret — 37 bytes: [version(1)][secret(32)][checksum(4)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret(Vec<u8>);

impl MasterSecret {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() != 37 {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        Ok(Self(bytes))
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, CryptoError> {
        Self::new(s.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Version byte (0x02 = V2, 0x05 = V5).
    pub fn version(&self) -> u8 {
        self.0[0]
    }

    /// The 32-byte secret payload (bytes 1..33).
    pub fn secret_bytes(&self) -> &[u8] {
        &self.0[1..33]
    }

    /// The 4-byte SHA-256 checksum (bytes 33..37).
    pub fn checksum(&self) -> &[u8] {
        &self.0[33..37]
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

// ─── Public / non-secret types ──────────────────────────────────────────────

/// ML-KEM-1024 public (encapsulation) key — 1568 bytes.
#[derive(Clone)]
pub struct MlKemPublicKey(Vec<u8>);

impl MlKemPublicKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, CryptoError> {
        if s.len() != 1568 {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        Ok(Self(s.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MlKemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlKemPublicKey({} bytes)", self.0.len())
    }
}

/// X25519 public key — 32 bytes.
#[derive(Clone)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; 32] = s.try_into().map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519PublicKey({:?})", &self.0[..4])
    }
}

/// 12-byte AES-GCM nonce. Not secret — no zeroization needed.
#[derive(Clone, Debug)]
pub struct Nonce12([u8; 12]);

impl Nonce12 {
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; 12] = s.try_into().map_err(|_| CryptoError::InvalidNonceLength)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// Hybrid ML-KEM-1024 + X25519 keypair.
/// Secret fields are zeroized on drop via ZeroizeOnDrop on the inner types.
/// Clone is intentionally not implemented to prevent silent key material duplication.
pub struct HybridKeypair {
    pub mlkem_public_key: MlKemPublicKey,
    pub mlkem_secret_key: MlKemSecretKey,
    pub x25519_public_key: X25519PublicKey,
    pub x25519_secret_key: X25519SecretKey,
}

impl fmt::Debug for HybridKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKeypair")
            .field("mlkem_public_key", &self.mlkem_public_key)
            .field("mlkem_secret_key", &"[REDACTED]")
            .field("x25519_public_key", &self.x25519_public_key)
            .field("x25519_secret_key", &"[REDACTED]")
            .finish()
    }
}
