use crate::byo::enrollment::EnrollmentError;
use crate::byo::vault_format::VaultError;

/// Top-level SDK error. All public API functions return `Result<T, SdkError>`.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),

    #[error("Enrollment error: {0}")]
    Enrollment(#[from] EnrollmentError),

    #[error("API error: {0}")]
    Api(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("HTTP error {status}: {message}")]
    Http { status: u16, message: String },

    #[error("Share relay error: {0}")]
    ShareRelay(#[from] ShareRelayError),
}

/// Errors from the BYO share-relay endpoints (B1 / B2).
#[derive(Debug, thiserror::Error)]
pub enum ShareRelayError {
    #[error("Share not found or expired")]
    NotFound,
    #[error("Share has been revoked")]
    Revoked,
    #[error("Unauthorized: invalid or missing owner token")]
    Unauthorized,
    #[error("Rate limited — too many requests")]
    RateLimited,
    #[error("Payload too large (max 200 MiB)")]
    TooLarge,
    #[error("Share ID already exists")]
    Conflict,
    #[error("Unexpected relay response: status {0}")]
    Unexpected(u16),
}

/// Errors from cryptographic operations.
/// Never include plaintext key material in any variant message.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid key material")]
    InvalidKeyMaterial,

    #[error("Key derivation failed")]
    KdfFailed,

    #[error("KEM encapsulation failed")]
    KemEncapFailed,

    #[error("KEM decapsulation failed")]
    KemDecapFailed,

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("Invalid nonce length")]
    InvalidNonceLength,

    #[error("Invalid ciphertext format: {0}")]
    InvalidFormat(String),

    #[error("Unsupported format version: {0}")]
    UnsupportedVersion(u8),

    #[error("Key commitment verification failed")]
    KeyCommitmentFailed,

    #[error("Argon2 parameters out of bounds: {0}")]
    Argon2ParamsOutOfBounds(String),
}

/// Errors from authentication flows.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Authentication failed")]
    AuthFailed,

    #[error("Session expired")]
    SessionExpired,

    #[error("MFA required")]
    MfaRequired,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Account locked")]
    AccountLocked,

    #[error("Rate limited: retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u64 },

    #[error("Account pending approval")]
    AccountPendingApproval,

    #[error("Registration incomplete")]
    RegistrationIncomplete,

    #[error("Two-factor authentication setup required")]
    TwoFaSetupRequired,

    #[error("Password change required")]
    PasswordChangeRequired,

    #[error("Challenge verification failed")]
    ChallengeFailed,

    #[error("Account recovery failed")]
    RecoveryFailed,

    #[error("Email not verified")]
    EmailNotVerified,
}

/// Errors from input validation.
/// Includes a message key for i18n lookup and a human-readable default.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("{message}")]
    Invalid {
        message_key: String,
        message: String,
    },
}

impl ValidationError {
    pub fn new(message_key: impl Into<String>, message: impl Into<String>) -> Self {
        ValidationError::Invalid {
            message_key: message_key.into(),
            message: message.into(),
        }
    }
}
