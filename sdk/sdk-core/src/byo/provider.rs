// StorageProvider type surface + trait definition.
//
// This module defines the authoritative contract for all BYO storage backends.
// Browser implementations satisfy the TS interface in byo/src/types.ts;
// Android implementations will satisfy a UniFFI callback interface generated
// from this trait. Both must remain in sync with this definition.
//
// Streaming I/O uses an explicit open/write/close/abort protocol keyed by
// a stream_id string. This maps cleanly to:
//   - wasm-bindgen: Promise-returning JS methods on the main thread
//   - UniFFI: [Async] callback interfaces with [Trait, WithForeign]
//
// The trait has no Rust implementations in this phase. TS providers continue
// to satisfy the TS interface unchanged; this trait is the reference contract
// for the Android follow-up.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Provider discriminator ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    Gdrive,
    Dropbox,
    Onedrive,
    Webdav,
    Sftp,
    Box,
    Pcloud,
    S3,
}

impl Default for ProviderType {
    /// Default is Gdrive; used only for `ProviderConfig::default()` in tests.
    fn default() -> Self {
        ProviderType::Gdrive
    }
}

// ─── Data types ───────────────────────────────────────────────────────────────

/// A file or folder entry returned by list().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageEntry {
    /// Provider-specific file/folder identifier (file ID, path, etc.).
    #[serde(rename = "ref")]
    pub ref_: String,
    /// Display name.
    pub name: String,
    /// Size in bytes (0 for folders).
    pub size: u64,
    /// Whether this entry is a folder.
    pub is_folder: bool,
    /// MIME type if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Last modification time as Unix milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<i64>,
}

/// Options for upload() and uploadStreamOpen().
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadOptions {
    /// Parent folder ref (None = root WattcloudVault/ directory).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_ref: Option<String>,
    /// ETag/rev for optimistic concurrency (vault saves).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,
    /// Content-Type override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Result returned by upload() and upload stream close().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadResult {
    /// Provider-specific file identifier.
    #[serde(rename = "ref")]
    pub ref_: String,
    /// ETag/rev for subsequent conflict detection.
    pub version: String,
}

/// Provider connection configuration (stored encrypted in vault SQLite).
/// Encryption/decryption is handled by ByoDataProvider, not StorageProvider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderConfig {
    #[serde(rename = "type")]
    pub type_: ProviderType,

    /// Stable UUID identifying this provider connection within the vault.
    /// Keyed by vault SQLite `providers.provider_id`. Empty for legacy single-provider vaults.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider_id: String,

    // OAuth providers (GDrive, Dropbox, OneDrive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix timestamp in ms when access_token expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_expiry: Option<i64>,

    // WebDAV
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// OAuth client_id (app-specific: Vite env for browser, BuildConfig for Android).
    /// Required for token refresh on OAuth providers (GDrive, Dropbox, OneDrive).
    /// Never transmitted to the provider's server — used only to build the
    /// `client_id` parameter in the refresh-token grant form body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    // SFTP
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sftp_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sftp_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sftp_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sftp_password: Option<String>,
    /// PEM-encoded private key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sftp_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sftp_passphrase: Option<String>,
    /// SHA-256 TOFU fingerprint of the SFTP server's host key ("SHA256:<base64>").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sftp_host_key_fingerprint: Option<String>,

    // pCloud
    /// pCloud datacenter region: "us" (default) or "eu".
    /// pCloud accounts are bound to a single datacenter; EU accounts must use eapi.pcloud.com.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcloud_region: Option<String>,

    // S3-family (S3, R2, B2, Wasabi, MinIO)
    /// Custom S3-compatible endpoint URL (R2/B2/Wasabi/MinIO). None = real AWS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_endpoint: Option<String>,
    /// AWS region or S3-compatible region string (e.g. "us-east-1", "auto").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_region: Option<String>,
    /// Target bucket name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_bucket: Option<String>,
    /// Access key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_access_key_id: Option<String>,
    /// Secret access key (stored encrypted in vault SQLite; never logged or transmitted to the Wattcloud relay).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_secret_access_key: Option<String>,
    /// Force path-style URLs (`https://endpoint/bucket/key` instead of `https://bucket.endpoint/key`).
    /// Required for MinIO and some B2 configurations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_path_style: Option<bool>,
    /// Optional in-bucket prefix. When set, the vault is stored at
    /// `{bucket}/{prefix}/WattcloudVault/...` instead of `{bucket}/WattcloudVault/...`.
    /// Absent or empty keeps the historical behaviour so existing vaults continue to resolve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_base_path: Option<String>,
}

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProviderError {
    /// ETag conflict: another writer changed the file since we last read it.
    #[error("conflict: current version {current_version}")]
    Conflict { current_version: String },
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("rate limited")]
    RateLimited,
    #[error("network error: {0}")]
    Network(String),
    #[error("provider error: {0}")]
    Provider(String),
    #[error("invalid response")]
    InvalidResponse,
    #[error("sftp relay error: {0}")]
    SftpRelay(String),
    /// Destination provider reports the object won't fit. Populated only when
    /// the provider exposes a portable free-space query (WebDAV RFC 4331
    /// `quota-available-bytes`, SFTP `statvfs@openssh.com`, …). Providers
    /// without a portable query skip this preflight and surface server
    /// errors mid-upload instead.
    #[error("insufficient space: need {needed} bytes, {available} available")]
    InsufficientSpace { needed: u64, available: u64 },
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Contract for a storage backend (GDrive/Dropbox/OneDrive/WebDAV/SFTP).
///
/// **Browser:** implemented in TypeScript (`byo/src/providers/*`); the TS
/// interface in `byo/src/types.ts` is kept in sync with this definition.
///
/// **Android (future):** UniFFI `[Trait, WithForeign]` callback interface.
/// Async methods map to Kotlin suspend functions.
///
/// Streaming I/O uses an explicit `stream_id`-keyed open/write/close/abort
/// protocol. This maps cleanly to wasm-bindgen Promise-returning methods and
/// UniFFI async callback interfaces without requiring `AsyncRead`/`AsyncWrite`
/// across the FFI boundary.
///
/// No Rust implementations exist in this phase; the trait is the authoritative
/// interface definition for the Android follow-up.
pub trait StorageProvider: Send + Sync {
    // ── Metadata ────────────────────────────────────────────────────────────

    fn provider_type(&self) -> ProviderType;
    fn display_name(&self) -> String;
    fn is_ready(&self) -> bool;
    fn get_config(&self) -> ProviderConfig;

    // ── Lifecycle ────────────────────────────────────────────────────────────

    fn init(
        &self,
        config: ProviderConfig,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    fn disconnect(&self) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    fn refresh_auth(&self) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    // ── Blob I/O (complete files — vault metadata, small blobs) ─────────────

    fn upload(
        &self,
        ref_: Option<String>,
        name: String,
        data: Vec<u8>,
        options: UploadOptions,
    ) -> impl std::future::Future<Output = Result<UploadResult, ProviderError>>;

    fn download(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, ProviderError>>;

    fn delete(&self, ref_: String) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    fn get_version(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>>;

    // ── Streaming I/O (V7 ciphertext — large files) ──────────────────────────
    //
    // Open returns a stream_id that identifies the in-progress transfer.
    // Write/close/abort operate on that stream_id.
    //
    // The concrete cross-boundary shape (AsyncWrite/AsyncRead vs chunk-callback)
    // will be finalised when the Rust orchestrator lands; for now the
    // interface is deliberately minimal so both UniFFI and wasm-bindgen
    // bindings can be added without changing the method signatures.

    fn upload_stream_open(
        &self,
        ref_: Option<String>,
        name: String,
        total_size: u64,
        options: UploadOptions,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>>;

    fn upload_stream_write(
        &self,
        stream_id: String,
        chunk: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    fn upload_stream_close(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<UploadResult, ProviderError>>;

    fn upload_stream_abort(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    fn download_stream_open(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>>;

    /// Pull the next chunk. Returns `None` at EOF.
    fn download_stream_read(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, ProviderError>>;

    fn download_stream_close(
        &self,
        stream_id: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    // ── Share link support (P10) ──────────────────────────────────────────────

    /// Create a provider-native public link for the blob at `ref_`.
    /// Returns the public URL. Not all providers support this; return
    /// `Err(ProviderError::Provider("no public link".into()))` when unsupported.
    fn create_public_link(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>>;

    /// Revoke a previously created public link.
    fn revoke_public_link(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>>;

    /// Create a presigned/time-bounded URL for the blob at `ref_` (Variant B1).
    /// `ttl_seconds` is the requested TTL; the actual TTL is provider-enforced.
    /// Return `Err(ProviderError::Provider("no presigned url".into()))` when unsupported.
    fn create_presigned_url(
        &self,
        ref_: String,
        ttl_seconds: u32,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>>;

    // ── Directory operations ─────────────────────────────────────────────────

    fn list(
        &self,
        parent_ref: Option<String>,
    ) -> impl std::future::Future<Output = Result<Vec<StorageEntry>, ProviderError>>;

    fn create_folder(
        &self,
        name: String,
        parent_ref: Option<String>,
    ) -> impl std::future::Future<Output = Result<String, ProviderError>>;

    fn delete_folder(
        &self,
        ref_: String,
    ) -> impl std::future::Future<Output = Result<(), ProviderError>>;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn provider_type_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&ProviderType::Gdrive).unwrap(),
            r#""gdrive""#
        );
        assert_eq!(
            serde_json::to_string(&ProviderType::Onedrive).unwrap(),
            r#""onedrive""#
        );
        assert_eq!(
            serde_json::to_string(&ProviderType::Sftp).unwrap(),
            r#""sftp""#
        );
    }

    #[test]
    fn provider_type_deserializes_lowercase() {
        let t: ProviderType = serde_json::from_str(r#""dropbox""#).unwrap();
        assert_eq!(t, ProviderType::Dropbox);
        let t2: ProviderType = serde_json::from_str(r#""webdav""#).unwrap();
        assert_eq!(t2, ProviderType::Webdav);
    }

    #[test]
    fn storage_entry_ref_field_name() {
        let entry = StorageEntry {
            ref_: "file-123".to_string(),
            name: "photo.jpg".to_string(),
            size: 1024,
            is_folder: false,
            mime_type: Some("image/jpeg".to_string()),
            modified_at: Some(1_700_000_000_000),
        };
        let json = serde_json::to_string(&entry).unwrap();
        // serde renames ref_ to "ref"
        assert!(json.contains(r#""ref":"file-123""#), "got: {json}");
        assert!(json.contains(r#""isFolder":false"#), "got: {json}");
    }

    #[test]
    fn upload_options_default_is_all_none() {
        let opts = UploadOptions::default();
        let json = serde_json::to_string(&opts).unwrap();
        // All optional fields are skipped when None
        assert_eq!(json, "{}");
    }

    #[test]
    fn upload_result_roundtrip() {
        let r = UploadResult {
            ref_: "abc".to_string(),
            version: "etag-xyz".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: UploadResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.ref_, "abc");
        assert_eq!(r2.version, "etag-xyz");
    }

    #[test]
    fn provider_config_oauth_roundtrip() {
        let cfg = ProviderConfig {
            type_: ProviderType::Gdrive,
            access_token: Some("tok".to_string()),
            refresh_token: Some("ref".to_string()),
            token_expiry: Some(9999),
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: ProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg2.type_, ProviderType::Gdrive);
        assert_eq!(cfg2.access_token, Some("tok".to_string()));
        assert!(cfg2.sftp_host.is_none());
    }

    #[test]
    fn provider_config_sftp_roundtrip() {
        let cfg = ProviderConfig {
            type_: ProviderType::Sftp,
            sftp_host: Some("host.example".to_string()),
            sftp_port: Some(22),
            sftp_username: Some("user".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: ProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg2.sftp_host, Some("host.example".to_string()));
        assert_eq!(cfg2.sftp_port, Some(22));
    }

    #[test]
    fn provider_error_display() {
        let e = ProviderError::Conflict {
            current_version: "v2".to_string(),
        };
        assert_eq!(e.to_string(), "conflict: current version v2");
        assert_eq!(ProviderError::NotFound.to_string(), "not found");
        assert_eq!(
            ProviderError::Network("timeout".to_string()).to_string(),
            "network error: timeout"
        );
    }
}
