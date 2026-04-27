// BYO (Bring Your Own) storage mode: vault file format, cryptographic operations, enrollment.
//
// This module is additive — managed mode remains unchanged.
// All functions are pure (no I/O) and return Result types (no panics).

pub mod cache;
pub mod cross_provider_move;
pub mod enrollment;
pub mod manifest;
pub mod merge_rows;
pub mod multi_vault;
pub mod oauth;
pub mod offline_monitor;
pub mod per_vault_key;
pub mod pkce;
pub mod provider;
pub mod relay_auth;
pub mod sftp;
pub mod share;
#[cfg(feature = "providers")]
pub mod share_relay_client;
pub mod stats;
pub mod streaming;
pub mod vault_body;
pub mod vault_crypto;
pub mod vault_format;
pub mod vault_journal;

#[cfg(feature = "providers")]
pub mod providers;
#[cfg(feature = "providers")]
pub use providers::{
    BoxProvider, DropboxProvider, GdriveProvider, OneDriveProvider, PCloudProvider, S3Provider,
    WebDAVProvider,
};

pub use enrollment::{
    decrypt_payload_from_transfer, decrypt_shard_from_transfer, encrypt_payload_for_transfer,
    encrypt_shard_for_transfer, enrollment_derive_session, enrollment_initiate, EnrollmentError,
    EnrollmentSession, PayloadEnvelope, SasCode, ShardEnvelope, MAX_PAYLOAD_PLAINTEXT_LEN,
};
pub use oauth::{
    build_auth_url, build_refresh_form, build_token_exchange_form, parse_token_response,
    OAuthError, OAuthExchangeFlow, OAuthProviderConfig, OAuthTokenResponse,
};
pub use pkce::{base64url_encode_no_pad, generate_pkce, PkcePair};
pub use provider::{
    ProviderConfig, ProviderError, ProviderType, StorageEntry, StorageProvider, UploadOptions,
    UploadResult,
};
pub use relay_auth::{
    derive_enrollment_purpose, derive_sftp_purpose, solve_pow, verify_pow, RelayTicketCache,
    RELAY_TICKET_TTL_MS,
};
pub use share::{
    decode_variant_a, encode_variant_a, unwrap_key_with_password, wrap_key_with_password,
    ShareError,
};
#[cfg(feature = "providers")]
pub use share_relay_client::{B1GetResponse, ShareCreateResponse, ShareRelayClient};
pub use vault_crypto::{
    argon2id_derive_byo, compute_header_hmac, compute_header_hmac_v1, decrypt_vault_body,
    derive_byo_kek, derive_client_kek_half_from_byo, derive_recovery_vault_kek, derive_vault_kek,
    encrypt_vault_body, generate_vault_keys, unwrap_vault_key, verify_header_hmac,
    verify_header_hmac_v1, wrap_vault_key, NewVaultKeys,
};
pub use vault_format::{DeviceSlot, SlotStatus, VaultError, VaultHeader};

// R6 multi-vault public API.
pub use cache::{VaultBodyCache, WalError, WalStorage};
pub use cross_provider_move::execution::{decide_replay, ReplayDecision};
pub use cross_provider_move::reconciler::{plan_reconcile, ReconcileAction};
pub use cross_provider_move::{
    plan_share_revocations, CrossProviderFolderMovePlan, CrossProviderMovePlan, FolderCreateStep,
    MoveStep, ShareRevokeStep, ShareRow,
};
pub use manifest::{
    decrypt_manifest, encrypt_manifest, manifest_add_provider, manifest_rename_provider,
    manifest_set_primary_provider, manifest_tombstone_provider, manifest_update_provider_config,
    merge_manifests, validate_manifest, Manifest, ManifestEntry, ManifestError,
};
pub use merge_rows::{merge_rows, MergeOp};
pub use multi_vault::{
    ManifestSyncTarget, SavePlan, UnlockPlan, UnlockStep, VaultBodySource, VaultUpload,
};
pub use offline_monitor::{OfflineMonitor, ProviderMonitor, ProviderStatus};
pub use per_vault_key::{
    derive_manifest_aead_key, derive_per_vault_aead_key, derive_per_vault_journal_keys,
    derive_per_vault_wal_key, JournalKeys,
};
#[cfg(feature = "providers")]
pub use stats::StatsUploader;
pub use stats::{
    bucket_log2, ErrorClass, InMemoryStatsSink, NoopStatsSink, ShareVariant, StatsError,
    StatsEvent, StatsSink,
};
pub use streaming::{ByoDownloadFlow, ByoUploadFlow, ChunkWriter};
pub use vault_body::{decrypt_body, encrypt_body};
pub use vault_journal::{
    build_journal_file, parse_journal, serialize_entry, JournalEntry, JournalError,
    ENTRY_TYPE_DELETE, ENTRY_TYPE_INSERT, ENTRY_TYPE_UPDATE, JOURNAL_MAGIC,
};
