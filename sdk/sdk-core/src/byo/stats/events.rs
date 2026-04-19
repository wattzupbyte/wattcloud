// StatsEvent — the canonical BYO usage-statistics event type.
//
// All events are serialised as flat JSON objects with a "kind" discriminator
// (matching the wire format expected by POST /relay/stats).
// Byte values always represent ciphertext bytes — never plaintext sizes.

use serde::{Deserialize, Serialize};

// Re-export so callers can use sdk_core::byo::stats::ProviderType without
// importing byo::provider directly.
pub use crate::byo::provider::ProviderType;

/// Error classification for upload / download / vault errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorClass {
    Network,
    Unauthorized,
    RateLimited,
    Conflict,
    Other,
}

/// BYO share variant discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareVariant {
    A,
    #[serde(rename = "A+")]
    APlus,
    B1,
    B2,
}

/// A single usage-statistics event.
///
/// Serialises with `kind` as the tag so the wire JSON matches the relay's
/// expected format exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StatsEvent {
    VaultUnlock { ts: u64 },
    VaultLock   { ts: u64 },
    VaultSave   { ts: u64 },

    /// Successful file upload. `bytes` = ciphertext size.
    Upload {
        ts: u64,
        provider_type: ProviderType,
        bytes: u64,
    },
    /// Successful file download. `bytes` = ciphertext size.
    Download {
        ts: u64,
        provider_type: ProviderType,
        bytes: u64,
    },
    /// Operation error (upload, download, vault save, etc.).
    Error {
        ts: u64,
        provider_type: ProviderType,
        error_class: ErrorClass,
    },

    ShareCreate  { ts: u64, share_variant: ShareVariant },
    ShareResolve { ts: u64, share_variant: ShareVariant },
    ShareRevoke  { ts: u64, share_variant: ShareVariant },

    /// Bytes transferred through the SFTP relay (ciphertext). Cumulative
    /// since last vault lock / periodic flush; supplied by the WASM layer.
    RelayBandwidthSftp  { ts: u64, bytes: u64 },
    /// Bytes transferred through the share relay (B1/B2 ciphertext).
    RelayBandwidthShare { ts: u64, bytes: u64 },

    /// Per-device, per-provider daily histogram snapshot.
    /// `file_count_bucket` and `vault_size_bucket` are `bucket_log2(n)`.
    DeviceSizeSnapshot {
        ts: u64,
        provider_type: ProviderType,
        file_count_bucket: u32,
        vault_size_bucket: u32,
    },
}

/// Exponential histogram bucket: `floor(log2(max(1, n)))`.
///
/// Maps counts / byte sizes to a compact index for server-side histograms.
/// Examples:
///   - 0 → 0    (represents the [0,1) range)
///   - 1 → 0    (represents the [1,2) range)
///   - 2 → 1
///   - 3 → 1
///   - 4 → 2
///   - 1 GiB (2^30) → 30
pub fn bucket_log2(n: u64) -> u32 {
    if n == 0 {
        0
    } else {
        63 - n.leading_zeros()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bucket_log2_edges() {
        assert_eq!(bucket_log2(0), 0);
        assert_eq!(bucket_log2(1), 0);
        assert_eq!(bucket_log2(2), 1);
        assert_eq!(bucket_log2(3), 1);
        assert_eq!(bucket_log2(4), 2);
        assert_eq!(bucket_log2(1 << 20), 20);
        assert_eq!(bucket_log2(u64::MAX), 63);
    }

    #[test]
    fn vault_unlock_roundtrip() {
        let ev = StatsEvent::VaultUnlock { ts: 1_000_000 };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""kind":"vault_unlock""#));
        let back: StatsEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, StatsEvent::VaultUnlock { ts: 1_000_000 }));
    }

    #[test]
    fn upload_roundtrip() {
        let ev = StatsEvent::Upload {
            ts: 1_713_283_200,
            provider_type: ProviderType::Gdrive,
            bytes: 12_345_678,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""kind":"upload""#));
        assert!(json.contains(r#""provider_type":"gdrive""#));
        assert!(json.contains("12345678"));
    }

    #[test]
    fn error_roundtrip() {
        let ev = StatsEvent::Error {
            ts: 42,
            provider_type: ProviderType::S3,
            error_class: ErrorClass::RateLimited,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""kind":"error""#));
        assert!(json.contains(r#""error_class":"RateLimited""#));
    }

    #[test]
    fn share_variant_aplus_serde() {
        let ev = StatsEvent::ShareCreate { ts: 1, share_variant: ShareVariant::APlus };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""share_variant":"A+""#));
        let back: StatsEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, StatsEvent::ShareCreate { share_variant: ShareVariant::APlus, .. }));
    }

    #[test]
    fn device_size_snapshot_roundtrip() {
        let ev = StatsEvent::DeviceSizeSnapshot {
            ts: 1,
            provider_type: ProviderType::Dropbox,
            file_count_bucket: 12,
            vault_size_bucket: 28,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""kind":"device_size_snapshot""#));
        assert!(json.contains(r#""provider_type":"dropbox""#));
    }

    #[test]
    fn relay_bandwidth_sftp_roundtrip() {
        let ev = StatsEvent::RelayBandwidthSftp { ts: 99, bytes: 524_288 };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""kind":"relay_bandwidth_sftp""#));
    }

    #[test]
    fn unknown_kind_deserialise_fails_gracefully() {
        // The server drops unknown kinds; sdk-core's deserialise should also fail
        // (the TS side filters before calling sdk-core, but test the boundary).
        let json = r#"{"kind":"unknown_future_event","ts":1}"#;
        let result: Result<StatsEvent, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown kind must not silently succeed");
    }
}
