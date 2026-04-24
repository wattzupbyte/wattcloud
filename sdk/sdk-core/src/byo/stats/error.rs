// StatsError — standalone error type for the BYO stats subsystem.
//
// Deliberately NOT nested in SdkError: stats failures must never
// propagate up and abort a user operation. Callers (WASM layer) map
// StatsError to JsValue or discard it.

/// Error type for BYO stats ingest operations.
#[derive(Debug, thiserror::Error)]
pub enum StatsError {
    #[error("network error posting stats")]
    Network,
    #[error("JSON encoding error")]
    Encoding,
    #[error("relay returned unauthorized (401/403)")]
    Unauthorized,
    #[error("payload too large")]
    TooLarge,
    #[error("rate limited by relay")]
    RateLimited,
    #[error("invalid device_id format")]
    InvalidDeviceId,
    #[error("unexpected relay status {0}")]
    Unexpected(u16),
}
