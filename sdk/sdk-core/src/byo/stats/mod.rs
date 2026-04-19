// BYO usage-statistics subsystem.
//
// Collects non-PII, aggregate-only metrics: vault lifecycle events, upload /
// download counts + encrypted-byte totals, error classification, share-link
// operations, relay bandwidth, and per-device-per-provider vault-size snapshots.
//
// Design invariants
// ─────────────────
// - `events` / `recorder` / `error` compile without the `providers` feature
//   so a future Android FFI layer can reuse them without any HTTP plumbing.
// - `uploader` requires the `providers` feature (uses ProviderHttpClient).
// - No plaintext sizes, filenames, paths, or user identifiers ever appear in
//   a StatsEvent.  All `bytes` fields carry ciphertext byte counts.
// - `StatsError` is NOT nested in `SdkError`; stats failures must never abort
//   a user operation.

pub mod error;
pub mod events;
pub mod recorder;
#[cfg(feature = "providers")]
pub mod uploader;

pub use error::StatsError;
pub use events::{bucket_log2, ErrorClass, ProviderType, ShareVariant, StatsEvent};
pub use recorder::{InMemoryStatsSink, NoopStatsSink, StatsSink};
#[cfg(feature = "providers")]
pub use uploader::StatsUploader;
