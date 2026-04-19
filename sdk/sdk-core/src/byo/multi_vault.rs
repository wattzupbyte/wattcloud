// Multi-vault orchestration plans for R6 per-provider vault architecture.
//
// Both `UnlockPlan` and `SavePlan` are pure data structures produced by pure
// functions.  They carry no I/O — the frontend/Android layer executes the steps
// and calls back into sdk-wasm/sdk-ffi for crypto operations.
//
// Design principles:
//   - Unlock is fail-closed: if a provider is neither online nor cached, its
//     tab appears as "unavailable" (not missing silently).
//   - Save only re-uploads vaults that were mutated this session.
//   - Manifest is uploaded to ALL reachable providers on every save (cheap;
//     ensures eventual consistency across the replicated manifest copies).

use serde::{Deserialize, Serialize};

// ─── Unlock ──────────────────────────────────────────────────────────────────

/// Where the frontend should fetch a provider's vault body from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultBodySource {
    /// Fetch from the provider's cloud storage.
    Cloud,
    /// Load from the local IndexedDB cache (provider is offline).
    Cache,
}

/// One step in the unlock plan — decrypt one provider's vault body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockStep {
    /// The provider to unlock.
    pub provider_id: String,
    /// Where to get the encrypted body bytes.
    pub source: VaultBodySource,
    /// True when this is the provider designated as primary in the manifest.
    pub is_primary: bool,
}

/// Which providers' manifests are behind the merged manifest version and need
/// an updated copy pushed to them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestSyncTarget {
    pub provider_id: String,
}

/// Ordered plan for unlocking a multi-vault session.
///
/// The frontend executes the `vault_steps` in any order (they are independent),
/// then starts one tab per step.  After the session is open, it pushes the
/// merged manifest to `manifest_sync_targets` in the background.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnlockPlan {
    /// One step per active (non-tombstone) provider in the manifest.
    pub vault_steps: Vec<UnlockStep>,
    /// Providers whose stored manifest is older than the merged manifest.
    /// The frontend should upload the merged manifest to these after unlock.
    pub manifest_sync_targets: Vec<ManifestSyncTarget>,
    /// True when zero providers were reachable and zero caches existed.
    /// The frontend must surface a "No providers reachable" error and abort.
    pub fail_closed: bool,
}

impl UnlockPlan {
    /// Build the unlock plan from provider availability information.
    ///
    /// Arguments:
    /// - `provider_ids`: all active (non-tombstone) provider IDs from the merged manifest.
    /// - `online_ids`: provider IDs confirmed reachable right now.
    /// - `cached_ids`: provider IDs with a valid encrypted body in IndexedDB.
    /// - `primary_id`: the `provider_id` of the primary provider (for is_primary flag).
    /// - `manifest_sync_targets`: provider IDs whose manifest copy is behind.
    ///
    /// A provider that is neither online nor cached contributes an "unavailable" step
    /// (not included in `vault_steps`), so the UI can show it as unreachable without
    /// a cached fallback.
    pub fn build(
        provider_ids: &[&str],
        online_ids: &[&str],
        cached_ids: &[&str],
        primary_id: &str,
        manifest_sync_targets: &[&str],
    ) -> Self {
        let online_set: std::collections::HashSet<&str> = online_ids.iter().copied().collect();
        let cached_set: std::collections::HashSet<&str> = cached_ids.iter().copied().collect();

        let vault_steps: Vec<UnlockStep> = provider_ids
            .iter()
            .filter_map(|&pid| {
                let source = if online_set.contains(pid) {
                    VaultBodySource::Cloud
                } else if cached_set.contains(pid) {
                    VaultBodySource::Cache
                } else {
                    // Neither online nor cached — skip (unavailable tab shown by UI).
                    return None;
                };
                Some(UnlockStep {
                    provider_id: pid.to_string(),
                    source,
                    is_primary: pid == primary_id,
                })
            })
            .collect();

        let fail_closed = vault_steps.is_empty() && !provider_ids.is_empty();

        let sync: Vec<ManifestSyncTarget> = manifest_sync_targets
            .iter()
            .map(|&pid| ManifestSyncTarget {
                provider_id: pid.to_string(),
            })
            .collect();

        UnlockPlan {
            vault_steps,
            manifest_sync_targets: sync,
            fail_closed,
        }
    }

    /// Provider IDs that have a usable vault body (online or cached).
    pub fn available_provider_ids(&self) -> Vec<&str> {
        self.vault_steps
            .iter()
            .map(|s| s.provider_id.as_str())
            .collect()
    }

    /// Provider IDs that are in read-only mode (cached, not online).
    pub fn read_only_provider_ids(&self) -> Vec<&str> {
        self.vault_steps
            .iter()
            .filter(|s| s.source == VaultBodySource::Cache)
            .map(|s| s.provider_id.as_str())
            .collect()
    }
}

// ─── Save ─────────────────────────────────────────────────────────────────────

/// One vault-body upload in the save plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultUpload {
    /// The provider whose vault body needs re-uploading.
    pub provider_id: String,
}

/// Ordered plan for saving after mutations.
///
/// The frontend executes `vault_uploads` in parallel (independent uploads),
/// then uploads the manifest to every provider in `manifest_upload_targets`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SavePlan {
    /// Re-upload only the vaults for providers that were mutated this session.
    pub vault_uploads: Vec<VaultUpload>,
    /// Upload the (possibly updated) manifest to every reachable provider.
    /// This is cheap (small JSON payload) and ensures eventual consistency.
    pub manifest_upload_targets: Vec<String>,
}

impl SavePlan {
    /// Build the save plan.
    ///
    /// Arguments:
    /// - `dirty_provider_ids`: providers whose in-memory vault rows were mutated.
    /// - `online_ids`: providers reachable right now.
    pub fn build(dirty_provider_ids: &[&str], online_ids: &[&str]) -> Self {
        let online_set: std::collections::HashSet<&str> = online_ids.iter().copied().collect();

        // Only re-upload vaults for dirty providers that are currently online.
        // Offline dirty providers are written to the WAL and synced on reconnect.
        let vault_uploads: Vec<VaultUpload> = dirty_provider_ids
            .iter()
            .filter(|&&pid| online_set.contains(pid))
            .map(|&pid| VaultUpload {
                provider_id: pid.to_string(),
            })
            .collect();

        let manifest_upload_targets: Vec<String> =
            online_ids.iter().map(|&s| s.to_string()).collect();

        SavePlan {
            vault_uploads,
            manifest_upload_targets,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── UnlockPlan ────────────────────────────────────────────────────────────

    #[test]
    fn unlock_all_online() {
        let plan = UnlockPlan::build(
            &["a", "b", "c"],
            &["a", "b", "c"],
            &[],
            "a",
            &[],
        );
        assert!(!plan.fail_closed);
        assert_eq!(plan.vault_steps.len(), 3);
        assert!(plan.vault_steps.iter().all(|s| s.source == VaultBodySource::Cloud));
    }

    #[test]
    fn unlock_one_offline_with_cache() {
        let plan = UnlockPlan::build(
            &["a", "b"],
            &["a"],
            &["b"],
            "a",
            &[],
        );
        assert!(!plan.fail_closed);
        assert_eq!(plan.vault_steps.len(), 2);
        let b_step = plan.vault_steps.iter().find(|s| s.provider_id == "b").unwrap();
        assert_eq!(b_step.source, VaultBodySource::Cache);
    }

    #[test]
    fn unlock_one_offline_no_cache_skipped() {
        let plan = UnlockPlan::build(
            &["a", "b"],
            &["a"],
            &[],   // no cache for b
            "a",
            &[],
        );
        assert!(!plan.fail_closed);
        assert_eq!(plan.vault_steps.len(), 1, "unreachable+uncached provider should be skipped");
        assert_eq!(plan.vault_steps[0].provider_id, "a");
    }

    #[test]
    fn unlock_fail_closed_all_unavailable() {
        let plan = UnlockPlan::build(&["a", "b"], &[], &[], "a", &[]);
        assert!(plan.fail_closed, "no online/cached providers → fail closed");
        assert!(plan.vault_steps.is_empty());
    }

    #[test]
    fn unlock_empty_manifest_not_fail_closed() {
        // No providers in manifest → not fail_closed (new vault or all tombstoned).
        let plan = UnlockPlan::build(&[], &[], &[], "", &[]);
        assert!(!plan.fail_closed);
        assert!(plan.vault_steps.is_empty());
    }

    #[test]
    fn unlock_primary_flag_set_correctly() {
        let plan = UnlockPlan::build(&["a", "b"], &["a", "b"], &[], "b", &[]);
        let a = plan.vault_steps.iter().find(|s| s.provider_id == "a").unwrap();
        let b = plan.vault_steps.iter().find(|s| s.provider_id == "b").unwrap();
        assert!(!a.is_primary);
        assert!(b.is_primary);
    }

    #[test]
    fn unlock_manifest_sync_targets_propagated() {
        let plan = UnlockPlan::build(&["a"], &["a"], &[], "a", &["b", "c"]);
        assert_eq!(plan.manifest_sync_targets.len(), 2);
    }

    #[test]
    fn unlock_read_only_ids() {
        let plan = UnlockPlan::build(&["a", "b"], &["a"], &["b"], "a", &[]);
        let ro = plan.read_only_provider_ids();
        assert_eq!(ro, vec!["b"]);
    }

    // ── SavePlan ──────────────────────────────────────────────────────────────

    #[test]
    fn save_only_dirty_providers_uploaded() {
        let plan = SavePlan::build(&["a"], &["a", "b"]);
        assert_eq!(plan.vault_uploads.len(), 1);
        assert_eq!(plan.vault_uploads[0].provider_id, "a");
        // Manifest goes to all online providers.
        assert_eq!(plan.manifest_upload_targets.len(), 2);
    }

    #[test]
    fn save_offline_dirty_provider_not_uploaded() {
        // Provider "b" is dirty but offline — not uploaded now (WAL will sync later).
        let plan = SavePlan::build(&["a", "b"], &["a"]);
        assert_eq!(plan.vault_uploads.len(), 1);
        assert_eq!(plan.vault_uploads[0].provider_id, "a");
    }

    #[test]
    fn save_no_dirty_providers() {
        let plan = SavePlan::build(&[], &["a", "b"]);
        assert!(plan.vault_uploads.is_empty());
        assert_eq!(plan.manifest_upload_targets.len(), 2);
    }

    #[test]
    fn save_all_offline() {
        let plan = SavePlan::build(&["a"], &[]);
        assert!(plan.vault_uploads.is_empty());
        assert!(plan.manifest_upload_targets.is_empty());
    }
}
