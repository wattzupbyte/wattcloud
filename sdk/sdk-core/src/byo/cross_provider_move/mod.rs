// Cross-provider move plan for R6 multi-vault architecture.
//
// V7 ciphertext blobs are transferred verbatim between providers — no
// re-encryption is required because content keys are per-file, not
// vault-key-derived (CLAUDE.md).
//
// Moving a file from provider A to provider B requires:
//   1. Download the encrypted blob from A (streamed; no full-file buffer).
//   2. Upload the same V7 ciphertext bytes to B (new provider_ref).
//   3. Insert the new row into B's vault (with new provider_ref from step 2).
//   4. Delete the blob from A.
//   5. Delete the old row from A's vault.
//
// Each step is logged to the per-provider WAL before execution so that crashes
// are recoverable:
//   - Crash before step 5: dst has orphan blob (detected by reconciler on reload).
//   - Crash after step 5 before step 7: dst row exists, src row still present
//     (treated as duplicate by reconciler; src is deleted on next session open).
//   - Crash after step 7: clean.
//
// The reconciler looks for rows whose `provider_ref` does not exist on the
// storage provider and removes them.  This is a lightweight background scan.
//
// NOTE: Folders are moved recursively: plan_cross_provider_folder_move produces
// a flat list of file-move plans in BFS order, preceded by folder-create steps.

pub mod execution;
pub mod reconciler;

use serde::{Deserialize, Serialize};

// ── Share revocation helpers ──────────────────────────────────────────────────

/// One share that must be revoked before the associated file's blobs are moved.
///
/// The host platform executes the revocation (provider public-link revoke or
/// relay DELETE) then marks the share_tokens row revoked via its WAL-aware
/// mutation path, before proceeding to step 0 (`DownloadSourceBlob`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShareRevokeStep {
    pub share_id: String,
    /// "A", "A+", "B1", or "B2"
    pub variant: String,
    pub provider_id: String,
    pub provider_ref: String,
    pub owner_token: Option<String>,
}

/// Opaque share row consumed by [`plan_share_revocations`].
pub struct ShareRow {
    pub share_id: String,
    pub file_id: u64,
    pub variant: String,
    pub provider_id: String,
    pub provider_ref: String,
    pub owner_token: Option<String>,
    pub revoked: bool,
}

/// Pure function: given the set of file_ids being moved and all share_token
/// rows in scope, return the ordered list of `ShareRevokeStep`s that must be
/// executed before any blob is transferred.
///
/// Rules:
/// - Only rows where `revoked = false` produce a step.
/// - Only rows whose `file_id` is in `file_ids` produce a step.
/// - Already-revoked rows are silently skipped (idempotent).
pub fn plan_share_revocations(file_ids: &[u64], share_rows: &[ShareRow]) -> Vec<ShareRevokeStep> {
    let file_id_set: std::collections::HashSet<u64> = file_ids.iter().copied().collect();
    share_rows
        .iter()
        .filter(|r| !r.revoked && file_id_set.contains(&r.file_id))
        .map(|r| ShareRevokeStep {
            share_id: r.share_id.clone(),
            variant: r.variant.clone(),
            provider_id: r.provider_id.clone(),
            provider_ref: r.provider_ref.clone(),
            owner_token: r.owner_token.clone(),
        })
        .collect()
}

// ── CrossProviderMovePlan ─────────────────────────────────────────────────────

/// A single file's cross-provider move plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProviderMovePlan {
    pub file_id: u64,
    /// Shares that must be revoked *before* any blob transfer begins.
    /// The host executes these via its WAL-aware revocation path.
    pub pre_revokes: Vec<ShareRevokeStep>,
    /// Ordered steps to execute (see module docs for crash semantics).
    pub steps: Vec<MoveStep>,
    /// Provider_ref on the source provider (opaque storage path).
    pub source_provider_ref: String,
    /// Human-readable description for progress UI.
    pub description: String,
}

/// One atomic step in a cross-provider file move.
///
/// Steps are ordered — execute sequentially.  Each step should be journaled
/// before execution so the reconciler can detect partial state on crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveStep {
    /// Download the encrypted blob from the source provider and stream it
    /// verbatim to the destination. No decryption or re-encryption.
    DownloadSourceBlob {
        provider_id: String,
        provider_ref: String,
    },
    /// Upload the V7 ciphertext to the destination provider.
    UploadDestBlob { provider_id: String },
    /// Insert a new row in the destination vault's `files` table.
    InsertDestVaultRow {
        provider_id: String,
        dest_folder_id: Option<u64>,
    },
    /// Delete the ciphertext blob from the source provider.
    DeleteSourceBlob {
        provider_id: String,
        provider_ref: String,
    },
    /// Remove the file row from the source vault's `files` table.
    DeleteSourceVaultRow { provider_id: String, file_id: u64 },
}

impl MoveStep {
    /// Serialize this step to an opaque byte payload for WAL persistence.
    ///
    /// The output is serde_json-encoded with a variant discriminator so the
    /// host platform can decode it without SDK knowledge of the Rust types.
    pub fn to_wal_entry(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize a step previously produced by [`MoveStep::to_wal_entry`].
    ///
    /// Returns an error if the bytes are corrupted or from an unknown variant.
    pub fn from_wal_entry(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

impl CrossProviderMovePlan {
    /// Build a move plan for a single file.
    ///
    /// Arguments:
    /// - `file_id`: the file row id in the source vault.
    /// - `source_provider_ref`: the opaque blob reference on the source provider.
    /// - `src_provider_id`: the source provider.
    /// - `dst_provider_id`: the destination provider.
    /// - `dest_folder_id`: the folder in the destination vault (None = root).
    /// - `display_name`: the file's display name (for the progress UI description).
    /// - `pre_revokes`: shares to revoke before the first blob operation (use
    ///   [`plan_share_revocations`] to build this list).
    pub fn build(
        file_id: u64,
        source_provider_ref: &str,
        src_provider_id: &str,
        dst_provider_id: &str,
        dest_folder_id: Option<u64>,
        display_name: &str,
        pre_revokes: Vec<ShareRevokeStep>,
    ) -> Self {
        let steps = vec![
            MoveStep::DownloadSourceBlob {
                provider_id: src_provider_id.to_string(),
                provider_ref: source_provider_ref.to_string(),
            },
            MoveStep::UploadDestBlob {
                provider_id: dst_provider_id.to_string(),
            },
            MoveStep::InsertDestVaultRow {
                provider_id: dst_provider_id.to_string(),
                dest_folder_id,
            },
            MoveStep::DeleteSourceBlob {
                provider_id: src_provider_id.to_string(),
                provider_ref: source_provider_ref.to_string(),
            },
            MoveStep::DeleteSourceVaultRow {
                provider_id: src_provider_id.to_string(),
                file_id,
            },
        ];

        CrossProviderMovePlan {
            file_id,
            pre_revokes,
            steps,
            source_provider_ref: source_provider_ref.to_string(),
            description: format!(
                "Move '{}' from {} to {}",
                display_name, src_provider_id, dst_provider_id
            ),
        }
    }
}

/// A folder creation step used when moving a folder tree across providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderCreateStep {
    pub provider_id: String,
    pub parent_folder_id: Option<u64>,
    pub name_encrypted_hint: String,
}

/// A plan for moving an entire folder tree (files + subfolders) across providers.
///
/// Execution order:
///   1. Create all destination folders in BFS order (roots first).
///   2. Execute each file move plan in any order (parallel safe).
///   3. Delete all source folders in reverse-BFS order (leaves first).
#[derive(Debug, Serialize, Deserialize)]
pub struct CrossProviderFolderMovePlan {
    /// Folders to create on the destination provider, in BFS order.
    pub folder_creates: Vec<FolderCreateStep>,
    /// One file move plan per file in the subtree.
    pub file_moves: Vec<CrossProviderMovePlan>,
    /// Source folder IDs to delete after all files have moved, in reverse-BFS order.
    pub source_folder_deletes: Vec<u64>,
    pub src_provider_id: String,
    pub dst_provider_id: String,
}

impl CrossProviderFolderMovePlan {
    /// Build a folder-tree move plan.
    ///
    /// Arguments:
    /// - `src_provider_id` / `dst_provider_id`: source and destination providers.
    /// - `folder_ids_bfs`: source folder IDs in BFS order (root of moved subtree first).
    /// - `files`: `(file_id, source_provider_ref, dest_folder_id, display_name)` per file.
    /// - `folder_creates`: destination folder create steps in BFS order.
    pub fn build(
        src_provider_id: &str,
        dst_provider_id: &str,
        folder_ids_bfs: &[u64],
        files: &[(u64, &str, Option<u64>, &str)],
        folder_creates: Vec<FolderCreateStep>,
    ) -> Self {
        let file_moves = files
            .iter()
            .map(|(fid, pref, dest_folder, name)| {
                CrossProviderMovePlan::build(
                    *fid,
                    pref,
                    src_provider_id,
                    dst_provider_id,
                    *dest_folder,
                    name,
                    vec![], // folder-move callers supply pre_revokes separately
                )
            })
            .collect();

        // Delete source folders in reverse BFS order (leaves first).
        let source_folder_deletes = folder_ids_bfs.iter().copied().rev().collect();

        CrossProviderFolderMovePlan {
            folder_creates,
            file_moves,
            source_folder_deletes,
            src_provider_id: src_provider_id.to_string(),
            dst_provider_id: dst_provider_id.to_string(),
        }
    }

    /// Total number of items to process (folders + files) for progress display.
    pub fn total_items(&self) -> usize {
        self.folder_creates.len() + self.file_moves.len() + self.source_folder_deletes.len()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn basic_plan() -> CrossProviderMovePlan {
        CrossProviderMovePlan::build(
            42,
            "ref/abc",
            "gdrive",
            "dropbox",
            None,
            "photo.jpg",
            vec![],
        )
    }

    #[test]
    fn plan_has_five_steps() {
        assert_eq!(basic_plan().steps.len(), 5);
    }

    #[test]
    fn plan_step_order() {
        let steps = basic_plan().steps;
        assert!(
            matches!(steps[0], MoveStep::DownloadSourceBlob { .. }),
            "step 0 must be DownloadSourceBlob"
        );
        assert!(
            matches!(steps[1], MoveStep::UploadDestBlob { .. }),
            "step 1 must be UploadDestBlob"
        );
        assert!(
            matches!(steps[2], MoveStep::InsertDestVaultRow { .. }),
            "step 2 must be InsertDestVaultRow"
        );
        assert!(
            matches!(steps[3], MoveStep::DeleteSourceBlob { .. }),
            "step 3 must be DeleteSourceBlob"
        );
        assert!(
            matches!(steps[4], MoveStep::DeleteSourceVaultRow { .. }),
            "step 4 must be DeleteSourceVaultRow"
        );
    }

    #[test]
    fn source_blob_deleted_before_vault_row() {
        // Step 4 (DeleteSourceBlob) must come before step 5 (DeleteSourceVaultRow)
        // so the reconciler can always detect orphan blobs by checking vault rows.
        let steps = basic_plan().steps;
        let del_blob = steps
            .iter()
            .position(|s| matches!(s, MoveStep::DeleteSourceBlob { .. }))
            .unwrap();
        let del_row = steps
            .iter()
            .position(|s| matches!(s, MoveStep::DeleteSourceVaultRow { .. }))
            .unwrap();
        assert!(
            del_blob < del_row,
            "blob delete must precede vault row delete"
        );
    }

    #[test]
    fn insert_dest_before_delete_source() {
        // InsertDestVaultRow must come before DeleteSourceVaultRow so that
        // a crash between them leaves the file discoverable in at least one vault.
        let steps = basic_plan().steps;
        let insert = steps
            .iter()
            .position(|s| matches!(s, MoveStep::InsertDestVaultRow { .. }))
            .unwrap();
        let delete = steps
            .iter()
            .position(|s| matches!(s, MoveStep::DeleteSourceVaultRow { .. }))
            .unwrap();
        assert!(
            insert < delete,
            "InsertDestVaultRow must precede DeleteSourceVaultRow"
        );
    }

    #[test]
    fn provider_ids_correct() {
        let plan = basic_plan();
        if let MoveStep::DownloadSourceBlob { provider_id, .. } = &plan.steps[0] {
            assert_eq!(provider_id, "gdrive");
        }
        if let MoveStep::UploadDestBlob { provider_id } = &plan.steps[2] {
            assert_eq!(provider_id, "dropbox");
        }
    }

    #[test]
    fn description_contains_providers() {
        let plan = basic_plan();
        assert!(plan.description.contains("gdrive"));
        assert!(plan.description.contains("dropbox"));
        assert!(plan.description.contains("photo.jpg"));
    }

    #[test]
    fn folder_plan_delete_order_is_reverse_bfs() {
        // If BFS order is [root=1, child=2, grandchild=3],
        // delete order must be [3, 2, 1] (leaves first).
        let plan = CrossProviderFolderMovePlan::build("a", "b", &[1, 2, 3], &[], vec![]);
        assert_eq!(plan.source_folder_deletes, vec![3, 2, 1]);
    }

    #[test]
    fn folder_plan_total_items() {
        let creates = vec![FolderCreateStep {
            provider_id: "b".into(),
            parent_folder_id: None,
            name_encrypted_hint: String::new(),
        }];
        let plan = CrossProviderFolderMovePlan::build(
            "a",
            "b",
            &[10, 11],
            &[(1, "ref/x", Some(99), "file.txt")],
            creates,
        );
        // 1 folder_create + 1 file_move + 2 folder_deletes = 4
        assert_eq!(plan.total_items(), 4);
    }

    // ── plan_share_revocations tests ─────────────────────────────────────────

    fn make_share(share_id: &str, file_id: u64, variant: &str, revoked: bool) -> ShareRow {
        ShareRow {
            share_id: share_id.to_string(),
            file_id,
            variant: variant.to_string(),
            provider_id: "gdrive".to_string(),
            provider_ref: format!("WattcloudVault/data/{share_id}"),
            owner_token: if variant == "B1" || variant == "B2" {
                Some("tok".to_string())
            } else {
                None
            },
            revoked,
        }
    }

    #[test]
    fn empty_share_rows_produces_no_revocations() {
        let revocations = plan_share_revocations(&[1, 2], &[]);
        assert!(revocations.is_empty());
    }

    #[test]
    fn already_revoked_rows_are_skipped() {
        let rows = vec![make_share("s1", 1, "A", true)];
        let revocations = plan_share_revocations(&[1], &rows);
        assert!(revocations.is_empty());
    }

    #[test]
    fn shares_for_other_files_are_skipped() {
        let rows = vec![make_share("s1", 99, "A", false)];
        let revocations = plan_share_revocations(&[1, 2], &rows);
        assert!(revocations.is_empty());
    }

    #[test]
    fn active_share_for_moved_file_produces_revocation() {
        let rows = vec![make_share("s1", 1, "A+", false)];
        let revocations = plan_share_revocations(&[1], &rows);
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].share_id, "s1");
        assert_eq!(revocations[0].variant, "A+");
        assert!(revocations[0].owner_token.is_none());
    }

    #[test]
    fn b2_share_carries_owner_token() {
        let rows = vec![make_share("s2", 5, "B2", false)];
        let revocations = plan_share_revocations(&[5], &rows);
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].owner_token, Some("tok".to_string()));
    }

    #[test]
    fn mixed_active_and_revoked_shares_only_returns_active() {
        let rows = vec![
            make_share("s1", 1, "A", false),
            make_share("s2", 1, "B1", true), // already revoked — skip
            make_share("s3", 2, "A+", false),
            make_share("s4", 99, "B2", false), // different file — skip
        ];
        let revocations = plan_share_revocations(&[1, 2], &rows);
        let ids: Vec<&str> = revocations.iter().map(|r| r.share_id.as_str()).collect();
        assert_eq!(ids, vec!["s1", "s3"]);
    }

    #[test]
    fn pre_revokes_field_is_carried_in_plan() {
        let rows = vec![make_share("share-x", 42, "A", false)];
        let pre_revokes = plan_share_revocations(&[42], &rows);
        let plan = CrossProviderMovePlan::build(
            42,
            "ref/abc",
            "gdrive",
            "dropbox",
            None,
            "photo.jpg",
            pre_revokes,
        );
        assert_eq!(plan.pre_revokes.len(), 1);
        assert_eq!(plan.pre_revokes[0].share_id, "share-x");
    }
}
