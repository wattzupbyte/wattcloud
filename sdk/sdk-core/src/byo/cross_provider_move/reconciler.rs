// Reconciler for pending cross-provider move WAL entries.
//
// After replaying SQL WAL mutations on vault unlock, the host calls
// `plan_reconcile` with any blob-op WAL entries that survived the crash.
// The returned `ReconcileAction` list tells the host which blob deletes
// to retry (in order). After each successful action the host removes the
// corresponding WAL entry.
//
// Design notes:
// - Only `DeleteSourceBlob` entries produce retry actions. All others are
//   discarded (consistent with `execution::decide_replay`).
// - `dst_file_exists` must be determined by the host after WAL SQL replay
//   (i.e., after the SQLite DB reflects the post-crash state).

use super::{execution::decide_replay, MoveStep};

/// An action the host should execute as part of move-step reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    /// Delete the named blob from the given provider (idempotent retry of
    /// a `DeleteSourceBlob` step that did not complete before the crash).
    DeleteBlob {
        provider_id: String,
        provider_ref: String,
    },
}

/// Given a list of pending WAL move steps and the current DB state, return
/// the ordered list of reconciliation actions the host should execute.
///
/// Arguments:
/// - `pending_steps`: `MoveStep` values decoded from WAL blob-op entries.
/// - `dst_file_exists`: whether the destination vault row for the moved file
///   now exists (post-SQL-replay). The host looks up the file by its known
///   `file_id` after completing WAL SQL replay.
/// - `src_blob_exists`: provider-reported blob existence. Pass `None` when
///   the provider is offline; the reconciler conservatively retries the
///   delete when the blob state is unknown.
pub fn plan_reconcile(
    pending_steps: &[MoveStep],
    dst_file_exists: bool,
    src_blob_exists: Option<bool>,
) -> Vec<ReconcileAction> {
    pending_steps
        .iter()
        .filter_map(|step| {
            match decide_replay(step, dst_file_exists, src_blob_exists) {
                super::execution::ReplayDecision::Retry { provider_id, provider_ref } => {
                    Some(ReconcileAction::DeleteBlob { provider_id, provider_ref })
                }
                _ => None,
            }
        })
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn del(provider_id: &str, provider_ref: &str) -> MoveStep {
        MoveStep::DeleteSourceBlob {
            provider_id: provider_id.to_string(),
            provider_ref: provider_ref.to_string(),
        }
    }

    #[test]
    fn empty_pending_returns_empty_actions() {
        let actions = plan_reconcile(&[], true, Some(true));
        assert!(actions.is_empty());
    }

    #[test]
    fn delete_step_with_dst_row_and_blob_present_returns_action() {
        let steps = vec![del("gdrive", "data/abc")];
        let actions = plan_reconcile(&steps, true, Some(true));
        assert_eq!(
            actions,
            vec![ReconcileAction::DeleteBlob {
                provider_id: "gdrive".to_string(),
                provider_ref: "data/abc".to_string(),
            }]
        );
    }

    #[test]
    fn delete_step_already_gone_skipped() {
        let steps = vec![del("gdrive", "data/abc")];
        let actions = plan_reconcile(&steps, true, Some(false));
        assert!(actions.is_empty());
    }

    #[test]
    fn delete_step_no_dst_row_skipped() {
        // Move never committed — do not delete source blob.
        let steps = vec![del("gdrive", "data/abc")];
        let actions = plan_reconcile(&steps, false, Some(true));
        assert!(actions.is_empty());
    }

    #[test]
    fn non_delete_steps_produce_no_actions() {
        let steps = vec![
            MoveStep::DownloadSourceBlob {
                provider_id: "g".to_string(),
                provider_ref: "r".to_string(),
            },
            MoveStep::UploadDestBlob { provider_id: "d".to_string() },
            MoveStep::InsertDestVaultRow {
                provider_id: "d".to_string(),
                dest_folder_id: None,
            },
        ];
        let actions = plan_reconcile(&steps, true, Some(true));
        assert!(actions.is_empty());
    }

    #[test]
    fn multiple_pending_deletes_all_returned() {
        let steps = vec![
            del("gdrive", "data/aaa"),
            del("dropbox", "data/bbb"),
        ];
        let actions = plan_reconcile(&steps, true, None);
        assert_eq!(actions.len(), 2);
        assert!(actions.iter().any(|a| matches!(a, ReconcileAction::DeleteBlob { provider_id, .. } if provider_id == "gdrive")));
        assert!(actions.iter().any(|a| matches!(a, ReconcileAction::DeleteBlob { provider_id, .. } if provider_id == "dropbox")));
    }

    #[test]
    fn wal_entry_round_trip() {
        let step = del("s3", "data/round-trip");
        let bytes = step.to_wal_entry().expect("encode");
        let decoded = MoveStep::from_wal_entry(&bytes).expect("decode");
        assert_eq!(decoded, step);
    }
}
