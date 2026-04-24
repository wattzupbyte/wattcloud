// Replay decision logic for crash-safe cross-provider move.
//
// After a crash, the WAL may contain journaled `MoveStep` entries that did not
// complete. `decide_replay` is a pure function that, given the persisted step
// and the current observable state (does the dst row exist? does the src blob
// still exist?), returns an action the host platform should take.
//
// Only `DeleteSourceBlob` is retryable — it is the only step that is safe to
// re-execute if the dst row already exists (idempotent provider DELETE) and
// dangerous to skip if it does not exist (would leave the only copy orphaned
// on the source).

use super::MoveStep;

/// Action the host should take for a pending WAL move step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDecision {
    /// The step either already completed or is not relevant — nothing to do.
    Skip,
    /// Re-execute the blob delete on the given provider.
    Retry {
        provider_id: String,
        provider_ref: String,
    },
    /// State is ambiguous — do not retry; log a warning and discard the entry.
    ///
    /// This happens when we cannot safely re-execute without risking data loss
    /// (e.g., the dst row does not exist, meaning the move never committed).
    Abort,
}

/// Decide what to do with a pending WAL `MoveStep` on vault unlock.
///
/// Arguments:
/// - `step`: the journaled move step to evaluate.
/// - `dst_file_exists`: whether the destination vault row for this file now
///   exists (i.e., `InsertDestVaultRow` completed before the crash).
/// - `src_blob_exists`: provider-reported existence of the source blob.
///   `None` means unknown (connectivity unavailable); `Some(false)` means
///   already deleted.
pub fn decide_replay(
    step: &MoveStep,
    dst_file_exists: bool,
    src_blob_exists: Option<bool>,
) -> ReplayDecision {
    match step {
        MoveStep::DeleteSourceBlob {
            provider_id,
            provider_ref,
        } => {
            if !dst_file_exists {
                // Move never committed to the destination vault — the source
                // blob is the only copy. Do not delete it.
                return ReplayDecision::Abort;
            }
            // dst row exists → move committed. Check if src blob is still there.
            match src_blob_exists {
                Some(false) => ReplayDecision::Skip, // already deleted
                _ => ReplayDecision::Retry {
                    provider_id: provider_id.clone(),
                    provider_ref: provider_ref.clone(),
                },
            }
        }
        // All other steps are not individually retryable via WAL replay.
        // The reconciler handles orphan detection for UploadDestBlob failures.
        _ => ReplayDecision::Abort,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn delete_step(provider_id: &str, provider_ref: &str) -> MoveStep {
        MoveStep::DeleteSourceBlob {
            provider_id: provider_id.to_string(),
            provider_ref: provider_ref.to_string(),
        }
    }

    #[test]
    fn delete_retried_when_dst_exists_and_blob_unknown() {
        let step = delete_step("gdrive", "data/abc");
        let decision = decide_replay(&step, true, None);
        assert_eq!(
            decision,
            ReplayDecision::Retry {
                provider_id: "gdrive".to_string(),
                provider_ref: "data/abc".to_string(),
            }
        );
    }

    #[test]
    fn delete_retried_when_dst_exists_and_blob_present() {
        let step = delete_step("dropbox", "data/xyz");
        let decision = decide_replay(&step, true, Some(true));
        assert_eq!(
            decision,
            ReplayDecision::Retry {
                provider_id: "dropbox".to_string(),
                provider_ref: "data/xyz".to_string(),
            }
        );
    }

    #[test]
    fn delete_skipped_when_blob_already_gone() {
        let step = delete_step("s3", "data/gone");
        let decision = decide_replay(&step, true, Some(false));
        assert_eq!(decision, ReplayDecision::Skip);
    }

    #[test]
    fn delete_aborted_when_dst_row_missing() {
        // Move never committed → do not delete the only copy.
        let step = delete_step("gdrive", "data/abc");
        let decision = decide_replay(&step, false, Some(true));
        assert_eq!(decision, ReplayDecision::Abort);
    }

    #[test]
    fn delete_aborted_when_dst_row_missing_even_if_blob_unknown() {
        let step = delete_step("gdrive", "data/abc");
        let decision = decide_replay(&step, false, None);
        assert_eq!(decision, ReplayDecision::Abort);
    }

    #[test]
    fn non_delete_steps_abort() {
        let steps = [
            MoveStep::DownloadSourceBlob {
                provider_id: "g".to_string(),
                provider_ref: "r".to_string(),
            },
            MoveStep::UploadDestBlob {
                provider_id: "d".to_string(),
            },
            MoveStep::InsertDestVaultRow {
                provider_id: "d".to_string(),
                dest_folder_id: None,
            },
            MoveStep::DeleteSourceVaultRow {
                provider_id: "g".to_string(),
                file_id: 1,
            },
        ];
        for step in &steps {
            assert_eq!(
                decide_replay(step, true, Some(true)),
                ReplayDecision::Abort,
                "non-delete step should abort: {step:?}"
            );
        }
    }
}
