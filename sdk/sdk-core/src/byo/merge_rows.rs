// Pure row-merge logic for BYO vault conflict resolution.
//
// Takes serialized row sets as serde_json::Value arrays and returns a
// list of operations to apply to the local database. No I/O, no crypto.
//
// Merge semantics:
//   key_versions  — union only; local wins on id conflict (never overwrite key material)
//   data tables   — last-writer-wins on `updated_at` (fall back to `created_at`);
//                   remote-only rows are inserted; local-only rows kept unchanged

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single merge operation to apply to the local database.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum MergeOp {
    /// Insert this row into the local DB (row only exists in remote).
    #[serde(rename = "insert")]
    Insert { row: Value },
    /// Update the local row with this data (remote is newer).
    #[serde(rename = "update")]
    Update { row: Value },
    /// Keep local row as-is (local is newer or equal, or key_versions conflict).
    #[serde(rename = "skip")]
    Skip,
}

/// Compute merge operations for one table.
///
/// - `local_rows`: rows currently in the local DB for this table (for the relevant provider).
/// - `remote_rows`: rows from the remote vault for this table.
/// - `is_key_versions`: if true, applies key_versions semantics (union, local wins on conflict).
///
/// Returns one `MergeOp` per remote row (in the same order as `remote_rows`).
/// Local-only rows are untouched and have no corresponding op.
pub fn merge_rows(
    local_rows: &[Value],
    remote_rows: &[Value],
    is_key_versions: bool,
) -> Vec<MergeOp> {
    remote_rows
        .iter()
        .map(|remote| {
            let remote_id = extract_id(remote);
            let local =
                remote_id.and_then(|id| local_rows.iter().find(|r| extract_id(r) == Some(id)));

            match local {
                None => MergeOp::Insert {
                    row: remote.clone(),
                },
                Some(_) if is_key_versions => MergeOp::Skip,
                Some(local_row) => {
                    if row_newer(remote, local_row) {
                        MergeOp::Update {
                            row: remote.clone(),
                        }
                    } else {
                        MergeOp::Skip
                    }
                }
            }
        })
        .collect()
}

/// Extract the `id` field as an i64 (SQLite INTEGER PRIMARY KEY).
fn extract_id(row: &Value) -> Option<i64> {
    row.get("id").and_then(|v| v.as_i64())
}

/// Return true if `remote` has a strictly newer timestamp than `local`.
/// Handles both numeric (Unix ms/s) and string (ISO 8601) timestamps.
/// Falls back through updated_at → created_at.
///
/// A5: if the local row has a missing/empty timestamp, prefer the local row
/// (return false). The previous behaviour — remote-wins-when-local-empty —
/// silently overwrote freshly-inserted rows whose `updated_at` hadn't yet been
/// stamped by the client, producing last-sync-wins data loss.
fn row_newer(remote: &Value, local: &Value) -> bool {
    for field in &["updated_at", "created_at"] {
        let r = remote.get(field);
        let l = local.get(field);
        match (r, l) {
            (Some(rv), Some(lv)) => {
                // Try numeric comparison first (both integers or floats).
                if let (Some(rn), Some(ln)) = (rv.as_f64(), lv.as_f64()) {
                    return rn > ln;
                }
                // Fall back to string comparison (ISO 8601 sorts correctly as strings).
                let rs = rv.as_str().unwrap_or("");
                let ls = lv.as_str().unwrap_or("");
                if ls.is_empty() {
                    // Local timestamp missing/empty → prefer local, fall through to created_at.
                    continue;
                }
                if !rs.is_empty() {
                    return rs > ls;
                }
                // Remote missing but local present → local newer.
                continue;
            }
            // Remote has field, local doesn't → prefer local (was previously remote-wins).
            (Some(_), None) => continue,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn remote_only_row_is_inserted() {
        let local = vec![];
        let remote = vec![json!({"id": 1, "name": "file.txt", "updated_at": "2024-01-01"})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Insert { .. }));
    }

    #[test]
    fn local_newer_is_skipped() {
        let local = vec![json!({"id": 1, "updated_at": "2024-02-01"})];
        let remote = vec![json!({"id": 1, "updated_at": "2024-01-01"})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Skip));
    }

    #[test]
    fn remote_newer_is_updated() {
        let local = vec![json!({"id": 1, "updated_at": "2024-01-01"})];
        let remote = vec![json!({"id": 1, "updated_at": "2024-02-01"})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Update { .. }));
    }

    #[test]
    fn equal_timestamps_skipped() {
        let local = vec![json!({"id": 1, "updated_at": "2024-01-01"})];
        let remote = vec![json!({"id": 1, "updated_at": "2024-01-01"})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Skip));
    }

    #[test]
    fn key_versions_conflict_skips() {
        let local = vec![json!({"id": 1, "version": 1})];
        let remote = vec![json!({"id": 1, "version": 1, "newer_field": true})];
        let ops = merge_rows(&local, &remote, true);
        assert!(matches!(ops[0], MergeOp::Skip));
    }

    #[test]
    fn key_versions_new_row_inserted() {
        let local = vec![];
        let remote = vec![json!({"id": 2, "version": 2})];
        let ops = merge_rows(&local, &remote, true);
        assert!(matches!(ops[0], MergeOp::Insert { .. }));
    }

    #[test]
    fn numeric_timestamps_compared_correctly() {
        // String comparison "9" > "10" but numeric 9 < 10
        let local = vec![json!({"id": 1, "updated_at": 10})];
        let remote = vec![json!({"id": 1, "updated_at": 9})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Skip)); // local (10) is newer
    }

    #[test]
    fn numeric_remote_newer_is_updated() {
        let local = vec![json!({"id": 1, "updated_at": 9})];
        let remote = vec![json!({"id": 1, "updated_at": 10})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Update { .. }));
    }

    #[test]
    fn falls_back_to_created_at() {
        let local = vec![json!({"id": 1, "created_at": "2024-01-01"})];
        let remote = vec![json!({"id": 1, "created_at": "2024-02-01"})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Update { .. }));
    }

    #[test]
    fn multiple_rows_correct_ops() {
        let local = vec![
            json!({"id": 1, "updated_at": "2024-02-01"}),
            json!({"id": 2, "updated_at": "2024-01-01"}),
        ];
        let remote = vec![
            json!({"id": 1, "updated_at": "2024-01-01"}), // local newer → skip
            json!({"id": 2, "updated_at": "2024-02-01"}), // remote newer → update
            json!({"id": 3, "updated_at": "2024-01-01"}), // remote only → insert
        ];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Skip));
        assert!(matches!(ops[1], MergeOp::Update { .. }));
        assert!(matches!(ops[2], MergeOp::Insert { .. }));
    }

    // A5: when the local row is missing a timestamp (freshly inserted,
    // not-yet-stamped), the merge must NOT overwrite it with a remote row that
    // has any timestamp — that would be silent data loss on every sync.
    #[test]
    fn remote_has_ts_local_missing_keeps_local() {
        let local = vec![json!({"id": 1})];
        let remote = vec![json!({"id": 1, "updated_at": "2024-01-01"})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Skip));
    }

    #[test]
    fn remote_has_ts_local_empty_string_keeps_local() {
        let local = vec![json!({"id": 1, "updated_at": ""})];
        let remote = vec![json!({"id": 1, "updated_at": "2024-01-01"})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Skip));
    }

    // The converse still works: when local has a timestamp and remote has an
    // updated_at falls back to created_at (still compared).
    #[test]
    fn both_have_ts_uses_newer() {
        let local = vec![json!({"id": 1, "updated_at": "2024-01-01"})];
        let remote = vec![json!({"id": 1, "updated_at": "2024-02-01"})];
        let ops = merge_rows(&local, &remote, false);
        assert!(matches!(ops[0], MergeOp::Update { .. }));
    }
}
