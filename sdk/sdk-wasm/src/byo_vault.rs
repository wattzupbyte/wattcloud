// R6 multi-vault WASM bindings.
//
// All byte arrays cross the JS boundary as base64 strings (standard SDK convention).
// JSON strings cross as plain UTF-8 strings.
// Errors return { error: "message" }.
//
// Functions that require a vault session take a `session_id: u32` to look up
// the `vault_key` inside WASM.  Pure orchestration functions (plan builders,
// merge) do not need the session.

use sdk_core::byo::{
    cross_provider_move::{
        execution::decide_replay,
        reconciler::{plan_reconcile, ReconcileAction},
        CrossProviderMovePlan,
    },
    decrypt_body, decrypt_manifest, encrypt_body, encrypt_manifest,
    manifest::Manifest,
    merge_manifests,
    multi_vault::{SavePlan, UnlockPlan},
    per_vault_key::{derive_manifest_aead_key, derive_per_vault_aead_key},
    validate_manifest,
};
use wasm_bindgen::prelude::*;

use crate::util::{b64_decode, b64_encode, js_error, js_set};
use crate::vault_session::with_vault_session;

// ─── Manifest encrypt / decrypt ───────────────────────────────────────────────

/// Encrypt a manifest JSON string into the vault_manifest.sc body blob.
///
/// `session_id`     — open vault session (vault_key extracted internally).
/// `manifest_json`  — UTF-8 JSON string of a `Manifest` object.
///
/// Returns `{ data: "<base64>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_manifest_encrypt(session_id: u32, manifest_json: &str) -> JsValue {
    let manifest: Manifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return js_error(&format!("manifest parse error: {e}")),
    };

    let result = with_vault_session(session_id, |sess| {
        encrypt_manifest(&sess.vault_key, &manifest)
    });

    match result {
        None => js_error("session not found"),
        Some(Err(e)) => js_error(&e.to_string()),
        Some(Ok(blob)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "data", &JsValue::from_str(&b64_encode(&blob)));
            obj.into()
        }
    }
}

/// Decrypt the body blob from vault_manifest.sc.
///
/// `session_id`  — open vault session.
/// `body_blob`   — base64-encoded `[ iv(12) | ct_with_tag ]` bytes.
///
/// Returns `{ manifest_json: "<string>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_manifest_decrypt(session_id: u32, body_blob_b64: &str) -> JsValue {
    let blob = match b64_decode(body_blob_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 input"),
    };

    let result = with_vault_session(session_id, |sess| decrypt_manifest(&sess.vault_key, &blob));

    match result {
        None => js_error("session not found"),
        Some(Err(e)) => js_error(&e.to_string()),
        Some(Ok(manifest)) => match serde_json::to_string(&manifest) {
            Err(e) => js_error(&format!("manifest serialize error: {e}")),
            Ok(json) => {
                let obj = js_sys::Object::new();
                js_set(&obj, "manifest_json", &JsValue::from_str(&json));
                obj.into()
            }
        },
    }
}

// ─── Manifest merge (no session required) ────────────────────────────────────

/// Merge two or more manifest JSON strings fetched from different providers.
///
/// `manifest_jsons_json` — a JSON array of manifest JSON strings.
///   Example: `["<json1>", "<json2>"]`
///
/// `now_unix_secs` — current Unix time in seconds for clock-skew rejection.
///   Pass `0` to skip the clock-skew check (e.g. in tests).
///
/// `min_acceptable_version` — the lowest merged manifest_version the caller
///   will accept.  Pass `0` to skip the rollback check.  Callers should pass
///   `last_seen_manifest_version` from IndexedDB here.
///
/// Returns `{ manifest_json: "<merged string>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_manifest_merge(
    manifest_jsons_json: &str,
    now_unix_secs: f64,
    min_acceptable_version: f64,
) -> JsValue {
    let now = if now_unix_secs <= 0.0 {
        u64::MAX // skip clock-skew check
    } else {
        now_unix_secs as u64
    };
    // min_acceptable_version <= 0 → no floor (None); positive → enforce floor.
    // The WASM boundary uses f64 for numeric arguments; map non-positive back
    // to the Option<u64> contract used by sdk-core (M1).
    let min_ver: Option<u64> = if min_acceptable_version <= 0.0 {
        None
    } else {
        Some(min_acceptable_version as u64)
    };

    const MAX_MANIFEST_SIZE_BYTES: usize = 1024 * 1024; // 1 MiB
    const MAX_MANIFEST_PROVIDERS: usize = 256;

    // Parse the outer JSON array of strings.
    let json_strs: Vec<String> = match serde_json::from_str(manifest_jsons_json) {
        Ok(v) => v,
        Err(e) => return js_error(&format!("input parse error: {e}")),
    };

    let mut manifests: Vec<Manifest> = Vec::with_capacity(json_strs.len());
    for (i, s) in json_strs.iter().enumerate() {
        if s.len() > MAX_MANIFEST_SIZE_BYTES {
            return js_error("manifest too large");
        }
        let m: Manifest = match serde_json::from_str(s) {
            Ok(m) => m,
            Err(e) => return js_error(&format!("manifest[{i}] parse error: {e}")),
        };
        if m.providers.len() > MAX_MANIFEST_PROVIDERS {
            return js_error("manifest: too many providers");
        }
        manifests.push(m);
    }

    let refs: Vec<&Manifest> = manifests.iter().collect();
    match merge_manifests(&refs, now, min_ver) {
        Err(e) => js_error(&e.to_string()),
        Ok(merged) => match serde_json::to_string(&merged) {
            Err(e) => js_error(&format!("serialize error: {e}")),
            Ok(json) => {
                let obj = js_sys::Object::new();
                js_set(&obj, "manifest_json", &JsValue::from_str(&json));
                obj.into()
            }
        },
    }
}

/// Validate a manifest JSON string and return errors if any invariants are violated.
///
/// `now_unix_secs` — current Unix time in seconds for clock-skew validation.
///   Pass `-1.0` (or any negative value) to explicitly skip the clock-skew check.
///   Passing `0` is treated as a valid timestamp (Unix epoch), NOT as "skip".
///
/// Returns `{}` on success or `{ error }`.
#[wasm_bindgen]
pub fn byo_manifest_validate(manifest_json: &str, now_unix_secs: f64) -> JsValue {
    const MAX_MANIFEST_SIZE_BYTES: usize = 1024 * 1024; // 1 MiB
    if manifest_json.len() > MAX_MANIFEST_SIZE_BYTES {
        return js_error("manifest too large");
    }
    let now = if now_unix_secs < 0.0 {
        u64::MAX // explicit skip sentinel
    } else {
        now_unix_secs as u64
    };
    let manifest: Manifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return js_error(&format!("manifest parse error: {e}")),
    };
    match validate_manifest(&manifest, now) {
        Err(e) => js_error(&e.to_string()),
        Ok(()) => js_sys::Object::new().into(),
    }
}

// ─── Manifest mutation helpers (P3.3) ────────────────────────────────────────

/// Add a new provider entry to the manifest JSON.
///
/// `manifest_json` — current manifest as a JSON string.
/// `entry_json`    — new ManifestEntry as a JSON string.
///
/// Returns `{ manifest_json: "<updated>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_manifest_add_provider(manifest_json: &str, entry_json: &str) -> JsValue {
    use sdk_core::byo::manifest::{manifest_add_provider, ManifestEntry};
    let mut manifest: Manifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return js_error(&format!("manifest parse error: {e}")),
    };
    let entry: ManifestEntry = match serde_json::from_str(entry_json) {
        Ok(e) => e,
        Err(e) => return js_error(&format!("entry parse error: {e}")),
    };
    if let Err(e) = manifest_add_provider(&mut manifest, entry) {
        return js_error(&e.to_string());
    }
    match serde_json::to_string(&manifest) {
        Err(e) => js_error(&format!("serialize error: {e}")),
        Ok(json) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "manifest_json", &JsValue::from_str(&json));
            obj.into()
        }
    }
}

/// Rename a provider's display name.
///
/// `now_unix_secs` — current Unix time (used to update `updated_at`).
/// Returns `{ manifest_json: "<updated>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_manifest_rename_provider(
    manifest_json: &str,
    provider_id: &str,
    new_name: &str,
    now_unix_secs: f64,
) -> JsValue {
    use sdk_core::byo::manifest::manifest_rename_provider;
    let mut manifest: Manifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return js_error(&format!("manifest parse error: {e}")),
    };
    let now = now_unix_secs as u64;
    if let Err(e) = manifest_rename_provider(&mut manifest, provider_id, new_name, now) {
        return js_error(&e.to_string());
    }
    match serde_json::to_string(&manifest) {
        Err(e) => js_error(&format!("serialize error: {e}")),
        Ok(json) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "manifest_json", &JsValue::from_str(&json));
            obj.into()
        }
    }
}

/// Replace a provider entry's `config_json`.
///
/// Used when the user edits provider settings (host, credentials, …) for an
/// already-enrolled provider. The new value is treated as opaque by the
/// manifest layer; the caller is expected to have already validated it
/// (e.g. by attempting `init()` against the new config).
///
/// `now_unix_secs` — current Unix time (used to update `updated_at`).
/// Returns `{ manifest_json: "<updated>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_manifest_update_provider_config(
    manifest_json: &str,
    provider_id: &str,
    new_config_json: &str,
    now_unix_secs: f64,
) -> JsValue {
    use sdk_core::byo::manifest::manifest_update_provider_config;
    let mut manifest: Manifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return js_error(&format!("manifest parse error: {e}")),
    };
    let now = now_unix_secs as u64;
    if let Err(e) =
        manifest_update_provider_config(&mut manifest, provider_id, new_config_json, now)
    {
        return js_error(&e.to_string());
    }
    match serde_json::to_string(&manifest) {
        Err(e) => js_error(&format!("serialize error: {e}")),
        Ok(json) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "manifest_json", &JsValue::from_str(&json));
            obj.into()
        }
    }
}

/// Designate a provider as the primary.
///
/// Clears `is_primary` on all others; sets it on `provider_id`.
/// Returns `{ manifest_json: "<updated>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_manifest_set_primary_provider(
    manifest_json: &str,
    provider_id: &str,
    now_unix_secs: f64,
) -> JsValue {
    use sdk_core::byo::manifest::manifest_set_primary_provider;
    let mut manifest: Manifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return js_error(&format!("manifest parse error: {e}")),
    };
    let now = now_unix_secs as u64;
    if let Err(e) = manifest_set_primary_provider(&mut manifest, provider_id, now) {
        return js_error(&e.to_string());
    }
    match serde_json::to_string(&manifest) {
        Err(e) => js_error(&format!("serialize error: {e}")),
        Ok(json) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "manifest_json", &JsValue::from_str(&json));
            obj.into()
        }
    }
}

/// Tombstone an active provider (mark as removed).
///
/// Sets `tombstone = true`; clears `is_primary`; updates `updated_at`.
/// Returns `{ manifest_json: "<updated>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_manifest_tombstone_provider(
    manifest_json: &str,
    provider_id: &str,
    now_unix_secs: f64,
) -> JsValue {
    use sdk_core::byo::manifest::manifest_tombstone_provider;
    let mut manifest: Manifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return js_error(&format!("manifest parse error: {e}")),
    };
    let now = now_unix_secs as u64;
    if let Err(e) = manifest_tombstone_provider(&mut manifest, provider_id, now) {
        return js_error(&e.to_string());
    }
    match serde_json::to_string(&manifest) {
        Err(e) => js_error(&format!("serialize error: {e}")),
        Ok(json) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "manifest_json", &JsValue::from_str(&json));
            obj.into()
        }
    }
}

// ─── Per-vault body encrypt / decrypt ────────────────────────────────────────

/// Encrypt a vault body (SQLite bytes) with the per-vault subkey for `provider_id`.
///
/// `session_id`   — open vault session.
/// `provider_id`  — the provider this vault body belongs to.
/// `sqlite_b64`   — base64-encoded SQLite bytes.
///
/// Returns `{ data: "<base64 body blob>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_body_encrypt(session_id: u32, provider_id: &str, sqlite_b64: &str) -> JsValue {
    let sqlite_bytes = match b64_decode(sqlite_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 input"),
    };

    let result = with_vault_session(session_id, |sess| {
        let aead_key = derive_per_vault_aead_key(&sess.vault_key, provider_id)?;
        encrypt_body(&sqlite_bytes, &aead_key)
    });

    match result {
        None => js_error("session not found"),
        Some(Err(e)) => js_error(&e.to_string()),
        Some(Ok(blob)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "data", &JsValue::from_str(&b64_encode(&blob)));
            obj.into()
        }
    }
}

/// Decrypt a vault body blob with the per-vault subkey for `provider_id`.
///
/// `session_id`   — open vault session.
/// `provider_id`  — the provider this vault body belongs to.
/// `body_blob_b64` — base64-encoded `[ iv(12) | ct_with_tag ]` bytes.
///
/// Returns `{ data: "<base64 sqlite bytes>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_vault_body_decrypt(session_id: u32, provider_id: &str, body_blob_b64: &str) -> JsValue {
    let blob = match b64_decode(body_blob_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 input"),
    };

    let result = with_vault_session(session_id, |sess| {
        let aead_key = derive_per_vault_aead_key(&sess.vault_key, provider_id)?;
        decrypt_body(&blob, &aead_key)
    });

    match result {
        None => js_error("session not found"),
        Some(Err(e)) => js_error(&e.to_string()),
        Some(Ok(sqlite_bytes)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "data", &JsValue::from_str(&b64_encode(&sqlite_bytes)));
            obj.into()
        }
    }
}

/// Derive the per-vault WAL key for `provider_id` and return it as base64.
///
/// Used by the frontend to initialise the per-provider IndexedDB WAL crypto context.
/// The key stays in JS memory for the session; it is derived fresh on each unlock.
///
/// Returns `{ key_b64: "<32-byte key in base64>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_derive_per_vault_wal_key(session_id: u32, provider_id: &str) -> JsValue {
    use sdk_core::byo::per_vault_key::derive_per_vault_wal_key;
    let result = with_vault_session(session_id, |sess| {
        derive_per_vault_wal_key(&sess.vault_key, provider_id)
    });
    match result {
        None => js_error("session not found"),
        Some(Err(e)) => js_error(&e.to_string()),
        Some(Ok(key)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "key_b64",
                &JsValue::from_str(&b64_encode(key.as_bytes())),
            );
            obj.into()
        }
    }
}

/// Derive the per-vault journal AEAD and HMAC keys for `provider_id`.
///
/// Returns `{ aead_key_b64: "...", hmac_key_b64: "..." }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_derive_per_vault_journal_keys(session_id: u32, provider_id: &str) -> JsValue {
    use sdk_core::byo::per_vault_key::derive_per_vault_journal_keys;
    let result = with_vault_session(session_id, |sess| {
        derive_per_vault_journal_keys(&sess.vault_key, provider_id)
    });
    match result {
        None => js_error("session not found"),
        Some(Err(e)) => js_error(&e.to_string()),
        Some(Ok(keys)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "aead_key_b64",
                &JsValue::from_str(&b64_encode(keys.aead.as_bytes())),
            );
            js_set(
                &obj,
                "hmac_key_b64",
                &JsValue::from_str(&b64_encode(keys.hmac.as_bytes())),
            );
            obj.into()
        }
    }
}

// ─── Orchestration plan builders (no session required) ───────────────────────

/// Build an unlock plan from provider availability information.
///
/// Arguments (all JSON strings):
/// - `manifest_json`: the merged manifest.
/// - `online_ids_json`: JSON array of currently reachable provider IDs.
/// - `cached_ids_json`: JSON array of provider IDs with a local IDB cache.
///
/// Returns `{ plan_json: "<UnlockPlan as JSON>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_plan_unlock(
    manifest_json: &str,
    online_ids_json: &str,
    cached_ids_json: &str,
) -> JsValue {
    let manifest: Manifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return js_error(&format!("manifest parse error: {e}")),
    };
    let online_ids: Vec<String> = match serde_json::from_str(online_ids_json) {
        Ok(v) => v,
        Err(e) => return js_error(&format!("online_ids parse error: {e}")),
    };
    let cached_ids: Vec<String> = match serde_json::from_str(cached_ids_json) {
        Ok(v) => v,
        Err(e) => return js_error(&format!("cached_ids parse error: {e}")),
    };

    // Extract active provider IDs and primary ID from the manifest.
    let provider_ids: Vec<&str> = manifest
        .active_providers()
        .map(|e| e.provider_id.as_str())
        .collect();
    let primary_id = manifest
        .primary_provider()
        .map(|e| e.provider_id.as_str())
        .unwrap_or("");

    // Manifest sync targets: providers whose manifest_version_hint is behind.
    // For now, we push to all online providers to keep it simple.
    // A future optimisation could diff per-provider version hints.
    let manifest_sync_targets: Vec<&str> = online_ids.iter().map(|s| s.as_str()).collect();

    let online_refs: Vec<&str> = online_ids.iter().map(|s| s.as_str()).collect();
    let cached_refs: Vec<&str> = cached_ids.iter().map(|s| s.as_str()).collect();

    let plan = UnlockPlan::build(
        &provider_ids,
        &online_refs,
        &cached_refs,
        primary_id,
        &manifest_sync_targets,
    );

    match serde_json::to_string(&plan) {
        Err(e) => js_error(&format!("plan serialize error: {e}")),
        Ok(json) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "plan_json", &JsValue::from_str(&json));
            obj.into()
        }
    }
}

/// Build a save plan from the set of dirty providers and currently online providers.
///
/// Arguments (all JSON arrays of strings):
/// - `dirty_ids_json`: provider IDs whose in-memory vault rows were mutated.
/// - `online_ids_json`: currently reachable provider IDs.
///
/// Returns `{ plan_json: "<SavePlan as JSON>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_plan_save(dirty_ids_json: &str, online_ids_json: &str) -> JsValue {
    let dirty_ids: Vec<String> = match serde_json::from_str(dirty_ids_json) {
        Ok(v) => v,
        Err(e) => return js_error(&format!("dirty_ids parse error: {e}")),
    };
    let online_ids: Vec<String> = match serde_json::from_str(online_ids_json) {
        Ok(v) => v,
        Err(e) => return js_error(&format!("online_ids parse error: {e}")),
    };

    let dirty_refs: Vec<&str> = dirty_ids.iter().map(|s| s.as_str()).collect();
    let online_refs: Vec<&str> = online_ids.iter().map(|s| s.as_str()).collect();

    let plan = SavePlan::build(&dirty_refs, &online_refs);

    match serde_json::to_string(&plan) {
        Err(e) => js_error(&format!("plan serialize error: {e}")),
        Ok(json) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "plan_json", &JsValue::from_str(&json));
            obj.into()
        }
    }
}

/// Build a cross-provider file move plan.
///
/// Arguments:
/// - `file_id`: the file's row ID (u64 as f64 — JS number).
/// - `source_provider_ref`: opaque blob reference on the source provider.
/// - `src_provider_id` / `dst_provider_id`: source and destination providers.
/// - `dest_folder_id`: folder on destination (negative = root / null).
/// - `display_name`: file's display name for the progress UI.
///
/// Returns `{ plan_json: "<CrossProviderMovePlan as JSON>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_plan_cross_provider_move(
    file_id: f64,
    source_provider_ref: &str,
    src_provider_id: &str,
    dst_provider_id: &str,
    dest_folder_id: f64,
    display_name: &str,
) -> JsValue {
    let fid = if file_id.is_finite() && file_id >= 0.0 && file_id <= (u64::MAX as f64) {
        file_id as u64
    } else {
        return js_error(&format!("file_id out of range: {file_id}"));
    };
    let dest_folder = if !dest_folder_id.is_finite() {
        return js_error(&format!("dest_folder_id out of range: {dest_folder_id}"));
    } else if dest_folder_id < 0.0 {
        None
    } else {
        Some(dest_folder_id as u64)
    };

    let plan = CrossProviderMovePlan::build(
        fid,
        source_provider_ref,
        src_provider_id,
        dst_provider_id,
        dest_folder,
        display_name,
        vec![], // pre_revokes populated by the TS layer before dispatching
    );

    match serde_json::to_string(&plan) {
        Err(e) => js_error(&format!("plan serialize error: {e}")),
        Ok(json) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "plan_json", &JsValue::from_str(&json));
            obj.into()
        }
    }
}

/// Evaluate whether a pending WAL `MoveStep` (serialized via `to_wal_entry`)
/// should be retried, skipped, or aborted after a crash recovery.
///
/// Arguments (all strings to avoid u64 precision loss in JS):
/// - `step_bytes_b64`: base64-encoded bytes from `MoveStep::to_wal_entry()`.
/// - `dst_file_exists`: `"true"` / `"false"`.
/// - `src_blob_exists`: `"true"` / `"false"` / `"unknown"`.
///
/// Returns `{ decision: "Retry" | "Skip" | "Abort", provider_id?, provider_ref? }`.
#[wasm_bindgen]
pub fn byo_cross_provider_move_decide_replay(
    step_bytes_b64: &str,
    dst_file_exists: bool,
    src_blob_exists_str: &str,
) -> JsValue {
    let bytes = match crate::util::b64_decode(step_bytes_b64) {
        Ok(b) => b,
        Err(_) => return js_error("step_bytes_b64 decode failed"),
    };
    let step = match sdk_core::byo::MoveStep::from_wal_entry(&bytes) {
        Ok(s) => s,
        Err(e) => return js_error(&format!("step decode: {e}")),
    };
    let src_blob_exists = match src_blob_exists_str {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    };
    let obj = js_sys::Object::new();
    match decide_replay(&step, dst_file_exists, src_blob_exists) {
        sdk_core::byo::ReplayDecision::Skip => {
            js_set(&obj, "decision", &JsValue::from_str("Skip"));
        }
        sdk_core::byo::ReplayDecision::Abort => {
            js_set(&obj, "decision", &JsValue::from_str("Abort"));
        }
        sdk_core::byo::ReplayDecision::Retry {
            provider_id,
            provider_ref,
        } => {
            js_set(&obj, "decision", &JsValue::from_str("Retry"));
            js_set(&obj, "provider_id", &JsValue::from_str(&provider_id));
            js_set(&obj, "provider_ref", &JsValue::from_str(&provider_ref));
        }
    }
    obj.into()
}

/// Given a list of pending WAL move steps and the current DB state, return
/// the ordered list of reconciliation actions the host should execute.
///
/// Arguments:
/// - `steps_json`: JSON array of base64-encoded step byte strings
///   (`Array<string>`, each element from `MoveStep::to_wal_entry()`).
/// - `dst_file_exists`: whether the dst vault row for the moved file now exists.
/// - `src_blob_exists_str`: `"true"` / `"false"` / `"unknown"`.
///
/// Returns `{ actions: Array<{ type: "DeleteBlob", provider_id, provider_ref }> }`.
#[wasm_bindgen]
pub fn byo_cross_provider_move_plan_reconcile(
    steps_json: &str,
    dst_file_exists: bool,
    src_blob_exists_str: &str,
) -> JsValue {
    let b64_list: Vec<String> = match serde_json::from_str(steps_json) {
        Ok(v) => v,
        Err(e) => return js_error(&format!("steps_json parse: {e}")),
    };
    let mut steps = Vec::with_capacity(b64_list.len());
    for b64 in &b64_list {
        let bytes = match crate::util::b64_decode(b64) {
            Ok(b) => b,
            Err(_) => return js_error("step b64 decode failed"),
        };
        match sdk_core::byo::MoveStep::from_wal_entry(&bytes) {
            Ok(s) => steps.push(s),
            Err(e) => return js_error(&format!("step decode: {e}")),
        }
    }
    let src_blob_exists = match src_blob_exists_str {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    };
    let actions = plan_reconcile(&steps, dst_file_exists, src_blob_exists);
    let arr = js_sys::Array::new();
    for action in actions {
        let item = js_sys::Object::new();
        match action {
            ReconcileAction::DeleteBlob {
                provider_id,
                provider_ref,
            } => {
                js_set(&item, "type", &JsValue::from_str("DeleteBlob"));
                js_set(&item, "provider_id", &JsValue::from_str(&provider_id));
                js_set(&item, "provider_ref", &JsValue::from_str(&provider_ref));
            }
        }
        arr.push(&item.into());
    }
    let obj = js_sys::Object::new();
    js_set(&obj, "actions", &arr.into());
    obj.into()
}

// ─── Manifest key derivation (for backward-compat vault header reuse) ─────────

/// Derive and return the manifest AEAD key (base64) for inspection / testing.
///
/// In production, this is only used internally; this export aids E2E tests.
/// Returns `{ key_b64: "<32-byte key>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_derive_manifest_aead_key(session_id: u32) -> JsValue {
    let result = with_vault_session(session_id, |sess| derive_manifest_aead_key(&sess.vault_key));
    match result {
        None => js_error("session not found"),
        Some(Err(e)) => js_error(&e.to_string()),
        Some(Ok(key)) => {
            let obj = js_sys::Object::new();
            js_set(
                &obj,
                "key_b64",
                &JsValue::from_str(&b64_encode(key.as_bytes())),
            );
            obj.into()
        }
    }
}

// ─── Row-merge (P3.2) ─────────────────────────────────────────────────────────

/// Compute merge operations for one database table.
///
/// Arguments (all JSON strings):
/// - `local_rows_json`: JSON array of row objects from the local DB
/// - `remote_rows_json`: JSON array of row objects from the remote DB
/// - `is_key_versions`: true to use key_versions semantics (union, local wins on conflict)
///
/// Returns `{ ops_json: "<MergeOp array as JSON>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_merge_rows(
    local_rows_json: &str,
    remote_rows_json: &str,
    is_key_versions: bool,
) -> JsValue {
    use sdk_core::byo::merge_rows::{merge_rows, MergeOp};
    use serde_json::Value;

    let local_rows: Vec<Value> = match serde_json::from_str(local_rows_json) {
        Ok(v) => v,
        Err(e) => return js_error(&format!("local_rows parse error: {e}")),
    };
    let remote_rows: Vec<Value> = match serde_json::from_str(remote_rows_json) {
        Ok(v) => v,
        Err(e) => return js_error(&format!("remote_rows parse error: {e}")),
    };

    let ops: Vec<MergeOp> = merge_rows(&local_rows, &remote_rows, is_key_versions);

    match serde_json::to_string(&ops) {
        Err(e) => js_error(&format!("ops serialize error: {e}")),
        Ok(ops_json) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "ops_json", &JsValue::from_str(&ops_json));
            obj.into()
        }
    }
}

// ─── Vault journal codec (P3.1) ───────────────────────────────────────────────

/// Serialize, encrypt, and HMAC one journal entry.
///
/// Arguments:
/// - `session_id`: open vault session (vault_key is looked up from it)
/// - `provider_id`: provider this journal belongs to
/// - `entry_type_str`: "INSERT" | "UPDATE" | "DELETE"
/// - `table`: table name
/// - `row_id`: row primary key (0 for INSERT when unknown)
/// - `data_json`: plaintext data JSON string
///
/// Returns `{ entry_b64: "<base64 entry bytes>" }` or `{ error }`.
#[wasm_bindgen]
pub fn byo_journal_append(
    session_id: u32,
    provider_id: &str,
    entry_type_str: &str,
    table: &str,
    row_id: u32,
    data_json: &str,
) -> JsValue {
    use sdk_core::byo::per_vault_key::derive_per_vault_journal_keys;
    use sdk_core::byo::vault_journal::{
        serialize_entry, ENTRY_TYPE_DELETE, ENTRY_TYPE_INSERT, ENTRY_TYPE_UPDATE,
    };

    let entry_type = match entry_type_str {
        "INSERT" => ENTRY_TYPE_INSERT,
        "UPDATE" => ENTRY_TYPE_UPDATE,
        "DELETE" => ENTRY_TYPE_DELETE,
        _ => return js_error(&format!("unknown entry_type: {entry_type_str}")),
    };

    let result: Option<Result<String, sdk_core::error::CryptoError>> =
        with_vault_session(session_id, |sess| {
            let keys = derive_per_vault_journal_keys(&sess.vault_key, provider_id)
                .map_err(|e| sdk_core::error::CryptoError::InvalidFormat(e.to_string()))?;
            let entry_bytes =
                serialize_entry(&keys, entry_type, table, row_id, data_json.as_bytes())
                    .map_err(|e| sdk_core::error::CryptoError::InvalidFormat(e.to_string()))?;
            Ok(b64_encode(&entry_bytes))
        });

    match result {
        None => js_error("session not found"),
        Some(Err(e)) => js_error(&e.to_string()),
        Some(Ok(b64)) => {
            let obj = js_sys::Object::new();
            js_set(&obj, "entry_b64", &JsValue::from_str(&b64));
            obj.into()
        }
    }
}

/// Parse and verify a vault journal file.
///
/// Arguments:
/// - `session_id`: open vault session
/// - `provider_id`: provider this journal belongs to
/// - `journal_b64`: base64-encoded journal file bytes
///
/// Returns `{ entries: [{ entry_type: "INSERT"|"UPDATE"|"DELETE", table, row_id, data }] }`
/// or `{ error }` on HMAC failure or corruption.
#[wasm_bindgen]
pub fn byo_journal_parse(session_id: u32, provider_id: &str, journal_b64: &str) -> JsValue {
    use sdk_core::byo::per_vault_key::derive_per_vault_journal_keys;
    use sdk_core::byo::vault_journal::{
        parse_journal, ENTRY_TYPE_DELETE, ENTRY_TYPE_INSERT, ENTRY_TYPE_UPDATE,
    };

    let journal_bytes = match b64_decode(journal_b64) {
        Ok(b) => b,
        Err(_) => return js_error("invalid base64 input"),
    };

    let result = with_vault_session(session_id, |sess| {
        let keys = derive_per_vault_journal_keys(&sess.vault_key, provider_id)
            .map_err(|e| sdk_core::error::CryptoError::InvalidFormat(e.to_string()))?;
        parse_journal(&keys, &journal_bytes)
            .map_err(|e| sdk_core::error::CryptoError::InvalidFormat(e.to_string()))
    });

    match result {
        None => js_error("session not found"),
        Some(Err(e)) => js_error(&e.to_string()),
        Some(Ok(entries)) => {
            let arr = js_sys::Array::new();
            for e in &entries {
                let type_str = match e.entry_type {
                    ENTRY_TYPE_INSERT => "INSERT",
                    ENTRY_TYPE_UPDATE => "UPDATE",
                    ENTRY_TYPE_DELETE => "DELETE",
                    _ => "UNKNOWN",
                };
                let data_str = String::from_utf8_lossy(&e.data).into_owned();
                let obj = js_sys::Object::new();
                js_set(&obj, "entry_type", &JsValue::from_str(type_str));
                js_set(&obj, "table", &JsValue::from_str(&e.table));
                js_set(&obj, "row_id", &JsValue::from_f64(e.row_id as f64));
                js_set(&obj, "data", &JsValue::from_str(&data_str));
                arr.push(&obj.into());
            }
            let result_obj = js_sys::Object::new();
            js_set(&result_obj, "entries", &arr.into());
            result_obj.into()
        }
    }
}
