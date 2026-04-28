// BYO vault manifest: encrypted provider registry replicated to every provider.
//
// Architecture (R6):
//   vault_manifest.sc = [ vault_header (1227) | body_blob (12 + n + 16) ]
//
//   The vault_header is shared with today's vault.sc format — same Argon2id
//   bootstrap, same device slots.  The body blob encrypts a JSON `Manifest`
//   using `derive_manifest_aead_key(vault_key)`.
//
//   Each `ManifestEntry` represents one storage provider.  Tombstones persist
//   for removed providers so that a device that was offline during removal does
//   not re-add the provider on next sync.
//
// Merge semantics (commutative, associative):
//   - Union of provider_ids.
//   - Per entry: last-writer-wins on `updated_at`.  Tombstones win if later.
//   - `is_primary`: exactly one entry with is_primary=true (latest updated_at).
//   - `manifest_version = max(all) + 1` on save; equal → skip upload.
//
// Follows sdk-core conventions (no panics, no base64, zeroize-on-drop).

use crate::byo::per_vault_key::derive_manifest_aead_key;
use crate::byo::vault_body::{decrypt_body, encrypt_body};
use crate::crypto::zeroize_utils::SymmetricKey;
use crate::error::CryptoError;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque wrapper for `config_json` that:
///  - Zeroizes the string on drop (OAuth tokens, passwords, etc.)
///  - Prints `[REDACTED]` in Debug output
///  - Serializes/deserializes as a plain JSON string
///
/// Deliberately does **not** implement [`Clone`] (CLAUDE.md key-material rule).
/// Callers that genuinely need to duplicate the secret must go through
/// [`SecretConfigJson::duplicate`], which makes the copy an explicit decision.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretConfigJson(String);

impl SecretConfigJson {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Produce a new, independent `SecretConfigJson` carrying the same bytes.
    ///
    /// Both the original and the duplicate remain `ZeroizeOnDrop`, so neither
    /// leaks ciphertext to un-zeroed memory. Use only when ownership must be
    /// split (e.g. manifest merge needs the entry in a HashMap while the
    /// source manifest remains borrowed).
    pub fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::fmt::Debug for SecretConfigJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<String> for SecretConfigJson {
    fn from(s: String) -> Self {
        Self(s)
    }
}
impl From<&str> for SecretConfigJson {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Maximum allowed clock skew for `updated_at` validation (1 hour in seconds).
const MAX_CLOCK_SKEW_SECS: u64 = 3600;

// ─── Data types ───────────────────────────────────────────────────────────────

/// A single provider entry in the manifest.
///
/// Does not derive [`Clone`] because `config_json` holds credentials;
/// use [`ManifestEntry::duplicate`] to make copying an explicit choice.
#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Stable unique id for this provider instance (random UUID at creation).
    pub provider_id: String,
    /// Provider type string: "gdrive" | "dropbox" | "onedrive" | "webdav" |
    /// "sftp" | "box" | "pcloud" | "s3".
    pub provider_type: String,
    /// Display name chosen by the user.
    pub display_name: String,
    /// Provider-specific credentials / config blob (JSON, may contain OAuth tokens).
    pub config_json: SecretConfigJson,
    /// True for the single "primary" provider used for Argon2id bootstrap.
    pub is_primary: bool,
    /// SFTP TOFU host-key fingerprint, or null for non-SFTP providers.
    #[serde(default)]
    pub sftp_host_key_fingerprint: Option<String>,
    /// Last-known ETag / version of this provider's vault body (advisory).
    #[serde(default)]
    pub vault_version_hint: Option<String>,
    /// Unix epoch (seconds) when this entry was created.
    pub created_at: u64,
    /// Unix epoch (seconds) when this entry was last modified.
    pub updated_at: u64,
    /// True when the provider has been removed. Tombstone entries are retained
    /// so offline devices do not re-add the provider on next sync.
    #[serde(default)]
    pub tombstone: bool,
}

/// The manifest payload stored in vault_manifest.sc.
///
/// Does not derive [`Clone`] (transitively contains credentials via
/// [`ManifestEntry::config_json`]).
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Monotonically increasing version counter.  Bumped on every save.
    pub manifest_version: u64,
    /// All provider entries, including tombstones.
    pub providers: Vec<ManifestEntry>,
}

impl ManifestEntry {
    /// Produce an independent copy of this entry, including a fresh
    /// `ZeroizeOnDrop` copy of `config_json`.
    ///
    /// Used by [`merge_manifests`] to move a candidate entry from a borrowed
    /// input manifest into the owned result. Callers should prefer borrowing
    /// over duplicating wherever possible.
    pub fn duplicate(&self) -> Self {
        Self {
            provider_id: self.provider_id.clone(),
            provider_type: self.provider_type.clone(),
            display_name: self.display_name.clone(),
            config_json: self.config_json.duplicate(),
            is_primary: self.is_primary,
            sftp_host_key_fingerprint: self.sftp_host_key_fingerprint.clone(),
            vault_version_hint: self.vault_version_hint.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            tombstone: self.tombstone,
        }
    }
}

impl Manifest {
    /// Return active (non-tombstone) provider entries.
    pub fn active_providers(&self) -> impl Iterator<Item = &ManifestEntry> {
        self.providers.iter().filter(|e| !e.tombstone)
    }

    /// Return the primary provider entry, if any.
    pub fn primary_provider(&self) -> Option<&ManifestEntry> {
        self.providers.iter().find(|e| !e.tombstone && e.is_primary)
    }

    /// Return an entry by provider_id (including tombstones).
    pub fn find_entry(&self, provider_id: &str) -> Option<&ManifestEntry> {
        self.providers.iter().find(|e| e.provider_id == provider_id)
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest encryption failed: {0}")]
    Encryption(CryptoError),

    #[error("manifest decryption failed: {0}")]
    Decryption(CryptoError),

    #[error("manifest JSON serialization failed: {0}")]
    Serialize(serde_json::Error),

    #[error("manifest JSON deserialization failed: {0}")]
    Deserialize(serde_json::Error),

    #[error("manifest invariant violated: {0}")]
    InvariantViolated(String),
}

// ─── Encrypt / Decrypt ────────────────────────────────────────────────────────

/// Encrypt a `Manifest` into the opaque body blob stored in vault_manifest.sc.
///
/// Returns `[ body_iv (12) | body_ct_with_gcm_tag (n + 16) ]`.
/// The caller prepends the vault header to produce the full vault_manifest.sc.
pub fn encrypt_manifest(
    vault_key: &SymmetricKey,
    manifest: &Manifest,
) -> Result<Vec<u8>, ManifestError> {
    let json = serde_json::to_vec(manifest).map_err(ManifestError::Serialize)?;
    let key = derive_manifest_aead_key(vault_key).map_err(ManifestError::Encryption)?;
    encrypt_body(&json, &key).map_err(ManifestError::Encryption)
}

/// Decrypt the body blob from vault_manifest.sc into a `Manifest`.
///
/// `body_blob` = `[ body_iv (12) | body_ct_with_gcm_tag (n + 16) ]`.
/// Fails if the GCM tag does not verify (wrong key, corruption, or truncation).
pub fn decrypt_manifest(
    vault_key: &SymmetricKey,
    body_blob: &[u8],
) -> Result<Manifest, ManifestError> {
    let key = derive_manifest_aead_key(vault_key).map_err(ManifestError::Decryption)?;
    let json_bytes = decrypt_body(body_blob, &key).map_err(ManifestError::Decryption)?;
    serde_json::from_slice(&json_bytes).map_err(ManifestError::Deserialize)
}

// ─── Merge ────────────────────────────────────────────────────────────────────

/// Merge two or more manifests fetched from different providers.
///
/// Rules (commutative, associative):
/// 1. Union of `provider_id`s across all inputs.
/// 2. Per `provider_id`: retain the entry with the highest `updated_at`.
///    If equal, tombstones win; otherwise the non-tombstone wins.
///    If both are tombstones, retain either (identical semantics).
///    Entries whose `updated_at` is more than `MAX_CLOCK_SKEW_SECS` in the
///    future relative to `now_unix_secs` are rejected (skew-clamped).
///    Pass `u64::MAX` for `now_unix_secs` to skip the clock-skew check.
/// 3. `is_primary` uniqueness: exactly one active entry is marked primary —
///    the active entry with the latest `updated_at` that has `is_primary=true`.
///    If there are no candidates, the oldest active entry (lowest `created_at`)
///    is designated primary.
/// 4. `manifest_version = max(all inputs) + 1`.
///    The result must be ≥ `min_acceptable_version.unwrap_or(0)`;
///    pass `None` to skip the rollback check, `Some(v)` to enforce a floor.
/// 5. The merged manifest is run through [`validate_manifest`] before return,
///    so invariants such as `!tombstone || !is_primary`, `provider_id`
///    uniqueness, and clock-skew bounds are enforced even if `merge` alone
///    would let them through (C4).
///
/// Returns an error if `manifests` is empty, if any entry is too far in the
/// future (clock skew), if the merged version would be a rollback, or if the
/// merged manifest violates any `validate_manifest` invariant.
pub fn merge_manifests(
    manifests: &[&Manifest],
    now_unix_secs: u64,
    min_acceptable_version: Option<u64>,
) -> Result<Manifest, ManifestError> {
    if manifests.is_empty() {
        return Err(ManifestError::InvariantViolated(
            "merge_manifests: no manifests provided".into(),
        ));
    }

    // Step 1+2: union, last-writer-wins per provider_id, with clock-skew rejection.
    let mut by_id: std::collections::HashMap<String, ManifestEntry> =
        std::collections::HashMap::new();

    for manifest in manifests {
        for entry in &manifest.providers {
            // Reject entries with updated_at too far in the future.
            if now_unix_secs != u64::MAX
                && entry.updated_at > now_unix_secs.saturating_add(MAX_CLOCK_SKEW_SECS)
            {
                return Err(ManifestError::InvariantViolated(format!(
                    "provider {} has updated_at {} which is more than {} seconds in the future \
                     (now={}); possible clock skew or hostile manifest",
                    entry.provider_id, entry.updated_at, MAX_CLOCK_SKEW_SECS, now_unix_secs
                )));
            }
            let winner = by_id
                .entry(entry.provider_id.clone())
                .or_insert_with(|| entry.duplicate());
            if entry_is_better(entry, winner) {
                *winner = entry.duplicate();
            }
        }
    }

    let mut providers: Vec<ManifestEntry> = by_id.into_values().collect();

    // Step 3: enforce exactly one is_primary among active entries.
    enforce_primary_uniqueness(&mut providers)?;

    // Step 4: manifest_version = max(all) + 1.
    let max_version = manifests
        .iter()
        .map(|m| m.manifest_version)
        .max()
        .unwrap_or(0);
    let manifest_version = max_version.saturating_add(1);

    // Rollback check: merged version must not be less than caller's last-seen version.
    // `None` = no floor; `Some(v)` enforces `merged ≥ v`.
    if let Some(floor) = min_acceptable_version {
        if manifest_version < floor {
            return Err(ManifestError::InvariantViolated(format!(
                "merged manifest_version {manifest_version} is less than \
                 min_acceptable_version {floor}; possible manifest rollback attack"
            )));
        }
    }

    let merged = Manifest {
        manifest_version,
        providers,
    };

    // Step 5: full invariant check before returning. Catches any invariant that
    // a hostile input might have smuggled past the preceding steps (e.g.
    // `tombstone && is_primary`, which neither the last-writer-wins merge nor
    // `enforce_primary_uniqueness` alone rejects — C4).
    validate_manifest(&merged, now_unix_secs)?;

    Ok(merged)
}

/// Returns true if `candidate` should replace `current` in the merge map.
fn entry_is_better(candidate: &ManifestEntry, current: &ManifestEntry) -> bool {
    if candidate.updated_at > current.updated_at {
        return true;
    }
    if candidate.updated_at == current.updated_at {
        // Tombstones win ties (removal is idempotent; re-adding is explicit).
        return candidate.tombstone && !current.tombstone;
    }
    false
}

/// Ensure at most one active entry has `is_primary = true`.
///
/// If multiple entries claim is_primary, the one with the latest `updated_at`
/// wins (alphabetical `provider_id` breaks further ties for determinism).
/// If no active entry claims is_primary, the one with the lowest `created_at`
/// is designated primary.
fn enforce_primary_uniqueness(providers: &mut [ManifestEntry]) -> Result<(), ManifestError> {
    // Collect indices of active entries claiming primary.
    let primary_indices: Vec<usize> = providers
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.tombstone && e.is_primary)
        .map(|(i, _)| i)
        .collect();

    if primary_indices.len() <= 1 {
        if primary_indices.is_empty() {
            // No primary — designate the active entry with the lowest created_at.
            if let Some(idx) = providers
                .iter()
                .enumerate()
                .filter(|(_, e)| !e.tombstone)
                .min_by(|(_, a), (_, b)| {
                    a.created_at
                        .cmp(&b.created_at)
                        .then(a.provider_id.cmp(&b.provider_id))
                })
                .map(|(i, _)| i)
            {
                providers
                    .get_mut(idx)
                    .ok_or_else(|| {
                        ManifestError::InvariantViolated("index out of bounds (no-primary)".into())
                    })?
                    .is_primary = true;
            }
        }
        return Ok(());
    }

    // Multiple claims: pick the winner (latest updated_at, then alpha provider_id).
    let first_idx = *primary_indices
        .first()
        .ok_or_else(|| ManifestError::InvariantViolated("empty primary_indices".into()))?;
    let winner_idx = primary_indices
        .iter()
        .copied()
        .max_by(|&a, &b| {
            let ua = providers.get(a).map(|e| e.updated_at).unwrap_or(0);
            let ub = providers.get(b).map(|e| e.updated_at).unwrap_or(0);
            let pa = providers
                .get(a)
                .map(|e| e.provider_id.as_str())
                .unwrap_or("");
            let pb = providers
                .get(b)
                .map(|e| e.provider_id.as_str())
                .unwrap_or("");
            ua.cmp(&ub).then(pa.cmp(pb))
        })
        .ok_or_else(|| ManifestError::InvariantViolated("winner index out of bounds".into()))?;
    let _ = first_idx; // used as fallback was replaced by ok_or_else above

    // Clear all, then re-set the winner.
    for &idx in &primary_indices {
        providers
            .get_mut(idx)
            .ok_or_else(|| {
                ManifestError::InvariantViolated("index out of bounds (clear primary)".into())
            })?
            .is_primary = false;
    }
    providers
        .get_mut(winner_idx)
        .ok_or_else(|| ManifestError::InvariantViolated("winner index out of bounds".into()))?
        .is_primary = true;

    Ok(())
}

// ─── Validate ─────────────────────────────────────────────────────────────────

/// Validate manifest invariants.
///
/// Checks:
/// - All `provider_id` values are non-empty and unique.
/// - Exactly one active entry has `is_primary = true`.
/// - No `updated_at` is more than `MAX_CLOCK_SKEW_SECS` in the future relative
///   to `now_unix_secs` (pass `u64::MAX` to skip this check).
pub fn validate_manifest(manifest: &Manifest, now_unix_secs: u64) -> Result<(), ManifestError> {
    // Unique, non-empty provider_ids; tombstone+primary contradiction.
    let mut seen = std::collections::HashSet::new();
    for entry in &manifest.providers {
        if entry.provider_id.is_empty() {
            return Err(ManifestError::InvariantViolated(
                "provider_id must not be empty".into(),
            ));
        }
        if entry.provider_id.contains('\0') {
            return Err(ManifestError::InvariantViolated(
                "provider_id must not contain NUL bytes".into(),
            ));
        }
        if entry.provider_id.len() > 64 {
            return Err(ManifestError::InvariantViolated(format!(
                "provider_id too long ({} > 64 bytes)",
                entry.provider_id.len()
            )));
        }
        if !seen.insert(&entry.provider_id) {
            return Err(ManifestError::InvariantViolated(format!(
                "duplicate provider_id: {}",
                entry.provider_id
            )));
        }
        // Clock skew check (skip when caller passes u64::MAX).
        if now_unix_secs != u64::MAX
            && entry.updated_at > now_unix_secs.saturating_add(MAX_CLOCK_SKEW_SECS)
        {
            return Err(ManifestError::InvariantViolated(format!(
                "provider {} has updated_at {} which is more than {} seconds in the future",
                entry.provider_id, entry.updated_at, MAX_CLOCK_SKEW_SECS
            )));
        }
        // A tombstoned entry must not also claim to be primary.
        if entry.tombstone && entry.is_primary {
            return Err(ManifestError::InvariantViolated(format!(
                "provider {} is both tombstoned and primary — invariant violation",
                entry.provider_id
            )));
        }
    }

    // Exactly one active primary.
    let primary_count = manifest
        .providers
        .iter()
        .filter(|e| !e.tombstone && e.is_primary)
        .count();

    let active_count = manifest.providers.iter().filter(|e| !e.tombstone).count();

    match (active_count, primary_count) {
        (0, 0) => {} // Empty manifest is valid (no providers yet).
        (_, 1) => {} // Exactly one primary — OK.
        (_, 0) => {
            return Err(ManifestError::InvariantViolated(
                "no active primary provider".into(),
            ))
        }
        (_, n) => {
            return Err(ManifestError::InvariantViolated(format!(
                "multiple primary providers ({n})"
            )))
        }
    }

    Ok(())
}

// ─── Manifest mutation helpers (P3.3) ────────────────────────────────────────

/// Add a new provider entry to the manifest.
///
/// The entry is appended to `providers`. Returns an error if a non-tombstone
/// entry with the same `provider_id` already exists.
pub fn manifest_add_provider(
    manifest: &mut Manifest,
    entry: ManifestEntry,
) -> Result<(), ManifestError> {
    if manifest
        .providers
        .iter()
        .any(|p| p.provider_id == entry.provider_id && !p.tombstone)
    {
        return Err(ManifestError::InvariantViolated(format!(
            "provider {} already exists (non-tombstone)",
            entry.provider_id
        )));
    }
    manifest.providers.push(entry);
    Ok(())
}

/// Rename the display name of an active provider.
///
/// Updates `display_name` and `updated_at`. Returns an error if the
/// provider is not found or is tombstoned.
pub fn manifest_rename_provider(
    manifest: &mut Manifest,
    provider_id: &str,
    new_name: &str,
    now_unix_secs: u64,
) -> Result<(), ManifestError> {
    let trimmed = new_name.trim();
    if trimmed.is_empty() {
        return Err(ManifestError::InvariantViolated(
            "display name must not be empty".into(),
        ));
    }
    let entry = manifest
        .providers
        .iter_mut()
        .find(|p| p.provider_id == provider_id && !p.tombstone)
        .ok_or_else(|| {
            ManifestError::InvariantViolated(format!(
                "provider {provider_id} not found or tombstoned"
            ))
        })?;
    entry.display_name = trimmed.to_owned();
    entry.updated_at = now_unix_secs;
    Ok(())
}

/// Designate a different active provider as primary.
///
/// Sets `is_primary = true` on the target and `false` on all others.
/// Updates `updated_at` on the new primary entry. Returns an error if
/// the target provider is not found or is tombstoned.
pub fn manifest_set_primary_provider(
    manifest: &mut Manifest,
    provider_id: &str,
    now_unix_secs: u64,
) -> Result<(), ManifestError> {
    // A3: validate first, mutate second — with a guard in the mutation loop
    // that additionally refuses to set is_primary on a tombstoned entry. The
    // prior two-pass version matched the mutation loop purely by `provider_id`,
    // so if a caller invoked this concurrently with a tombstone on the same
    // target the result could be (tombstone=true, is_primary=true), which
    // `validate_manifest` rejects on the next load. Belt-and-braces: the match
    // arm below won't promote a tombstone even if state shifts mid-loop.
    let found = manifest
        .providers
        .iter()
        .any(|p| p.provider_id == provider_id && !p.tombstone);
    if !found {
        return Err(ManifestError::InvariantViolated(format!(
            "provider {provider_id} not found or tombstoned"
        )));
    }
    for p in manifest.providers.iter_mut() {
        if p.provider_id == provider_id && !p.tombstone {
            p.is_primary = true;
            p.updated_at = now_unix_secs;
        } else {
            p.is_primary = false;
        }
    }
    Ok(())
}

/// Replace the `config_json` of an active provider entry.
///
/// Used when the user edits provider settings (host, port, credentials, …)
/// after enrollment.  Updates `updated_at` so peer devices' merges treat
/// this as the newer record.  Returns an error if the provider is not
/// found or is tombstoned.  No validation of `new_config_json` content —
/// the value is opaque to the manifest layer; callers are expected to
/// have already verified the new config (e.g. by attempting `init()`)
/// before persisting.
pub fn manifest_update_provider_config(
    manifest: &mut Manifest,
    provider_id: &str,
    new_config_json: &str,
    now_unix_secs: u64,
) -> Result<(), ManifestError> {
    let entry = manifest
        .providers
        .iter_mut()
        .find(|p| p.provider_id == provider_id && !p.tombstone)
        .ok_or_else(|| {
            ManifestError::InvariantViolated(format!(
                "provider {provider_id} not found or tombstoned"
            ))
        })?;
    entry.config_json = SecretConfigJson::new(new_config_json);
    entry.updated_at = now_unix_secs;
    Ok(())
}

/// Tombstone an active provider (marks it as removed).
///
/// Sets `tombstone = true`, clears `is_primary`, and updates `updated_at`.
/// Returns an error if the provider is not found, already tombstoned, or
/// is the current primary.
pub fn manifest_tombstone_provider(
    manifest: &mut Manifest,
    provider_id: &str,
    now_unix_secs: u64,
) -> Result<(), ManifestError> {
    // Guard: cannot tombstone the primary.
    if manifest
        .providers
        .iter()
        .any(|p| p.provider_id == provider_id && p.is_primary)
    {
        return Err(ManifestError::InvariantViolated(
            "cannot tombstone the primary provider".into(),
        ));
    }
    let entry = manifest
        .providers
        .iter_mut()
        .find(|p| p.provider_id == provider_id && !p.tombstone)
        .ok_or_else(|| {
            ManifestError::InvariantViolated(format!(
                "provider {provider_id} not found or already tombstoned"
            ))
        })?;
    entry.tombstone = true;
    entry.is_primary = false;
    entry.updated_at = now_unix_secs;
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::symmetric::generate_aes_key;

    fn test_vault_key() -> SymmetricKey {
        generate_aes_key().unwrap()
    }

    fn make_entry(id: &str, is_primary: bool, updated_at: u64) -> ManifestEntry {
        ManifestEntry {
            provider_id: id.to_string(),
            provider_type: "gdrive".to_string(),
            display_name: id.to_string(),
            config_json: "{}".into(),
            is_primary,
            sftp_host_key_fingerprint: None,
            vault_version_hint: None,
            created_at: 1000,
            updated_at,
            tombstone: false,
        }
    }

    fn make_tombstone(id: &str, updated_at: u64) -> ManifestEntry {
        let mut e = make_entry(id, false, updated_at);
        e.tombstone = true;
        e
    }

    fn make_manifest(version: u64, entries: Vec<ManifestEntry>) -> Manifest {
        Manifest {
            manifest_version: version,
            providers: entries,
        }
    }

    // ── Encrypt / Decrypt ──────────────────────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_vault_key();
        let m = make_manifest(1, vec![make_entry("prov-a", true, 1000)]);
        let blob = encrypt_manifest(&key, &m).unwrap();
        let recovered = decrypt_manifest(&key, &blob).unwrap();
        assert_eq!(recovered.manifest_version, 1);
        assert_eq!(recovered.providers.len(), 1);
        assert_eq!(recovered.providers[0].provider_id, "prov-a");
    }

    #[test]
    fn wrong_key_decryption_fails() {
        let key = test_vault_key();
        let wrong = test_vault_key();
        let blob = encrypt_manifest(&key, &make_manifest(1, vec![])).unwrap();
        assert!(decrypt_manifest(&wrong, &blob).is_err());
    }

    #[test]
    fn tampered_blob_fails() {
        let key = test_vault_key();
        let mut blob = encrypt_manifest(&key, &make_manifest(1, vec![])).unwrap();
        if let Some(b) = blob.get_mut(20) {
            *b ^= 0xFF;
        }
        assert!(decrypt_manifest(&key, &blob).is_err());
    }

    // ── Merge ─────────────────────────────────────────────────────────────────

    #[test]
    fn merge_two_identical_manifests_increments_version() {
        let m = make_manifest(5, vec![make_entry("a", true, 1000)]);
        let merged = merge_manifests(&[&m, &m], u64::MAX, None).unwrap();
        assert_eq!(merged.manifest_version, 6);
        assert_eq!(merged.providers.len(), 1);
    }

    #[test]
    fn merge_union_of_providers() {
        let m1 = make_manifest(1, vec![make_entry("a", true, 1000)]);
        let m2 = make_manifest(1, vec![make_entry("b", false, 1000)]);
        let merged = merge_manifests(&[&m1, &m2], u64::MAX, None).unwrap();
        assert_eq!(merged.providers.len(), 2);
        // Exactly one primary is enforced.
        let primaries: Vec<_> = merged
            .providers
            .iter()
            .filter(|e| e.is_primary && !e.tombstone)
            .collect();
        assert_eq!(primaries.len(), 1);
    }

    #[test]
    fn merge_last_writer_wins() {
        let old = make_entry("x", true, 1000);
        let new = make_entry("x", false, 2000);
        let m1 = make_manifest(1, vec![old]);
        let m2 = make_manifest(2, vec![new]);
        let merged = merge_manifests(&[&m1, &m2], u64::MAX, None).unwrap();
        assert_eq!(merged.providers.len(), 1);
        // newer entry (updated_at=2000) wins
        assert_eq!(merged.providers[0].updated_at, 2000);
    }

    #[test]
    fn merge_tombstone_wins_on_tie() {
        let live = make_entry("x", true, 1000);
        let tomb = make_tombstone("x", 1000); // same updated_at
        let m1 = make_manifest(1, vec![live]);
        let m2 = make_manifest(1, vec![tomb]);
        let merged = merge_manifests(&[&m1, &m2], u64::MAX, None).unwrap();
        assert!(
            merged.providers[0].tombstone,
            "tombstone should win the tie"
        );
    }

    #[test]
    fn merge_newer_live_beats_older_tombstone() {
        let old_tomb = make_tombstone("x", 1000);
        let new_live = make_entry("x", true, 2000);
        let m1 = make_manifest(1, vec![old_tomb]);
        let m2 = make_manifest(1, vec![new_live]);
        let merged = merge_manifests(&[&m1, &m2], u64::MAX, None).unwrap();
        assert!(
            !merged.providers[0].tombstone,
            "newer live should beat older tombstone"
        );
    }

    #[test]
    fn merge_commutativity() {
        let m1 = make_manifest(
            3,
            vec![make_entry("a", true, 2000), make_entry("b", false, 1000)],
        );
        let m2 = make_manifest(
            5,
            vec![make_entry("b", false, 1500), make_entry("c", false, 500)],
        );
        let ab = merge_manifests(&[&m1, &m2], u64::MAX, None).unwrap();
        let ba = merge_manifests(&[&m2, &m1], u64::MAX, None).unwrap();
        // Same provider set and versions after sorting.
        let mut ab_ids: Vec<_> = ab.providers.iter().map(|e| &e.provider_id).collect();
        let mut ba_ids: Vec<_> = ba.providers.iter().map(|e| &e.provider_id).collect();
        ab_ids.sort();
        ba_ids.sort();
        assert_eq!(ab_ids, ba_ids, "merge must be commutative");
        assert_eq!(ab.manifest_version, ba.manifest_version);
    }

    #[test]
    fn merge_version_is_max_plus_one() {
        let m1 = make_manifest(10, vec![make_entry("a", true, 1000)]);
        let m2 = make_manifest(7, vec![make_entry("a", true, 1000)]);
        let merged = merge_manifests(&[&m1, &m2], u64::MAX, None).unwrap();
        assert_eq!(merged.manifest_version, 11);
    }

    #[test]
    fn merge_empty_slice_fails() {
        assert!(merge_manifests(&[], u64::MAX, None).is_err());
    }

    #[test]
    fn merge_single_manifest_increments_version() {
        let m = make_manifest(0, vec![make_entry("a", true, 1000)]);
        let merged = merge_manifests(&[&m], u64::MAX, None).unwrap();
        assert_eq!(merged.manifest_version, 1);
    }

    #[test]
    fn merge_multiple_primary_claims_resolved() {
        // Both entries claim is_primary; later updated_at wins.
        let mut e1 = make_entry("a", true, 2000);
        let mut e2 = make_entry("b", true, 1000);
        e1.is_primary = true;
        e2.is_primary = true;
        let m = make_manifest(1, vec![e1, e2]);
        let merged = merge_manifests(&[&m], u64::MAX, None).unwrap();
        let primaries: Vec<_> = merged
            .providers
            .iter()
            .filter(|e| e.is_primary && !e.tombstone)
            .collect();
        assert_eq!(primaries.len(), 1);
        assert_eq!(
            primaries[0].provider_id, "a",
            "provider with later updated_at should be primary"
        );
    }

    // ── Validate ──────────────────────────────────────────────────────────────

    #[test]
    fn validate_valid_manifest() {
        let m = make_manifest(1, vec![make_entry("a", true, 1000)]);
        assert!(validate_manifest(&m, u64::MAX).is_ok());
    }

    #[test]
    fn validate_empty_manifest_ok() {
        let m = make_manifest(0, vec![]);
        assert!(validate_manifest(&m, u64::MAX).is_ok());
    }

    #[test]
    fn validate_duplicate_provider_id_fails() {
        let m = make_manifest(
            1,
            vec![
                make_entry("dup", true, 1000),
                make_entry("dup", false, 2000),
            ],
        );
        assert!(validate_manifest(&m, u64::MAX).is_err());
    }

    #[test]
    fn validate_multiple_primary_fails() {
        let m = make_manifest(
            1,
            vec![make_entry("a", true, 1000), make_entry("b", true, 2000)],
        );
        assert!(validate_manifest(&m, u64::MAX).is_err());
    }

    #[test]
    fn validate_no_primary_with_active_entries_fails() {
        let m = make_manifest(
            1,
            vec![make_entry("a", false, 1000), make_entry("b", false, 2000)],
        );
        assert!(validate_manifest(&m, u64::MAX).is_err());
    }

    #[test]
    fn validate_tombstone_only_no_primary_ok() {
        let m = make_manifest(1, vec![make_tombstone("a", 1000)]);
        // All entries are tombstones → active_count = 0 → valid (empty manifest rule).
        assert!(validate_manifest(&m, u64::MAX).is_ok());
    }

    #[test]
    fn validate_future_timestamp_rejected() {
        let now = 1_700_000_000u64;
        let future = now + MAX_CLOCK_SKEW_SECS + 1;
        let mut e = make_entry("a", true, future);
        e.updated_at = future;
        let m = make_manifest(1, vec![e]);
        assert!(validate_manifest(&m, now).is_err());
    }

    #[test]
    fn validate_future_check_skipped_when_max() {
        let future = u64::MAX;
        let mut e = make_entry("a", true, future);
        e.updated_at = future;
        let m = make_manifest(1, vec![e]);
        // u64::MAX as now_unix_secs → skip clock check
        assert!(validate_manifest(&m, u64::MAX).is_ok());
    }

    #[test]
    fn validate_empty_provider_id_fails() {
        let mut e = make_entry("", true, 1000);
        e.provider_id = String::new();
        let m = make_manifest(1, vec![e]);
        assert!(validate_manifest(&m, u64::MAX).is_err());
    }

    #[test]
    fn validate_tombstone_and_primary_fails() {
        let mut e = make_tombstone("a", 1000);
        e.is_primary = true; // contradiction
        let m = make_manifest(1, vec![e]);
        assert!(validate_manifest(&m, u64::MAX).is_err());
    }

    // ── Merge security ────────────────────────────────────────────────────────

    #[test]
    fn merge_rejects_future_timestamp_attack() {
        let now = 1_700_000_000u64;
        let hostile = now + MAX_CLOCK_SKEW_SECS + 1;
        let mut e = make_entry("a", true, hostile);
        e.updated_at = hostile;
        let m = make_manifest(1, vec![e]);
        // merge with skew check enabled
        assert!(merge_manifests(&[&m], now, None).is_err());
    }

    #[test]
    fn merge_skips_future_check_when_now_is_max() {
        let future = u64::MAX - 1;
        let mut e = make_entry("a", true, future);
        e.updated_at = future;
        let m = make_manifest(1, vec![e]);
        // u64::MAX skips the clock check
        assert!(merge_manifests(&[&m], u64::MAX, None).is_ok());
    }

    #[test]
    fn merge_rejects_rollback_below_min_acceptable() {
        // Merge produces version 6 (max=5, +1); require ≥ 10 → error.
        let m = make_manifest(5, vec![make_entry("a", true, 1000)]);
        assert!(merge_manifests(&[&m], u64::MAX, Some(10)).is_err());
    }

    #[test]
    fn merge_accepts_version_at_min_acceptable() {
        // Merge produces version 6; min_acceptable_version = 6 → ok.
        let m = make_manifest(5, vec![make_entry("a", true, 1000)]);
        assert!(merge_manifests(&[&m], u64::MAX, Some(6)).is_ok());
    }

    #[test]
    fn merge_accepts_version_above_min_acceptable() {
        // Merge produces version 6; min_acceptable = 5 → ok.
        let m = make_manifest(5, vec![make_entry("a", true, 1000)]);
        assert!(merge_manifests(&[&m], u64::MAX, Some(5)).is_ok());
    }

    #[test]
    fn merge_rejects_tombstone_primary_contradiction() {
        // C4: a hostile input with `tombstone && is_primary` must be rejected
        // by `merge_manifests` itself (not only by a separately-called
        // `validate_manifest`). Earlier behavior relied on callers validating
        // post-merge, which is a footgun.
        let mut e = make_tombstone("a", 1000);
        e.is_primary = true;
        let m = make_manifest(1, vec![e]);
        let err = merge_manifests(&[&m], u64::MAX, None).unwrap_err();
        match err {
            ManifestError::InvariantViolated(msg) => {
                assert!(
                    msg.contains("tombstoned") && msg.contains("primary"),
                    "expected tombstone+primary message, got: {msg}"
                );
            }
            other => panic!("expected InvariantViolated, got {other:?}"),
        }
    }

    #[test]
    fn merge_none_floor_allows_any_version() {
        // M1: `None` explicitly disables the rollback floor. A previous merge
        // at version 999 followed by a fresh merge at version 2 is allowed.
        let m = make_manifest(1, vec![make_entry("a", true, 1000)]);
        let merged = merge_manifests(&[&m], u64::MAX, None).unwrap();
        assert_eq!(merged.manifest_version, 2);
    }

    #[test]
    fn merge_some_zero_is_never_rollback() {
        // Some(0) is semantically "floor = 0". Every positive merge passes it.
        // Guards against a regression where 0 was treated as the skip-sentinel.
        let m = make_manifest(1, vec![make_entry("a", true, 1000)]);
        let merged = merge_manifests(&[&m], u64::MAX, Some(0)).unwrap();
        assert_eq!(merged.manifest_version, 2);
    }

    #[test]
    fn merge_three_manifests_associativity() {
        let m1 = make_manifest(3, vec![make_entry("a", true, 2000)]);
        let m2 = make_manifest(
            5,
            vec![make_entry("b", false, 1500), make_entry("a", false, 1000)],
        );
        let m3 = make_manifest(
            7,
            vec![make_entry("c", false, 500), make_entry("b", false, 2500)],
        );

        // (m1 ∪ m2) ∪ m3
        let ab = merge_manifests(&[&m1, &m2], u64::MAX, None).unwrap();
        let abc = merge_manifests(&[&ab, &m3], u64::MAX, None).unwrap();

        // m1 ∪ (m2 ∪ m3)
        let bc = merge_manifests(&[&m2, &m3], u64::MAX, None).unwrap();
        let abc2 = merge_manifests(&[&m1, &bc], u64::MAX, None).unwrap();

        // Provider sets must match.
        let mut ids1: Vec<_> = abc
            .providers
            .iter()
            .map(|e| e.provider_id.as_str())
            .collect();
        let mut ids2: Vec<_> = abc2
            .providers
            .iter()
            .map(|e| e.provider_id.as_str())
            .collect();
        ids1.sort();
        ids2.sort();
        assert_eq!(ids1, ids2, "3-manifest merge must be associative");

        // Primary must agree.
        let p1 = abc
            .providers
            .iter()
            .find(|e| e.is_primary && !e.tombstone)
            .map(|e| e.provider_id.as_str());
        let p2 = abc2
            .providers
            .iter()
            .find(|e| e.is_primary && !e.tombstone)
            .map(|e| e.provider_id.as_str());
        assert_eq!(
            p1, p2,
            "primary must agree across associative merge orderings"
        );
    }

    // ── M8: provider_id validation ────────────────────────────────────────────

    #[test]
    fn provider_id_rejects_nul() {
        let mut e = make_entry("valid", true, 1000);
        e.provider_id = "abc\0def".to_string();
        let m = make_manifest(1, vec![e]);
        assert!(
            validate_manifest(&m, u64::MAX).is_err(),
            "NUL byte in provider_id must be rejected"
        );
    }

    #[test]
    fn provider_id_rejects_too_long() {
        let mut e = make_entry("valid", true, 1000);
        e.provider_id = "a".repeat(65);
        let m = make_manifest(1, vec![e]);
        assert!(
            validate_manifest(&m, u64::MAX).is_err(),
            "provider_id > 64 bytes must be rejected"
        );
    }

    // ── manifest_update_provider_config ──────────────────────────────────────

    #[test]
    fn update_provider_config_replaces_config_and_bumps_updated_at() {
        let mut m = make_manifest(1, vec![make_entry("a", true, 1000)]);
        manifest_update_provider_config(&mut m, "a", r#"{"type":"sftp","sftpHost":"new"}"#, 2000)
            .unwrap();
        let entry = m.providers.iter().find(|p| p.provider_id == "a").unwrap();
        assert_eq!(
            entry.config_json.as_str(),
            r#"{"type":"sftp","sftpHost":"new"}"#
        );
        assert_eq!(entry.updated_at, 2000);
    }

    #[test]
    fn update_provider_config_works_on_primary() {
        let mut m = make_manifest(1, vec![make_entry("a", true, 1000)]);
        // Editing the primary's config must be allowed; the user needs this
        // when their primary's host/credentials change.
        assert!(manifest_update_provider_config(&mut m, "a", "{}", 1500).is_ok());
        let entry = m.providers.iter().find(|p| p.provider_id == "a").unwrap();
        assert!(entry.is_primary);
        assert_eq!(entry.config_json.as_str(), "{}");
    }

    #[test]
    fn update_provider_config_rejects_missing_provider() {
        let mut m = make_manifest(1, vec![make_entry("a", true, 1000)]);
        let err = manifest_update_provider_config(&mut m, "nope", "{}", 2000).unwrap_err();
        match err {
            ManifestError::InvariantViolated(msg) => assert!(msg.contains("not found")),
            other => panic!("expected InvariantViolated, got {other:?}"),
        }
    }

    #[test]
    fn update_provider_config_rejects_tombstoned() {
        let mut m = make_manifest(
            1,
            vec![make_entry("a", true, 1000), make_tombstone("b", 1500)],
        );
        let err = manifest_update_provider_config(&mut m, "b", "{}", 2000).unwrap_err();
        match err {
            ManifestError::InvariantViolated(msg) => {
                assert!(msg.contains("not found") || msg.contains("tombstoned"));
            }
            other => panic!("expected InvariantViolated, got {other:?}"),
        }
    }

    #[test]
    fn update_provider_config_does_not_change_other_fields() {
        let mut m = make_manifest(1, vec![make_entry("a", true, 1000)]);
        let before = m.providers[0].duplicate();
        manifest_update_provider_config(&mut m, "a", r#"{"x":1}"#, 2000).unwrap();
        let after = &m.providers[0];
        assert_eq!(after.provider_id, before.provider_id);
        assert_eq!(after.provider_type, before.provider_type);
        assert_eq!(after.display_name, before.display_name);
        assert_eq!(after.is_primary, before.is_primary);
        assert_eq!(after.created_at, before.created_at);
        assert!(!after.tombstone);
    }
}
