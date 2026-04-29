/**
 * BYO Vault Lifecycle Manager (R6 — per-provider multi-vault)
 *
 * Orchestrates the R6 vault lifecycle:
 *   - Download vault_manifest.sc from primary provider (header + encrypted manifest)
 *   - Merge manifests from all reachable providers
 *   - Per-vault body fetch: vault_<provider_id>.sc (body-only, per-vault AEAD key)
 *   - IDB cache fallback for offline providers
 *   - Unified in-memory SQLite with provider_id-stamped rows
 *   - Per-provider save: extract rows, encrypt with per-vault key, upload
 *   - Manifest replicated to all reachable providers on every save
 *   - Per-provider WAL + VaultJournal for crash recovery
 *
 * SECURITY: vault_key and kek are stored inside WASM heap (vault session).
 * Only an opaque u32 session ID is held in JS scope. Per-vault AEAD keys are
 * derived inside WASM; plaintext SQLite bytes never touch IndexedDB.
 */

import type { StorageProvider, ProviderConfig, ProviderType } from '@wattcloud/sdk';
import { recordEvent, classifyErr, bucketLog2, SftpProvider, getShareRelayBandwidthAndReset } from '@wattcloud/sdk';
import * as byoWorker from '@wattcloud/sdk';
import { runMigrations, providerDisplayName } from './VaultMigration';
import type { ProviderMeta } from './stores/vaultStore';
import {
  getDeviceRecord,
  setDeviceRecord,
  getDeviceCryptoKey,
  getDirtyFlag,
  setDirtyFlag,
} from './DeviceKeyStore';
import { getWalEntryGroups, replayWal, clearWal } from './IndexedDBWal';
import { VaultJournal } from './VaultJournal';
import { loadSqlJs, queryRows } from './ConflictResolver';
import { vaultStore } from './stores/vaultStore';
import {
  storeCachedBody,
  loadCachedBody,
  storeCachedManifest,
  loadCachedManifest,
} from './VaultBodyCache';
import { saveProviderConfig, updateProviderDisplayNameLocal } from './ProviderConfigStore';
// Re-export for backwards compat (ByoRecovery, ByoSetup import from VaultLifecycle).
export { bytesToBase64, base64ToBytes } from './base64';
import { bytesToBase64, base64ToBytes } from './base64';

/**
 * Convert the hex device_id stored in IDB (`DeviceRecord.device_id`) to the
 * base64 form `byoParseVaultHeader` emits for `slot.device_id`. Both sides
 * describe the same 16 raw bytes; the mismatch exists only because IDB uses
 * hex everywhere and the WASM header parser b64-encodes all byte fields.
 */
function deviceIdHexToB64(hex: string): string {
  if (!hex) return '';
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytesToBase64(bytes);
}

// ── Constants ─────────────────────────────────────────────────────────────

/** v2 vault header: 1227 bytes (magic + argon2 params + master_salt + vault_id + slots + HMAC). */
const VAULT_HEADER_SIZE = 1227;
/** HMAC offset in the v2 header (covers bytes [0..1195]). */
const VAULT_HEADER_HMAC_OFFSET = 1195;

export const MANIFEST_FILE = 'WattcloudVault/vault_manifest.sc';
export const VAULT_BODY_PATH_PREFIX = 'WattcloudVault/';

const DEBOUNCE_NORMAL_MS = 3_000;
const DEBOUNCE_BATCH_MS = 30_000;
const BATCH_THRESHOLD = 3;
const BATCH_WINDOW_MS = 5_000;
const BACKUP_PROMPT_INTERVAL_DAYS = 60;

// ── Session state ─────────────────────────────────────────────────────────

/** Merged in-memory manifest (decrypted). */
let _manifest: ManifestJson | null = null;
/** Primary provider (manifest lives here). */
let _provider: StorageProvider | null = null;
/** All initialized providers keyed by provider_id. */
let _providers: Map<string, StorageProvider> = new Map();
/** provider_id of the primary provider. */
let _primaryProviderId: string = '';

let _db: import('sql.js').Database | null = null;
/** Opaque WASM vault session ID — vault_key/kek in WASM heap. */
let _vaultSessionId: number | null = null;
let _vaultId: string = '';

/** Per-provider WAL keys (derived from per-vault HKDF subkeys). */
let _walKeys: Map<string, CryptoKey> = new Map();
/** Per-provider journals. */
let _journals: Map<string, VaultJournal> = new Map();

/** Which providers have unsaved mutations in the master DB. */
const _dirtyProviders: Set<string> = new Set();

/** Providers marked dirty while a save is in flight. Merged back after save. */
let _dirtyDuringSave: Set<string> = new Set();

/** Last known encrypted body size (bytes) per provider — updated on each save. */
const _lastBodySizesPerProvider: Map<string, number> = new Map();

/** Current manifest version (incremented on each save). */
let _manifestVersion: number = 1;

/**
 * Cached manifest header bytes (1227 bytes) from unlock. Saving needs the
 * header to recompute the HMAC + reassemble vault_manifest.sc; re-reading
 * from the primary on every save is fragile (the underlying storage may
 * have been wiped between sessions, or a fresh-secondary flow can race the
 * first manifest write). Used as a fallback when the live read fails.
 */
let _manifestHeader: Uint8Array | null = null;

/**
 * Resolver that releases the navigator.locks exclusive vault lock held by this tab.
 * null when no lock is held or when navigator.locks is unavailable.
 * C6: prevents two tabs from concurrently unlocking/saving the same vault.
 */
let _lockRelease: (() => void) | null = null;

// Debounce state
let _debounceTimer: ReturnType<typeof setTimeout> | null = null;
let _mutationCountInWindow = 0;
let _windowTimer: ReturnType<typeof setTimeout> | null = null;
let _batchMode = false;

// Save serialisation mutex — coalesces concurrent saveVault() calls so only one runs at a time.
let _savePromise: Promise<void> | null = null;

// ── Types ─────────────────────────────────────────────────────────────────

/** Minimal shape of the manifest JSON (mirrors sdk-core Manifest struct). */
interface ManifestProviderEntry {
  provider_id: string;
  provider_type: string;
  display_name: string;
  config_json: string;
  is_primary: boolean;
  sftp_host_key_fingerprint: string | null;
  vault_version_hint: string | null;
  created_at: number;
  updated_at: number;
  tombstone: boolean;
}

interface ManifestJson {
  manifest_version: number;
  providers: ManifestProviderEntry[];
}

// ── UnlockParams ──────────────────────────────────────────────────────────

export interface UnlockParams {
  /**
   * Passphrase for the knowledge-factor unlock path. Ignored when
   * `preopenedSessionId` is provided (opt-in passkey-unlock, SECURITY.md §12).
   */
  passphrase: string;
  /**
   * Session ID for the BYO worker's private-key registry (ML-KEM / X25519 keys).
   * The vault session ID (vault_key + kek) is managed internally by VaultLifecycle.
   */
  keySessionId: string;
  /**
   * Known vault ID (hex-encoded 16 bytes), if available from a previous session.
   * Used to attempt an IDB cache lookup when the primary provider is offline (H2).
   * Optional: if omitted, cache fallback is skipped and the unlock fails when
   * no provider is reachable.
   */
  vaultId?: string;
  /**
   * Opt-in passkey-unlock path: when set, the caller has already reproduced
   * `vault_key` via the PRF-unwrap flow and stored it in a fresh WASM vault
   * session. We skip Argon2id + the passphrase-wrapped-vault_key step and
   * carry this session through the remaining unlock steps (shard decrypt,
   * HMAC verify, manifest merge). Mutually exclusive with a meaningful
   * `passphrase` — if both are provided, the preopened session wins.
   */
  preopenedSessionId?: number;
}

// ── Error helpers ─────────────────────────────────────────────────────────

/**
 * Stringify an arbitrary thrown value into a human-readable message.
 * Rust-via-wasm-bindgen often rejects with raw JsValue objects that don't have
 * `.message`; falling back to `.name`, `.toString`, and `String(…)` ensures we
 * never surface the literal word "undefined" to the user.
 */
function describeErr(err: unknown): string {
  if (err === null) return 'null';
  if (err === undefined) return 'undefined (no error object)';
  if (typeof err === 'string' && err.length > 0) return err;
  if (typeof err === 'object') {
    const e = err as { message?: unknown; name?: unknown; toString?: () => string };
    if (typeof e.message === 'string' && e.message.length > 0) return e.message;
    if (typeof e.name === 'string' && e.name.length > 0) return e.name;
    if (typeof e.toString === 'function') {
      const s = e.toString();
      if (s && s !== '[object Object]') return s;
    }
  }
  return String(err);
}

// ── Unlock ────────────────────────────────────────────────────────────────

/**
 * Download and unlock the vault. Populates module state.
 *
 * Caller must have already called provider.init() before passing it here.
 *
 * @throws if passphrase is wrong (AES-GCM tag fails)
 * @throws if header HMAC fails (corrupted vault)
 * @throws if no providers are reachable and no cache exists (fail-closed)
 */
export async function unlockVault(
  provider: StorageProvider,
  params: UnlockParams,
): Promise<import('sql.js').Database> {
  vaultStore.setStatus('downloading');

  // ── Step 1: Download vault_manifest.sc from primary provider ──────────
  // On failure: fall back to IDB-cached header + manifest body (H2).
  // The cache is only useful when the caller supplies a vaultId hint AND
  // a previous unlock has stored the header bytes alongside the manifest body.
  // If neither the live provider nor the cache is available, fail closed.
  let manifestFileBytes: Uint8Array;
  let manifestVersion: string;
  let primaryLoadedFromCache = false;

  try {
    ({ data: manifestFileBytes, version: manifestVersion } =
      await provider.download(provider.manifestRef()));
  } catch (primaryErr) {
    // Primary is offline. Try the IDB cache if the caller provided a vaultId hint.
    const primaryMsg = describeErr(primaryErr);
    if (!params.vaultId) {
      throw new Error(
        `Primary provider is offline and no vault ID hint was provided for cache fallback. ` +
        `Original error: ${primaryMsg}`,
      );
    }
    const cached = await loadCachedManifest(params.vaultId).catch(() => null);
    if (!cached?.header_bytes_b64 || !cached.blob_b64) {
      throw new Error(
        `Primary provider is offline and no cached vault header is available. ` +
        `Open the vault while online at least once to enable offline fallback. ` +
        `Original error: ${primaryMsg}`,
      );
    }
    // Reconstruct the full manifest file from the cached header + body so the
    // rest of the unlock flow is unmodified.
    const cachedHeader = base64ToBytes(cached.header_bytes_b64);
    const cachedBody = base64ToBytes(cached.blob_b64);
    const combined = new Uint8Array(cachedHeader.length + cachedBody.length);
    combined.set(cachedHeader, 0);
    combined.set(cachedBody, cachedHeader.length);
    manifestFileBytes = combined;
    manifestVersion = cached.version;
    primaryLoadedFromCache = true;
  }

  if (manifestFileBytes.length <= VAULT_HEADER_SIZE) {
    throw new Error('vault_manifest.sc too short');
  }

  const headerBytes = manifestFileBytes.slice(0, VAULT_HEADER_SIZE);
  const manifestBodyBlob = manifestFileBytes.slice(VAULT_HEADER_SIZE);

  vaultStore.setStatus('unlocking');

  // ── Step 2: Parse header ──────────────────────────────────────────────
  const header = await byoWorker.Worker.byoParseVaultHeader(headerBytes);
  const vaultIdFromHeader = header.vault_id as string;

  // ── Step 2b: Acquire exclusive vault lock (C6) ────────────────────────
  // Prevents two tabs from concurrently unlocking/saving the same vault,
  // which would produce duplicate manifest_version values or lost writes.
  //
  // The lock is held inside a navigator.locks.request callback whose
  // resolution we control via _lockRelease. Because await on the request
  // would block until the lock is released, we signal acquisition through
  // a side-channel Promise and only the holder side keeps the request
  // open.
  //
  // Real-world races we have to tolerate:
  //   - Hard reload: the previous page context is still tearing down
  //     when the new context tries to grab the lock. The OS releases
  //     the old holder within a few hundred ms but the gap is visible.
  //   - bfcache return: the prior document was paused with the lock
  //     held; coming back in the same tab grants it immediately, but
  //     opening the app in a *fresh* tab while the bfcache copy still
  //     lives loses the race.
  // ifAvailable:true gives up instantly, so a one-shot attempt was
  // surfacing as a hard "Another tab is already managing this vault"
  // for what's actually a sub-second handoff. Retry with backoff
  // before declaring contention.
  if (typeof navigator !== 'undefined' && 'locks' in navigator) {
    const lockName = `byo-vault-${vaultIdFromHeader}`;

    const tryAcquire = (): Promise<boolean> =>
      new Promise<boolean>((signalResolve) => {
        navigator.locks.request(
          lockName,
          { mode: 'exclusive', ifAvailable: true },
          async (lock) => {
            if (!lock) {
              signalResolve(false);
              return;
            }
            signalResolve(true);
            // Hold the lock until _lockRelease() fires on vault lock.
            await new Promise<void>((hold) => { _lockRelease = hold; });
          },
        ).catch(() => signalResolve(false));
      });

    // 5 attempts with backoff: 0ms, 200ms, 400ms, 800ms, 1600ms — total
    // budget ~3s, which covers the unload + bfcache races without
    // hanging the unlock UI on a genuinely contested vault.
    const BACKOFFS_MS = [0, 200, 400, 800, 1600];
    let acquired = false;
    for (const delay of BACKOFFS_MS) {
      if (delay > 0) await new Promise((r) => setTimeout(r, delay));
      acquired = await tryAcquire();
      if (acquired) break;
    }
    if (!acquired) {
      vaultStore.setStatus('idle');
      vaultStore.setTabOwnership('other');
      throw new Error(
        'Another tab is already managing this vault. Close that tab to take over.',
      );
    }
    vaultStore.setTabOwnership('this');
  }

  // Opt-in passkey-unlock: the caller has already reproduced `vault_key`
  // from a PRF assertion and loaded it into a fresh WASM session. Skip
  // Argon2id + the passphrase-wrapped-vault_key unwrap entirely — the HMAC
  // verify below still guarantees the passkey-reconstituted session agrees
  // with the current header.
  const vaultSessionId =
    params.preopenedSessionId !== undefined
      ? params.preopenedSessionId
      : await byoWorker.Worker.byoVaultOpen(
          params.passphrase,
          header.master_salt,
          header.argon2_memory_kb,
          header.argon2_iterations,
          header.argon2_parallelism,
          header.pass_wrap_iv,
          header.pass_wrapped_vault_key,
        );

  // ── Step 3: Verify header HMAC ────────────────────────────────────────
  const headerPrefixB64 = bytesToBase64(headerBytes.slice(0, VAULT_HEADER_HMAC_OFFSET));
  const hmacB64 = bytesToBase64(headerBytes.slice(VAULT_HEADER_HMAC_OFFSET));
  const { valid } = await byoWorker.Worker.byoVaultVerifyHeaderHmac(
    vaultSessionId,
    headerPrefixB64,
    hmacB64,
  );
  if (!valid) {
    await byoWorker.Worker.byoVaultClose(vaultSessionId);
    throw new Error('Vault header HMAC verification failed');
  }

  // ── Step 4: Decrypt primary manifest body ─────────────────────────────
  const manifestBlobB64 = bytesToBase64(manifestBodyBlob);
  const { manifestJson: primaryManifestJson } = await byoWorker.Worker.byoManifestDecrypt(
    vaultSessionId,
    manifestBlobB64,
  );
  const primaryManifest = JSON.parse(primaryManifestJson) as ManifestJson;

  // Extract vault_id from header (hex-encoded 16 bytes).
  const vaultIdHex = header.vault_id as string;

  // Cache this manifest version (including header bytes for offline fallback — H2).
  // Only update the header in the cache when we loaded it live (not from cache itself).
  await storeCachedManifest(
    vaultIdHex,
    manifestBlobB64,
    manifestVersion,
    primaryManifest.manifest_version,
    primaryLoadedFromCache ? undefined : bytesToBase64(headerBytes),
  ).catch(() => {});

  // ── Step 5: Derive KEK + load private keys ────────────────────────────
  //
  // The passphrase path needs to unwrap the device shard from the header
  // (decrypted with the per-vault device `CryptoKey`) and use it to derive
  // the BYO KEK, because `vault_key` isn't known yet.
  //
  // The passkey-unlock path (SECURITY.md §12 "Passkey replaces passphrase")
  // already has `vault_key` loaded into the WASM session — `vault_key`
  // alone is enough for manifest AEAD, body AEAD, and every per-vault
  // subkey derivation. `kek` is vestigial in the current WASM session
  // (set by `byo_vault_derive_kek`, never read anywhere downstream), so
  // skipping the shard decrypt is safe. Skipping also avoids a second
  // authenticator prompt — `getDeviceCryptoKey` would route back through
  // the WebAuthn gate here, and the user-gesture activation from the
  // unlock click has typically been consumed by the WASM awaits above.
  let deviceRecord: Awaited<ReturnType<typeof getDeviceRecord>> | null = null;
  if (params.preopenedSessionId === undefined) {
    const cryptoKey = await getDeviceCryptoKey(vaultIdHex);
    if (!cryptoKey) {
      await byoWorker.Worker.byoVaultClose(vaultSessionId);
      throw new Error('No device key found for this vault. Use recovery flow or QR enrollment.');
    }

    deviceRecord = await getDeviceRecord(vaultIdHex);
    const myDeviceId = deviceIdHexToB64(deviceRecord?.device_id ?? '');
    const deviceSlots: Array<{ device_id: string; wrap_iv: string; encrypted_payload: string }> =
      header.device_slots ?? [];

    let shard: Uint8Array | null = null;
    for (const slot of deviceSlots) {
      if (slot.device_id === myDeviceId) {
        const slotIv = base64ToBytes(slot.wrap_iv) as Uint8Array<ArrayBuffer>;
        const slotCt = base64ToBytes(slot.encrypted_payload) as Uint8Array<ArrayBuffer>;
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: slotIv }, cryptoKey, slotCt);
        shard = new Uint8Array(decrypted);
        break;
      }
    }
    if (!shard) {
      await byoWorker.Worker.byoVaultClose(vaultSessionId);
      throw new Error('Device slot not found in vault header. Use QR enrollment or recovery.');
    }

    await byoWorker.Worker.byoVaultDeriveKek(vaultSessionId, bytesToBase64(shard));
    shard.fill(0);
  } else {
    // Still fetch the device record — the backup-prompt-due check at step 14
    // reads `last_backup_prompt_at`, and the HMAC-verify step has already
    // passed so we know the session's vault_key matches this vault.
    deviceRecord = await getDeviceRecord(vaultIdHex);
  }

  // ── Step 6: Merge manifests from all providers ─────────────────────────
  const activeProviders = primaryManifest.providers.filter((p) => !p.tombstone);
  const otherProviders = activeProviders.filter(
    (p) => p.provider_id !== findPrimaryEntry(primaryManifest)?.provider_id,
  );

  // Try to fetch + decrypt vault_manifest.sc from each secondary provider.
  const collectedManifestJsons: string[] = [primaryManifestJson];
  const onlineProviderIds: string[] = [];
  const cachedProviderIds: string[] = [];

  // Determine the primary provider's ID.
  const primaryEntry = findPrimaryEntry(primaryManifest);
  if (primaryEntry && !primaryLoadedFromCache) {
    // Primary is reachable: mark it online. When loaded from cache the primary
    // is offline and its status will be derived from the absence in onlineProviderIds.
    onlineProviderIds.push(primaryEntry.provider_id);
  }

  const secondaryFetches = otherProviders.map(async (entry) => {
    // Wrap the cache fallback in a helper so both "init returned null"
    // and "live download failed" paths fall back consistently. Pre-fix,
    // a null return from init silently dropped the secondary entirely —
    // its body wasn't even loaded from the IDB cache, so its files
    // disappeared on every reload where the secondary couldn't connect.
    const fallbackToCache = async () => {
      const cached = await loadCachedBody(vaultIdHex, entry.provider_id).catch(() => null);
      if (cached) cachedProviderIds.push(entry.provider_id);
    };
    let secondaryProvider: StorageProvider | null = null;
    try {
      secondaryProvider = await initializeProviderFromConfig(entry);
    } catch {
      /* init exceptions are already logged inside initializeProviderFromConfig */
    }
    if (!secondaryProvider) {
      await fallbackToCache();
      return;
    }
    try {
      const { data: secondaryManifestBytes, version: secManifestVersion } =
        await secondaryProvider.download(secondaryProvider.manifestRef());
      const secManifestBlob = secondaryManifestBytes.slice(VAULT_HEADER_SIZE);
      const secManifestBlobB64 = bytesToBase64(secManifestBlob);
      const { manifestJson: secManifestJson } = await byoWorker.Worker.byoManifestDecrypt(
        vaultSessionId,
        secManifestBlobB64,
      );
      const secManifest = JSON.parse(secManifestJson) as ManifestJson;
      collectedManifestJsons.push(secManifestJson);
      onlineProviderIds.push(entry.provider_id);
      await storeCachedManifest(
        vaultIdHex,
        secManifestBlobB64,
        secManifestVersion,
        secManifest.manifest_version,
      ).catch(() => {});
    } catch (err) {
      console.warn(
        `[VaultLifecycle] secondary manifest fetch failed for ${entry.provider_id}:`,
        err,
      );
      await fallbackToCache();
    }
  });
  await Promise.allSettled(secondaryFetches);

  // Merge all collected manifests.
  // Pass now + last_seen_manifest_version for clock-skew and rollback checks.
  const nowUnixSecs = Math.floor(Date.now() / 1000);
  const minAcceptableVersion = deviceRecord?.last_seen_manifest_version ?? 0;
  let mergedManifestJson = primaryManifestJson;
  if (collectedManifestJsons.length > 1) {
    const { manifestJson } = await byoWorker.Worker.byoManifestMerge(
      JSON.stringify(collectedManifestJsons),
      nowUnixSecs,
      minAcceptableVersion,
    );
    mergedManifestJson = manifestJson;
  } else {
    // Single-manifest case: still check rollback via validate path.
    const singleManifest = JSON.parse(primaryManifestJson) as ManifestJson;
    if (minAcceptableVersion > 0 && singleManifest.manifest_version < minAcceptableVersion) {
      vaultStore.setRollbackWarning(true);
    }
  }
  const mergedManifest = JSON.parse(mergedManifestJson) as ManifestJson;

  // ── Step 7: Build unlock plan ─────────────────────────────────────────
  const { planJson } = await byoWorker.Worker.byoPlanUnlock(
    mergedManifestJson,
    JSON.stringify(onlineProviderIds),
    JSON.stringify(cachedProviderIds),
  );
  const unlockPlan = JSON.parse(planJson) as {
    vault_steps: Array<{ provider_id: string; source: 'Cloud' | 'Cache'; is_primary: boolean }>;
    fail_closed: boolean;
  };

  if (unlockPlan.fail_closed) {
    await byoWorker.Worker.byoVaultClose(vaultSessionId);
    throw new Error('No providers reachable and no cached vault bodies available.');
  }

  // ── Step 8: Fetch + decrypt per-vault bodies ──────────────────────────
  const SQL = await loadSqlJs();
  const masterDb = new SQL.Database();
  // Apply the schema to the master DB.
  masterDb.run(getVaultSchema());

  // Initialize provider instances for all active providers.
  const providerInstances = new Map<string, StorageProvider>();
  for (const entry of mergedManifest.providers.filter((p) => !p.tombstone)) {
    if (primaryEntry && entry.provider_id === primaryEntry.provider_id) {
      providerInstances.set(entry.provider_id, provider);
    } else {
      const inst = await initializeProviderFromConfig(entry).catch(() => null);
      if (inst) providerInstances.set(entry.provider_id, inst);
    }
  }

  // Process each unlock step: fetch body → decrypt → merge into masterDb.
  for (const step of unlockPlan.vault_steps) {
    const pid = step.provider_id;
    const provForRef = providerInstances.get(pid);
    const vaultFileName = provForRef
      ? provForRef.bodyRef(pid)
      : `WattcloudVault/vault_${pid}.sc`;

    let bodyBlobB64: string | null = null;
    let bodyVersion = '';

    if (step.source === 'Cloud') {
      const provInst = providerInstances.get(pid);
      if (provInst) {
        try {
          const { data: bodyBytes, version } = await provInst.download(vaultFileName);
          bodyBlobB64 = bytesToBase64(bodyBytes);
          bodyVersion = version;
          // Cache for offline use.
          await storeCachedBody(vaultIdHex, pid, bodyBlobB64, bodyVersion).catch(() => {});
        } catch {
          // Fall back to cache if download fails.
          const cached = await loadCachedBody(vaultIdHex, pid).catch(() => null);
          if (cached) {
            bodyBlobB64 = cached.blob_b64;
            vaultStore.updateProviderStatus(pid, 'offline');
          }
        }
      }
    } else {
      // Cache source.
      const cached = await loadCachedBody(vaultIdHex, pid).catch(() => null);
      if (cached) {
        bodyBlobB64 = cached.blob_b64;
        vaultStore.updateProviderStatus(pid, 'offline');
      }
    }

    if (!bodyBlobB64) continue;

    // Decrypt per-vault body.
    const { data: sqliteB64 } = await byoWorker.Worker.byoVaultBodyDecrypt(
      vaultSessionId,
      pid,
      bodyBlobB64,
    );
    const sqliteBytes = base64ToBytes(sqliteB64);

    // Open per-provider SQLite and merge rows into masterDb.
    const provDb = new SQL.Database(sqliteBytes);
    mergeProviderDb(masterDb, provDb, pid, step.is_primary);
    provDb.close();
  }

  // Run migrations. `primaryEntry?.provider_id` lets the migration
  // backfill files/folders/favorites.provider_id for legacy vaults that
  // pre-date the per-row provider stamping (otherwise downloads resolve
  // to the wrong provider when secondaries exist).
  runMigrations(masterDb, primaryEntry?.provider_id);

  // ── Step 9: Read vault metadata ────────────────────────────────────────
  const metaRows = queryRows(masterDb, "SELECT key, value FROM vault_meta WHERE key IN ('vault_version', 'vault_id')");
  const metaMap: Record<string, string> = {};
  for (const row of metaRows) metaMap[row['key'] as string] = row['value'] as string;
  const vaultVersion = parseInt(metaMap['vault_version'] ?? '0', 10);

  // ── Step 10: Rollback detection ────────────────────────────────────────
  if (deviceRecord && vaultVersion < deviceRecord.last_seen_vault_version) {
    vaultStore.setRollbackWarning(true);
  }
  // Manifest rollback: merged version must not regress (single-manifest path warning).
  if (deviceRecord &&
    mergedManifest.manifest_version < (deviceRecord.last_seen_manifest_version ?? 0)) {
    vaultStore.setRollbackWarning(true);
  }

  // ── Step 11: Load private keys into worker ─────────────────────────────
  await loadKeyVersionsIntoWorker(masterDb, vaultSessionId, params.keySessionId);

  // ── Step 12: Update device record ─────────────────────────────────────
  if (deviceRecord) {
    await setDeviceRecord({
      ...deviceRecord,
      last_seen_vault_version: Math.max(deviceRecord.last_seen_vault_version, vaultVersion),
      last_seen_manifest_version: Math.max(
        deviceRecord.last_seen_manifest_version ?? 0,
        mergedManifest.manifest_version,
      ),
    });
  }

  // ── Step 13: Per-provider WAL + journal setup ──────────────────────────
  const newWalKeys = new Map<string, CryptoKey>();
  const newJournals = new Map<string, VaultJournal>();

  for (const step of unlockPlan.vault_steps) {
    const pid = step.provider_id;

    // Per-vault WAL key — returned as a non-extractable WebCrypto handle so
    // the raw HKDF output never crosses the worker/main-thread boundary.
    const { key: walKey } = await byoWorker.Worker.byoDerivePerVaultWalKey(vaultSessionId, pid);
    newWalKeys.set(pid, walKey);

    // Replay WAL if dirty.
    const walId = vaultIdHex + ':' + pid;
    const isDirty = await getDirtyFlag(walId).catch(() => false);
    if (isDirty) {
      const { mutations, blobDeletes } = await getWalEntryGroups(walId, walKey).catch(() => ({ mutations: [], blobDeletes: [] }));
      if (mutations.length > 0) replayWal(masterDb, mutations);

      // Reconcile pending blob-delete WAL entries from cross-provider moves that
      // crashed before srcProvider.delete() completed. Each entry carries the
      // file_id so we can check whether the dst vault row now exists (which
      // means the move committed and the src blob is safe to delete).
      if (blobDeletes.length > 0) {
        const provInst = providerInstances.get(pid);
        for (const bd of blobDeletes) {
          try {
            const dstRows = queryRows(masterDb, 'SELECT id FROM files WHERE id = ? AND provider_id != ?', [bd.file_id, pid]);
            const dstFileExists = dstRows.length > 0;
            const result = await byoWorker.Worker.byoCrossProviderMoveDecideReplay(
              bd.step_b64,
              dstFileExists,
              'unknown',
            );
            if (result.decision === 'Retry' && provInst && result.providerId && result.providerRef) {
              await provInst.delete(result.providerRef).catch(() => {
                console.warn('[VaultLifecycle] Reconciler blob delete failed for', result.providerRef);
              });
            }
          } catch (err) {
            console.warn('[VaultLifecycle] Reconciler error for blob-delete entry:', err);
          }
        }
      }

      await clearWal(walId).catch(() => {});
      await setDirtyFlag(walId, false).catch(() => {});
    }

    // Per-vault journal.
    const provInst = providerInstances.get(pid);
    if (provInst && step.source === 'Cloud') {
      const journal = new VaultJournal(provInst, pid, vaultSessionId);
      await journal.replayIfExists(masterDb).catch(() => {});
      newJournals.set(pid, journal);
    }
  }

  // ── Step 14: Backup prompt ─────────────────────────────────────────────
  if (!deviceRecord?.last_backup_prompt_at) {
    vaultStore.setBackupPromptDue(true);
  } else {
    const daysSince =
      (Date.now() - new Date(deviceRecord.last_backup_prompt_at).getTime()) / (1000 * 60 * 60 * 24);
    if (daysSince > BACKUP_PROMPT_INTERVAL_DAYS) vaultStore.setBackupPromptDue(true);
  }

  // ── Step 15: Store session state ────────────────────────────────────────
  _manifest = mergedManifest;
  _manifestVersion = mergedManifest.manifest_version;
  _provider = provider;
  _db = masterDb;
  _vaultSessionId = vaultSessionId;
  _vaultId = vaultIdHex;
  _walKeys = newWalKeys;
  _journals = newJournals;
  _providers = providerInstances;
  _primaryProviderId = primaryEntry?.provider_id ?? '';
  _dirtyProviders.clear();
  _manifestHeader = new Uint8Array(headerBytes);

  // ── Step 16: Populate vaultStore ──────────────────────────────────────
  const providerMetas: ProviderMeta[] = mergedManifest.providers
    .filter((p) => !p.tombstone)
    .map((p) => ({
      providerId: p.provider_id,
      type: p.provider_type as ProviderType,
      displayName: p.display_name,
      isPrimary: p.is_primary,
      status: onlineProviderIds.includes(p.provider_id) ? 'connected' : 'offline',
      failCount: 0,
      lastPingTs: 0,
    }));

  const storedActiveId = (() => {
    try { return sessionStorage.getItem('byo:activeProviderId'); } catch { return null; }
  })();
  const activeProviderId =
    storedActiveId && providerMetas.some((p) => p.providerId === storedActiveId)
      ? storedActiveId
      : _primaryProviderId;

  vaultStore.setStatus('unlocked');
  recordEvent('vault_unlock');
  vaultStore.setVaultId(vaultIdHex);
  vaultStore.setProvider(provider.type as ProviderType);
  vaultStore.setProviders(providerMetas);
  vaultStore.setPrimaryProviderId(_primaryProviderId);
  vaultStore.setActiveProviderId(activeProviderId);
  // H3: set partialView if any provider was loaded from IDB cache rather than live download.
  const hasOfflineProviders = providerMetas.some((p) => p.status === 'offline');
  vaultStore.setPartialView(hasOfflineProviders);

  window.addEventListener('beforeunload', handleBeforeUnload);

  return masterDb;
}

// ── Save ──────────────────────────────────────────────────────────────────

/**
 * Save the vault immediately (bypasses debounce).
 *
 * For each dirty+online provider:
 *   1. Extract that provider's rows from masterDb → per-provider SQLite
 *   2. Encrypt with per-vault AEAD subkey
 *   3. Upload as vault_<provider_id>.sc
 *
 * Then upload updated manifest to all online providers.
 */
export function saveVault(): Promise<void> {
  if (_savePromise) return _savePromise;
  _dirtyDuringSave = new Set();
  _savePromise = _doSave().finally(() => {
    _savePromise = null;
    // Re-add providers dirtied mid-save and schedule follow-up if needed.
    for (const pid of _dirtyDuringSave) {
      _dirtyProviders.add(pid);
      setDirtyFlag(_vaultId + ':' + pid, true).catch(() => {});
    }
    _dirtyDuringSave = new Set();
    if (_dirtyProviders.size > 0) scheduleDebounce();
  });
  return _savePromise;
}

async function _doSave(): Promise<void> {
  if (!_db || _vaultSessionId === null || !_provider || !_manifest) {
    throw new Error('Vault not unlocked');
  }

  clearDebounce();
  vaultStore.setStatus('saving');

  // Track the provider being saved so the error catch can emit provider_type.
  let _saveProviderId = _primaryProviderId;

  try {
    // ── Phase 1: Flush journals (fail hard — no partial save) ──────────────
    // H6: await flush(); any failure aborts the save and leaves dirty state intact.
    for (const [pid, journal] of _journals) {
      try {
        await journal.flush();
      } catch (err) {
        // Journal flush failed — abort save; dirty flag remains set for next retry.
        throw new Error(`Journal flush failed for provider ${pid}: ${err}`);
      }
    }

    // ── Phase 2: Build save plan ───────────────────────────────────────────
    const onlineProviderIds = Array.from(_providers.keys());
    const { planJson } = await byoWorker.Worker.byoPlanSave(
      JSON.stringify(Array.from(_dirtyProviders)),
      JSON.stringify(onlineProviderIds),
    );
    const savePlan = JSON.parse(planJson) as {
      vault_uploads: Array<{ provider_id: string }>;
      manifest_upload_targets: string[];
    };

    const SQL = await loadSqlJs();

    // Track which providers had their body successfully uploaded.
    const successfulBodyUploads = new Set<string>();

    // ── Phase 3: Upload vault bodies ───────────────────────────────────────
    for (const { provider_id: pid } of savePlan.vault_uploads) {
      _saveProviderId = pid;
      const provInst = _providers.get(pid);
      if (!provInst) continue;

      // Extract per-provider rows into a fresh SQLite.
      const provDb = new SQL.Database();
      provDb.run(getVaultSchema());
      copyProviderRows(_db, provDb, pid);

      const sqliteBytes = provDb.export();
      provDb.close();

      const sqliteB64 = bytesToBase64(sqliteBytes);
      const { data: bodyBlobB64 } = await byoWorker.Worker.byoVaultBodyEncrypt(
        _vaultSessionId!,
        pid,
        sqliteB64,
      );
      const bodyBlob = base64ToBytes(bodyBlobB64);
      _lastBodySizesPerProvider.set(pid, bodyBlob.length);

      // ref = provider's canonical body path (SFTP: {vaultRoot}/data/…; others: logical path).
      // name = bare filename so providers that auto-prefix 'WattcloudVault/' build the right key.
      const bodyRef = provInst.bodyRef(pid);
      const { version: uploadedBodyVersion } = await provInst.upload(bodyRef, `vault_${pid}.sc`, bodyBlob, {});

      successfulBodyUploads.add(pid);
      // Update IDB cache with real ETag from upload response.
      await storeCachedBody(_vaultId, pid, bodyBlobB64, uploadedBodyVersion).catch(() => {});
    }

    // ── Phase 4: Build and upload manifest ────────────────────────────────
    // Compute next version locally; only commit to _manifestVersion after a
    // successful upload so a failed attempt retries with the same target version.
    const nextVersion = _manifestVersion + 1;
    const updatedManifest: ManifestJson = {
      ..._manifest,
      manifest_version: nextVersion,
    };

    const updatedManifestJson = JSON.stringify(updatedManifest);
    const { data: manifestBlobB64 } = await byoWorker.Worker.byoManifestEncrypt(
      _vaultSessionId!,
      updatedManifestJson,
    );
    const manifestBlob = base64ToBytes(manifestBlobB64);

    // Re-read header from primary so cross-device slot updates land here. If
    // the primary's manifest is unreadable (no-such-file from a wiped server,
    // or any other I/O error), fall back to the header we cached at unlock —
    // saving still produces a valid file, the user just won't pick up
    // header-level changes from other devices until the next unlock.
    let currentHeader: Uint8Array;
    try {
      const { data: currentManifestFile } = await _provider.download(_provider.manifestRef());
      currentHeader = currentManifestFile.slice(0, VAULT_HEADER_SIZE);
    } catch (readErr) {
      if (!_manifestHeader) throw readErr;
      console.warn('[saveVault] Primary manifest re-read failed; using cached header from unlock:', readErr);
      currentHeader = _manifestHeader;
    }

    // Recompute header HMAC.
    const headerPrefixB64 = bytesToBase64(currentHeader.slice(0, VAULT_HEADER_HMAC_OFFSET));
    const { hmac } = await byoWorker.Worker.byoVaultComputeHeaderHmac(_vaultSessionId!, headerPrefixB64);
    const finalHeader = new Uint8Array(currentHeader);
    finalHeader.set(base64ToBytes(hmac), VAULT_HEADER_HMAC_OFFSET);

    const manifestFile = new Uint8Array(VAULT_HEADER_SIZE + manifestBlob.length);
    manifestFile.set(finalHeader, 0);
    manifestFile.set(manifestBlob, VAULT_HEADER_SIZE);

    // Upload manifest to all online providers.
    // C5: manifest must be confirmed before WAL/journal are cleared.
    //
    // The PRIMARY upload is mandatory — vault_manifest.sc on the primary is
    // the unlock-time source of truth, so a failed primary upload means the
    // next reload will read a stale manifest (e.g. without a freshly-added
    // secondary). Secondary uploads remain best-effort: if one is offline
    // the save still succeeds, the secondary will sync on reconnect via
    // its WAL. We track primary success explicitly instead of just counting
    // total successes — counting any-success would let the save "succeed"
    // when the primary fails but a secondary works (the freshly-attached
    // secondary on retryOrphan can hide a primary failure this way).
    let primaryManifestUploaded = false;
    let manifestUploadedCount = 0;
    let primaryUploadErr: unknown = null;
    for (const pid of savePlan.manifest_upload_targets) {
      const provInst = _providers.get(pid);
      if (!provInst) continue;
      try {
        const { version: uploadedManifestVersion } = await provInst.upload(provInst.manifestRef(), 'vault_manifest.sc', manifestFile, {});
        manifestUploadedCount++;
        if (pid === _primaryProviderId) primaryManifestUploaded = true;
        await storeCachedManifest(_vaultId, manifestBlobB64, uploadedManifestVersion, nextVersion).catch(() => {});
      } catch (err) {
        if (pid === _primaryProviderId) {
          primaryUploadErr = err;
          console.error('[saveVault] primary manifest upload failed:', err);
        } else {
          // Secondary failures are non-fatal — the secondary will catch up
          // on reconnect — but still log so silent regressions don't hide.
          console.warn('[saveVault] secondary manifest upload failed for', pid, err);
        }
      }
    }

    // Primary must succeed. If it didn't, the vault bodies are ahead of the
    // primary's manifest — abort the save so dirty state stays set for retry
    // and the caller surfaces a real error rather than a misleading success.
    if (!primaryManifestUploaded) {
      throw new Error(
        `Manifest upload to primary failed — save aborted; dirty state preserved. Reason: ${describeErr(primaryUploadErr)}`,
      );
    }
    if (manifestUploadedCount === 0) {
      throw new Error('Manifest upload failed on all providers — save aborted; dirty state preserved');
    }

    // Commit manifest version to in-memory state only after at least one upload confirmed.
    _manifestVersion = nextVersion;
    _manifest = updatedManifest;

    // ── Phase 5: Two-phase commit — only clear state once manifest is confirmed ──
    // C5: clear WAL + journal only for providers whose body+manifest both confirmed.
    for (const pid of successfulBodyUploads) {
      const walId = _vaultId + ':' + pid;
      await clearWal(walId).catch(() => {});
      await setDirtyFlag(walId, false).catch(() => {});
      // H6: await journal.commit(); on failure, log but don't re-dirty (manifest already up).
      const journal = _journals.get(pid);
      if (journal) {
        try {
          await journal.commit();
        } catch (err) {
          console.warn('[saveVault] journal.commit() failed for provider', pid, err);
        }
      }
      _dirtyProviders.delete(pid);
    }

    // Clear global dirty flag only if all dirty providers committed successfully.
    if (_dirtyProviders.size === 0) {
      await setDirtyFlag(_vaultId, false).catch(() => {});
    }

    // Update device record.
    const vaultVersionRows = queryRows(_db, "SELECT value FROM vault_meta WHERE key = 'vault_version'");
    const vaultVersion = parseInt((vaultVersionRows[0]?.['value'] as string) ?? '0', 10);
    const record = await getDeviceRecord(_vaultId);
    if (record) {
      await setDeviceRecord({ ...record, last_seen_vault_version: vaultVersion });
    }

    vaultStore.setSaved(Date.now());
    vaultStore.setStatus('unlocked');
    recordEvent('vault_save');
  } catch (err) {
    vaultStore.setStatus('unlocked');
    const provType = (_providers.get(_saveProviderId)?.type ?? '') as string;
    recordEvent('error', { provider_type: provType, error_class: classifyErr(err) });
    throw err;
  }
}

// ── Dirty / debounce ──────────────────────────────────────────────────────

/**
 * Mark a provider dirty and schedule a debounced save.
 *
 * @param providerId — the provider whose vault rows were mutated
 */
export function markDirty(providerId?: string): void {
  const pid = providerId ?? _primaryProviderId;
  if (pid) _dirtyProviders.add(pid);
  // If a save is in flight, record which providers were dirtied during it so
  // Phase 5 doesn't incorrectly clear their dirty mark (their new mutations
  // were not included in the in-flight body upload).
  if (_savePromise && pid) _dirtyDuringSave.add(pid);

  vaultStore.setDirty(true);
  // Also set the legacy dirty flag on the vault_id namespace for WAL crash recovery.
  setDirtyFlag(_vaultId, true).catch(() => {});
  if (pid) setDirtyFlag(_vaultId + ':' + pid, true).catch(() => {});

  _mutationCountInWindow++;
  if (!_windowTimer) {
    _windowTimer = setTimeout(() => {
      _mutationCountInWindow = 0;
      _batchMode = false;
      _windowTimer = null;
    }, BATCH_WINDOW_MS);
  }
  if (_mutationCountInWindow > BATCH_THRESHOLD) _batchMode = true;

  scheduleDebounce();
}

function scheduleDebounce(): void {
  clearDebounce();
  const delay = _batchMode ? DEBOUNCE_BATCH_MS : DEBOUNCE_NORMAL_MS;
  _debounceTimer = setTimeout(() => {
    saveVault().catch((err) => {
      console.error('[VaultLifecycle] Debounced save failed:', err);
      vaultStore.setError(`Save failed: ${String(err)}`);
    });
  }, delay);
}

function clearDebounce(): void {
  if (_debounceTimer) {
    clearTimeout(_debounceTimer);
    _debounceTimer = null;
  }
}

// ── Lock ──────────────────────────────────────────────────────────────────

export function lockVault(): void {
  clearDebounce();

  // Emit stats before tearing down session state.
  recordEvent('vault_lock');

  // device_size_snapshot per provider (ciphertext sizes from last save).
  if (_db) {
    try {
      const fileCountRows = queryRows(_db, 'SELECT COUNT(*) AS c FROM files WHERE deleted = 0');
      const fileCount = (fileCountRows[0]?.['c'] as number | undefined) ?? 0;
      for (const [pid, provider] of _providers) {
        const vaultSizeBytes = _lastBodySizesPerProvider.get(pid) ?? 0;
        recordEvent('device_size_snapshot', {
          provider_type: provider.type,
          file_count_bucket: bucketLog2(fileCount),
          vault_size_bucket: bucketLog2(vaultSizeBytes),
        });
      }
    } catch { /* best-effort */ }
  }

  // Collect SFTP relay bandwidth (read-and-reset from WASM session).
  for (const provider of _providers.values()) {
    if (provider instanceof SftpProvider) {
      const { sent, recv } = provider.getBandwidthAndReset();
      if (sent > 0) recordEvent('relay_bandwidth_sftp', { bytes: sent });
      if (recv > 0) recordEvent('relay_bandwidth_sftp', { bytes: recv });
    }
  }

  // Collect share relay bandwidth (B1/B2 create/revoke requests, read-and-reset).
  const shareRelayBytes = getShareRelayBandwidthAndReset();
  if (shareRelayBytes > 0) recordEvent('relay_bandwidth_share', { bytes: shareRelayBytes });

  for (const [, journal] of _journals) journal.clear();
  if (_db) { try { _db.close(); } catch { /* ignore */ } }

  if (_vaultSessionId !== null) {
    byoWorker.Worker.byoVaultClose(_vaultSessionId).catch(() => {});
    _vaultSessionId = null;
  }

  // F1: sweep every worker-held secret registry — key bundles, HTTP provider
  // credentials in configRegistry (OAuth tokens, WebDAV/SFTP passwords, S3
  // secrets), and any pending OAuth verifiers. Previously only SFTP was
  // cleared; OAuth/WebDAV/S3 credentials survived lockVault because they
  // live in the worker's configRegistry (not in `_providers`).
  byoWorker.Worker.byoClearAllWorkerState().catch(() => {});
  // Belt-and-suspenders: also clear the WASM-side SFTP credential store
  // (separate heap from the worker's configRegistry).
  byoWorker.Worker.sftpClearAllCredentials().catch(() => {});

  // C6: release the exclusive vault lock so other tabs can take over.
  if (_lockRelease) {
    _lockRelease();
    _lockRelease = null;
  }

  _db = null;
  _manifest = null;
  _provider = null;
  _providers.clear();
  _primaryProviderId = '';
  _walKeys.clear();
  _journals.clear();
  _dirtyProviders.clear();
  _dirtyDuringSave = new Set();
  _lastBodySizesPerProvider.clear();
  _vaultId = '';
  _manifestVersion = 1;
  _manifestHeader = null;
  _mutationCountInWindow = 0;
  _batchMode = false;

  window.removeEventListener('beforeunload', handleBeforeUnload);
  vaultStore.reset();
}

// ── Accessors ─────────────────────────────────────────────────────────────

export function getDb(): import('sql.js').Database | null { return _db; }
export function getVaultSessionId(): number | null { return _vaultSessionId; }
export function getVaultId(): string { return _vaultId; }

/**
 * Pull the primary provider's vault body fresh from the backend, decrypt
 * it with the current vault session, and union its `vault_meta.enrolled_devices`
 * with the local `_db`. Lets the Settings → Devices view pick up entries
 * other devices added (e.g. after a remote enrollment) without a full
 * lock+unlock cycle. Best-effort: on any failure (no live primary, decrypt
 * fails, malformed JSON) we log and leave the local `_db` untouched.
 *
 * Returns true iff the local list changed (caller can trigger a re-render).
 */
export async function refreshEnrolledDevicesFromRemote(): Promise<boolean> {
  if (!_db || _vaultSessionId === null || !_provider || !_primaryProviderId) return false;

  let remoteDb: import('sql.js').Database | null = null;
  try {
    const bodyRef = _provider.bodyRef(_primaryProviderId);
    const { data: bodyBytes } = await _provider.download(bodyRef);
    const { data: sqliteB64 } = await byoWorker.Worker.byoVaultBodyDecrypt(
      _vaultSessionId,
      _primaryProviderId,
      bytesToBase64(bodyBytes),
    );
    const sqliteBytes = base64ToBytes(sqliteB64);

    const SQL = await loadSqlJs();
    remoteDb = new SQL.Database(sqliteBytes);

    const remoteRows = queryRows(remoteDb, "SELECT value FROM vault_meta WHERE key = 'enrolled_devices'");
    if (remoteRows.length === 0) return false;

    type Entry = { device_id: string; device_name: string; enrolled_at: string };
    let remoteList: Entry[];
    try {
      remoteList = JSON.parse(remoteRows[0]['value'] as string) as Entry[];
    } catch {
      return false;
    }

    const localRows = queryRows(_db, "SELECT value FROM vault_meta WHERE key = 'enrolled_devices'");
    let localList: Entry[] = [];
    if (localRows.length > 0) {
      try { localList = JSON.parse(localRows[0]['value'] as string) as Entry[]; }
      catch { localList = []; }
    }

    // Union by device_id. Prefer the entry with the earlier `enrolled_at`
    // when both sides have one — first enrollment wins and we don't churn
    // the timestamp on every refresh.
    const merged = new Map<string, Entry>();
    for (const e of remoteList) merged.set(e.device_id, e);
    for (const e of localList) {
      const existing = merged.get(e.device_id);
      if (!existing || e.enrolled_at < existing.enrolled_at) {
        merged.set(e.device_id, e);
      }
    }
    const mergedList = Array.from(merged.values());

    const changed =
      mergedList.length !== localList.length ||
      JSON.stringify(mergedList) !== JSON.stringify(localList);
    if (changed) {
      _db.run(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('enrolled_devices', ?)",
        [JSON.stringify(mergedList)],
      );
      // markDirty so the union propagates back to the backend on the next
      // save; otherwise this device's local copy would diverge silently.
      markDirty();
    }
    return changed;
  } catch (e) {
    console.warn('[VaultLifecycle] refreshEnrolledDevicesFromRemote failed', e);
    return false;
  } finally {
    if (remoteDb) {
      try { remoteDb.close(); } catch { /* best-effort */ }
    }
  }
}

/**
 * Re-decrypt this device's shard from the current primary manifest header so
 * the caller can forward it over an enrollment channel. The shard is NOT
 * cached across calls — we re-read the device's non-extractable CryptoKey and
 * decrypt on demand so the plaintext lives in a short-lived JS buffer.
 *
 * Returns the 32-byte shard as base64. Throws if no vault is open, no device
 * record exists, or the device's slot is missing from the header.
 */
export async function exportCurrentShard(): Promise<string> {
  if (!_provider) throw new Error('No active vault — open the vault before enrolling a device.');
  if (!_vaultId) throw new Error('No active vault session.');

  const cryptoKey = await getDeviceCryptoKey(_vaultId);
  if (!cryptoKey) {
    throw new Error('No device key found for this vault — unlock again before enrolling.');
  }
  const record = await getDeviceRecord(_vaultId);
  if (!record) {
    throw new Error('No device record found for this vault — unlock again before enrolling.');
  }
  const myDeviceId = deviceIdHexToB64(record.device_id);

  // Fetch the latest manifest header so we pick the current slot even if the
  // header was rotated (recovery, device-list edits) since unlock.
  const { data: manifestBytes } = await _provider.download(_provider.manifestRef());
  if (manifestBytes.length < VAULT_HEADER_SIZE) {
    throw new Error('Vault manifest too small to contain a header.');
  }
  const headerBytes = manifestBytes.slice(0, VAULT_HEADER_SIZE);
  const header = await byoWorker.Worker.byoParseVaultHeader(headerBytes);
  const deviceSlots: Array<{ device_id: string; wrap_iv: string; encrypted_payload: string }> =
    header.device_slots ?? [];

  for (const slot of deviceSlots) {
    if (slot.device_id === myDeviceId) {
      const slotIv = base64ToBytes(slot.wrap_iv) as Uint8Array<ArrayBuffer>;
      const slotCt = base64ToBytes(slot.encrypted_payload) as Uint8Array<ArrayBuffer>;
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: slotIv },
        cryptoKey,
        slotCt,
      );
      const shard = new Uint8Array(decrypted);
      const b64 = bytesToBase64(shard);
      shard.fill(0);
      return b64;
    }
  }
  throw new Error('Device slot not present in current vault header — has this device been revoked?');
}


export function getProvider(): StorageProvider | null { return _provider; }
export function getProviders(): Map<string, StorageProvider> { return _providers; }
export function getPrimaryProviderId(): string { return _primaryProviderId; }
export function getManifest(): ManifestJson | null { return _manifest; }

/** Get the VaultJournal for a provider. */
export function getJournalForProvider(providerId: string): VaultJournal | null {
  return _journals.get(providerId) ?? null;
}

/** Get the WAL CryptoKey for a provider. */
export function getWalKeyForProvider(providerId: string): CryptoKey | null {
  return _walKeys.get(providerId) ?? null;
}

/** Legacy accessor: returns the primary provider's journal. */
export function getJournal(): VaultJournal | null {
  return _journals.get(_primaryProviderId) ?? null;
}

/** Legacy accessor: returns the primary provider's WAL key. */
export function getWalKey(): CryptoKey | null {
  return _walKeys.get(_primaryProviderId) ?? null;
}

/**
 * Get or lazy-initialize a provider instance by provider_id.
 * Falls back to initializing from manifest config.
 */
export async function getOrInitProvider(providerId: string): Promise<StorageProvider | null> {
  const existing = _providers.get(providerId);
  if (existing) return existing;

  if (!_manifest) return null;

  const entry = _manifest.providers.find((p) => p.provider_id === providerId && !p.tombstone);
  if (!entry) return null;

  const instance = await initializeProviderFromConfig(entry).catch(() => null);
  if (instance) {
    _providers.set(providerId, instance);
    vaultStore.updateProviderStatus(providerId, 'connected');
  }
  return instance;
}

/**
 * Return the stored ProviderConfig for a provider (from manifest config_json).
 * Used by reconnect UI to pre-populate host/username fields.
 */
export function getProviderConfig(providerId: string): ProviderConfig | null {
  if (!_manifest) return null;
  const entry = _manifest.providers.find((p) => p.provider_id === providerId && !p.tombstone);
  if (!entry) return null;
  try {
    return JSON.parse(entry.config_json) as ProviderConfig;
  } catch {
    return null;
  }
}

/**
 * Reconnect an SFTP secondary provider using a worker-held credential handle.
 * Call after the user has entered credentials via the reconnect form.
 * On success, the provider is added to _providers and its status set to 'connected'.
 */
export async function reconnectSftpProvider(providerId: string, credHandle: number): Promise<void> {
  if (!_manifest) throw new Error('Vault not unlocked');
  const entry = _manifest.providers.find((p) => p.provider_id === providerId && !p.tombstone);
  if (!entry) throw new Error('Provider not found in manifest');

  const config = JSON.parse(entry.config_json) as ProviderConfig;
  const instance = new SftpProvider();

  instance.credHandle = credHandle;
  instance.credUsername = config.sftpUsername || '';

  await instance.init({ ...config, providerId });

  _providers.set(providerId, instance);
  vaultStore.updateProviderStatus(providerId, 'connected');
}

// ── Provider management ────────────────────────────────────────────────────

/**
 * Add a new provider to the vault.
 * Inserts a manifest entry and uploads the initial (empty) vault body.
 */
export async function addProvider(
  instance: StorageProvider,
  config: ProviderConfig,
  displayName?: string,
): Promise<string> {
  if (!_db || _vaultSessionId === null || !_manifest) throw new Error('Vault not unlocked');

  const providerId = config.providerId ?? crypto.randomUUID();
  const type = instance.type;
  const name = displayName ?? providerDisplayName(type as ProviderType);
  const nowSec = Math.floor(Date.now() / 1000);

  // Create initial empty per-provider SQLite and upload it.
  const SQL = await loadSqlJs();
  const provDb = new SQL.Database();
  provDb.run(getVaultSchema());
  const emptyBytes = provDb.export();
  provDb.close();

  const { data: bodyBlobB64 } = await byoWorker.Worker.byoVaultBodyEncrypt(
    _vaultSessionId,
    providerId,
    bytesToBase64(emptyBytes),
  );
  await instance.upload(null, `vault_${providerId}.sc`, base64ToBytes(bodyBlobB64), {});

  // Derive WAL + journal keys for the new provider. The WAL key is returned
  // as a non-extractable WebCrypto handle — raw bytes stay inside the worker.
  const { key: walKey } = await byoWorker.Worker.byoDerivePerVaultWalKey(_vaultSessionId, providerId);
  _walKeys.set(providerId, walKey);

  _journals.set(providerId, new VaultJournal(instance, providerId, _vaultSessionId));

  // Add entry to in-memory manifest via Rust (validates constraints + tombstone rules).
  const newEntry: ManifestProviderEntry = {
    provider_id: providerId,
    provider_type: type,
    display_name: name,
    config_json: JSON.stringify({ ...config, providerId }),
    is_primary: false,
    sftp_host_key_fingerprint: null,
    vault_version_hint: null,
    created_at: nowSec,
    updated_at: nowSec,
    tombstone: false,
  };
  const { manifestJson: addedManifestJson } = await byoWorker.Worker.byoManifestAddProvider(
    JSON.stringify(_manifest), JSON.stringify(newEntry),
  );
  _manifest = JSON.parse(addedManifestJson) as ManifestJson;
  _providers.set(providerId, instance);

  const newMeta: ProviderMeta = {
    providerId,
    type: type as ProviderType,
    displayName: name,
    isPrimary: false,
    status: 'connected',
    failCount: 0,
    lastPingTs: 0,
  };
  let currentProviders: ProviderMeta[] = [];
  const unsub = vaultStore.subscribe((s) => { currentProviders = s.providers; });
  unsub();
  vaultStore.setProviders([...currentProviders, newMeta]);

  markDirty(_primaryProviderId);
  // Force-save inline so the new provider's manifest entry survives an
  // immediate reload (see renameProvider for rationale). Saving failures
  // propagate so the caller can surface "couldn't persist" rather than
  // returning a providerId that won't be there on next unlock.
  await saveVault();
  return providerId;
}

/** Rename a provider's display name in the manifest.
 *
 * Force-saves inline rather than relying on the 3 s debounce so the rename
 * survives an immediate reload. Without the inline save, the manifest entry
 * lives only in memory until debounce fires; if the user reloads before
 * that, the rename is lost and they'd see the old name re-appear with no
 * indication anything went wrong.
 */
export async function renameProvider(providerId: string, newName: string): Promise<void> {
  if (!_manifest) throw new Error('Vault not unlocked');
  const trimmed = newName.trim();
  if (!trimmed) throw new Error('Name cannot be empty');
  const nowSec = Math.floor(Date.now() / 1000);
  const { manifestJson: renamedManifestJson } = await byoWorker.Worker.byoManifestRenameProvider(
    JSON.stringify(_manifest), providerId, trimmed, nowSec,
  );
  _manifest = JSON.parse(renamedManifestJson) as ManifestJson;
  let current: ProviderMeta[] = [];
  const unsub = vaultStore.subscribe((s) => { current = s.providers; });
  unsub();
  vaultStore.setProviders(current.map((p) => p.providerId === providerId ? { ...p, displayName: trimmed } : p));
  // Mirror the rename onto the per-device IDB row so the vault-list landing
  // page (which reads display_name from IDB pre-unlock) reflects it on next
  // reload. Best-effort — the manifest write above is the source of truth.
  try {
    await updateProviderDisplayNameLocal(providerId, trimmed);
  } catch (e) {
    console.warn('[VaultLifecycle] renameProvider: local IDB update failed', e);
  }
  markDirty(_primaryProviderId);
  await saveVault();
}

/**
 * Replace a provider's stored config (host, port, credentials, …) and reconnect.
 *
 * Always test-connects before committing: hydrates a fresh provider with the
 * proposed config, and only mutates state if `init()` succeeds. This makes
 * it safe to edit the primary — a typo in the host can't lock the user out
 * because the bad config never reaches the manifest.
 *
 * On success:
 *  - rewrites the manifest entry's `config_json` (peer devices pick up host
 *    changes on their next merge);
 *  - upserts the per-device IDB row via `saveProviderConfig` so reload
 *    auto-hydrates with the new values;
 *  - swaps the live `_providers` instance and clears the old WS;
 *  - markDirty + save.
 *
 * `newDisplayName` is optional — pass null to keep the existing name.
 */
export async function updateProviderConfig(
  providerId: string,
  newConfig: ProviderConfig,
  newDisplayName?: string | null,
): Promise<void> {
  if (!_manifest || _vaultSessionId === null) throw new Error('Vault not unlocked');
  const entry = _manifest.providers.find((p) => p.provider_id === providerId && !p.tombstone);
  if (!entry) throw new Error('Provider not found in manifest');

  // Test-connect: hydrate a fresh provider against the new config. Throws on
  // bad host / wrong credentials / TOFU mismatch / etc. Old live instance is
  // untouched at this point.
  const candidate = await hydrateProviderForUpdate({ ...newConfig, providerId });

  try {
    const nowSec = Math.floor(Date.now() / 1000);
    const newConfigJson = JSON.stringify({ ...newConfig, providerId });
    const { manifestJson: updatedManifestJson } = await byoWorker.Worker.byoManifestUpdateProviderConfig(
      JSON.stringify(_manifest), providerId, newConfigJson, nowSec,
    );
    _manifest = JSON.parse(updatedManifestJson) as ManifestJson;

    // Persist to per-device IDB so reload picks up the new config too.
    if (_vaultId) {
      try {
        await saveProviderConfig(
          {
            provider_id: providerId,
            vault_id: _vaultId,
            vault_label: entry.display_name,
            type: candidate.type,
            display_name: newDisplayName?.trim() || entry.display_name,
            is_primary: entry.is_primary,
            saved_at: new Date().toISOString(),
          },
          { ...newConfig, providerId },
        );
      } catch (persistErr) {
        console.warn('[VaultLifecycle] saveProviderConfig during update failed', persistErr);
      }
    }

    // Swap the live instance: disconnect the old session before we lose the
    // reference (so the WebSocket closes cleanly), then install the candidate.
    const old = _providers.get(providerId);
    if (old) {
      await old.disconnect().catch(() => {});
    }
    _providers.set(providerId, candidate);
    if (providerId === _primaryProviderId) {
      _provider = candidate;
    }

    let current: ProviderMeta[] = [];
    const unsub = vaultStore.subscribe((s) => { current = s.providers; });
    unsub();
    vaultStore.setProviders(current.map((p) => p.providerId === providerId
      ? { ...p, status: 'connected', failCount: 0, lastPingTs: Date.now() }
      : p));

    markDirty(_primaryProviderId);
    // Force-save so the manifest_json change reaches the primary before any
    // reload (see renameProvider for rationale).
    await saveVault();
  } catch (e) {
    // Commit failed after a successful test-connect. Drop the candidate
    // session so we don't leak the WebSocket.
    await candidate.disconnect().catch(() => {});
    throw e;
  }
}

/** Local wrapper around hydrateProvider that defers the import (the function
 *  pulls in provider factory code that the byo worker bundle must not load
 *  eagerly via VaultLifecycle's static graph). */
async function hydrateProviderForUpdate(config: ProviderConfig): Promise<StorageProvider> {
  const { hydrateProvider } = await import('./ProviderHydrate');
  return hydrateProvider(config);
}

/** Set a provider as the primary.
 *
 * Force-saves inline so primary-swap survives an immediate reload (see
 * renameProvider for rationale).
 */
export async function setAsPrimaryProvider(providerId: string): Promise<void> {
  if (!_manifest) throw new Error('Vault not unlocked');
  const nowSec = Math.floor(Date.now() / 1000);
  const { manifestJson: primaryManifestJson } = await byoWorker.Worker.byoManifestSetPrimary(
    JSON.stringify(_manifest), providerId, nowSec,
  );
  _manifest = JSON.parse(primaryManifestJson) as ManifestJson;
  _primaryProviderId = providerId;
  let current: ProviderMeta[] = [];
  const unsub = vaultStore.subscribe((s) => { current = s.providers; });
  unsub();
  vaultStore.setProviders(current.map((p) => ({ ...p, isPrimary: p.providerId === providerId })));
  vaultStore.setPrimaryProviderId(providerId);
  markDirty(_primaryProviderId);
  await saveVault();
}

/** Remove a non-primary provider (tombstones the manifest entry). */
export async function removeProvider(providerId: string): Promise<void> {
  if (!_manifest) throw new Error('Vault not unlocked');
  if (providerId === _primaryProviderId) throw new Error('Cannot remove the primary provider');

  // H7: best-effort delete vault body + journal from the provider's own storage
  // before tombstoning the manifest entry, so a future rollback cannot resurrect it.
  const provInst = _providers.get(providerId);
  if (provInst) {
    await Promise.allSettled([
      provInst.delete(provInst.bodyRef(providerId)),
      provInst.delete(provInst.journalRef(providerId)),
    ]);
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const { manifestJson: tombstonedManifestJson } = await byoWorker.Worker.byoManifestTombstone(
    JSON.stringify(_manifest), providerId, nowSec,
  );
  _manifest = JSON.parse(tombstonedManifestJson) as ManifestJson;
  _providers.delete(providerId);
  _walKeys.delete(providerId);
  const journal = _journals.get(providerId);
  if (journal) journal.clear();
  _journals.delete(providerId);
  let current: ProviderMeta[] = [];
  const unsub = vaultStore.subscribe((s) => { current = s.providers; });
  unsub();
  vaultStore.setProviders(current.filter((p) => p.providerId !== providerId));
  vaultStore.setActiveProviderId(_primaryProviderId);
  markDirty(_primaryProviderId);
  // Force-save inline so removal persists across an immediate reload (see
  // renameProvider for rationale).
  await saveVault();
}

// ── Before-unload handler ──────────────────────────────────────────────────

function handleBeforeUnload(): void {
  if (_vaultId) {
    setDirtyFlag(_vaultId, true).catch(() => {});
    for (const pid of _dirtyProviders) {
      setDirtyFlag(_vaultId + ':' + pid, true).catch(() => {});
    }
  }
}

// ── Private helpers ────────────────────────────────────────────────────────

function findPrimaryEntry(manifest: ManifestJson): ManifestProviderEntry | undefined {
  return manifest.providers.find((p) => p.is_primary && !p.tombstone);
}

/**
 * Initialize a StorageProvider instance from a manifest entry's config_json.
 *
 * Routes through `hydrateProvider` so SFTP secondaries get their credential
 * handle set up before init() (the bare `initializeProvider` factory creates
 * an empty SftpProvider and init() throws "credHandle + credUsername must be
 * set before init()" — which is why pre-fix unlocks left every SFTP
 * secondary "offline" until the user manually re-entered creds).
 *
 * Errors are logged to the console so connection failures don't silently
 * vanish — the unlock UI shows the provider as "offline" but no clue why.
 */
async function initializeProviderFromConfig(
  entry: ManifestProviderEntry,
): Promise<StorageProvider | null> {
  try {
    const config = JSON.parse(entry.config_json) as ProviderConfig;
    const { hydrateProvider } = await import('./ProviderHydrate');
    return await hydrateProvider({ ...config, providerId: entry.provider_id });
  } catch (err) {
    console.warn(
      `[VaultLifecycle] initializeProviderFromConfig failed for ${entry.provider_id} (${entry.provider_type}):`,
      err,
    );
    return null;
  }
}

/**
 * Merge rows from a per-provider SQLite into the master DB.
 * - If isPrimary: also copies key_versions and vault_meta.
 * - All tables: copies rows from the provider's DB that match provider_id.
 */
function mergeProviderDb(
  masterDb: import('sql.js').Database,
  provDb: import('sql.js').Database,
  providerId: string,
  isPrimary: boolean,
): void {
  if (isPrimary) {
    // Copy global tables from primary.
    const kvRows = queryRows(provDb, 'SELECT * FROM key_versions');
    for (const row of kvRows) {
      masterDb.run(
        `INSERT OR REPLACE INTO key_versions
          (id, version, mlkem_public_key, mlkem_private_key_encrypted, x25519_public_key,
           x25519_private_key_encrypted, mlkem_private_key_recovery_encrypted,
           x25519_private_key_recovery_encrypted, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          row['id'], row['version'], row['mlkem_public_key'], row['mlkem_private_key_encrypted'],
          row['x25519_public_key'], row['x25519_private_key_encrypted'],
          row['mlkem_private_key_recovery_encrypted'], row['x25519_private_key_recovery_encrypted'],
          row['status'], row['created_at'],
        ] as import('sql.js').BindParams,
      );
    }
    const metaRows = queryRows(provDb, 'SELECT key, value FROM vault_meta');
    for (const row of metaRows) {
      masterDb.run(
        `INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)`,
        [row['key'], row['value']] as import('sql.js').BindParams,
      );
    }
  }

  // Copy per-provider rows for all data tables.
  // M9: INSERT OR IGNORE — intentional unlock-time semantics.
  //   Each provider's rows are scoped by provider_id, so id collisions between
  //   providers should not occur in normal operation. If they do (e.g. data
  //   corruption or a future provider-id bug), IGNORE keeps the first loaded
  //   copy (primary wins over secondaries), preventing silent data overwrite.
  //   This is distinct from copyProviderRows (save path) which uses
  //   INSERT OR REPLACE because it writes to an empty per-provider SQLite.
  const tables = ['folders', 'files', 'favorites', 'trash', 'share_tokens', 'collections'] as const;
  for (const table of tables) {
    try {
      const rows = queryRows(provDb, `SELECT * FROM ${table} WHERE provider_id = ?`, [providerId]);
      for (const row of rows) {
        const cols = Object.keys(row);
        const placeholders = cols.map(() => '?').join(', ');
        masterDb.run(
          `INSERT OR IGNORE INTO ${table} (${cols.join(', ')}) VALUES (${placeholders})`,
          cols.map((c) => row[c]) as import('sql.js').BindParams,
        );
      }
    } catch {
      // Table may not exist in older vault bodies — skip.
    }
  }

  // collection_files has no provider_id — mirror the save path's JOIN-by-
  // collection approach so membership rows travel with their parent
  // collections across the save/load roundtrip.
  try {
    const rows = queryRows(
      provDb,
      `SELECT cf.* FROM collection_files cf
       JOIN collections c ON c.id = cf.collection_id
       WHERE c.provider_id = ?`,
      [providerId],
    );
    for (const row of rows) {
      const cols = Object.keys(row);
      const placeholders = cols.map(() => '?').join(', ');
      masterDb.run(
        `INSERT OR IGNORE INTO collection_files (${cols.join(', ')}) VALUES (${placeholders})`,
        cols.map((c) => row[c]) as import('sql.js').BindParams,
      );
    }
  } catch {
    // Older vault bodies may lack the table — skip.
  }
}

/**
 * Copy rows WHERE provider_id = pid from masterDb into provDb (for save).
 * Also copies key_versions and vault_meta (replicated in every vault).
 */
function copyProviderRows(
  masterDb: import('sql.js').Database,
  provDb: import('sql.js').Database,
  providerId: string,
): void {
  // Global tables (replicated in every vault).
  const kvRows = queryRows(masterDb, 'SELECT * FROM key_versions');
  for (const row of kvRows) {
    provDb.run(
      `INSERT OR REPLACE INTO key_versions
        (id, version, mlkem_public_key, mlkem_private_key_encrypted, x25519_public_key,
         x25519_private_key_encrypted, mlkem_private_key_recovery_encrypted,
         x25519_private_key_recovery_encrypted, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        row['id'], row['version'], row['mlkem_public_key'], row['mlkem_private_key_encrypted'],
        row['x25519_public_key'], row['x25519_private_key_encrypted'],
        row['mlkem_private_key_recovery_encrypted'], row['x25519_private_key_recovery_encrypted'],
        row['status'], row['created_at'],
      ] as import('sql.js').BindParams,
    );
  }
  const metaRows = queryRows(masterDb, 'SELECT key, value FROM vault_meta');
  for (const row of metaRows) {
    provDb.run(
      `INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)`,
      [row['key'], row['value']] as import('sql.js').BindParams,
    );
  }

  // Per-provider data (provider_id column).
  const tables = ['folders', 'files', 'favorites', 'trash', 'share_tokens', 'collections'] as const;
  for (const table of tables) {
    try {
      const rows = queryRows(masterDb, `SELECT * FROM ${table} WHERE provider_id = ?`, [providerId]);
      for (const row of rows) {
        const cols = Object.keys(row);
        const placeholders = cols.map(() => '?').join(', ');
        provDb.run(
          `INSERT OR REPLACE INTO ${table} (${cols.join(', ')}) VALUES (${placeholders})`,
          cols.map((c) => row[c]) as import('sql.js').BindParams,
        );
      }
    } catch {
      // Skip tables that don't exist.
    }
  }

  // collection_files has no provider_id column — follow collections to the
  // membership rows so each per-provider body carries its own collection
  // graph, and nothing else.
  try {
    const rows = queryRows(
      masterDb,
      `SELECT cf.* FROM collection_files cf
       JOIN collections c ON c.id = cf.collection_id
       WHERE c.provider_id = ?`,
      [providerId],
    );
    for (const row of rows) {
      const cols = Object.keys(row);
      const placeholders = cols.map(() => '?').join(', ');
      provDb.run(
        `INSERT OR REPLACE INTO collection_files (${cols.join(', ')}) VALUES (${placeholders})`,
        cols.map((c) => row[c]) as import('sql.js').BindParams,
      );
    }
  } catch {
    // Skip if the table doesn't exist yet.
  }
}

async function loadKeyVersionsIntoWorker(
  db: import('sql.js').Database,
  vaultSessionId: number,
  keySessionId: string,
): Promise<void> {
  const activeRows = queryRows(
    db,
    "SELECT mlkem_private_key_encrypted, x25519_private_key_encrypted FROM key_versions WHERE status = 'active' ORDER BY version DESC LIMIT 1",
  );
  if (activeRows.length === 0) throw new Error('No active key version found in vault');

  const row = activeRows[0];
  const mlkemEncrypted = toUint8Array(row['mlkem_private_key_encrypted'] as Uint8Array | string);
  const x25519Encrypted = toUint8Array(row['x25519_private_key_encrypted'] as Uint8Array | string);

  await byoWorker.Worker.byoVaultLoadKeys(vaultSessionId, mlkemEncrypted, x25519Encrypted, keySessionId);
}

function toUint8Array(value: Uint8Array | string): Uint8Array {
  if (typeof value === 'string') return base64ToBytes(value);
  return value;
}

/**
 * Returns the full SQLite schema for per-provider vault bodies (R6 greenfield).
 * Must stay in sync with ByoSetup.svelte VAULT_SCHEMA.
 */
function getVaultSchema(): string {
  return `
    CREATE TABLE IF NOT EXISTS key_versions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      version INTEGER NOT NULL UNIQUE,
      mlkem_public_key BLOB NOT NULL,
      mlkem_private_key_encrypted BLOB NOT NULL,
      x25519_public_key BLOB NOT NULL,
      x25519_private_key_encrypted BLOB NOT NULL,
      mlkem_private_key_recovery_encrypted BLOB,
      x25519_private_key_recovery_encrypted BLOB,
      status TEXT DEFAULT 'active' CHECK (status IN ('active','archived')),
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      parent_id INTEGER REFERENCES folders(id) ON DELETE CASCADE,
      name BLOB NOT NULL,
      name_key BLOB NOT NULL,
      provider_id TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      folder_id INTEGER REFERENCES folders(id) ON DELETE CASCADE,
      name BLOB NOT NULL,
      filename_key BLOB NOT NULL,
      size INTEGER NOT NULL,
      encrypted_size INTEGER NOT NULL,
      storage_ref TEXT NOT NULL,
      mime_type TEXT DEFAULT '',
      file_type TEXT DEFAULT '',
      key_version_id INTEGER NOT NULL REFERENCES key_versions(id),
      metadata TEXT DEFAULT '',
      provider_id TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS favorites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_type TEXT NOT NULL CHECK (item_type IN ('file','folder')),
      item_id INTEGER NOT NULL,
      provider_id TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(item_type, item_id)
    );
    CREATE TABLE IF NOT EXISTS vault_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS trash (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_type TEXT NOT NULL CHECK (item_type IN ('file','folder')),
      original_id INTEGER NOT NULL,
      data BLOB NOT NULL,
      provider_id TEXT NOT NULL,
      deleted_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS share_tokens (
      share_id TEXT PRIMARY KEY,
      kind TEXT NOT NULL DEFAULT 'file' CHECK (kind IN ('file','folder','collection')),
      file_id INTEGER,
      folder_id INTEGER,
      collection_id INTEGER,
      provider_id TEXT NOT NULL,
      provider_ref TEXT,
      public_link TEXT,
      presigned_expires_at INTEGER,
      owner_token TEXT,
      total_bytes INTEGER,
      blob_count INTEGER,
      created_at INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      -- URL fragment carrying the bundle/content key. Stored locally so
      -- the user can recover the share link from Settings → Active shares
      -- after the create-flow modal is dismissed. The fragment is the
      -- decryption key + (optional) bundle name; never sent to the relay.
      -- Vault SQLite is wrapped under vault_key (SECURITY.md §4), same
      -- threat model as every other secret in the vault.
      fragment TEXT,
      -- Finer-grained classification than 'kind' for the Settings UI.
      -- The relay schema is closed at file/folder/collection so multi-
      -- file and mixed bundles ride 'folder' there; this column lets the
      -- creator UI show the right badges (e.g. Folder + Files for a
      -- mixed bundle) without changing the wire protocol. Values:
      -- 'file' | 'folder' | 'collection' | 'multi-files' | 'mixed'.
      -- Vault-only; never sent anywhere.
      bundle_kind TEXT,
      -- Optional user-supplied display name for this share. Surfaces
      -- both in Settings → Active shares AND on the recipient's landing
      -- page (carried in the fragment as &n=<percent-encoded>) so the
      -- two ends agree. NULL → both ends fall back to the inferred
      -- name (folder name, "N items", filename, etc.).
      label TEXT
    );
    CREATE TABLE IF NOT EXISTS collections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name BLOB NOT NULL,
      name_key BLOB NOT NULL,
      provider_id TEXT NOT NULL,
      cover_file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS collection_files (
      collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
      file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
      added_at TEXT DEFAULT (datetime('now')),
      PRIMARY KEY (collection_id, file_id)
    );
    CREATE INDEX IF NOT EXISTS idx_collection_files_file ON collection_files(file_id);
    CREATE TABLE IF NOT EXISTS share_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      direction TEXT NOT NULL CHECK (direction IN ('outbound','inbound')),
      file_ref TEXT NOT NULL,
      counterparty_hint TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_share_audit_ts ON share_audit(ts);
    CREATE TRIGGER IF NOT EXISTS folders_parent_provider_check
      BEFORE INSERT ON folders WHEN NEW.parent_id IS NOT NULL
      BEGIN
        SELECT RAISE(ABORT, 'cross-provider folder parent')
        FROM folders WHERE id = NEW.parent_id AND provider_id != NEW.provider_id;
      END;
    CREATE TRIGGER IF NOT EXISTS folders_parent_provider_check_update
      BEFORE UPDATE ON folders WHEN NEW.parent_id IS NOT NULL
      BEGIN
        SELECT RAISE(ABORT, 'cross-provider folder parent')
        FROM folders WHERE id = NEW.parent_id AND provider_id != NEW.provider_id;
      END;
    CREATE TRIGGER IF NOT EXISTS files_folder_provider_check
      BEFORE INSERT ON files WHEN NEW.folder_id IS NOT NULL
      BEGIN
        SELECT RAISE(ABORT, 'cross-provider file folder')
        FROM folders WHERE id = NEW.folder_id AND provider_id != NEW.provider_id;
      END;
    CREATE TRIGGER IF NOT EXISTS files_folder_provider_check_update
      BEFORE UPDATE ON files WHEN NEW.folder_id IS NOT NULL
      BEGIN
        SELECT RAISE(ABORT, 'cross-provider file folder')
        FROM folders WHERE id = NEW.folder_id AND provider_id != NEW.provider_id;
      END;
  `;
}

