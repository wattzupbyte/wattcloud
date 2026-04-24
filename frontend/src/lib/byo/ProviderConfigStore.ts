/**
 * ProviderConfigStore — per-device persistence for provider configs.
 *
 * Persists the minimum metadata needed to auto-hydrate providers on page
 * reload (vault_id, type, display_name, vault_label, primary flag) plus the
 * secret `config` object wrapped with AES-GCM under the non-extractable
 * device CryptoKey from DeviceKeyStore.
 *
 * Zero-knowledge stance:
 * - Nothing from this store ever leaves the device.
 * - The wrapping CryptoKey has `extractable: false` — filesystem-level
 *   profile theft cannot unwrap offline.
 * - The non-secret metadata (vault_label, provider type, display_name) is
 *   stored in clear so the "Your vaults" list can render without unlock;
 *   those fields are not sensitive and need to be readable before the user
 *   has chosen which vault key to load.
 *
 * Threat model caveat (documented in SECURITY.md §12): same-origin RCE
 * (e.g. DOM XSS) can invoke `crypto.subtle.decrypt` against the key handle.
 * Non-extractability protects raw key bytes, not functional misuse.
 */

import type { ProviderConfig, ProviderType } from '@wattcloud/sdk';
import { openDB, STORE_PROVIDER_CONFIGS, getDeviceCryptoKey } from './DeviceKeyStore';

// ── Types ──────────────────────────────────────────────────────────────────

/** Non-secret metadata — readable without the device key. */
export interface ProviderConfigMeta {
  /** UUID from the vault manifest. Primary key. */
  provider_id: string;
  /** Hex vault_id this provider is enrolled in. Used to group rows per-vault. */
  vault_id: string;
  /** User-set vault label (e.g. "Personal", "Work"). Not a secret. */
  vault_label: string;
  /** Provider type for icon + dispatch (sftp, s3, gdrive, …). */
  type: ProviderType;
  /** Provider-supplied display name (e.g. "Hetzner Storage Box"). */
  display_name: string;
  /** True for the manifest's designated primary provider. */
  is_primary: boolean;
  /** ISO timestamp of the last write; used to sort the vault list. */
  saved_at: string;
}

/** Full stored row: meta + wrapped config. */
interface StoredProviderConfig extends ProviderConfigMeta {
  /** AES-GCM IV used for this wrap operation. 12 bytes. */
  iv: ArrayBuffer;
  /** AES-GCM(deviceCryptoKey, UTF8(JSON.stringify(config))). */
  wrapped_config: ArrayBuffer;
}

/** Aggregate shape returned when caller wants meta + decrypted config. */
export interface HydratedProviderConfig extends ProviderConfigMeta {
  config: ProviderConfig;
}

/**
 * Result of a hydrate attempt for a whole vault. `hydrated` is every row
 * that decrypted cleanly; `failed` is every row we have on disk but
 * couldn't unwrap — typically a leftover from an interrupted device-key
 * migration. Callers can treat a non-empty `failed` with empty `hydrated`
 * as a systematic decrypt failure and offer the user a "forget & re-add"
 * self-heal, rather than the opaque "no saved providers" dead end.
 */
export interface LoadedProvidersForVault {
  hydrated: HydratedProviderConfig[];
  failed: ProviderConfigMeta[];
}

/** One vault's worth of persisted provider rows, grouped for UI listing. */
export interface PersistedVaultSummary {
  vault_id: string;
  vault_label: string;
  providers: ProviderConfigMeta[];
  /** Convenience: the entry with is_primary=true, or the newest entry if none flagged. */
  primary: ProviderConfigMeta;
  /** Max saved_at across this vault's providers — for "most recent" sort. */
  last_saved_at: string;
}

// ── Save / update ──────────────────────────────────────────────────────────

/**
 * Upsert a provider config. Wraps `config` with the device CryptoKey for
 * `vault_id`. Caller must ensure `generateDeviceCryptoKey(vault_id)` has
 * already been called during vault creation / enrolment.
 */
export async function saveProviderConfig(
  meta: ProviderConfigMeta,
  config: ProviderConfig,
): Promise<void> {
  const deviceKey = await getDeviceCryptoKey(meta.vault_id);
  if (!deviceKey) {
    throw new Error(
      `saveProviderConfig: no device CryptoKey for vault ${meta.vault_id}. ` +
        `Call generateDeviceCryptoKey during enrolment before persisting configs.`,
    );
  }

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(config));
  const wrapped = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    deviceKey,
    plaintext,
  );

  const row: StoredProviderConfig = {
    ...meta,
    iv: iv.buffer,
    wrapped_config: wrapped,
  };

  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_PROVIDER_CONFIGS, 'readwrite');
    tx.objectStore(STORE_PROVIDER_CONFIGS).put(row);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── Listing (meta-only, no decrypt) ────────────────────────────────────────

/** Return every persisted provider row, meta only. No decrypt; safe to call pre-unlock. */
export async function listAllProviderMetas(): Promise<ProviderConfigMeta[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PROVIDER_CONFIGS, 'readonly');
    const req = tx.objectStore(STORE_PROVIDER_CONFIGS).getAll();
    req.onsuccess = () => {
      const rows = (req.result ?? []) as StoredProviderConfig[];
      resolve(rows.map(stripWrapped));
    };
    req.onerror = () => reject(req.error);
  });
}

/** Group persisted rows into vault summaries — one per unique vault_id. */
export async function listPersistedVaults(): Promise<PersistedVaultSummary[]> {
  const metas = await listAllProviderMetas();
  const byVault = new Map<string, ProviderConfigMeta[]>();
  for (const m of metas) {
    const arr = byVault.get(m.vault_id) ?? [];
    arr.push(m);
    byVault.set(m.vault_id, arr);
  }
  const vaults: PersistedVaultSummary[] = [];
  for (const [vault_id, providers] of byVault) {
    const primary =
      providers.find((p) => p.is_primary) ??
      providers.slice().sort((a, b) => b.saved_at.localeCompare(a.saved_at))[0];
    if (!primary) continue;
    const last_saved_at = providers
      .map((p) => p.saved_at)
      .reduce((a, b) => (a > b ? a : b), primary.saved_at);
    vaults.push({
      vault_id,
      vault_label: primary.vault_label,
      providers,
      primary,
      last_saved_at,
    });
  }
  // Sort most-recent-first so the list reflects recency of use.
  vaults.sort((a, b) => b.last_saved_at.localeCompare(a.last_saved_at));
  return vaults;
}

// ── Load (decrypts) ────────────────────────────────────────────────────────

/**
 * Load all persisted providers for a vault. Returns both the rows that
 * decrypted cleanly and the metas of rows that didn't — a split the caller
 * needs to distinguish "never saved anything here" from "we have rows but
 * the device key doesn't unwrap them" (usually a device-key migration left
 * this vault in a bad state). Rows that fail to decrypt are still skipped
 * in the hydrated list so one bad row doesn't block the rest.
 */
export async function loadProvidersForVault(
  vault_id: string,
): Promise<LoadedProvidersForVault> {
  const db = await openDB();
  const rows: StoredProviderConfig[] = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PROVIDER_CONFIGS, 'readonly');
    const idx = tx.objectStore(STORE_PROVIDER_CONFIGS).index('by_vault_id');
    const req = idx.getAll(IDBKeyRange.only(vault_id));
    req.onsuccess = () => resolve((req.result ?? []) as StoredProviderConfig[]);
    req.onerror = () => reject(req.error);
  });

  const deviceKey = await getDeviceCryptoKey(vault_id);
  if (!deviceKey) {
    // No key to attempt decrypt with — surface all rows as failed so the
    // UI can offer the self-heal instead of pretending nothing exists.
    return { hydrated: [], failed: rows.map(stripWrapped) };
  }

  const hydrated: HydratedProviderConfig[] = [];
  const failed: ProviderConfigMeta[] = [];
  for (const row of rows) {
    try {
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: row.iv },
        deviceKey,
        row.wrapped_config,
      );
      const config = JSON.parse(new TextDecoder().decode(pt)) as ProviderConfig;
      hydrated.push({ ...stripWrapped(row), config });
    } catch (err) {
      console.warn('[ProviderConfigStore] failed to decrypt row', row.provider_id, err);
      failed.push(stripWrapped(row));
    }
  }
  return { hydrated, failed };
}

// ── Delete ─────────────────────────────────────────────────────────────────

/** Forget one provider on this device. Does not touch the remote vault manifest. */
export async function deleteProviderConfig(provider_id: string): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_PROVIDER_CONFIGS, 'readwrite');
    tx.objectStore(STORE_PROVIDER_CONFIGS).delete(provider_id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Forget every provider for a vault on this device. */
export async function deleteVaultProviderConfigs(vault_id: string): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_PROVIDER_CONFIGS, 'readwrite');
    const idx = tx.objectStore(STORE_PROVIDER_CONFIGS).index('by_vault_id');
    const req = idx.openCursor(IDBKeyRange.only(vault_id));
    req.onsuccess = () => {
      const cursor = req.result;
      if (cursor) {
        cursor.delete();
        cursor.continue();
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Nuke every persisted provider across every vault. Panic-button. */
export async function clearAllProviderConfigs(): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_PROVIDER_CONFIGS, 'readwrite');
    tx.objectStore(STORE_PROVIDER_CONFIGS).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Rename a vault locally — touches every row sharing its vault_id. */
export async function renameVaultLabel(vault_id: string, new_label: string): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_PROVIDER_CONFIGS, 'readwrite');
    const store = tx.objectStore(STORE_PROVIDER_CONFIGS);
    const idx = store.index('by_vault_id');
    const req = idx.openCursor(IDBKeyRange.only(vault_id));
    req.onsuccess = () => {
      const cursor = req.result;
      if (cursor) {
        const row = cursor.value as StoredProviderConfig;
        row.vault_label = new_label;
        cursor.update(row);
        cursor.continue();
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── Helpers ────────────────────────────────────────────────────────────────

function stripWrapped(row: StoredProviderConfig): ProviderConfigMeta {
  const { iv: _iv, wrapped_config: _wc, ...meta } = row;
  return meta;
}
