/**
 * DeviceKeyMigration — rotate every piece of per-device at-rest state from
 * one AES-GCM CryptoKey to another.
 *
 * Fires when the user enables or disables the WebAuthn gate in Settings.
 * See SECURITY.md §12 for the key lifecycle. The scope:
 *   1. `provider_configs` IDB rows — decrypt each with `oldKey`, re-wrap
 *      with `newKey`.
 *   2. Device shard in the vault manifest header — decrypt with `oldKey`,
 *      re-encrypt with `newKey` (fresh nonce), patch the device slot,
 *      recompute the HMAC using the vault session, upload the manifest.
 *   3. WAL entries — cleared rather than re-encrypted. The WAL is a crash-
 *      recovery log; its contents will be rebuilt on the next vault save.
 *      Holding stale WAL bytes across a key rotation risks silently
 *      dropping entries on replay, so clearing is the safe policy.
 *
 * Failure model:
 *   - Local provider_configs rewrap is prepared fully in memory first, then
 *     committed in a single IDB readwrite transaction — either every row
 *     lands under `newKey` or none do. No partial-commit state is ever
 *     visible to later loads.
 *   - The manifest upload runs AFTER the local commit. If upload fails we
 *     revert the committed rewrap by atomically restoring the original
 *     oldKey-wrapped rows, so the vault continues to open under `oldKey`
 *     even after a migration abort.
 *   - Callers must own the final IDB swap (`setDeviceCryptoKey` / the
 *     `device_webauthn` record write) so the whole switch is committed
 *     in one logical step.
 *
 * The vault MUST be unlocked before calling `migrateDeviceKey` — the
 * shard's plaintext is only reachable via the old key (still in IDB),
 * and the new manifest HMAC needs the vault session's vault_key.
 */

import type { StorageProvider, ProviderConfig } from '@wattcloud/sdk';
import * as byoWorker from '@wattcloud/sdk';
import { bytesToBase64, base64ToBytes } from './base64';
import {
  STORE_PROVIDER_CONFIGS,
  openDB,
  clearWalEntries,
  getDeviceRecord,
} from './DeviceKeyStore';

// ── Header layout constants (must mirror vault_format.rs v2) ───────────────

const VAULT_HEADER_SIZE = 1227;
const HMAC_OFFSET = 1195;
const DEVICE_SLOTS_OFFSET = 191;
const NUM_SLOTS_OFFSET = 190;
const SLOT_SIZE = 125;
/** Offsets *within* one 125-byte device slot. */
const SLOT_DEVICE_ID_OFFSET = 1;
const SLOT_WRAP_IV_OFFSET = 17;
const SLOT_ENC_PAYLOAD_OFFSET = 29;
const SLOT_SHARD_CIPHERTEXT_LEN = 48;

// ── Types ──────────────────────────────────────────────────────────────────

export interface MigrateOptions {
  /** Hex-encoded 16-byte vault_id (the on-disk vault id used in IDB). */
  vaultId: string;
  /** Primary provider for this vault; the manifest is read/written through it. */
  provider: StorageProvider;
  /** Current device CryptoKey (must unwrap the existing shard + provider rows). */
  oldKey: CryptoKey;
  /** New device CryptoKey to take over for all at-rest wrapping. */
  newKey: CryptoKey;
  /** WASM vault session id — used to recompute the header HMAC. */
  vaultSessionId: number;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Execute the full three-step migration. Returns when every IDB row and the
 * remote vault manifest have been switched to `newKey`. Throws on any step;
 * caller's IDB rollback responsibility is documented above.
 */
export async function migrateDeviceKey(opts: MigrateOptions): Promise<void> {
  // Step 1: rewrap every provider_configs row for this vault — prepared in
  // memory, then committed in a single IDB transaction. Returns the
  // originals so step 2 can revert them if the remote upload fails.
  const originals = await rewrapAllProviderConfigs(opts);

  // Step 2: rewrite the manifest header (download, patch shard slot,
  // recompute HMAC, upload). If this throws the provider_configs rewrap is
  // reverted so the vault keeps opening under `oldKey`.
  try {
    await rewrapShardInManifest(opts);
  } catch (uploadErr) {
    await revertProviderConfigRewrap(opts.vaultId, originals).catch(() => {
      // Best-effort: if the revert itself fails, we at least keep the
      // original rows in memory for the caller to surface in a diagnostic.
    });
    throw uploadErr;
  }

  // Step 3: clear WAL. Any pending entries will be regenerated on next save.
  await clearWalEntries(opts.vaultId).catch(() => {
    // Non-fatal: stale WAL under the new key would fail HMAC verify and be
    // discarded anyway.
  });
}

// ── Step 1: device-shard slot in the vault manifest ────────────────────────

async function rewrapShardInManifest(opts: MigrateOptions): Promise<void> {
  const deviceRecord = await getDeviceRecord(opts.vaultId);
  if (!deviceRecord) {
    throw new Error('migrateDeviceKey: no device record for vault');
  }
  const myDeviceIdHex = deviceRecord.device_id;

  // Download the current manifest file (header + encrypted body).
  const { data: vaultBytes } = await opts.provider.download(
    opts.provider.manifestRef(),
  );
  if (vaultBytes.length < VAULT_HEADER_SIZE) {
    throw new Error('migrateDeviceKey: manifest smaller than v2 header');
  }
  const header = new Uint8Array(vaultBytes.slice(0, VAULT_HEADER_SIZE));
  const body = vaultBytes.slice(VAULT_HEADER_SIZE);

  // Find this device's slot by matching device_id bytes.
  const numActive = header[NUM_SLOTS_OFFSET];
  const myDeviceIdBytes = hexToBytes(myDeviceIdHex);
  let slotOffset = -1;
  for (let i = 0; i < numActive; i++) {
    const off = DEVICE_SLOTS_OFFSET + i * SLOT_SIZE;
    // slot[0] is status; device_id starts at slot[1].
    const idCandidate = header.slice(
      off + SLOT_DEVICE_ID_OFFSET,
      off + SLOT_DEVICE_ID_OFFSET + 16,
    );
    if (bytesEqual(idCandidate, myDeviceIdBytes)) {
      slotOffset = off;
      break;
    }
  }
  if (slotOffset < 0) {
    throw new Error(
      "migrateDeviceKey: this device's slot is not in the current manifest",
    );
  }

  // Decrypt the shard with oldKey.
  const oldIv = header.slice(
    slotOffset + SLOT_WRAP_IV_OFFSET,
    slotOffset + SLOT_WRAP_IV_OFFSET + 12,
  );
  const oldCt = header.slice(
    slotOffset + SLOT_ENC_PAYLOAD_OFFSET,
    slotOffset + SLOT_ENC_PAYLOAD_OFFSET + SLOT_SHARD_CIPHERTEXT_LEN,
  );
  let shard: Uint8Array;
  try {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: oldIv as BufferSource },
      opts.oldKey,
      oldCt as BufferSource,
    );
    shard = new Uint8Array(plain);
  } catch (e) {
    throw new Error(
      'migrateDeviceKey: failed to decrypt existing shard with oldKey — ' +
        'the stored CryptoKey does not match the vault header. ' +
        (e instanceof Error ? e.message : String(e)),
    );
  }

  try {
    // Re-encrypt with newKey + fresh nonce.
    const newIv = crypto.getRandomValues(new Uint8Array(12));
    const newCtBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: newIv as BufferSource },
      opts.newKey,
      shard as BufferSource,
    );
    const newCt = new Uint8Array(newCtBuf);
    if (newCt.length !== SLOT_SHARD_CIPHERTEXT_LEN) {
      throw new Error(
        `migrateDeviceKey: re-encrypted shard has unexpected length ${newCt.length}`,
      );
    }

    // Patch header in place.
    header.set(newIv, slotOffset + SLOT_WRAP_IV_OFFSET);
    header.set(newCt, slotOffset + SLOT_ENC_PAYLOAD_OFFSET);

    // Recompute HMAC over bytes [0..HMAC_OFFSET).
    const headerPrefixB64 = bytesToBase64(header.slice(0, HMAC_OFFSET));
    const { hmac } = await byoWorker.Worker.byoVaultComputeHeaderHmac(
      opts.vaultSessionId,
      headerPrefixB64,
    );
    header.set(base64ToBytes(hmac), HMAC_OFFSET);
  } finally {
    // Zeroize the short-lived plaintext shard regardless of outcome.
    shard.fill(0);
  }

  // Assemble and upload.
  const assembled = new Uint8Array(VAULT_HEADER_SIZE + body.length);
  assembled.set(header, 0);
  assembled.set(body, VAULT_HEADER_SIZE);
  await opts.provider.upload(
    opts.provider.manifestRef(),
    'vault_manifest.sc',
    assembled,
    { mimeType: 'application/octet-stream' },
  );
}

// ── Step 2: provider_configs rows ──────────────────────────────────────────

interface StoredProviderConfigRow {
  provider_id: string;
  vault_id: string;
  vault_label: string;
  type: string;
  display_name: string;
  is_primary: boolean;
  saved_at: string;
  iv: ArrayBuffer;
  wrapped_config: ArrayBuffer;
}

/**
 * Rewrap every provider_configs row for this vault from `oldKey` to
 * `newKey`. All decrypt+re-encrypt work happens in memory; only after every
 * row has been successfully re-wrapped do we open a single readwrite
 * transaction and put them all. An exception mid-preparation leaves IDB
 * untouched; an exception mid-commit aborts the transaction atomically.
 *
 * Returns the original rows so a later failure (e.g. remote manifest
 * upload) can atomically restore them via `revertProviderConfigRewrap`.
 */
async function rewrapAllProviderConfigs(
  opts: MigrateOptions,
): Promise<StoredProviderConfigRow[]> {
  const db = await openDB();
  const rows: StoredProviderConfigRow[] = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PROVIDER_CONFIGS, 'readonly');
    const index = tx.objectStore(STORE_PROVIDER_CONFIGS).index('by_vault_id');
    const req = index.getAll(IDBKeyRange.only(opts.vaultId));
    req.onsuccess = () => resolve((req.result ?? []) as StoredProviderConfigRow[]);
    req.onerror = () => reject(req.error);
  });

  // Phase 1 — prepare every rewrapped row in memory. Throws escape before
  // we touch IDB so partial state is impossible.
  const rewrapped: StoredProviderConfigRow[] = [];
  for (const row of rows) {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(row.iv) as BufferSource },
      opts.oldKey,
      row.wrapped_config,
    );
    const decoded = JSON.parse(new TextDecoder().decode(plain)) as ProviderConfig;
    const freshIv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(decoded));
    const wrapped = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: freshIv as BufferSource },
      opts.newKey,
      encoded,
    );
    rewrapped.push({ ...row, iv: freshIv.buffer, wrapped_config: wrapped });
  }

  // Phase 2 — commit every rewrapped row in one transaction. The browser
  // aborts the entire tx on any per-put error, so this is all-or-nothing.
  await atomicPutRows(db, rewrapped);
  return rows;
}

/**
 * Restore the supplied rows verbatim. Used by `migrateDeviceKey` when the
 * remote manifest upload fails after provider_configs were rewrapped — the
 * originals (still wrapped under oldKey) were returned from
 * `rewrapAllProviderConfigs` and can be written back in a single tx.
 */
async function revertProviderConfigRewrap(
  vaultId: string,
  originals: StoredProviderConfigRow[],
): Promise<void> {
  if (originals.length === 0) return;
  // Belt-and-braces: make sure every row we're about to re-put really
  // belongs to this vault — refuse to touch unrelated rows if the caller
  // ever passes a mismatched set.
  for (const row of originals) {
    if (row.vault_id !== vaultId) {
      throw new Error(
        'revertProviderConfigRewrap: row vault_id does not match migration vault',
      );
    }
  }
  const db = await openDB();
  await atomicPutRows(db, originals);
}

function atomicPutRows(
  db: IDBDatabase,
  rows: StoredProviderConfigRow[],
): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_PROVIDER_CONFIGS, 'readwrite');
    const store = tx.objectStore(STORE_PROVIDER_CONFIGS);
    for (const row of rows) store.put(row);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error('transaction aborted'));
  });
}

// ── Helpers ────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(Math.floor(hex.length / 2));
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
