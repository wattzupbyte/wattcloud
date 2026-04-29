<script lang="ts">
  /**
   * ByoSetup — Vault creation wizard.
   *
   * Steps: Passphrase → Creating Vault → Recovery Key → Complete
   *
   * Security invariants:
   * - Passphrase is passed to worker and cleared from component state immediately
   * - vault_key / vault_kek never leave the worker after being used
   * - shard is encrypted with non-extractable CryptoKey before IndexedDB storage
   */
  import type { StorageProvider, ProviderConfig } from '@wattcloud/sdk';
  import * as byoWorker from '@wattcloud/sdk';
  import { bytesToBase64, base64ToBytes, MANIFEST_FILE } from '../../byo/VaultLifecycle';
  import { generateDeviceCryptoKey, setDeviceRecord } from '../../byo/DeviceKeyStore';
  import { saveProviderConfig } from '../../byo/ProviderConfigStore';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import StepIndicator from '../StepIndicator.svelte';
  import RecoveryKeyDisplay from '../RecoveryKeyDisplay.svelte';
  import CheckCircle from 'phosphor-svelte/lib/CheckCircle';
  import ByoPassphraseInput from './ByoPassphraseInput.svelte';
  import Argon2Progress from './Argon2Progress.svelte';
  import BrowserSyncWarning from './BrowserSyncWarning.svelte';
  import MemoryFailurePrompt from './MemoryFailurePrompt.svelte';
  import { loadSqlJs } from '../../byo/ConflictResolver';
  import { byoToast } from '../../byo/stores/byoToasts';

  
  
  interface Props {
    provider: StorageProvider;
    /** JSON-serialized ProviderConfig for this provider — stored in the manifest. */
    configJson?: string;
    /**
   * Parsed ProviderConfig — persisted on this device after successful vault
   * creation so subsequent reloads auto-hydrate the provider. If omitted, we
   * fall back to parsing `configJson`.
   */
    providerConfig?: import('@wattcloud/sdk').ProviderConfig | null;
  onCancel?: (...args: any[]) => void;
  onComplete?: (...args: any[]) => void;
  }

  let { provider, configJson = '{}', providerConfig = null,
  onCancel,
  onComplete }: Props = $props();
// sync-warning-pre: show browser-tab warning before creating the vault
  type Step = 'passphrase' | 'sync-warning-pre' | 'creating' | 'recovery-key' | 'complete';

  const STEPS = ['Passphrase', 'Creating Vault', 'Recovery Key', 'Complete'];

  const SYNC_WARNING_ACK_KEY = 'sc-byo-sync-warning-ack';

  let step: Step = $state('passphrase');
  let argon2Done = $state(false);
  let memoryError = $state(false);
  let recoveryKeyB64 = $state('');
  // Passphrase is held briefly between sync-warning-pre and creating; cleared after doCreate.
  let _pendingPassphrase = '';
  // User-set vault label, shown on the vault-list start screen. Defaults to
  // the provider's display name; user can override before pressing Create.
  // svelte-ignore state_referenced_locally
  let vaultLabel = $state(provider.displayName);

  let stepIndex = $derived({
    passphrase: 0,
    'sync-warning-pre': 0,
    creating: 1,
    'recovery-key': 2,
    complete: 3,
  }[step] ?? 0);

  let completedSteps = $derived(Array.from({ length: stepIndex }, (_, i) => i));

  // ── SQLite schema (R6 greenfield — no providers/provider_config; provider_id NOT NULL) ──

  const VAULT_SCHEMA = `
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
      revoked INTEGER NOT NULL DEFAULT 0
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

  // ── Setup flow ─────────────────────────────────────────────────────────────

  async function handlePassphrase(passphrase: string) {
    memoryError = false;

    if (!localStorage.getItem(SYNC_WARNING_ACK_KEY)) {
      _pendingPassphrase = passphrase;
      step = 'sync-warning-pre';
      return;
    }

    await doCreate(passphrase);
  }

  function handleSyncWarningAcknowledgedPre() {
    localStorage.setItem(SYNC_WARNING_ACK_KEY, '1');
    const passphrase = _pendingPassphrase;
    _pendingPassphrase = '';
    doCreate(passphrase);
  }

  async function doCreate(passphrase: string) {
    step = 'creating';
    argon2Done = false;

    let sessionId: number | null = null;
    try {
      // 1. Generate vault keys + run Argon2id — all inside WASM.
      //    vault_key and vault_kek never appear as JS variables.
      //    shard_b64 is returned so it can be encrypted with the non-extractable
      //    device CryptoKey (WebCrypto non-extractable keys cannot be used from WASM).
      const created = await byoWorker.Worker.byoVaultCreate(passphrase, 131072, 3, 4);
      sessionId = created.sessionId;
      argon2Done = true;

      // 2. Generate recovery key (browser entropy)
      const recoveryKeyBytes = crypto.getRandomValues(new Uint8Array(37));
      recoveryKeyB64 = btoa(String.fromCharCode(...recoveryKeyBytes));

      // 3. Wrap vault_key with recovery_vault_kek — inside WASM
      const { recWrapIvB64, recWrappedKeyB64 } =
        await byoWorker.Worker.byoVaultWrapRecovery(sessionId, recoveryKeyB64);

      // 4. Encrypt shard with non-extractable device CryptoKey
      const vaultIdB64 = created.vaultIdB64;
      const deviceCryptoKey = await generateDeviceCryptoKey(vaultIdB64);
      const shardBytes = Uint8Array.from(atob(created.shardB64), (c) => c.charCodeAt(0));
      const slotIv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedShardBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: slotIv },
        deviceCryptoKey,
        shardBytes,
      );
      shardBytes.fill(0); // zeroize shard after encryption
      const encryptedShardBytes = new Uint8Array(encryptedShardBuf);

      // 5. Generate device_id (stored in device record only after successful upload)
      const deviceIdBytes = crypto.getRandomValues(new Uint8Array(16));
      const deviceId = Array.from(deviceIdBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      // 6. Generate provider_id for this provider (canonical UUID for the vault manifest).
      const providerId = crypto.randomUUID();

      // 7. Create per-provider SQLite + populate vault_meta + seed key_versions.
      //    The hybrid ML-KEM + X25519 keypair is generated inside WASM; only
      //    public keys and vault-key-wrapped private keys cross the boundary.
      //    See SECURITY.md §BYO "key_versions wrap v1".
      const initialKeys =
        await byoWorker.Worker.byoVaultGenerateKeypairWrapped(sessionId);
      const SQL = await loadSqlJs();
      const db = new SQL.Database();
      db.run(VAULT_SCHEMA);
      db.run(
        `INSERT INTO vault_meta (key, value) VALUES
          ('vault_version', '1'),
          ('created_at', datetime('now')),
          ('last_modified', datetime('now')),
          ('provider_type', ?),
          ('enrolled_devices', ?)`,
        [
          provider.type,
          JSON.stringify([{
            device_id: deviceId,
            device_name: navigator.userAgent.slice(0, 64),
            enrolled_at: new Date().toISOString(),
          }]),
        ],
      );
      db.run(
        `INSERT INTO key_versions
           (version, mlkem_public_key, mlkem_private_key_encrypted,
            x25519_public_key, x25519_private_key_encrypted, status)
         VALUES (1, ?, ?, ?, ?, 'active')`,
        [
          base64ToBytes(initialKeys.mlkemPublicKeyB64),
          initialKeys.mlkemPrivateKeyEncrypted,
          base64ToBytes(initialKeys.x25519PublicKeyB64),
          initialKeys.x25519PrivateKeyEncrypted,
        ],
      );
      // Defensive: confirm the seed row landed. If this count is zero we
      // would otherwise ship an unopenable vault (unlock would throw
      // "No active key version found in vault").
      const kvStmt = db.prepare("SELECT COUNT(*) AS n FROM key_versions WHERE status = 'active'");
      kvStmt.step();
      const kvRow = kvStmt.getAsObject() as { n: number | bigint };
      kvStmt.free();
      if (Number(kvRow.n ?? 0) < 1) {
        throw new Error('key_versions seed failed: no active row after INSERT');
      }
      const sqliteBytes = db.export();
      db.close();

      // 7. Build vault header bytes (v2 format, 1227 bytes) and compute HMAC using session.
      //    Layout from vault_format.rs:
      //    [0..8]    magic "SCVAULT\x00"
      //    [8..10]   format_version u16 LE = 2
      //    [10..14]  argon2_memory_kb u32 LE
      //    [14..18]  argon2_iterations u32 LE
      //    [18..22]  argon2_parallelism u32 LE
      //    [22..54]  master_salt (32 bytes)
      //    [54..70]  vault_id (16 bytes)
      //    [70..82]  pass_wrap_iv (12 bytes)
      //    [82..130] pass_wrapped_vault_key (48 bytes)
      //    [130..142] rec_wrap_iv (12 bytes)
      //    [142..190] rec_wrapped_vault_key (48 bytes)
      //    [190]     num_active_slots (u8)
      //    [191..1191] device_slots (8 × 125 bytes)
      //      slot: [status(1)][device_id(16)][wrap_iv(12)][encrypted_payload(48)][signing_key_wrapped(48)]
      //    [1191..1195] revocation_epoch u32 LE = 0
      //    [1195..1227] header_hmac (32 bytes, covers bytes[0..1195])
      const HEADER_SIZE = 1227;
      const HMAC_OFFSET = 1195;
      const DEVICE_SLOTS_OFFSET = 191;
      const header = new Uint8Array(HEADER_SIZE);
      const dv = new DataView(header.buffer);
      header.set(new TextEncoder().encode('SCVAULT\x00'), 0);  // magic [0..8]
      dv.setUint16(8, 2, true);                                // format_version LE [8..10]
      dv.setUint32(10, 131072, true);  // argon2_memory_kb u32 LE [10..14]
      dv.setUint32(14, 3, true);       // argon2_iterations u32 LE [14..18]
      dv.setUint32(18, 4, true);       // argon2_parallelism u32 LE [18..22]
      header.set(base64ToBytes(created.masterSaltB64), 22);   // master_salt [22..54]
      header.set(base64ToBytes(vaultIdB64), 54);              // vault_id [54..70]
      header.set(base64ToBytes(created.passWrapIvB64), 70);   // pass_wrap_iv [70..82]
      header.set(base64ToBytes(created.passWrappedKeyB64), 82); // pass_wrapped_key [82..130]
      header.set(base64ToBytes(recWrapIvB64), 130);           // rec_wrap_iv [130..142]
      header.set(base64ToBytes(recWrappedKeyB64), 142);       // rec_wrapped_key [142..190]
      header[190] = 1;                                         // num_active_slots
      // Device slot 0: status=Active, device_id, wrap_iv, encrypted_shard, signing_key=zeros
      header[DEVICE_SLOTS_OFFSET] = 0x01;                     // status Active
      header.set(deviceIdBytes, DEVICE_SLOTS_OFFSET + 1);     // device_id [1..17]
      header.set(slotIv, DEVICE_SLOTS_OFFSET + 17);           // wrap_iv [17..29]
      header.set(encryptedShardBytes, DEVICE_SLOTS_OFFSET + 29); // encrypted_payload [29..77]
      // signing_key_wrapped [77..125] = zeros (not yet provisioned) — already zero from new Uint8Array
      // revocation_epoch [1191..1195] = 0 — already zero
      // Compute HMAC over bytes [0..1195) using session
      const headerPrefixB64 = bytesToBase64(header.slice(0, HMAC_OFFSET));
      const { hmac } = await byoWorker.Worker.byoVaultComputeHeaderHmac(sessionId, headerPrefixB64);
      header.set(base64ToBytes(hmac), HMAC_OFFSET);

      // 8. Encrypt per-vault SQLite using the per-provider AEAD subkey (R6).
      const sqliteB64 = bytesToBase64(sqliteBytes);
      const { data: vaultBodyBlobB64 } = await byoWorker.Worker.byoVaultBodyEncrypt(
        sessionId,
        providerId,
        sqliteB64,
      );
      const vaultBodyBlob = base64ToBytes(vaultBodyBlobB64);

      // 9. Create manifest JSON and encrypt it using the manifest AEAD key (R6).
      const nowSec = Math.floor(Date.now() / 1000);
      const manifestJson = JSON.stringify({
        manifest_version: 1,
        providers: [{
          provider_id: providerId,
          provider_type: provider.type,
          display_name: provider.displayName,
          config_json: configJson,
          is_primary: true,
          sftp_host_key_fingerprint: null,
          vault_version_hint: null,
          created_at: nowSec,
          updated_at: nowSec,
          tombstone: false,
        }],
      });
      const { data: manifestBlobB64 } = await byoWorker.Worker.byoManifestEncrypt(sessionId, manifestJson);
      const manifestBlob = base64ToBytes(manifestBlobB64);

      // 10. Upload vault_manifest.sc = header + encrypted manifest body
      const manifestFile = new Uint8Array(HEADER_SIZE + manifestBlob.length);
      manifestFile.set(header, 0);
      manifestFile.set(manifestBlob, HEADER_SIZE);
      await provider.upload(provider.manifestRef(), 'vault_manifest.sc', manifestFile, { mimeType: 'application/octet-stream' });

      // 11. Upload vault_<provider_id>.sc = encrypted per-vault body (body-only, no header)
      //     If this fails we delete the manifest to avoid a half-initialized state.
      try {
        await provider.upload(provider.bodyRef(providerId), `vault_${providerId}.sc`, vaultBodyBlob, { mimeType: 'application/octet-stream' });
      } catch (bodyErr) {
        provider.delete(MANIFEST_FILE).catch(() => {});
        throw bodyErr;
      }

      // 12. Only persist device record after both uploads succeed — prevents
      //     orphaned IDB state if the provider uploads fail and the user retries.
      await setDeviceRecord({
        vault_id: vaultIdB64,
        device_id: deviceId,
        device_name: navigator.userAgent.slice(0, 64),
        last_seen_vault_version: 1,
        last_seen_manifest_version: 0,
        last_backup_prompt_at: null,
      });

      // 13. Persist provider config on this device so the next reload can
      //     auto-hydrate without re-typing credentials / re-running OAuth.
      //     Wrapped with the deviceCryptoKey; see ProviderConfigStore for the
      //     threat model caveat (non-extractability only defends against
      //     filesystem exfil, not same-origin RCE).
      try {
        const configToPersist: ProviderConfig | null =
          providerConfig ?? (configJson ? (JSON.parse(configJson) as ProviderConfig) : null);
        if (configToPersist) {
          await saveProviderConfig(
            {
              provider_id: providerId,
              vault_id: vaultIdB64,
              vault_label: vaultLabel.trim() || provider.displayName,
              type: provider.type,
              display_name: provider.displayName,
              is_primary: true,
              saved_at: new Date().toISOString(),
            },
            configToPersist,
          );
        }
      } catch (persistErr) {
        // Non-fatal — vault still exists on the provider, just won't appear
        // in the vault-list on next reload until the user re-adds it.
        console.warn('[ByoSetup] saveProviderConfig failed', persistErr);
      }

      vaultStore.setVaultId(vaultIdB64);
      step = 'recovery-key';
    } catch (e: any) {
      if (e.name === 'RangeError' || (e.message && e.message.includes('memory'))) {
        memoryError = true;
        step = 'passphrase';
      } else {
        // Surface the raw error for diagnosis — the generic fallback was
        // hiding upload/worker/network failures the user couldn't act on.
        console.error('[ByoSetup] Vault creation failed', e);
        const detail = e?.message || e?.toString?.() || e?.name || 'Unknown error';
        // If the failure signature matches an existing-vault collision
        // (rename/exists/timeout on vault_manifest.sc), the probe missed an
        // existing vault at this destination — tell the user plainly so they
        // can go back and unlock instead of retrying setup.
        const msg = String(detail).toLowerCase();
        const looksLikeExistingVault =
          (msg.includes('rename') && (msg.includes('timeout') || msg.includes('exists') || msg.includes('failure'))) ||
          msg.includes('already exists') ||
          msg.includes('eexist') ||
          msg.includes('ssh_fx_file_already_exists');
        if (looksLikeExistingVault) {
          byoToast.show(
            'A vault already exists at this destination. Go back and choose "Unlock" instead of creating a new one.',
            { icon: 'danger' },
          );
        } else {
          byoToast.show(`Vault creation failed: ${detail}`, { icon: 'danger' });
        }
        step = 'passphrase';
      }
    } finally {
      // Close creation session — vault_key is only needed for the upload above
      if (sessionId !== null) byoWorker.Worker.byoVaultClose(sessionId);
    }
  }
</script>

<div class="byo-setup">
  <StepIndicator steps={STEPS} currentStep={stepIndex} {completedSteps} />

  {#if memoryError}
    <MemoryFailurePrompt
      onRetry={() => { memoryError = false; }}
      onBack={() => onCancel?.()}
    />
  {:else if step === 'passphrase'}
    <div class="step-content">
      <h2 class="step-title">Create your vault passphrase</h2>
      <p class="step-sub">
        This passphrase protects your vault. Choose something long and memorable —
        you'll need it every time you open Wattcloud on this device.
      </p>
      <div class="field">
        <label class="input-label" for="vault-label-input">Name this vault <span class="field-optional">(optional)</span></label>
        <input
          id="vault-label-input"
          class="input"
          type="text"
          bind:value={vaultLabel}
          placeholder="e.g. Personal, Work, Photos"
          autocomplete="off"
          maxlength="64"
        />
        <span class="field-hint">Shown on this device's start screen so you can tell vaults apart. Local-only — other devices keep their own label.</span>
      </div>
      <p class="zk-disclaimer">
        Your passphrase never leaves this device. Forgetting it and losing your recovery key means permanent data loss — this cannot be reset.
      </p>
      <ByoPassphraseInput mode="create" submitLabel="Create Vault" onSubmit={handlePassphrase} />
      <button type="button" class="btn btn-ghost back-link" onclick={() => onCancel?.()}>
        &larr; Back to providers
      </button>
    </div>

  {:else if step === 'sync-warning-pre'}
    <div class="step-content">
      <BrowserSyncWarning onAcknowledged={handleSyncWarningAcknowledgedPre} />
    </div>

  {:else if step === 'creating'}
    <div class="step-content">
      <h2 class="step-title">Creating your vault…</h2>
      <Argon2Progress done={argon2Done} />
      {#if argon2Done}
        <p class="status-line">Assembling vault file…</p>
      {/if}
    </div>

  {:else if step === 'recovery-key'}
    <div class="step-content">
      <h2 class="step-title">Save your recovery key</h2>
      <RecoveryKeyDisplay
        recoveryKey={recoveryKeyB64}
        embedded
        onConfirmed={() => { step = 'complete'; }}
      />
    </div>

  {:else if step === 'complete'}
    <div class="step-content complete">
      <div class="success-icon" aria-hidden="true">
        <CheckCircle size={72} weight="regular" color="var(--accent, #2EB860)" />
      </div>
      <h2 class="step-title">Vault created!</h2>
      <p class="step-sub">Your encrypted vault is ready. Files you add will be stored in {provider.displayName}.</p>
      <button class="btn btn-primary" onclick={() => onComplete?.()}>
        Open vault
      </button>
    </div>
  {/if}
</div>

<style>
  .byo-setup {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xl, 32px);
    max-width: 480px;
    margin: 0 auto;
    padding: var(--sp-lg, 24px) var(--sp-md, 16px);
  }

  .step-content {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
  }

  .step-title {
    margin: 0;
    font-size: var(--t-title-size, 1.25rem);
    font-weight: 700;
    color: var(--text-primary, #EDEDED);
  }

  .step-sub {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    line-height: 1.5;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .field-optional {
    color: var(--text-disabled, #616161);
    font-weight: 400;
  }

  .field-hint {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
    line-height: 1.4;
  }

  .zk-disclaimer {
    margin: 0;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--accent-warm-muted, #3D2E10);
    border: 1px solid var(--accent-warm, #E0A320);
    border-radius: var(--r-input, 12px);
    color: var(--accent-warm-text, #F0C04A);
    font-size: var(--t-body-sm-size, 0.8125rem);
    line-height: 1.5;
  }

  .status-line {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    text-align: center;
  }

  .complete {
    align-items: center;
    text-align: center;
    padding: var(--sp-2xl, 48px) 0;
  }

  .success-icon {
    margin-bottom: var(--sp-sm, 8px);
  }

  .back-link {
    align-self: center;
    margin-top: var(--sp-sm, 8px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
  }
</style>
