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
  import { createEventDispatcher } from 'svelte';
  import type { StorageProvider } from '@secure-cloud/byo';
  import * as byoWorker from '@secure-cloud/byo';
  import { bytesToBase64, base64ToBytes, MANIFEST_FILE, VAULT_BODY_PATH_PREFIX } from '../../byo/VaultLifecycle';
  import { generateDeviceCryptoKey, setDeviceRecord } from '../../byo/DeviceKeyStore';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import StepIndicator from '../StepIndicator.svelte';
  import RecoveryKeyDisplay from '../RecoveryKeyDisplay.svelte';
  import HexShield from '../HexShield.svelte';
  import ByoPassphraseInput from './ByoPassphraseInput.svelte';
  import Argon2Progress from './Argon2Progress.svelte';
  import BrowserSyncWarning from './BrowserSyncWarning.svelte';
  import MemoryFailurePrompt from './MemoryFailurePrompt.svelte';

  export let provider: StorageProvider;
  /** JSON-serialized ProviderConfig for this provider — stored in the manifest. */
  export let configJson: string = '{}';

  const dispatch = createEventDispatcher<{ complete: void; cancel: void }>();

  // sync-warning-pre: show browser-tab warning before creating the vault
  type Step = 'passphrase' | 'sync-warning-pre' | 'creating' | 'recovery-key' | 'complete';

  const STEPS = ['Passphrase', 'Creating Vault', 'Recovery Key', 'Complete'];

  const SYNC_WARNING_ACK_KEY = 'sc-byo-sync-warning-ack';

  let step: Step = 'passphrase';
  let argon2Done = false;
  let memoryError = false;
  let recoveryKeyB64 = '';
  let error = '';
  // Passphrase is held briefly between sync-warning-pre and creating; cleared after doCreate.
  let _pendingPassphrase = '';

  $: stepIndex = {
    passphrase: 0,
    'sync-warning-pre': 0,
    creating: 1,
    'recovery-key': 2,
    complete: 3,
  }[step] ?? 0;

  $: completedSteps = Array.from({ length: stepIndex }, (_, i) => i);

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
      file_id INTEGER NOT NULL,
      provider_id TEXT NOT NULL,
      provider_ref TEXT NOT NULL,
      variant TEXT NOT NULL CHECK (variant IN ('A','A+','B1','B2')),
      public_link TEXT,
      presigned_expires_at INTEGER,
      owner_token TEXT,
      created_at INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0
    );
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

  async function handlePassphrase(event: CustomEvent<string>) {
    const passphrase = event.detail;
    error = '';
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

      // 7. Create per-provider SQLite + populate vault_meta
      const sql = await import('sql.js');
      const SQL = await sql.default({ locateFile: (f: string) => `/sql.js/${f}` });
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
      await provider.upload(MANIFEST_FILE, 'vault_manifest.sc', manifestFile, { mimeType: 'application/octet-stream' });

      // 11. Upload vault_<provider_id>.sc = encrypted per-vault body (body-only, no header)
      //     If this fails we delete the manifest to avoid a half-initialized state.
      try {
        await provider.upload(`${VAULT_BODY_PATH_PREFIX}vault_${providerId}.sc`, `vault_${providerId}.sc`, vaultBodyBlob, { mimeType: 'application/octet-stream' });
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

      vaultStore.setVaultId(vaultIdB64);
      step = 'recovery-key';
    } catch (e: any) {
      if (e.name === 'RangeError' || (e.message && e.message.includes('memory'))) {
        memoryError = true;
        step = 'passphrase';
      } else {
        error = e.message || 'Vault creation failed';
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
      onBack={() => dispatch('cancel')}
    />
  {:else if step === 'passphrase'}
    <div class="step-content">
      <h2 class="step-title">Create your vault passphrase</h2>
      <p class="step-sub">
        This passphrase protects your vault. Choose something long and memorable —
        you'll need it every time you open SecureCloud on this device.
      </p>
      <p class="zk-disclaimer">
        Your passphrase never leaves this device. Forgetting it and losing your recovery key means permanent data loss — we cannot reset this.
      </p>
      {#if error}
        <p class="error-msg" role="alert">{error}</p>
      {/if}
      <ByoPassphraseInput mode="create" submitLabel="Create Vault" on:submit={handlePassphrase} />
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
      <p class="step-sub">
        If you lose all enrolled devices, this key is the only way to recover your vault.
        Store it somewhere safe — offline, not in the cloud.
      </p>
      <RecoveryKeyDisplay
        recoveryKey={recoveryKeyB64}
        embedded
        onConfirmed={() => { step = 'complete'; }}
      />
    </div>

  {:else if step === 'complete'}
    <div class="step-content complete">
      <div class="success-icon" aria-hidden="true">
        <HexShield
          size={72}
          variant="check"
          color="var(--accent, #2EB860)"
          fillColor="var(--accent-muted, #1B3627)"
        />
      </div>
      <h2 class="step-title">Vault created!</h2>
      <p class="step-sub">Your encrypted vault is ready. Files you add will be stored in {provider.displayName}.</p>
      <button class="btn btn-primary" on:click={() => dispatch('complete')}>
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

  .zk-disclaimer {
    margin: 0;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 12px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
    line-height: 1.5;
  }

  .error-msg {
    margin: 0;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 12px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
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
</style>
