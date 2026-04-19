<script lang="ts">
  /**
   * ByoRecovery — Recovery key entry + full vault re-keying wizard.
   *
   * Steps: Recovery Key → New Passphrase → Re-keying → New Recovery Key
   *
   * Security invariants:
   * - Recovery key bytes are zeroized in onDestroy
   * - New passphrase cleared from component state immediately after worker call
   * - All slots (device + old passphrase) cleared before new keys are written
   */
  import { createEventDispatcher, onDestroy } from 'svelte';
  import type { StorageProvider } from '@secure-cloud/byo';
  import * as byoWorker from '@secure-cloud/byo';
  import { bytesToBase64, base64ToBytes } from '../../byo/VaultLifecycle';
  // recoverySessionId is stored between the verify and rekey steps
  let recoverySessionId: number | null = null;
  import { generateDeviceCryptoKey, setDeviceRecord } from '../../byo/DeviceKeyStore';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import StepIndicator from '../StepIndicator.svelte';
  import RecoveryKeyDisplay from '../RecoveryKeyDisplay.svelte';
  import ByoPassphraseInput from './ByoPassphraseInput.svelte';
  import Argon2Progress from './Argon2Progress.svelte';

  export let provider: StorageProvider;

  const dispatch = createEventDispatcher<{
    complete: void;
    cancel: void;
  }>();

  const STEPS = ['Recovery Key', 'New Passphrase', 'Re-keying', 'New Recovery Key'];
  type RecoveryStep = 'enter-key' | 'verifying' | 'new-passphrase' | 'rekeying' | 'new-recovery-key' | 'error';

  let step: RecoveryStep = 'enter-key';
  let recoveryInput = '';
  let error = '';
  let argon2Done = false;
  let newRecoveryKeyB64 = '';
  let vaultIdB64 = '';

  $: stepIndex = {
    'enter-key': 0,
    'verifying': 0,
    'new-passphrase': 1,
    'rekeying': 2,
    'new-recovery-key': 3,
    'error': 0,
  }[step] ?? 0;

  $: completedSteps = Array.from({ length: stepIndex }, (_, i) => i);

  async function verifyRecoveryKey() {
    const trimmed = recoveryInput.trim();
    if (!trimmed) { error = 'Please enter your recovery key'; return; }

    step = 'verifying';
    error = '';

    try {
      // C3: the generated recovery key is a 37-byte buffer rendered as base64
      // (see newRecoveryKeyB64 below); the display splits it into 8-char
      // groups joined by spaces. Strip the cosmetic whitespace/dashes to get
      // the original base64 string — do NOT re-encode via btoa, which was
      // double-base64-encoding the input and breaking every recovery attempt.
      const recoveryKeyB64 = trimmed.replace(/[\s-]/g, '');

      // Validate the base64 decodes to exactly 37 bytes so users get a clear
      // "invalid recovery key" error instead of a confusing AES-GCM failure.
      let decodedLen = 0;
      try {
        decodedLen = base64ToBytes(recoveryKeyB64).length;
      } catch {
        throw new Error('Invalid recovery key. Please check and try again.');
      }
      if (decodedLen !== 37 && decodedLen !== 32) {
        throw new Error('Invalid recovery key. Please check and try again.');
      }

      // Download manifest and parse header to get the recovery slot
      const { data: vaultBytes } = await provider.download('SecureCloud/vault_manifest.sc');
      const header = await byoWorker.Worker.byoParseVaultHeader(new Uint8Array(vaultBytes));

      // Open a session using the recovery slot — vault_key and recovery_vault_kek stay in WASM
      if (recoverySessionId !== null) {
        byoWorker.Worker.byoVaultClose(recoverySessionId);
        recoverySessionId = null;
      }
      recoverySessionId = await byoWorker.Worker.byoVaultOpenRecovery(
        recoveryKeyB64,
        header.rec_wrap_iv,
        header.rec_wrapped_vault_key,
      );
      vaultIdB64 = header.vault_id;

      // Recovery key is valid — proceed to new passphrase
      step = 'new-passphrase';
    } catch (e: any) {
      error = e.message?.includes('AES-GCM') || e.message?.includes('tag')
        ? 'Invalid recovery key. Please check and try again.'
        : e.message || 'Recovery verification failed';
      step = 'enter-key';
    }
  }

  async function handleNewPassphrase(event: CustomEvent<string>) {
    const newPassphrase = event.detail;
    step = 'rekeying';
    argon2Done = false;
    error = '';

    // vault_manifest.sc header byte offsets (vault_format.rs)
    const HEADER_SIZE = 1227;
    const MASTER_SALT_OFFSET = 22;
    const PASS_WRAP_IV_OFFSET = 70;
    const PASS_WRAPPED_KEY_OFFSET = 82;
    const REC_WRAP_IV_OFFSET = 130;
    const REC_WRAPPED_KEY_OFFSET = 142;
    const NUM_SLOTS_OFFSET = 190;
    const DEVICE_SLOTS_OFFSET = 191;
    const HMAC_OFFSET = 1195;
    const REVOCATION_EPOCH_OFFSET = 1191;
    const SLOT_SIZE = 125;
    const SLOT_STATUS_ACTIVE = 0x01;

    try {
      if (recoverySessionId === null) throw new Error('No recovery session — please re-enter your recovery key');

      // 1. Download vault_manifest.sc + split header from encrypted manifest blob
      //    vault_key does NOT change during recovery — only its wrapping changes.
      //    The manifest body remains valid under the same vault_key-derived subkeys.
      const { data: vaultBytes } = await provider.download('SecureCloud/vault_manifest.sc');
      const headerArr = new Uint8Array(vaultBytes.slice(0, HEADER_SIZE));
      const manifestBlob = new Uint8Array(vaultBytes.slice(HEADER_SIZE));

      // 3. Re-wrap vault_key with new passphrase — Argon2id + KEK derivation inside WASM
      //    new master_salt is generated inside byo_vault_rewrap_with_passphrase
      const passSlot = await byoWorker.Worker.byoVaultRewrapWithPassphrase(
        recoverySessionId,
        newPassphrase,
        131072, 3, 4,
      );
      argon2Done = true;

      // 4. Generate new recovery key + wrap vault_key under it — KEK inside WASM
      const newRecoveryKeyBytes = crypto.getRandomValues(new Uint8Array(37));
      newRecoveryKeyB64 = bytesToBase64(newRecoveryKeyBytes);
      const recSlot = await byoWorker.Worker.byoVaultWrapRecovery(recoverySessionId, newRecoveryKeyB64);

      // 5. Enroll this device — new device_id + new shard + device CryptoKey (non-extractable)
      const newDeviceIdBytes = crypto.getRandomValues(new Uint8Array(16));
      const newDeviceIdHex = Array.from(newDeviceIdBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const newShardBytes = crypto.getRandomValues(new Uint8Array(32));
      const deviceCryptoKey = await generateDeviceCryptoKey(vaultIdB64);
      const encIv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedShardBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: encIv },
        deviceCryptoKey,
        newShardBytes,
      );
      const encryptedShardBytes = new Uint8Array(encryptedShardBuf);
      newShardBytes.fill(0); // zeroize shard after encryption

      // 6. Patch header in-place — rewrap slots, bump revocation epoch, recompute HMAC
      //   a. New master_salt (generated inside byo_vault_rewrap_with_passphrase)
      headerArr.set(base64ToBytes(passSlot.masterSaltB64), MASTER_SALT_OFFSET);
      //   b. New passphrase slot
      headerArr.set(base64ToBytes(passSlot.wrapIvB64), PASS_WRAP_IV_OFFSET);
      headerArr.set(base64ToBytes(passSlot.wrappedKeyB64), PASS_WRAPPED_KEY_OFFSET);
      //   c. New recovery slot
      headerArr.set(base64ToBytes(recSlot.recWrapIvB64), REC_WRAP_IV_OFFSET);
      headerArr.set(base64ToBytes(recSlot.recWrappedKeyB64), REC_WRAPPED_KEY_OFFSET);
      //   d. Clear all device slots, write new slot 0
      headerArr.fill(0, DEVICE_SLOTS_OFFSET, DEVICE_SLOTS_OFFSET + SLOT_SIZE * 8);
      headerArr[DEVICE_SLOTS_OFFSET] = SLOT_STATUS_ACTIVE;
      headerArr.set(newDeviceIdBytes, DEVICE_SLOTS_OFFSET + 1);
      headerArr.set(encIv, DEVICE_SLOTS_OFFSET + 17);
      headerArr.set(encryptedShardBytes, DEVICE_SLOTS_OFFSET + 29);
      headerArr[NUM_SLOTS_OFFSET] = 1;
      //   e. Bump revocation_epoch
      const prevEpoch = new DataView(headerArr.buffer).getUint32(REVOCATION_EPOCH_OFFSET, true);
      new DataView(headerArr.buffer).setUint32(REVOCATION_EPOCH_OFFSET, prevEpoch + 1, true);
      //   f. Re-compute header HMAC using recovery session
      const { hmac } = await byoWorker.Worker.byoVaultComputeHeaderHmac(
        recoverySessionId,
        bytesToBase64(headerArr.slice(0, HMAC_OFFSET)),
      );
      headerArr.set(base64ToBytes(hmac), HMAC_OFFSET);

      // 7. Assemble patched header + preserved manifest blob and upload
      //    vault_key is unchanged → manifest body remains valid, no re-encryption needed
      const assembled = new Uint8Array(HEADER_SIZE + manifestBlob.length);
      assembled.set(headerArr, 0);
      assembled.set(manifestBlob, HEADER_SIZE);
      await provider.upload('SecureCloud/vault_manifest.sc', 'vault_manifest.sc', assembled);

      // 8. Store updated device record
      await setDeviceRecord({
        vault_id: vaultIdB64,
        device_id: newDeviceIdHex,
        device_name: navigator.userAgent.slice(0, 64),
        last_seen_vault_version: 1,
        last_seen_manifest_version: 0,
        last_backup_prompt_at: null,
      });

      recoveryInput = '';
      step = 'new-recovery-key';
    } catch (e: any) {
      error = e.message || 'Re-keying failed';
      step = 'error';
    } finally {
      // Close recovery session — only used for this re-key operation
      if (recoverySessionId !== null) {
        byoWorker.Worker.byoVaultClose(recoverySessionId);
        recoverySessionId = null;
      }
    }
  }

  onDestroy(() => {
    recoveryInput = '';
    newRecoveryKeyB64 = '';
    if (recoverySessionId !== null) {
      byoWorker.Worker.byoVaultClose(recoverySessionId);
      recoverySessionId = null;
    }
  });
</script>

<div class="byo-recovery">
  <StepIndicator steps={STEPS} currentStep={stepIndex} {completedSteps} />

  {#if step === 'enter-key' || step === 'verifying'}
    <div class="step-content">
      <h2 class="step-title">Enter your recovery key</h2>
      <p class="step-sub">
        Enter the recovery key you saved when you created your vault.
        Using your recovery key will sign out every other device — you'll set a new passphrase next.
      </p>
      {#if error}
        <p class="error-msg" role="alert">{error}</p>
      {/if}
      <div class="field">
        <label for="recovery-key-input">Recovery key</label>
        <input
          id="recovery-key-input"
          type="password"
          bind:value={recoveryInput}
          placeholder="Your recovery key"
          class="input recovery-input"
          autocomplete="off"
          disabled={step === 'verifying'}
          on:keydown={(e) => e.key === 'Enter' && verifyRecoveryKey()}
        />
      </div>
      <button
        class="btn btn-primary"
        on:click={verifyRecoveryKey}
        disabled={step === 'verifying' || !recoveryInput.trim()}
      >
        {step === 'verifying' ? 'Verifying…' : 'Continue'}
      </button>
      <button class="btn btn-secondary" on:click={() => dispatch('cancel')}>Cancel</button>
    </div>

  {:else if step === 'new-passphrase'}
    <div class="step-content">
      <h2 class="step-title">Set a new passphrase</h2>
      <p class="step-sub">
        Choose a strong new passphrase. Your old passphrase will no longer work.
      </p>
      <ByoPassphraseInput mode="create" submitLabel="Re-key Vault" on:submit={handleNewPassphrase} />
    </div>

  {:else if step === 'rekeying'}
    <div class="step-content">
      <h2 class="step-title">Re-keying vault…</h2>
      <p class="step-sub">Revoking old access and generating new keys. Please wait.</p>
      <Argon2Progress done={argon2Done} />
      {#if argon2Done}
        <p class="status-line">Updating vault header and saving…</p>
      {/if}
    </div>

  {:else if step === 'new-recovery-key'}
    <div class="step-content">
      <h2 class="step-title">Save your new recovery key</h2>
      <p class="step-sub">Your old recovery key is now invalid. Save this new one securely.</p>
      <RecoveryKeyDisplay
        recoveryKey={newRecoveryKeyB64}
        embedded
        onConfirmed={() => dispatch('complete')}
      />
    </div>

  {:else if step === 'error'}
    <div class="step-content">
      <p class="error-msg" role="alert">{error}</p>
      <button class="btn btn-secondary" on:click={() => { error = ''; step = 'enter-key'; }}>
        Try again
      </button>
      <button class="btn btn-ghost" on:click={() => dispatch('cancel')}>Cancel</button>
    </div>
  {/if}
</div>

<style>
  .byo-recovery {
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

  label {
    /* §13.1: field labels are --t-body-sm weight 500, not uppercase. */
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 500;
    color: var(--text-secondary, #999999);
  }

  .recovery-input {
    font-family: var(--font-mono, ui-monospace, 'SF Mono', 'JetBrains Mono', Consolas, monospace);
    letter-spacing: 0.05em;
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
</style>
