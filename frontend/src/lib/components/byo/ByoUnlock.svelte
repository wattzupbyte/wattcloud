<script lang="ts">
  /**
   * ByoUnlock — Passphrase entry + vault unlock.
   *
   * Calls VaultLifecycle.unlockVault() which handles the full Argon2id +
   * SQLite decrypt pipeline in the BYO worker. Shows progress via Argon2Progress.
   * Handles rollback warnings and backup prompts from vaultStore.
   */
  import { onMount } from 'svelte';
  import type { StorageProvider } from '@wattcloud/sdk';
  import { unlockVault } from '../../byo/VaultLifecycle';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import { getWebAuthnRecord } from '../../byo/DeviceKeyStore';
  import {
    isWebAuthnAvailable,
    unlockVaultKeyViaPasskey,
  } from '../../byo/WebAuthnGate';
  import ByoPassphraseInput from './ByoPassphraseInput.svelte';
  import Argon2Progress from './Argon2Progress.svelte';
  import MemoryFailurePrompt from './MemoryFailurePrompt.svelte';
  import VaultLockAnimation from './VaultLockAnimation.svelte';
  import Lock from 'phosphor-svelte/lib/Lock';
  import Key from 'phosphor-svelte/lib/Key';
  import DeviceMobile from 'phosphor-svelte/lib/DeviceMobile';
  import Fingerprint from 'phosphor-svelte/lib/Fingerprint';
  import ArrowLeft from 'phosphor-svelte/lib/ArrowLeft';
  import BottomSheet from '../BottomSheet.svelte';

  
  interface Props {
    provider: StorageProvider;
    /**
   * Hex vault_id known from a prior unlock on this device, passed by
   * ByoApp when the user opens a vault from the persisted list. Threaded
   * into `unlockVault` so the IDB cache fallback engages if the provider
   * is unreachable at unlock time (H2).
   */
    vaultIdHint?: string | null;
  onUnlocked?: (...args: any[]) => void;
  onCancel?: (...args: any[]) => void;
  onLinkDevice?: (...args: any[]) => void;
  onUseRecovery?: (...args: any[]) => void;
  }

  let { provider, vaultIdHint = null,
  onUnlocked,
  onCancel,
  onLinkDevice,
  onUseRecovery }: Props = $props();
type UnlockStep = 'passphrase' | 'unlocking';

  let step: UnlockStep = $state('passphrase');
  let argon2Done = $state(false);
  let memoryError = $state(false);
  let showRollback = $state(false);
  let error = $state('');
  let db: import('sql.js').Database | null = null;
  // §29.3.1 vault lock animation plays on cold unlock, then the passphrase
  // form fades in beneath. VaultLockAnimation self-skips within a 5-minute
  // session via sessionStorage, so re-renders on the same tab stay snappy.
  let vaultLockDone = $state(false);

  // Stable session ID for the BYO worker key storage
  const sessionId = crypto.randomUUID();

  // Opt-in passkey-unlock (SECURITY.md §12 "Passkey replaces passphrase").
  // Resolved once on mount from the `device_webauthn` IDB row for the
  // hinted vault. When true, a prominent "Unlock with passkey" button is
  // rendered above the passphrase field; the passphrase stays available
  // as a fallback (lost passkey, new device, etc.).
  let passkeyUnlockAvailable = $state(false);
  let passkeyBusy = $state(false);

  onMount(async () => {
    if (!vaultIdHint || !isWebAuthnAvailable()) return;
    try {
      const record = await getWebAuthnRecord(vaultIdHint);
      if (!record) return;
      if (record.mode !== 'prf' || !record.passkey_unlocks_vault) return;
      passkeyUnlockAvailable = record.credentials.some((c) => !!c.wrapped_vault_key);
    } catch {
      passkeyUnlockAvailable = false;
    }
  });

  async function handlePasskeyUnlock() {
    if (!vaultIdHint || passkeyBusy) return;
    passkeyBusy = true;
    error = '';
    try {
      const preopenedSessionId = await unlockVaultKeyViaPasskey(vaultIdHint);
      step = 'unlocking';
      argon2Done = true;
      db = await unlockVault(provider, {
        // passphrase is ignored when preopenedSessionId is set; passing an
        // empty string avoids Argon2id work on the fallback branch.
        passphrase: '',
        keySessionId: sessionId,
        vaultId: vaultIdHint,
        preopenedSessionId,
      });

      const state = $vaultStore;
      if (state.rollbackWarning) {
        showRollback = true;
        return;
      }

      onUnlocked?.({ db, sessionId });
    } catch (e: any) {
      argon2Done = false;
      step = 'passphrase';
      const msg: string = e?.message ?? String(e);
      // Silent cancel — user backed out of the passkey prompt; stay on the
      // passphrase screen without a scary red banner.
      if (!/cancel|NotAllowedError/i.test(msg)) {
        error = `Couldn't unlock with passkey: ${msg}`;
      }
    } finally {
      passkeyBusy = false;
    }
  }

  async function handlePassphrase(passphrase: string) {
    step = 'unlocking';
    argon2Done = false;
    error = '';
    memoryError = false;

    try {
      db = await unlockVault(provider, {
        passphrase,
        keySessionId: sessionId,
        vaultId: vaultIdHint ?? undefined,
      });
      argon2Done = true;

      // Check for rollback warning from vaultStore
      const state = $vaultStore;
      if (state.rollbackWarning) {
        showRollback = true;
        return;
      }

      // Check for backup prompt
      if (state.backupPromptDue) {
        // Show inline, then proceed
      }

      onUnlocked?.({ db, sessionId });
    } catch (e: any) {
      argon2Done = false;
      if (e.name === 'RangeError' || (e.message && e.message.includes('memory'))) {
        memoryError = true;
        step = 'passphrase';
      } else if (e.message?.includes('Wrong passphrase') || e.message?.includes('AES-GCM')) {
        error = 'Incorrect passphrase. Please try again.';
        step = 'passphrase';
      } else {
        error = e.message || 'Failed to unlock vault';
        step = 'passphrase';
      }
    }
  }


  function abortRollback() {
    showRollback = false;
    step = 'passphrase';
    db = null;
  }

  function confirmRollback() {
    showRollback = false;
    vaultStore.setRollbackWarning(false);
    if (db) onUnlocked?.({ db, sessionId });
  }
</script>

<VaultLockAnimation onDone={() => (vaultLockDone = true)} />

{#if vaultLockDone}
<div class="byo-unlock">
  {#if memoryError}
    <MemoryFailurePrompt
      onRetry={() => { memoryError = false; }}
      onBack={() => { memoryError = false; onCancel?.(); }}
    />

  {:else if step === 'passphrase'}
    <div class="header">
      <div class="hex" aria-hidden="true">
        <Lock size={56} weight="regular" color="var(--accent, #2EB860)" />
      </div>
      <h2 class="title">Unlock your vault</h2>
      <p class="subtitle">
        {#if passkeyUnlockAvailable}
          Tap your passkey, or enter your passphrase to unlock on this device.
        {:else}
          Enter your passphrase to decrypt the vault on this device.
        {/if}
      </p>
    </div>

    {#if error}
      <p class="error-msg" role="alert">{error}</p>
    {/if}

    {#if passkeyUnlockAvailable}
      <button
        class="passkey-primary"
        onclick={handlePasskeyUnlock}
        disabled={passkeyBusy}
        aria-busy={passkeyBusy}
      >
        <Fingerprint size={20} weight="bold" />
        <span>
          {#if passkeyBusy}Waiting for passkey…{:else}Unlock with passkey{/if}
        </span>
      </button>
      <div class="alt-divider" aria-hidden="true"><span>or enter passphrase</span></div>
    {/if}

    <ByoPassphraseInput mode="unlock" submitLabel="Unlock" onSubmit={handlePassphrase} />

    <div class="alt-divider" aria-hidden="true"><span>or</span></div>

    <div class="alt-actions">
      <button class="alt-row" onclick={() => onLinkDevice?.()}>
        <span class="alt-icon" aria-hidden="true"><DeviceMobile size={18} weight="bold" /></span>
        <span class="alt-text">
          <span class="alt-title">Link this device</span>
          <span class="alt-sub">Scan a code from a device that already has your vault</span>
        </span>
      </button>
      <button class="alt-row" onclick={() => onUseRecovery?.()}>
        <span class="alt-icon" aria-hidden="true"><Key size={18} weight="bold" /></span>
        <span class="alt-text">
          <span class="alt-title">Use recovery key</span>
          <span class="alt-sub">Enter the key you saved when you created the vault</span>
        </span>
      </button>
    </div>

    <button class="btn btn-ghost back-btn" onclick={() => onCancel?.()}>
      <ArrowLeft size={16} weight="bold" />
      <span>Back to providers</span>
    </button>

  {:else if step === 'unlocking'}
    <div class="header">
      <div class="hex" aria-hidden="true">
        <Lock size={56} weight="regular" color="var(--accent, #2EB860)" />
      </div>
      <h2 class="title">Unlocking vault…</h2>
    </div>
    <Argon2Progress done={argon2Done} />
  {/if}
</div>
{/if}

<!-- Rollback warning as BottomSheet (sits on top of passphrase/unlocking step) -->
<BottomSheet open={showRollback} title="Vault may have been rolled back" onClose={abortRollback}>
  <div class="rollback-body">
    <div class="warning-icon" aria-hidden="true">
      <svg width="28" height="28" viewBox="0 0 32 32" fill="none">
        <path d="M16 4L28 26H4L16 4Z" stroke="var(--danger,#D64545)" stroke-width="2" stroke-linejoin="round" fill="none"/>
        <line x1="16" y1="14" x2="16" y2="20" stroke="var(--danger,#D64545)" stroke-width="2" stroke-linecap="round"/>
        <circle cx="16" cy="23" r="1" fill="var(--danger,#D64545)"/>
      </svg>
    </div>
    <p class="rollback-text">
      The vault version on your provider is older than the last version this device saw.
      Another device may have reverted recent changes.
    </p>
    <p class="rollback-risk">Proceeding may overwrite newer changes on next save.</p>
    <div class="rollback-actions">
      <button class="btn btn-secondary" onclick={abortRollback}>Abort — go back</button>
      <button class="btn btn-danger proceed-btn" onclick={confirmRollback}>Proceed anyway</button>
    </div>
  </div>
</BottomSheet>

<style>
  .byo-unlock {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
    max-width: 420px;
    margin: 0 auto;
    padding: var(--sp-xl, 32px) var(--sp-md, 16px);
    animation: fadeIn 260ms ease-out;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .header {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-sm, 8px);
    text-align: center;
    margin-bottom: var(--sp-xs, 4px);
  }

  .hex {
    color: var(--accent, #2EB860);
    filter: drop-shadow(0 0 10px rgba(46, 184, 96, 0.3));
  }

  .title {
    margin: 0;
    font-size: var(--t-h2-size, 1.125rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
    letter-spacing: -0.01em;
  }

  .subtitle {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    max-width: 320px;
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

  .alt-divider {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    color: var(--text-disabled, #616161);
    font-size: var(--t-label-size, 0.75rem);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: var(--sp-sm, 8px);
  }
  .alt-divider::before,
  .alt-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border, #2E2E2E);
  }

  .alt-actions {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
  }

  .alt-row {
    display: flex;
    align-items: center;
    gap: var(--sp-md, 12px);
    width: 100%;
    padding: var(--sp-sm, 10px) var(--sp-md, 14px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    color: var(--text-primary, #EDEDED);
    text-align: left;
    cursor: pointer;
    transition: background 120ms ease, border-color 120ms ease;
  }
  .alt-row:hover {
    background: var(--bg-surface-hover, #2E2E2E);
    border-color: var(--accent, #2EB860);
  }

  .alt-icon {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--r-pill, 9999px);
    background: var(--accent-muted, #1B3627);
    color: var(--accent-text, #5FDB8A);
  }

  .alt-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .alt-title {
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 500;
  }
  .alt-sub {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.35;
  }

  .back-btn {
    align-self: center;
    margin-top: var(--sp-sm, 8px);
  }

  .passkey-primary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-sm, 8px);
    height: 48px;
    padding: 0 var(--sp-lg, 24px);
    background: var(--accent, #2EB860);
    color: var(--text-inverse, #121212);
    border: none;
    border-radius: var(--r-pill, 9999px);
    font-size: var(--t-button-size, 0.9375rem);
    font-weight: 600;
    cursor: pointer;
    transition: background 120ms ease, transform 80ms ease;
  }
  .passkey-primary:hover:not([disabled]) { background: var(--accent-hover, #40D474); }
  .passkey-primary:active:not([disabled]) { transform: scale(0.98); }
  .passkey-primary[disabled] { opacity: 0.7; cursor: not-allowed; }

  /* Rollback warning inside BottomSheet */
  .rollback-body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
    padding: 0 var(--sp-md, 16px) var(--sp-md, 16px);
  }

  .warning-icon { align-self: flex-start; }

  .rollback-text {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    line-height: 1.5;
  }

  .rollback-risk {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--danger, #D64545);
    font-weight: 600;
  }

  .rollback-actions {
    display: flex;
    gap: var(--sp-sm, 8px);
    flex-wrap: wrap;
  }

  .rollback-actions .btn { flex: 1; min-width: 120px; justify-content: center; }
</style>
