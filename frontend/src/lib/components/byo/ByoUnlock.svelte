<script lang="ts">
  /**
   * ByoUnlock — Passphrase entry + vault unlock.
   *
   * Calls VaultLifecycle.unlockVault() which handles the full Argon2id +
   * SQLite decrypt pipeline in the BYO worker. Shows progress via Argon2Progress.
   * Handles rollback warnings and backup prompts from vaultStore.
   */
  import { createEventDispatcher } from 'svelte';
  import type { StorageProvider } from '@secure-cloud/byo';
  import { unlockVault } from '../../byo/VaultLifecycle';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import ByoPassphraseInput from './ByoPassphraseInput.svelte';
  import Argon2Progress from './Argon2Progress.svelte';
  import MemoryFailurePrompt from './MemoryFailurePrompt.svelte';
  import BottomSheet from '../BottomSheet.svelte';

  export let provider: StorageProvider;

  const dispatch = createEventDispatcher<{
    unlocked: { db: import('sql.js').Database; sessionId: string };
    'use-recovery': void;
    'link-device': void;
    cancel: void;
  }>();

  type UnlockStep = 'passphrase' | 'unlocking';

  let step: UnlockStep = 'passphrase';
  let argon2Done = false;
  let memoryError = false;
  let showRollback = false;
  let error = '';
  let db: import('sql.js').Database | null = null;

  // Stable session ID for the BYO worker key storage
  const sessionId = crypto.randomUUID();

  async function handlePassphrase(event: CustomEvent<string>) {
    const passphrase = event.detail;
    step = 'unlocking';
    argon2Done = false;
    error = '';
    memoryError = false;

    try {
      db = await unlockVault(provider, { passphrase, keySessionId: sessionId });
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

      dispatch('unlocked', { db, sessionId });
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
    if (db) dispatch('unlocked', { db, sessionId });
  }
</script>

<div class="byo-unlock">
  {#if memoryError}
    <MemoryFailurePrompt
      onRetry={() => { memoryError = false; }}
      onBack={() => { memoryError = false; dispatch('cancel'); }}
    />

  {:else if step === 'passphrase'}
    <div class="header">
      <h2 class="title">Unlock your vault</h2>
      <p class="subtitle">Enter your vault passphrase to access your files.</p>
    </div>

    {#if error}
      <p class="error-msg" role="alert">{error}</p>
    {/if}

    <ByoPassphraseInput mode="unlock" submitLabel="Unlock" on:submit={handlePassphrase} />

    <div class="alt-actions">
      <button class="btn-link" on:click={() => dispatch('link-device')}>
        Link another device instead
      </button>
      <button class="btn-link" on:click={() => dispatch('use-recovery')}>
        Use recovery key
      </button>
    </div>

  {:else if step === 'unlocking'}
    <div class="header">
      <h2 class="title">Unlocking vault…</h2>
    </div>
    <Argon2Progress done={argon2Done} />
  {/if}
</div>

<!-- Rollback warning as BottomSheet (sits on top of passphrase/unlocking step) -->
<BottomSheet open={showRollback} title="Vault may have been rolled back" on:close={abortRollback}>
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
      <button class="btn btn-secondary" on:click={abortRollback}>Abort — go back</button>
      <button class="btn btn-danger proceed-btn" on:click={confirmRollback}>Proceed anyway</button>
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
    padding: var(--sp-lg, 24px) var(--sp-md, 16px);
  }

  .header {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .title {
    margin: 0;
    font-size: var(--t-title-size, 1.25rem);
    font-weight: 700;
    color: var(--text-primary, #EDEDED);
  }

  .subtitle {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
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

  .alt-actions {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-xs, 4px);
    margin-top: var(--sp-sm, 8px);
  }

  .btn-link {
    background: none;
    border: none;
    color: var(--accent-text, #5FDB8A);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    min-height: 44px;
    padding: 0 var(--sp-sm, 8px);
    display: inline-flex;
    align-items: center;
    text-decoration: underline;
    text-underline-offset: 3px;
  }

  .btn-link:hover { color: var(--accent, #2EB860); }

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
