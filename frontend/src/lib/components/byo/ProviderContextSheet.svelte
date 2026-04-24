<script lang="ts">

  /**
   * ProviderContextSheet — action sheet for a provider chip.
   *
   * Actions:
   *   - Set as primary (disabled if already primary or only one provider)
   *   - Rename
   *   - Remove (disabled if primary; confirmation required)
   *
   * Fires `on:close` when dismissed without an action.
   * Fires `on:change` after any successful mutation so the parent can refresh.
   */
  import { tick } from 'svelte';
  import type { ProviderMeta } from '../../byo/stores/vaultStore';
  import { renameProvider, setAsPrimaryProvider, removeProvider, reconnectSftpProvider } from '../../byo/VaultLifecycle';
  import { deleteProviderConfig } from '../../byo/ProviderConfigStore';
  import * as byoWorker from '@wattcloud/sdk';
  import PasswordInput from '../common/PasswordInput.svelte';
  import { byoToast } from '../../byo/stores/byoToasts';

  interface Props {
    provider: ProviderMeta;
    isOnlyProvider?: boolean;
  onChange?: (...args: any[]) => void;
  onClose?: (...args: any[]) => void;
  }

  let { provider, isOnlyProvider = false,
  onChange,
  onClose }: Props = $props();
// ── State ────────────────────────────────────────────────────────────────

  type Sheet = 'menu' | 'rename' | 'confirm-remove' | 'sftp-reconnect' | 'confirm-forget';
  let sheet: Sheet = $state('menu');
  // svelte-ignore state_referenced_locally
  let newName = $state(provider.displayName);

  // SFTP reconnect form state
  let sftpPass = $state('');
  let sftpKey = $state('');
  let sftpPassphrase = $state('');
  let reconnecting = $state(false);

  // Svelte action: focus the input once it mounts. Replaces the
  // deprecated autofocus attribute so screen readers / modal-with-focus
  // conventions behave consistently (§25 accessibility). Guards against
  // the component unmounting before the tick resolves (e.g. rapid sheet
  // switch) — calling focus() on a detached node is benign on every
  // current browser but not spec-guaranteed.
  function autofocusInput(node: HTMLInputElement) {
    tick().then(() => {
      if (node.isConnected) node.focus();
    });
  }

  // ── Actions ─────────────────────────────────────────────────────────────

  async function handleSetAsPrimary() {
    try {
      await setAsPrimaryProvider(provider.providerId);
      onChange?.();
      onClose?.();
    } catch (e: any) {
      byoToast.show(e.message, { icon: 'danger' });
    }
  }

  async function handleRename() {
    try {
      await renameProvider(provider.providerId, newName);
      onChange?.();
      onClose?.();
    } catch (e: any) {
      byoToast.show(e.message, { icon: 'danger' });
    }
  }

  async function handleRemove() {
    try {
      await removeProvider(provider.providerId);
      onChange?.();
      onClose?.();
    } catch (e: any) {
      byoToast.show(e.message, { icon: 'danger' });
    }
  }

  async function handleForgetLocal() {
    try {
      await deleteProviderConfig(provider.providerId);
      byoToast.show('Credentials forgotten on this device.');
      onChange?.();
      onClose?.();
    } catch (e: any) {
      byoToast.show(e?.message ?? 'Forget failed', { icon: 'danger' });
    }
  }

  async function handleSftpReconnect() {
    if (!sftpPass && !sftpKey) {
      byoToast.show('Password or private key is required', { icon: 'danger' });
      return;
    }
    reconnecting = true;
    let credHandle: number | undefined;
    try {
      credHandle = await byoWorker.Worker.sftpStoreCredential(
        sftpPass || undefined,
        sftpKey || undefined,
        sftpPassphrase || undefined,
      );
      sftpPass = ''; sftpKey = ''; sftpPassphrase = '';
      await reconnectSftpProvider(provider.providerId, credHandle);
      onChange?.();
      onClose?.();
    } catch (e: any) {
      if (credHandle !== undefined) {
        byoWorker.Worker.sftpClearCredential(credHandle).catch(() => {});
      }
      byoToast.show(e.message, { icon: 'danger' });
    } finally {
      reconnecting = false;
    }
  }
</script>

<div class="sheet-overlay" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) onClose?.(); }}>
  <div class="sheet" role="dialog" aria-modal="true" aria-label="Provider options">
    <div class="drag-handle" aria-hidden="true"></div>

    <div class="sheet-header">
      <span class="provider-type-badge">{provider.displayName}</span>
      {#if provider.isPrimary}
        <span class="primary-badge">Primary</span>
      {/if}
    </div>

    {#if sheet === 'menu'}
      <div class="action-list">
        <button
          class="action-row"
          disabled={provider.isPrimary || isOnlyProvider}
          onclick={handleSetAsPrimary}
        >
          <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
            <path d="M10 2l2.4 5H18l-4.4 3.3 1.7 5.2L10 12.5 4.7 15.5l1.7-5.2L2 7h5.6L10 2z"/>
          </svg>
          Set as primary
        </button>

        <button class="action-row" onclick={() => { sheet = 'rename'; newName = provider.displayName; }}>
          <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
            <path d="M14.7 3.3a1 1 0 011.4 1.4l-10 10L3 16l1.3-3.1 10.4-9.6z"/>
          </svg>
          Rename
        </button>

        {#if provider.type === 'sftp' && provider.status === 'offline'}
          <button class="action-row action-accent" onclick={() => { sheet = 'sftp-reconnect'; }}>
            <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
              <path d="M4 10a6 6 0 1 1 12 0" stroke-linecap="round"/>
              <path d="M4 10l-2 2m2-2l2 2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            Reconnect
          </button>
        {/if}

        <button class="action-row" onclick={() => { sheet = 'confirm-forget'; }}>
          <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
            <path d="M5 5h10v12H5z"/>
            <path d="M8 8v6M12 8v6" stroke-linecap="round"/>
          </svg>
          Forget on this device
        </button>

        <button
          class="action-row action-danger"
          disabled={provider.isPrimary || isOnlyProvider}
          onclick={() => { sheet = 'confirm-remove'; }}
        >
          <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
            <path d="M5 5l10 10M15 5L5 15" stroke-linecap="round"/>
          </svg>
          Remove from vault
        </button>
      </div>

    {:else if sheet === 'rename'}
      <form class="inline-form" onsubmit={(e) => { e.preventDefault(); handleRename(); }}>
        <label class="field-label">Provider name
          <input
            class="field-input"
            type="text"
            bind:value={newName}
            required
            autocomplete="off"
            use:autofocusInput
          />
        </label>
        <div class="form-actions">
          <button type="button" class="btn-ghost-sm" onclick={() => sheet = 'menu'}>Back</button>
          <button type="submit" class="btn-primary-sm">Save</button>
        </div>
      </form>

    {:else if sheet === 'sftp-reconnect'}
      <form class="inline-form" onsubmit={(e) => { e.preventDefault(); handleSftpReconnect(); }}>
        <p class="reconnect-hint">Enter credentials to reconnect <strong>{provider.displayName}</strong>.</p>
        <!-- svelte-ignore a11y_label_has_associated_control -->
        <label class="field-label">Password
          <PasswordInput bind:value={sftpPass} autocomplete="current-password" showLabel="Show password" hideLabel="Hide password" />
        </label>
        <label class="field-label">Private key (PEM)
          <textarea class="field-input field-textarea" bind:value={sftpKey} rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
        </label>
        <!-- svelte-ignore a11y_label_has_associated_control -->
        <label class="field-label">Key passphrase
          <PasswordInput bind:value={sftpPassphrase} autocomplete="off" showLabel="Show passphrase" hideLabel="Hide passphrase" />
        </label>
        <div class="form-actions">
          <button type="button" class="btn-ghost-sm" onclick={() => sheet = 'menu'}>Back</button>
          <button type="submit" class="btn-primary-sm" disabled={reconnecting}>
            {reconnecting ? 'Connecting…' : 'Connect'}
          </button>
        </div>
      </form>

    {:else if sheet === 'confirm-remove'}
      <div class="confirm-body">
        <p>Remove <strong>{provider.displayName}</strong> from this vault?</p>
        <p class="confirm-sub">Files stored on this provider remain encrypted. You can reconnect it later.</p>
        <div class="form-actions">
          <button class="btn-ghost-sm" onclick={() => sheet = 'menu'}>Cancel</button>
          <button class="btn-danger-sm" onclick={handleRemove}>Remove</button>
        </div>
      </div>

    {:else if sheet === 'confirm-forget'}
      <div class="confirm-body">
        <p>Forget <strong>{provider.displayName}</strong> on this device?</p>
        <p class="confirm-sub">Deletes the saved credentials from this browser only. The provider stays enrolled in the vault and continues working on your other devices. Re-entering credentials will restore access here.</p>
        <div class="form-actions">
          <button class="btn-ghost-sm" onclick={() => sheet = 'menu'}>Cancel</button>
          <button class="btn-danger-sm" onclick={handleForgetLocal}>Forget</button>
        </div>
      </div>
    {/if}

    <button class="btn-ghost" onclick={() => onClose?.()}>Dismiss</button>
  </div>
</div>

<style>
  .sheet-overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,.55);
    display: flex; align-items: flex-end; justify-content: center;
    z-index: 910;
  }

  .sheet {
    background: var(--bg-surface-raised, #1E1E1E);
    border-radius: var(--r-card, 16px) var(--r-card, 16px) 0 0;
    width: 100%; max-width: 600px;
    padding: var(--sp-sm, 8px) var(--sp-lg, 24px) var(--sp-xl, 32px);
    display: flex; flex-direction: column; gap: var(--sp-md, 16px);
    animation: slideUp 300ms cubic-bezier(.32,.72,0,1);
  }
  @keyframes slideUp { from { transform: translateY(100%); } }

  .drag-handle {
    width: 36px; height: 4px;
    background: var(--border, #2E2E2E);
    border-radius: 2px;
    align-self: center; margin-bottom: var(--sp-xs, 4px);
  }

  .sheet-header {
    display: flex; align-items: center; gap: 8px;
  }
  .provider-type-badge {
    font-weight: 600; font-size: 1rem; color: var(--text-primary, #EDEDED);
    flex: 1;
  }
  .primary-badge {
    font-size: .75rem; padding: 2px 8px;
    border-radius: 10px;
    background: var(--accent-muted, #1A3D2B);
    color: var(--accent-text, #5FDB8A);
  }

  .action-list { display: flex; flex-direction: column; gap: 2px; }

  .action-row {
    display: flex; align-items: center; gap: 12px;
    min-height: 48px; width: 100%;
    padding: 10px 16px;
    background: var(--bg-surface, #161616);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    color: var(--text-primary, #EDEDED);
    font-size: .9375rem;
    cursor: pointer; text-align: left;
    transition: background 120ms;
  }
  .action-row:hover:not(:disabled) { background: var(--bg-surface-raised, #1E1E1E); }
  .action-row:disabled { opacity: .4; cursor: not-allowed; }
  .action-danger { color: var(--danger, #D64545); }
  .action-danger:not(:disabled):hover { background: var(--danger-muted, #3D1F1F); }
  .action-accent { color: var(--accent, #2EB860); }
  .action-accent:not(:disabled):hover { background: var(--accent-muted, #1A3D2B); }

  .inline-form {
    display: flex; flex-direction: column; gap: 8px;
  }
  .reconnect-hint { margin: 0; color: var(--text-secondary, #999); font-size: .8125rem; }
  .field-textarea { resize: vertical; font-family: monospace; font-size: .8125rem; }
  .field-label {
    display: flex; flex-direction: column; gap: 4px;
    font-size: .8125rem; color: var(--text-secondary, #999);
  }
  .field-input {
    width: 100%; padding: 8px 16px;
    background: var(--bg-surface, #161616);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    color: var(--text-primary, #EDEDED);
    font-size: .9375rem; box-sizing: border-box;
  }

  .confirm-body { display: flex; flex-direction: column; gap: 8px; }
  .confirm-body p { margin: 0; color: var(--text-primary, #EDEDED); font-size: .9375rem; }
  .confirm-sub { color: var(--text-secondary, #999) !important; font-size: .8125rem !important; }

  .form-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 8px; }

  .btn-primary-sm, .btn-ghost-sm, .btn-danger-sm {
    padding: 8px 16px; border-radius: 10px;
    font-size: .875rem; cursor: pointer;
  }
  .btn-primary-sm {
    border: none; background: var(--accent, #2EB860); color: #fff;
  }
  .btn-ghost-sm {
    border: 1px solid var(--border, #2E2E2E);
    background: transparent; color: var(--text-secondary, #999);
  }
  .btn-danger-sm {
    border: 1px solid var(--danger, #D64545);
    background: transparent; color: var(--danger, #D64545);
  }

  .btn-ghost {
    padding: 10px 24px; border-radius: 999px;
    border: 1px solid var(--border, #2E2E2E);
    background: transparent; color: var(--text-secondary, #999);
    font-size: .9375rem; cursor: pointer; width: 100%;
  }
</style>
