<script lang="ts">
  /**
   * VaultContextSheet — per-vault action sheet shown from VaultsListScreen.
   *
   * Actions:
   *   - Open: unlock the vault
   *   - Rename: prompt for new label, updates every IDB row for this vault
   *   - Forget on this device: drops all provider_configs rows + device key
   *     + body cache + WAL for this vault. Does NOT touch the remote vault
   *     manifest. The user can re-add this vault later via the same provider.
   */
  import { createEventDispatcher } from 'svelte';
  import BottomSheet from '../BottomSheet.svelte';
  import type { PersistedVaultSummary } from '../../byo/ProviderConfigStore';
  import { renameVaultLabel, deleteVaultProviderConfigs } from '../../byo/ProviderConfigStore';
  import { deleteDeviceCryptoKey, deleteDeviceRecord } from '../../byo/DeviceKeyStore';
  import { deleteVaultThumbnails } from '../../byo/ThumbnailStore';
  import ArrowRight from 'phosphor-svelte/lib/ArrowRight';
  import PencilSimple from 'phosphor-svelte/lib/PencilSimple';
  import Trash from 'phosphor-svelte/lib/Trash';

  export let open = false;
  export let vault: PersistedVaultSummary | null = null;

  const dispatch = createEventDispatcher<{
    close: void;
    open: { vault_id: string };
    forgotten: { vault_id: string };
    renamed: { vault_id: string };
  }>();

  type SheetMode = 'menu' | 'rename' | 'confirm-forget';
  let mode: SheetMode = 'menu';
  let newLabel = '';
  let busy = false;
  let err = '';

  $: if (!open) {
    mode = 'menu';
    newLabel = vault?.vault_label ?? '';
    err = '';
  }

  async function doRename() {
    if (!vault) return;
    const trimmed = newLabel.trim();
    if (!trimmed) { err = 'Label cannot be empty'; return; }
    busy = true;
    err = '';
    try {
      await renameVaultLabel(vault.vault_id, trimmed);
      dispatch('renamed', { vault_id: vault.vault_id });
      dispatch('close');
    } catch (e: any) {
      err = e?.message ?? 'Rename failed';
    } finally {
      busy = false;
    }
  }

  async function doForget() {
    if (!vault) return;
    busy = true;
    err = '';
    try {
      // Wipe the thumbnail cache *before* the device CryptoKey is
      // deleted — once the key is gone, the ciphertext in the
      // thumbnails store becomes undecryptable garbage that would
      // leak disk space without anyone being able to reclaim it on
      // re-enrollment.
      await deleteVaultThumbnails(vault.vault_id).catch(() => {});
      await deleteVaultProviderConfigs(vault.vault_id);
      await deleteDeviceCryptoKey(vault.vault_id).catch(() => {});
      await deleteDeviceRecord(vault.vault_id).catch(() => {});
      dispatch('forgotten', { vault_id: vault.vault_id });
      dispatch('close');
    } catch (e: any) {
      err = e?.message ?? 'Forget failed';
    } finally {
      busy = false;
    }
  }
</script>

<BottomSheet
  open={open && vault !== null}
  title={vault?.vault_label ?? ''}
  subtitle={vault ? `${vault.primary.type.toUpperCase()} · ${vault.primary.display_name}` : ''}
  on:close={() => dispatch('close')}
>
  {#if vault}
    {#if mode === 'menu'}
      <div class="rows">
        <button
          class="row"
          on:click={() => { dispatch('open', { vault_id: vault.vault_id }); dispatch('close'); }}
        >
          <span class="row-icon"><ArrowRight size={18} weight="bold" /></span>
          <span class="row-text">
            <span class="row-title">Open</span>
            <span class="row-sub">Unlock and open this vault</span>
          </span>
        </button>
        <button class="row" on:click={() => { mode = 'rename'; newLabel = vault.vault_label; }}>
          <span class="row-icon"><PencilSimple size={18} weight="bold" /></span>
          <span class="row-text">
            <span class="row-title">Rename</span>
            <span class="row-sub">Local label only — other devices keep the original</span>
          </span>
        </button>
        <button class="row danger" on:click={() => { mode = 'confirm-forget'; }}>
          <span class="row-icon"><Trash size={18} weight="bold" /></span>
          <span class="row-text">
            <span class="row-title">Forget on this device</span>
            <span class="row-sub">Deletes saved credentials here. The vault itself is untouched.</span>
          </span>
        </button>
      </div>
    {:else if mode === 'rename'}
      <div class="body">
        <label for="vault-rename-input" class="input-label">New label</label>
        <input
          id="vault-rename-input"
          class="input"
          type="text"
          bind:value={newLabel}
          placeholder="e.g. Personal, Work, Photos"
          autocomplete="off"
          disabled={busy}
        />
        {#if err}<p class="input-error-msg">{err}</p>{/if}
        <div class="btn-row">
          <button class="btn btn-secondary" on:click={() => (mode = 'menu')} disabled={busy}>Cancel</button>
          <button class="btn btn-primary" on:click={doRename} disabled={busy || !newLabel.trim()}>Save</button>
        </div>
      </div>
    {:else if mode === 'confirm-forget'}
      <div class="body">
        <p class="confirm-text">
          Forget <strong>{vault.vault_label}</strong> on this device?
          The remote vault keeps every file. You'll need to reconnect the provider
          and re-enter your passphrase to open it again here.
        </p>
        {#if err}<p class="input-error-msg">{err}</p>{/if}
        <div class="btn-row">
          <button class="btn btn-secondary" on:click={() => (mode = 'menu')} disabled={busy}>Cancel</button>
          <button class="btn btn-danger" on:click={doForget} disabled={busy}>
            {busy ? 'Forgetting…' : 'Forget'}
          </button>
        </div>
      </div>
    {/if}
  {/if}
</BottomSheet>

<style>
  .rows {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
    padding: 0 var(--sp-md, 16px) var(--sp-md, 16px);
  }

  .row {
    display: grid;
    grid-template-columns: 32px 1fr;
    gap: var(--sp-md, 12px);
    align-items: center;
    padding: var(--sp-md, 12px);
    background: transparent;
    border: 1px solid transparent;
    border-radius: var(--r-input, 12px);
    color: var(--text-primary, #EDEDED);
    cursor: pointer;
    text-align: left;
    transition: background 120ms ease;
  }
  .row:hover {
    background: var(--bg-surface-hover, #2E2E2E);
  }
  .row.danger .row-title { color: var(--danger, #D64545); }
  .row.danger .row-icon { color: var(--danger, #D64545); }

  .row-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: var(--r-pill, 9999px);
    background: var(--bg-surface-raised, #262626);
    color: var(--accent-text, #5FDB8A);
  }

  .row-text { display: flex; flex-direction: column; gap: 2px; }
  .row-title { font-size: var(--t-body-size, 0.9375rem); font-weight: 500; }
  .row-sub { font-size: var(--t-body-sm-size, 0.8125rem); color: var(--text-secondary, #999); }

  .body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
    padding: 0 var(--sp-md, 16px) var(--sp-md, 16px);
  }
  .confirm-text {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.5;
  }
  .btn-row {
    display: flex;
    gap: var(--sp-sm, 8px);
    margin-top: var(--sp-sm, 8px);
  }
  .btn-row .btn { flex: 1; }
</style>
