<script lang="ts">
  /**
   * VaultsListScreen — first-run / cold-start landing page.
   *
   * Rendered when ByoApp detects at least one persisted vault in IDB.
   * Lets the user pick a saved vault to unlock (auto-hydrates providers
   * from IDB) or connect a brand-new one (falls through to the existing
   * AddProviderSheet flow).
   */
  import { createEventDispatcher } from 'svelte';
  import type { PersistedVaultSummary } from '../../byo/ProviderConfigStore';
  import Lock from 'phosphor-svelte/lib/Lock';
  import DotsThreeVertical from 'phosphor-svelte/lib/DotsThreeVertical';
  import Plus from 'phosphor-svelte/lib/Plus';
  import GoogleDriveLogo from 'phosphor-svelte/lib/GoogleDriveLogo';
  import DropboxLogo from 'phosphor-svelte/lib/DropboxLogo';
  import Cloud from 'phosphor-svelte/lib/Cloud';
  import Package from 'phosphor-svelte/lib/Package';
  import CloudCheck from 'phosphor-svelte/lib/CloudCheck';
  import HardDrives from 'phosphor-svelte/lib/HardDrives';
  import Terminal from 'phosphor-svelte/lib/Terminal';
  import Database from 'phosphor-svelte/lib/Database';
  import DeviceMobile from 'phosphor-svelte/lib/DeviceMobile';
  import type { ComponentType } from 'svelte';
  import type { ProviderType } from '@wattcloud/sdk';

  export let vaults: PersistedVaultSummary[] = [];

  const dispatch = createEventDispatcher<{
    open: { vault_id: string };
    menu: { vault_id: string };
    addNew: void;
    linkDevice: void;
  }>();

  const ICONS: Record<ProviderType, ComponentType> = {
    gdrive: GoogleDriveLogo,
    dropbox: DropboxLogo,
    onedrive: Cloud,
    box: Package,
    pcloud: CloudCheck,
    webdav: HardDrives,
    sftp: Terminal,
    s3: Database,
    mock: Cloud,
  } as unknown as Record<ProviderType, ComponentType>;

  function relativeTime(iso: string): string {
    const then = new Date(iso).getTime();
    const now = Date.now();
    const deltaSec = Math.max(0, Math.floor((now - then) / 1000));
    if (deltaSec < 60) return 'just now';
    if (deltaSec < 3600) return `${Math.floor(deltaSec / 60)} min ago`;
    if (deltaSec < 86400) return `${Math.floor(deltaSec / 3600)} h ago`;
    const days = Math.floor(deltaSec / 86400);
    if (days < 7) return `${days} day${days === 1 ? '' : 's'} ago`;
    const weeks = Math.floor(days / 7);
    if (weeks < 5) return `${weeks} week${weeks === 1 ? '' : 's'} ago`;
    return new Date(iso).toLocaleDateString();
  }
</script>

<div class="vaults-page">
  <div class="header">
    <Lock size={56} weight="regular" color="var(--accent, #2EB860)" />
    <h1 class="title">Your vaults</h1>
    <p class="subtitle">Pick a vault to unlock, or connect a new one.</p>
  </div>

  <div class="vault-list">
    {#each vaults as v (v.vault_id)}
      <div class="vault-card">
        <button
          class="vault-main"
          on:click={() => dispatch('open', { vault_id: v.vault_id })}
          aria-label={`Open vault ${v.vault_label}`}
        >
          <span class="vault-icon" aria-hidden="true">
            <svelte:component this={ICONS[v.primary.type] ?? Cloud} size={20} weight="regular" />
          </span>
          <span class="vault-body">
            <span class="vault-label">{v.vault_label || 'Untitled vault'}</span>
            <span class="vault-meta">
              {v.primary.type.toUpperCase()} · {v.primary.display_name}
              {#if v.providers.length > 1}
                · +{v.providers.length - 1} provider{v.providers.length - 1 === 1 ? '' : 's'}
              {/if}
            </span>
            <span class="vault-time">Last opened {relativeTime(v.last_saved_at)}</span>
          </span>
        </button>
        <button
          class="vault-menu"
          on:click={() => dispatch('menu', { vault_id: v.vault_id })}
          aria-label={`More actions for ${v.vault_label}`}
        >
          <DotsThreeVertical size={20} weight="bold" />
        </button>
      </div>
    {/each}
  </div>

  <div class="divider" aria-hidden="true"><span>or</span></div>

  <button class="add-new" on:click={() => dispatch('addNew')}>
    <span class="add-icon" aria-hidden="true"><Plus size={18} weight="bold" /></span>
    <span class="add-text">
      <span class="add-title">Connect a new vault</span>
      <span class="add-sub">Google Drive, Dropbox, OneDrive, Box, pCloud, WebDAV, SFTP, S3</span>
    </span>
  </button>

  <button class="link-device" on:click={() => dispatch('linkDevice')}>
    <span class="link-icon" aria-hidden="true"><DeviceMobile size={18} weight="bold" /></span>
    <span class="link-text">
      <span class="link-title">Link from another device</span>
      <span class="link-sub">Scan a QR on a device that already has the vault — no credentials needed here.</span>
    </span>
  </button>
</div>

<style>
  .vaults-page {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
    max-width: 480px;
    margin: 0 auto;
    padding: var(--sp-xl, 32px) var(--sp-md, 16px) var(--sp-2xl, 48px);
    width: 100%;
  }

  .header {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-sm, 8px);
    text-align: center;
    padding: var(--sp-md, 16px) 0 var(--sp-sm, 8px);
    color: var(--accent, #2EB860);
  }

  .title {
    margin: 0;
    font-size: var(--t-h1-size, 1.5rem);
    font-weight: 700;
    color: var(--text-primary, #EDEDED);
    letter-spacing: -0.02em;
  }

  .subtitle {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
  }

  .vault-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
  }

  .vault-card {
    display: flex;
    align-items: stretch;
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    overflow: hidden;
    transition: border-color 120ms ease;
  }
  .vault-card:hover {
    border-color: var(--accent, #2EB860);
  }

  .vault-main {
    flex: 1;
    display: grid;
    grid-template-columns: 40px 1fr;
    gap: var(--sp-md, 12px);
    padding: var(--sp-md, 14px);
    background: transparent;
    border: none;
    color: inherit;
    cursor: pointer;
    text-align: left;
    min-width: 0;
  }

  .vault-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: var(--r-input, 12px);
    background: var(--accent-muted, #1B3627);
    color: var(--accent-text, #5FDB8A);
    flex-shrink: 0;
  }

  .vault-body {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .vault-label {
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .vault-meta {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .vault-time {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
  }

  .vault-menu {
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 44px;
    background: transparent;
    border: none;
    border-left: 1px solid var(--border, #2E2E2E);
    color: var(--text-secondary, #999);
    cursor: pointer;
    transition: background 120ms ease, color 120ms ease;
  }
  .vault-menu:hover {
    background: var(--bg-surface-hover, #2E2E2E);
    color: var(--text-primary, #EDEDED);
  }

  .divider {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    color: var(--text-disabled, #616161);
    font-size: var(--t-label-size, 0.75rem);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: var(--sp-sm, 8px) 0;
  }
  .divider::before,
  .divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border, #2E2E2E);
  }

  .add-new {
    display: grid;
    grid-template-columns: 40px 1fr;
    gap: var(--sp-md, 12px);
    align-items: center;
    padding: var(--sp-md, 14px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px dashed var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    color: var(--text-primary, #EDEDED);
    cursor: pointer;
    text-align: left;
    transition: border-color 120ms ease, background 120ms ease;
  }
  .add-new:hover {
    border-color: var(--accent, #2EB860);
    background: var(--bg-surface-hover, #2E2E2E);
  }

  .add-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: var(--r-pill, 9999px);
    background: var(--accent, #2EB860);
    color: var(--text-inverse, #121212);
  }

  .add-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .add-title {
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 600;
  }
  .add-sub {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .link-device {
    display: grid;
    grid-template-columns: 40px 1fr;
    gap: var(--sp-md, 12px);
    align-items: center;
    padding: var(--sp-md, 14px);
    background: transparent;
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    color: var(--text-primary, #EDEDED);
    cursor: pointer;
    text-align: left;
    transition: border-color 120ms ease, background 120ms ease;
    margin-top: var(--sp-xs, 4px);
  }
  .link-device:hover {
    border-color: var(--accent-warm, #E0A320);
    background: var(--bg-surface-hover, #2E2E2E);
  }

  .link-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border-radius: var(--r-input, 12px);
    background: var(--accent-warm-muted, #3D2E10);
    color: var(--accent-warm-text, #F0C04A);
  }

  .link-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .link-title {
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 600;
  }
  .link-sub {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.35;
  }
</style>
