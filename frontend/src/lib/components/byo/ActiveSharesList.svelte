<script lang="ts">
  /**
   * ActiveSharesList — sender's share management screen (Settings → BYO → Active shares).
   *
   * Lists all active (non-revoked) share tokens from vault SQLite.
   * Allows revoking individual shares.
   */

  import { getContext, onMount, onDestroy } from 'svelte';
  import type { DataProvider, ShareEntry } from '../../byo/DataProvider';
  import HexShield from '../HexShield.svelte';
  import ConfirmModal from '../ConfirmModal.svelte';
  import Link from 'phosphor-svelte/lib/Link';
  import Lock from 'phosphor-svelte/lib/Lock';
  import Clock from 'phosphor-svelte/lib/Clock';
  import UploadSimple from 'phosphor-svelte/lib/UploadSimple';
  import Globe from 'phosphor-svelte/lib/Globe';
  import Trash from 'phosphor-svelte/lib/Trash';

  const dataProvider = getContext<DataProvider>('byo:dataProvider');

  let shares: ShareEntry[] = [];
  let fileNames: Map<number, string> = new Map();
  let revoking: Set<string> = new Set();
  let error = '';
  let pollInterval: ReturnType<typeof setInterval> | null = null;

  // Revoke confirmation (§11.2 — destructive action needs consequence line).
  let confirmShareId: string | null = null;
  let confirmFileName = '';

  async function loadShares() {
    shares = dataProvider.listShares();
    const ids = [...new Set(shares.map((s) => s.file_id))];
    const resolved = await Promise.all(ids.map((id) => dataProvider.getDecryptedFileName(id)));
    fileNames = new Map(ids.map((id, i) => [id, resolved[i]]));
  }

  onMount(() => {
    loadShares();
    pollInterval = setInterval(loadShares, 30_000);
  });

  onDestroy(() => {
    if (pollInterval !== null) clearInterval(pollInterval);
  });

  function promptRevoke(share: ShareEntry) {
    confirmShareId = share.share_id;
    confirmFileName = fileNames.get(share.file_id) ?? 'this file';
  }

  async function revokeConfirmed() {
    const shareId = confirmShareId;
    if (!shareId) return;
    confirmShareId = null;
    revoking = new Set([...revoking, shareId]);
    try {
      await dataProvider.revokeShare(shareId);
      shares = shares.filter((s) => s.share_id !== shareId);
    } catch (e: any) {
      error = e.message || 'Failed to revoke share';
    } finally {
      revoking = new Set([...revoking].filter((id) => id !== shareId));
    }
  }

  function variantIcon(variant: string) {
    return { A: Globe, 'A+': Lock, B1: Clock, B2: UploadSimple }[variant] ?? Link;
  }

  function variantLabel(variant: string) {
    return { A: 'Public', 'A+': 'Password', B1: 'Timed', B2: 'Relayed' }[variant] ?? variant;
  }

  function timeAgo(ms: number): string {
    const diff = Date.now() - ms;
    const m = Math.floor(diff / 60000);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  }

  function expiryLabel(entry: ShareEntry): string {
    if (!entry.presigned_expires_at) return '';
    const rem = entry.presigned_expires_at - Date.now();
    if (rem <= 0) return 'Expired';
    const h = Math.floor(rem / 3600000);
    if (h < 24) return `Expires in ${h}h`;
    return `Expires in ${Math.floor(h / 24)}d`;
  }
</script>

<div class="shares-list">
  <div class="shares-header">
    <h3 class="shares-title">Active shares</h3>
    <p class="shares-subtitle">Links you generate appear here. Revoke to stop access instantly.</p>
  </div>

  {#if error}
    <div class="error-banner" role="alert">{error}</div>
  {/if}

  {#if shares.length === 0}
    <!-- Branded empty state (§29.5) -->
    <div class="empty-state">
      <HexShield size={72} color="var(--text-disabled, #616161)">
        <Link size={28} weight="regular" color="var(--text-disabled, #616161)" />
      </HexShield>
      <p class="empty-heading">No active shares</p>
      <p class="empty-sub">Links you generate will appear here.</p>
    </div>
  {:else}
    <ul class="shares-items" aria-label="Active share links">
      {#each shares as share (share.share_id)}
        <li class="share-item">
          <div class="share-item-icon" aria-hidden="true">
            <svelte:component this={variantIcon(share.variant)} size={20} />
          </div>
          <div class="share-item-body">
            <div class="share-item-top">
              <span class="share-filename">{fileNames.get(share.file_id) ?? '…'}</span>
              <span class="variant-pill">{variantLabel(share.variant)}</span>
            </div>
            <div class="share-item-meta">
              <span>{timeAgo(share.created_at)}</span>
              {#if expiryLabel(share)}
                <span class="expiry-label">{expiryLabel(share)}</span>
              {/if}
            </div>
          </div>
          <button
            class="revoke-btn"
            on:click={() => promptRevoke(share)}
            disabled={revoking.has(share.share_id)}
            aria-label="Revoke share link for {fileNames.get(share.file_id) ?? 'file'}"
            title="Revoke"
          >
            <span class="revoke-visual" aria-hidden="true">
              {#if revoking.has(share.share_id)}
                <span class="spinner-sm" />
              {:else}
                <Trash size={18} />
              {/if}
            </span>
          </button>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<ConfirmModal
  isOpen={confirmShareId !== null}
  title="Revoke share link?"
  message="Anyone holding this link will immediately lose access to {confirmFileName}. This cannot be undone."
  confirmText="Revoke"
  confirmClass="btn-danger"
  on:confirm={revokeConfirmed}
  on:cancel={() => { confirmShareId = null; }}
/>

<style>
  .shares-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
  }

  .shares-header { display: flex; flex-direction: column; gap: 4px; }

  .shares-title {
    margin: 0;
    font-size: var(--t-title-size, 1rem);
    font-weight: 600;
    color: var(--text-primary, #ededed);
  }

  .shares-subtitle {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
  }

  .error-banner {
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 12px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  /* Empty state (§29.5) */
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-xl, 32px) var(--sp-md, 16px);
    text-align: center;
  }

  .empty-heading {
    margin: 0;
    font-size: var(--t-title-size, 1rem);
    color: var(--text-primary, #ededed);
  }

  .empty-sub {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
  }

  /* Share items (§14.1 48dp rows) */
  .shares-items {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .share-item {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    min-height: 48px;
    padding: var(--sp-sm, 8px) 0;
    border-bottom: 1px solid var(--border, #2E2E2E);
  }

  .share-item-icon {
    width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--r-input, 12px);
    background: var(--bg-surface-raised, #1E1E1E);
    color: var(--accent, #2EB860);
    flex-shrink: 0;
  }

  .share-item-body { flex: 1; min-width: 0; }

  .share-item-top {
    display: flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
  }

  .share-filename {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #ededed);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .variant-pill {
    font-size: 0.65rem;
    font-weight: 600;
    padding: 2px 6px;
    border-radius: var(--r-pill, 9999px);
    background: var(--accent-muted, rgba(46, 184, 96, 0.12));
    color: var(--accent-text, #5FDB8A);
    white-space: nowrap;
    flex-shrink: 0;
  }

  .share-item-meta {
    display: flex;
    gap: var(--sp-sm, 8px);
    font-size: 0.7rem;
    color: var(--text-secondary, #999);
    margin-top: 2px;
  }

  .expiry-label { color: var(--accent-warm, #E0A320); }

  .revoke-btn {
    width: 44px;
    height: 44px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: none;
    background: transparent;
    cursor: pointer;
    flex-shrink: 0;
    color: var(--danger, #D64545);
    padding: 0;
  }

  .revoke-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .revoke-visual {
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--r-pill, 9999px);
    border: 1px solid var(--border, #2E2E2E);
    background: transparent;
    transition: background 150ms;
  }

  .revoke-btn:hover:not(:disabled) .revoke-visual { background: var(--danger-muted, #3D1F1F); }

  .spinner-sm {
    width: 14px;
    height: 14px;
    border: 2px solid rgba(214, 69, 69, 0.3);
    border-top-color: var(--danger, #D64545);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }
</style>
