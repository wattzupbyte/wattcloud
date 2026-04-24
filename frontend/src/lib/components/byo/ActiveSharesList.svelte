<script lang="ts">
  /**
   * ActiveSharesList — sender's share management screen (Settings → BYO → Active shares).
   *
   * Lists all active (non-revoked) share tokens from vault SQLite.
   * Allows revoking individual shares.
   */

  import { getContext, onMount, onDestroy } from 'svelte';
  import type { DataProvider, ShareEntry } from '../../byo/DataProvider';
  import ConfirmModal from '../ConfirmModal.svelte';
  import Link from 'phosphor-svelte/lib/Link';
  import FolderSimple from 'phosphor-svelte/lib/FolderSimple';
  import ImageSquare from 'phosphor-svelte/lib/ImageSquare';
  import UploadSimple from 'phosphor-svelte/lib/UploadSimple';
  import Trash from 'phosphor-svelte/lib/Trash';
  import { byoToast } from '../../byo/stores/byoToasts';

  const dataProvider = getContext<{ current: DataProvider }>('byo:dataProvider').current;

  let shares: ShareEntry[] = [];
  let displayNames: Map<string, string> = new Map(); // share_id → label
  let revoking: Set<string> = new Set();
  let pollInterval: ReturnType<typeof setInterval> | null = null;

  // Revoke confirmation (§11.2 — destructive action needs consequence line).
  let confirmShareId: string | null = null;
  let confirmDisplayName = '';

  async function loadShares() {
    shares = dataProvider.listShares();
    const next = new Map<string, string>();
    await Promise.all(
      shares.map(async (s) => {
        let name = 'Share';
        if (s.kind === 'file' && s.file_id !== null) {
          name = await dataProvider.getDecryptedFileName(s.file_id);
        } else if (s.kind === 'folder' && s.folder_id !== null) {
          name = await dataProvider.getDecryptedFolderName(s.folder_id);
        } else if (s.kind === 'collection' && s.collection_id !== null) {
          name = await dataProvider.getDecryptedCollectionName(s.collection_id);
        }
        next.set(s.share_id, name);
      }),
    );
    displayNames = next;
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
    confirmDisplayName = displayNames.get(share.share_id) ?? 'this share';
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
      byoToast.show(e.message || 'Failed to revoke share', { icon: 'danger' });
    } finally {
      revoking = new Set([...revoking].filter((id) => id !== shareId));
    }
  }

  function kindIcon(kind: string) {
    if (kind === 'folder') return FolderSimple;
    if (kind === 'collection') return ImageSquare;
    return UploadSimple;
  }

  function kindLabel(kind: string) {
    if (kind === 'folder') return 'Folder';
    if (kind === 'collection') return 'Collection';
    return 'File';
  }

  const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];
  function formatBytes(n: number | null): string {
    if (n === null || n <= 0) return '';
    let v = n;
    let i = 0;
    while (v >= 1024 && i < UNITS.length - 1) {
      v /= 1024;
      i++;
    }
    return v < 10 && i > 0 ? `${v.toFixed(1)} ${UNITS[i]}` : `${Math.round(v)} ${UNITS[i]}`;
  }

  /** Blob count on the relay is N+1 for bundles (manifest); N=1 for single files. */
  function fileCountLabel(entry: ShareEntry): string {
    if (entry.kind === 'file') return '';
    if (entry.blob_count === null || entry.blob_count < 2) return '';
    const files = entry.blob_count - 1;
    return files === 1 ? '1 file' : `${files} files`;
  }

  function timeAgo(ms: number): string {
    const diff = Date.now() - ms;
    const m = Math.floor(diff / 60000);
    if (m < 1) return 'Just now';
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
    if (h < 1) return `<1h left`;
    if (h < 24) return `${h}h left`;
    return `${Math.floor(h / 24)}d left`;
  }

  function metaParts(entry: ShareEntry): string[] {
    const parts: string[] = [timeAgo(entry.created_at)];
    const files = fileCountLabel(entry);
    if (files) parts.push(files);
    const bytes = formatBytes(entry.total_bytes);
    if (bytes) parts.push(bytes);
    return parts;
  }
</script>

<div class="shares-list">
  <div class="shares-header">
    <h3 class="shares-title">Active shares</h3>
    <p class="shares-subtitle">Links you generate appear here. Revoke to stop access instantly.</p>
  </div>

  {#if shares.length === 0}
    <!-- Branded empty state (§29.5) -->
    <div class="empty-state">
      <Link size={56} weight="light" color="var(--text-disabled, #616161)" />
      <p class="empty-heading">No active shares</p>
      <p class="empty-sub">Links you generate will appear here.</p>
    </div>
  {:else}
    <ul class="shares-items" aria-label="Active share links">
      {#each shares as share (share.share_id)}
        <li class="share-item">
          <div class="share-item-icon" aria-hidden="true">
            <svelte:component this={kindIcon(share.kind)} size={20} />
          </div>
          <div class="share-item-body">
            <div class="share-item-top">
              <span class="share-filename">{displayNames.get(share.share_id) ?? '…'}</span>
              <span class="kind-pill">{kindLabel(share.kind)}</span>
            </div>
            <div class="share-item-meta">
              {#each metaParts(share) as part, i}
                {#if i > 0}<span class="meta-dot" aria-hidden="true">·</span>{/if}
                <span>{part}</span>
              {/each}
              {#if expiryLabel(share)}
                <span class="meta-dot" aria-hidden="true">·</span>
                <span class="expiry-label">{expiryLabel(share)}</span>
              {/if}
            </div>
          </div>
          <button
            class="revoke-btn"
            on:click={() => promptRevoke(share)}
            disabled={revoking.has(share.share_id)}
            aria-label="Revoke share link for {displayNames.get(share.share_id) ?? 'share'}"
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
  message="Anyone holding this link will immediately lose access to {confirmDisplayName}. This cannot be undone."
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

  .kind-pill {
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
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-secondary, #999);
    margin-top: var(--sp-xs, 4px);
    font-variant-numeric: tabular-nums;
  }

  .meta-dot { opacity: 0.5; }

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
