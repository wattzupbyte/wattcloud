<script lang="ts">
  import { getContext, onMount } from 'svelte';
  import type { DataProvider } from '../../byo/DataProvider';
  import type { TrashEntry } from '../../byo/DataProvider';
  import ConfirmModal from '../ConfirmModal.svelte';
  import Icon from '../Icons.svelte';
  import Trash from 'phosphor-svelte/lib/Trash';
  import { byoToast } from '../../byo/stores/byoToasts';

  export let onBack: () => void;

  const dataProvider = getContext<{ current: DataProvider }>('byo:dataProvider').current;

  let entries: TrashEntry[] = [];
  let loading = true;

  // Confirm modal state
  let confirmOpen = false;
  let confirmTitle = '';
  let confirmMessage = '';
  let confirmAction: (() => Promise<void>) | null = null;
  let confirmDanger = false;

  // Per-entry blob check state
  let blobCheckPending = new Set<number>();

  onMount(() => {
    loadTrash();
  });

  function loadTrash() {
    loading = true;
    try {
      entries = dataProvider.listTrash();
    } catch (e: any) {
      byoToast.show(e.message ?? 'Failed to load trash', { icon: 'danger' });
    } finally {
      loading = false;
    }
  }

  async function checkBlob(entry: TrashEntry) {
    if (entry.item_type !== 'file') return;
    blobCheckPending = new Set([...blobCheckPending, entry.id]);
    try {
      const available = await dataProvider.checkBlobAvailability(entry);
      entries = entries.map((e) =>
        e.id === entry.id ? { ...e, blob_available: available } : e,
      );
    } finally {
      blobCheckPending = new Set([...blobCheckPending].filter((id) => id !== entry.id));
    }
  }

  async function handleRestore(entry: TrashEntry) {
    if (entry.item_type === 'file' && entry.blob_available === false) {
      // Blob gone — only option is permanent delete
      showConfirm(
        'Data Unavailable',
        `"${itemName(entry)}" can no longer be restored — its data was deleted from the provider. Permanently remove this entry?`,
        () => doDelete(entry.id),
        true,
      );
      return;
    }

    try {
      const ok = await dataProvider.restoreItem(entry.id);
      if (!ok) {
        // Blob check failed during restore
        entries = entries.map((e) =>
          e.id === entry.id ? { ...e, blob_available: false } : e,
        );
        return;
      }
      entries = entries.filter((e) => e.id !== entry.id);
    } catch (e: any) {
      byoToast.show(e.message ?? 'Restore failed', { icon: 'danger' });
    }
  }

  async function doDelete(trashId: number) {
    try {
      await dataProvider.permanentDelete(trashId);
      entries = entries.filter((e) => e.id !== trashId);
    } catch (e: any) {
      byoToast.show(e.message ?? 'Delete failed', { icon: 'danger' });
    }
  }

  function confirmDelete(entry: TrashEntry) {
    showConfirm(
      'Delete Permanently',
      `Permanently delete "${itemName(entry)}"? This cannot be undone.`,
      () => doDelete(entry.id),
      true,
    );
  }

  async function handleEmptyTrash() {
    showConfirm(
      'Empty Trash',
      `Permanently delete all ${entries.length} item${entries.length !== 1 ? 's' : ''} in trash? This cannot be undone.`,
      async () => {
        await dataProvider.emptyTrash();
        entries = [];
      },
      true,
    );
  }

  function showConfirm(
    title: string,
    message: string,
    action: () => Promise<void>,
    danger = false,
  ) {
    confirmTitle = title;
    confirmMessage = message;
    confirmAction = action;
    confirmDanger = danger;
    confirmOpen = true;
  }

  async function handleConfirm() {
    confirmOpen = false;
    if (confirmAction) {
      try {
        await confirmAction();
      } catch (e: any) {
        byoToast.show(e.message ?? 'Operation failed', { icon: 'danger' });
      }
      confirmAction = null;
    }
  }

  function itemName(entry: TrashEntry): string {
    try {
      const data = JSON.parse(entry.data) as Record<string, unknown>;
      return (data['decrypted_name'] as string) || `Item #${entry.original_id}`;
    } catch {
      return `Item #${entry.original_id}`;
    }
  }

  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        month: 'short', day: 'numeric', year: 'numeric',
      });
    } catch {
      return iso;
    }
  }

  function daysUntilExpiry(expiresAt: string): number {
    const ms = new Date(expiresAt).getTime() - Date.now();
    return Math.max(0, Math.ceil(ms / (1000 * 60 * 60 * 24)));
  }
</script>

<div class="byo-trash">
  <div class="trash-header">
    <button class="back-btn" on:click={onBack} aria-label="Back">
      <Icon name="arrowLeft" size={20} />
    </button>
    <h2 class="trash-title">Trash</h2>
    {#if entries.length > 0}
      <button class="empty-btn" on:click={handleEmptyTrash}>
        Empty Trash
      </button>
    {/if}
  </div>

  {#if loading}
    <div class="loading">
      <div class="spinner"></div>
      <p>Loading…</p>
    </div>

  {:else if entries.length === 0}
    <div class="empty-state">
      <Trash size={56} weight="light" color="var(--text-disabled, #616161)" />
      <p class="empty-heading">Nothing in trash</p>
      <p class="empty-sub">Deleted files you can still restore appear here for 30 days.</p>
    </div>

  {:else}
    <div class="entry-list">
      {#each entries as entry (entry.id)}
        <div class="entry" class:unavailable={entry.blob_available === false}>
          <div class="entry-icon" aria-hidden="true">
            <Icon name={entry.item_type === 'folder' ? 'folder' : 'file'} size={22} />
          </div>

          <div class="entry-info">
            <span class="entry-name">{itemName(entry)}</span>
            <span class="entry-meta">
              Deleted {formatDate(entry.deleted_at)}
              · Expires in {daysUntilExpiry(entry.expires_at)} day{daysUntilExpiry(entry.expires_at) !== 1 ? 's' : ''}
            </span>

            {#if entry.item_type === 'file'}
              {#if entry.blob_available === null || entry.blob_available === undefined}
                <button
                  class="check-blob-btn"
                  on:click={() => checkBlob(entry)}
                  disabled={blobCheckPending.has(entry.id)}
                >
                  {blobCheckPending.has(entry.id) ? 'Checking…' : 'Check availability'}
                </button>
              {:else if entry.blob_available === false}
                <span class="blob-unavailable">Data unavailable on provider</span>
              {:else}
                <span class="blob-available">Data available</span>
              {/if}
            {/if}
          </div>

          <div class="entry-actions">
            <button
              class="action-btn restore-btn"
              on:click={() => handleRestore(entry)}
              title="Restore"
            >
              <Icon name="refresh" size={16} />
              Restore
            </button>
            <button
              class="action-btn delete-btn"
              on:click={() => confirmDelete(entry)}
              title="Delete permanently"
            >
              <Icon name="trash" size={16} />
            </button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<ConfirmModal
  isOpen={confirmOpen}
  title={confirmTitle}
  message={confirmMessage}
  confirmText={confirmDanger ? 'Delete' : 'Confirm'}
  confirmClass={confirmDanger ? 'btn-danger' : 'btn-primary'}
  on:confirm={handleConfirm}
  on:cancel={() => { confirmOpen = false; confirmAction = null; }}
/>

<style>
  .byo-trash {
    display: flex;
    flex-direction: column;
    height: 100%;
    overflow: hidden;
    box-sizing: border-box;
  }

  /* Desktop: shift content clear of the fixed shared Drawer so the
     trash list isn't rendered underneath the sidebar. */
  @media (min-width: 600px) {
    .byo-trash {
      padding-left: var(--drawer-current-width, var(--drawer-width));
      transition: padding-left 0.2s ease;
    }
  }

  .trash-header {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-md, 16px);
    border-bottom: 1px solid var(--border, #2E2E2E);
    flex-shrink: 0;
  }

  .back-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    background: none;
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-pill, 9999px);
    color: var(--text-secondary, #999999);
    cursor: pointer;
    transition: all 150ms;
  }

  .back-btn:hover {
    background: var(--bg-surface-hover, #2E2E2E);
    color: var(--text-primary, #EDEDED);
  }

  .trash-title {
    flex: 1;
    margin: 0;
    font-size: var(--t-title-size, 1rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }

  .empty-btn {
    padding: var(--sp-xs, 4px) var(--sp-sm, 8px);
    background: none;
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-pill, 9999px);
    color: var(--danger, #D64545);
    font-size: var(--t-label-size, 0.75rem);
    cursor: pointer;
    transition: all 150ms;
  }

  .empty-btn:hover {
    background: var(--danger-muted, #3D1F1F);
  }


  .loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-2xl, 48px);
    color: var(--text-secondary, #999999);
  }

  .spinner {
    width: 28px;
    height: 28px;
    border: 2px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-2xl, 48px) var(--sp-md, 16px);
    text-align: center;
  }
  .empty-heading {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }
  .empty-sub {
    margin: 0;
    font-size: var(--t-body-sm-size, .8125rem);
    color: var(--text-secondary, #999);
  }

  .empty-sub {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-disabled, #616161);
  }

  .entry-list {
    flex: 1;
    overflow-y: auto;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  /* §14.1 — 64dp rows with 40dp thumbnail icon box. */
  .entry {
    display: flex;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    min-height: 64px;
    transition: border-color 150ms;
  }

  .entry.unavailable {
    opacity: 0.65;
    border-color: var(--danger, #D64545);
  }

  .entry-icon {
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--r-thumbnail, 8px);
    background: var(--bg-surface-raised, #262626);
    color: var(--text-disabled, #616161);
    flex-shrink: 0;
  }

  .entry-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .entry-name {
    /* §14.1: name uses --t-body, not body-sm. */
    font-size: var(--t-body-size, 0.9375rem);
    color: var(--text-primary, #EDEDED);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .entry-meta {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
  }

  .check-blob-btn {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent-text, #5FDB8A);
    font-size: var(--t-label-size, 0.75rem);
    cursor: pointer;
    text-align: left;
    width: fit-content;
  }

  .check-blob-btn:hover { text-decoration: underline; }
  .check-blob-btn:disabled { color: var(--text-disabled, #616161); cursor: default; }

  .blob-unavailable {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--danger, #D64545);
  }

  .blob-available {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--accent-text, #5FDB8A);
  }

  .entry-actions {
    display: flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    flex-shrink: 0;
  }

  .action-btn {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: var(--sp-xs, 4px) var(--sp-sm, 8px);
    background: none;
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-pill, 9999px);
    color: var(--text-secondary, #999999);
    font-size: var(--t-label-size, 0.75rem);
    cursor: pointer;
    transition: all 150ms;
  }

  .restore-btn:hover {
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
    background: var(--accent-muted, #1B3627);
  }

  .delete-btn:hover {
    border-color: var(--danger, #D64545);
    color: var(--danger, #D64545);
    background: var(--danger-muted, #3D1F1F);
  }
</style>
