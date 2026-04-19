<script lang="ts">
  /**
   * ProviderMoveSheet — bottom sheet for cross-provider file move.
   */
  import { createEventDispatcher } from 'svelte';
  import { slide, fade } from 'svelte/transition';
  import type { ProviderMeta } from '../../byo/stores/vaultStore';
  import ArrowSquareOut from 'phosphor-svelte/lib/ArrowSquareOut';
  import WifiSlash from 'phosphor-svelte/lib/WifiSlash';

  const reducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  export let open = false;
  export let fileCount = 0;
  export let currentProviderId = '';
  export let providers: ProviderMeta[] = [];
  export let progress: { done: number; total: number } | null = null;
  export let fileErrors: { fileId: number; fileName: string; error: string }[] = [];
  export let succeededCount: number | null = null;

  const dispatch = createEventDispatcher<{
    confirm: { destProviderId: string };
    retry: { fileIds: number[] };
    skipErrors: { fileId: number };
    close: void;
  }>();

  let selectedProviderId: string | null = null;
  let confirmed = false;

  $: otherProviders = providers.filter(p => p.providerId !== currentProviderId);

  $: if (!open) {
    selectedProviderId = null;
    confirmed = false;
  }

  function selectProvider(p: ProviderMeta) {
    if (p.status === 'offline' || p.status === 'error' || p.status === 'unauthorized') return;
    selectedProviderId = p.providerId;
  }

  function handleConfirm() {
    if (!selectedProviderId) return;
    confirmed = true;
    dispatch('confirm', { destProviderId: selectedProviderId });
  }

  function providerIcon(type: string): string {
    const icons: Record<string, string> = {
      gdrive: 'G', dropbox: 'D', onedrive: 'O', webdav: 'W', sftp: 'S', box: 'B', pcloud: 'P', s3: 'S3',
    };
    return icons[type] ?? '?';
  }

  $: inProgress = progress !== null;
  $: progressPct = progress ? Math.round((progress.done / Math.max(progress.total, 1)) * 100) : 0;
  $: isSuccess = succeededCount !== null && fileErrors.length === 0;
  $: hasErrors = fileErrors.length > 0;
  $: showResult = succeededCount !== null;
</script>

{#if open}
  <div
    class="sheet-backdrop"
    role="button"
    tabindex="-1"
    aria-label="Close"
    on:click={() => !inProgress && dispatch('close')}
    on:keydown={(e) => e.key === 'Escape' && !inProgress && dispatch('close')}
    transition:fade={{ duration: reducedMotion ? 0 : 150 }}
  />

  <div class="sheet" role="dialog" aria-modal="true" aria-label="Move to provider" transition:slide={{ duration: reducedMotion ? 0 : 220, axis: 'y' }}>
    <div class="sheet-handle" aria-hidden="true" />

    {#if inProgress}
      <div class="sheet-section">
        <h2 class="sheet-title">Moving files…</h2>
        <p class="sheet-subtitle">Transferring {fileCount} file{fileCount !== 1 ? 's' : ''} to another provider</p>
        <div class="progress-bar-track">
          <div class="progress-bar-fill" style="width: {progressPct}%"></div>
        </div>
        <p class="progress-label">{progress?.done ?? 0} of {progress?.total ?? 0} files</p>
      </div>

    {:else if showResult && isSuccess}
      <!-- Success state (§29.1 solid-with-check) -->
      <div class="sheet-section success-section">
        <div class="success-icon" aria-hidden="true">
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
            <path d="M24 4 L40 13 L40 35 L24 44 L8 35 L8 13 Z"
              fill="var(--accent-muted, rgba(46,184,96,0.15))"
              stroke="var(--accent, #2EB860)" stroke-width="2" stroke-linejoin="round"/>
            <polyline points="16,24 22,30 32,18"
              stroke="var(--accent, #2EB860)" stroke-width="2.5"
              stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <p class="success-label">Integrity verified · {succeededCount} file{succeededCount !== 1 ? 's' : ''}</p>
      </div>
      <div class="sheet-actions">
        <button class="btn btn-primary" on:click={() => dispatch('close')}>Done</button>
      </div>

    {:else if showResult && hasErrors}
      <!-- Partial success / error list -->
      {#if succeededCount !== null && succeededCount > 0}
        <div class="sheet-section">
          <h2 class="sheet-title">{succeededCount} of {(succeededCount ?? 0) + fileErrors.length} moved</h2>
          <p class="sheet-subtitle">{fileErrors.length} file{fileErrors.length !== 1 ? 's' : ''} failed.</p>
        </div>
      {:else}
        <div class="sheet-section">
          <h2 class="sheet-title">Move failed</h2>
          <p class="sheet-subtitle">{fileErrors.length} file{fileErrors.length !== 1 ? 's' : ''} could not be moved.</p>
        </div>
      {/if}

      <div class="error-list">
        {#each fileErrors as e (e.fileId)}
          <div class="error-row">
            <div class="error-info">
              <span class="error-filename">{e.fileName}</span>
              <span class="error-msg">{e.error}</span>
            </div>
            <div class="error-actions">
              <button class="btn-sm btn-sm-primary" on:click={() => dispatch('retry', { fileIds: [e.fileId] })}>Retry</button>
              <button class="btn-sm btn-sm-ghost" on:click={() => dispatch('skipErrors', { fileId: e.fileId })}>Skip</button>
            </div>
          </div>
        {/each}
      </div>

      <div class="sheet-actions">
        <button class="btn btn-ghost" on:click={() => dispatch('close')}>Close</button>
        <button class="btn btn-primary" on:click={() => dispatch('retry', { fileIds: fileErrors.map(e => e.fileId) })}>
          Retry all
        </button>
      </div>

    {:else if confirmed}
      <div class="sheet-section">
        <h2 class="sheet-title">Starting move…</h2>
      </div>

    {:else}
      <div class="sheet-section">
        <h2 class="sheet-title">Move to provider</h2>
        <p class="sheet-subtitle">
          Move {fileCount} file{fileCount !== 1 ? 's' : ''} to another storage provider.
          Each file will be decrypted in memory and re-uploaded encrypted. Source copies are deleted on success.
        </p>
      </div>

      <div class="provider-list" role="listbox" aria-label="Select destination provider">
        {#each otherProviders as p (p.providerId)}
          {@const isOffline = p.status === 'offline' || p.status === 'error' || p.status === 'unauthorized'}
          <button
            class="provider-row"
            class:selected={p.providerId === selectedProviderId}
            class:offline={isOffline}
            disabled={isOffline}
            role="option"
            aria-selected={p.providerId === selectedProviderId}
            title={isOffline ? `${p.displayName} is offline` : p.displayName}
            on:click={() => selectProvider(p)}
          >
            <span class="prow-icon" aria-hidden="true">{providerIcon(p.type)}</span>
            <span class="prow-name">{p.displayName}</span>
            {#if isOffline}
              <WifiSlash size={14} class="prow-offline-icon" />
              <span class="prow-offline-label">Offline</span>
            {:else if p.providerId === selectedProviderId}
              <span class="prow-check" aria-hidden="true">✓</span>
            {/if}
          </button>
        {/each}

        {#if otherProviders.length === 0}
          <p class="empty-providers">No other providers connected. Add a second provider first.</p>
        {/if}
      </div>

      <div class="sheet-actions">
        <button class="btn btn-ghost" on:click={() => dispatch('close')}>Cancel</button>
        <button
          class="btn btn-primary"
          disabled={!selectedProviderId}
          on:click={handleConfirm}
        >
          <ArrowSquareOut size={16} />
          Move here
        </button>
      </div>
    {/if}
  </div>
{/if}

<style>
  .sheet-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: 200;
  }

  .sheet {
    position: fixed;
    left: 0;
    right: 0;
    bottom: 0;
    z-index: 201;
    background: var(--bg-surface, #1A1A1A);
    border-radius: var(--r-lg, 16px) var(--r-lg, 16px) 0 0;
    border-top: 1px solid var(--border, #2E2E2E);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px) calc(var(--sp-lg, 24px) + env(safe-area-inset-bottom));
    max-height: 80dvh;
    overflow-y: auto;
  }

  .sheet-handle {
    width: 36px;
    height: 4px;
    border-radius: 2px;
    background: var(--border, #2E2E2E);
    margin: 0 auto var(--sp-md, 16px);
  }

  .sheet-section {
    margin-bottom: var(--sp-md, 16px);
  }

  .sheet-title {
    font-size: var(--t-heading-size, 1.125rem);
    font-weight: 600;
    color: var(--text-primary, #ededed);
    margin: 0 0 var(--sp-xs, 4px);
  }

  .sheet-subtitle {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    margin: 0;
    line-height: 1.5;
  }

  /* Success state */
  .success-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: var(--sp-lg, 24px) 0 var(--sp-md, 16px);
    gap: var(--sp-sm, 8px);
  }

  .success-label {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--accent-text, #5FDB8A);
    font-weight: 500;
    margin: 0;
  }

  /* Error list */
  .error-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-bottom: var(--sp-md, 16px);
    max-height: 200px;
    overflow-y: auto;
  }

  .error-row {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, rgba(214, 69, 69, 0.08));
    border-radius: var(--r-md, 10px);
  }

  .error-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .error-filename {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #ededed);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .error-msg {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--danger, #D64545);
  }

  .error-actions {
    display: flex;
    gap: var(--sp-xs, 4px);
    flex-shrink: 0;
  }

  .btn-sm {
    padding: 3px 10px;
    border-radius: var(--r-pill, 9999px);
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 500;
    cursor: pointer;
    border: 1px solid transparent;
    white-space: nowrap;
  }

  .btn-sm-primary {
    background: var(--accent-muted, rgba(46, 184, 96, 0.12));
    color: var(--accent-text, #5FDB8A);
    border-color: var(--accent, #2EB860);
  }

  .btn-sm-ghost {
    background: transparent;
    color: var(--text-secondary, #999);
    border-color: var(--border, #2E2E2E);
  }

  /* Provider list */
  .provider-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
    margin-bottom: var(--sp-md, 16px);
  }

  .provider-row {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    border-radius: var(--r-md, 10px);
    background: var(--bg-surface-raised, #1E1E1E);
    border: 1px solid var(--border, #2E2E2E);
    color: var(--text-primary, #ededed);
    cursor: pointer;
    text-align: left;
    transition: background 120ms, border-color 120ms;
    width: 100%;
  }

  .provider-row:hover:not(:disabled) {
    background: var(--surface-2, #222);
    border-color: var(--border-bright, #3E3E3E);
  }

  .provider-row.selected {
    background: var(--accent-muted, rgba(46, 184, 96, 0.12));
    border-color: var(--accent, #2EB860);
  }

  .provider-row.offline {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .prow-icon {
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 6px;
    background: var(--glass-bg, rgba(255,255,255,0.06));
    font-size: 0.7rem;
    font-weight: 700;
    flex-shrink: 0;
    color: var(--text-secondary, #999);
  }

  .provider-row.selected .prow-icon {
    background: var(--accent-muted, rgba(46, 184, 96, 0.2));
    color: var(--accent-text, #5FDB8A);
  }

  .prow-name { flex: 1; font-size: var(--t-body-size, 0.9375rem); }
  .prow-check { color: var(--accent, #2EB860); font-weight: 700; }
  .prow-offline-label { font-size: var(--t-label-size, 0.75rem); color: var(--danger, #D64545); }

  .empty-providers {
    padding: var(--sp-md, 16px);
    text-align: center;
    color: var(--text-disabled, #616161);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  /* Action buttons — stack on mobile */
  .sheet-actions {
    display: flex;
    gap: var(--sp-sm, 8px);
    justify-content: flex-end;
  }

  @media (max-width: 599px) {
    .sheet-actions {
      flex-direction: column-reverse;
    }
    .sheet-actions .btn {
      width: 100%;
      justify-content: center;
    }
  }

  .btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    border-radius: var(--r-pill, 9999px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 500;
    cursor: pointer;
    border: 1px solid transparent;
    transition: background 120ms;
  }

  .btn:disabled { opacity: 0.45; cursor: not-allowed; }

  .btn-ghost {
    background: transparent;
    color: var(--text-secondary, #999);
    border-color: var(--border, #2E2E2E);
  }
  .btn-ghost:hover:not(:disabled) { background: var(--surface-2, #222); }

  .btn-primary {
    background: var(--accent, #2EB860);
    color: var(--text-inverse, #000);
    border-color: var(--accent, #2EB860);
  }
  .btn-primary:hover:not(:disabled) {
    background: var(--accent-text, #5FDB8A);
    border-color: var(--accent-text, #5FDB8A);
  }

  /* Progress */
  .progress-bar-track {
    height: 6px;
    border-radius: 3px;
    background: var(--bg-surface-raised, #1E1E1E);
    margin: var(--sp-md, 16px) 0 var(--sp-xs, 4px);
    overflow: hidden;
  }

  .progress-bar-fill {
    height: 100%;
    border-radius: 3px;
    background: var(--accent, #2EB860);
    transition: width 300ms linear;
  }

  .progress-label {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-secondary, #999);
    text-align: center;
    margin: 0;
  }
</style>
