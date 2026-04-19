<script lang="ts">
  import { createEventDispatcher, onMount } from 'svelte';

  /**
   * Full-screen overlay shown during key rotation (compromise response).
   * Prevents navigation until complete or errored.
   * Caller drives progress via updateProgress() / complete() / setError().
   */
  export let totalFiles: number;

  const dispatch = createEventDispatcher<{ complete: void; error: string }>();

  let filesProcessed = 0;
  let currentFileName = '';
  let error = '';
  let done = false;

  export function updateProgress(processed: number, fileName: string) {
    filesProcessed = processed;
    currentFileName = fileName;
  }

  export function complete() {
    filesProcessed = totalFiles;
    done = true;
    dispatch('complete');
  }

  export function setError(msg: string) {
    error = msg;
    dispatch('error', msg);
  }

  $: progressPct = totalFiles > 0 ? Math.round((filesProcessed / totalFiles) * 100) : 0;

  // Block navigation during rotation
  function handleBeforeUnload(e: BeforeUnloadEvent) {
    if (!done && !error) {
      e.preventDefault();
    }
  }
</script>

<svelte:window on:beforeunload={handleBeforeUnload} />

<div class="rotation-overlay" role="alertdialog" aria-modal="true" aria-label="Key rotation in progress">
  <div class="rotation-card">
    <div class="icon-wrap" class:error={!!error} class:done>
      {#if error}
        <!-- Error icon -->
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <circle cx="12" cy="12" r="10"/>
          <line x1="15" y1="9" x2="9" y2="15"/>
          <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
      {:else if done}
        <!-- Check icon -->
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
      {:else}
        <div class="spinner"></div>
      {/if}
    </div>

    <h2 class="title">
      {#if error}
        Rotation failed
      {:else if done}
        Rotation complete
      {:else}
        Rotating encryption keys…
      {/if}
    </h2>

    <p class="subtitle">
      {#if error}
        {error}
      {:else if done}
        All {totalFiles} file{totalFiles !== 1 ? 's' : ''} re-encrypted with new keys.
      {:else}
        Re-encrypting files with new keys. Do not close this tab.
      {/if}
    </p>

    {#if !error}
      <div class="progress-wrap">
        <div class="bar-track">
          <div class="bar-fill" class:done style="width: {progressPct}%"></div>
        </div>
        <div class="progress-stats">
          <span>{filesProcessed} / {totalFiles} files</span>
          <span>{progressPct}%</span>
        </div>
      </div>

      {#if currentFileName && !done}
        <p class="current-file" aria-live="polite">{currentFileName}</p>
      {/if}
    {/if}

    {#if done || error}
      <button class="btn btn-primary" on:click={() => dispatch(done ? 'complete' : 'error', error || '')}>
        {done ? 'Done' : 'Dismiss'}
      </button>
    {/if}
  </div>
</div>

<style>
  .rotation-overlay {
    position: fixed;
    inset: 0;
    background: rgba(18, 18, 18, 0.96);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
    padding: var(--sp-lg, 24px);
  }

  .rotation-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-2xl, 48px) var(--sp-xl, 32px);
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    max-width: 400px;
    width: 100%;
    text-align: center;
  }

  .icon-wrap {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 64px;
    height: 64px;
    background: var(--accent-muted, #1B3627);
    border-radius: 50%;
    color: var(--accent, #2EB860);
    flex-shrink: 0;
  }

  .icon-wrap.error {
    background: var(--danger-muted, #3D1F1F);
    color: var(--danger, #D64545);
  }

  .icon-wrap.done {
    background: var(--accent-muted, #1B3627);
    color: var(--accent, #2EB860);
  }

  .spinner {
    width: 32px;
    height: 32px;
    border: 3px solid rgba(46, 184, 96, 0.3);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

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
    line-height: 1.5;
  }

  .progress-wrap {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .bar-track {
    width: 100%;
    height: 8px;
    background: var(--bg-input, #212121);
    border-radius: 4px;
    overflow: hidden;
  }

  .bar-fill {
    height: 100%;
    background: var(--accent, #2EB860);
    border-radius: 4px;
    transition: width 300ms ease-out;
  }

  .bar-fill.done { background: var(--accent, #2EB860); }

  .progress-stats {
    display: flex;
    justify-content: space-between;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
  }

  .current-file {
    margin: 0;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
  }
</style>
