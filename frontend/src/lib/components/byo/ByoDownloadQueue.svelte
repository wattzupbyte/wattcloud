<script lang="ts">
  import { slide, fly, fade } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  const reducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  import {
    byoDownloadQueue,
    isByoDownloading,
    byoDownloadCompletedCount,
    byoDownloadErrorCount,
  } from '../../byo/stores/byoDownloadQueue';
  import type { ByoDownloadItem } from '../../byo/stores/byoDownloadQueue';
  import Icon from '../Icons.svelte';

  let expanded = false;

  $: if ($isByoDownloading && !expanded) expanded = true;
  $: items = $byoDownloadQueue.items as ByoDownloadItem[];
  $: totalCount = items.length;
  $: inProgressCount = items.filter((i) => i.status === 'downloading' || i.status === 'decrypting' || i.status === 'paused' || i.status === 'ready-to-save').length;
  $: errorCount = $byoDownloadErrorCount;

  function formatBytes(bytes: number): string {
    if (bytes <= 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function isActive(item: ByoDownloadItem): boolean {
    return item.status === 'downloading' || item.status === 'decrypting';
  }

  /** iOS buffered-save path: handle.save() MUST run synchronously inside
   *  the click event so the gesture propagates into navigator.share /
   *  <a download>. Don't await — the promise it returns is the share
   *  sheet lifecycle and blocking on it would detach the gesture.
   *  After the first tap we flip the item to 'completed' so the Save
   *  button doesn't stick around; if the user cancelled the share
   *  sheet they can still retry via the normal retry affordance. */
  function onIOSSaveTap(item: ByoDownloadItem) {
    const handle = item.iosSaveHandle;
    if (!handle) return;
    handle.save().catch((err: any) => {
      console.error('[byo-download] iOS save failed', err);
      byoDownloadQueue.setStatus(item.id, 'error', err?.message || 'Save failed');
    });
    byoDownloadQueue.setStatus(item.id, 'completed');
    byoDownloadQueue.clearIOSSaveHandle(item.id);
  }
</script>

{#if items.length > 0}
  <div class="download-queue" transition:slide={{ duration: reducedMotion ? 0 : 200 }}>
    <button class="queue-header" on:click={() => expanded = !expanded}>
      <Icon name="download" size={16} />
      <span class="queue-label">
        {#if inProgressCount > 0}
          Downloading {inProgressCount} file{inProgressCount !== 1 ? 's' : ''}…
        {:else if errorCount > 0}
          {errorCount} download error{errorCount !== 1 ? 's' : ''}
        {:else}
          {$byoDownloadCompletedCount} / {totalCount} downloaded
        {/if}
      </span>
      <button class="clear-btn" on:click|stopPropagation={() => byoDownloadQueue.clearCompleted()}>
        Clear done
      </button>
      <Icon name={expanded ? 'chevronUp' : 'chevronDown'} size={16} />
    </button>

    {#if expanded}
      <div class="queue-items" transition:slide={{ duration: reducedMotion ? 0 : 200 }}>
        {#each items as item, i (item.id)}
          <div
            class="queue-item"
            class:error={item.status === 'error'}
            class:done={item.status === 'completed' || item.status === 'cancelled'}
            class:paused={item.status === 'paused'}
            in:fly={{ y: reducedMotion ? 0 : 12, duration: reducedMotion ? 0 : 220, delay: reducedMotion ? 0 : Math.min(i * 30, 200), easing: quintOut }}
            out:fade={{ duration: reducedMotion ? 0 : 150 }}
          >
            <div class="item-info">
              <span class="item-name">{item.name}</span>
              {#if item.status === 'error'}
                <span class="item-error">{item.error}</span>
              {:else if item.status === 'ready-to-save'}
                <span class="item-meta">
                  <span class="item-phase">Tap Save to finish</span>
                  {#if item.bytesDone > 0}
                    <span class="item-bytes">{formatBytes(item.bytesDone)}</span>
                  {/if}
                </span>
              {:else if isActive(item) || item.status === 'paused'}
                <span class="item-meta">
                  <span class="item-phase">
                    {item.status === 'paused' ? 'Paused' : item.status === 'decrypting' ? 'Decrypting…' : 'Downloading…'}
                  </span>
                  {#if item.totalSize > 0}
                    <span class="item-bytes">{formatBytes(item.bytesDone)} / {formatBytes(item.totalSize)}</span>
                  {/if}
                </span>
              {/if}
            </div>

            <div class="item-right">
              {#if item.status === 'ready-to-save' && item.iosSaveHandle}
                <button
                  class="action-btn action-btn--save"
                  on:click|stopPropagation={() => onIOSSaveTap(item)}
                  aria-label="Save file"
                  title="Save"
                >
                  Save
                </button>
                <button class="remove-btn" on:click={() => byoDownloadQueue.cancelDownload(item.id)} aria-label="Cancel">
                  <Icon name="close" size={14} />
                </button>
              {:else if isActive(item)}
                <div class="item-progress">
                  <div class="progress-bar" style="width: {item.progress}%"></div>
                </div>
                <button
                  class="action-btn"
                  on:click|stopPropagation={() => byoDownloadQueue.pauseDownload(item.id)}
                  aria-label="Pause download"
                  title="Pause"
                >
                  <Icon name="pause" size={14} />
                </button>
                <button class="remove-btn" on:click={() => byoDownloadQueue.cancelDownload(item.id)} aria-label="Cancel">
                  <Icon name="close" size={14} />
                </button>
              {:else if item.status === 'paused'}
                <button
                  class="action-btn action-btn--resume"
                  on:click|stopPropagation={() => byoDownloadQueue.resumeDownload(item.id)}
                  aria-label="Resume download"
                  title="Resume"
                >
                  <Icon name="play" size={14} />
                </button>
                <button class="remove-btn" on:click={() => byoDownloadQueue.cancelDownload(item.id)} aria-label="Cancel">
                  <Icon name="close" size={14} />
                </button>
              {:else if item.status === 'error'}
                <button
                  class="action-btn action-btn--retry"
                  on:click|stopPropagation={() => byoDownloadQueue.retryDownload(item.id)}
                  aria-label="Retry download"
                  title="Retry"
                >
                  <Icon name="retry" size={14} />
                </button>
                <button class="remove-btn" on:click={() => byoDownloadQueue.removeItem(item.id)} aria-label="Remove">
                  <Icon name="close" size={14} />
                </button>
              {:else}
                <Icon name={item.status === 'completed' ? 'check' : item.status === 'cancelled' ? 'close' : 'download'} size={16} />
                <button class="remove-btn" on:click={() => byoDownloadQueue.removeItem(item.id)} aria-label="Remove">
                  <Icon name="close" size={14} />
                </button>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<style>
  .download-queue {
    border: var(--glass-border, 1px solid rgba(255, 255, 255, 0.08));
    border-radius: var(--r-input, 12px);
    background: var(--glass-bg, rgba(28, 28, 28, 0.65));
    backdrop-filter: var(--glass-blur-light, blur(12px));
    -webkit-backdrop-filter: var(--glass-blur-light, blur(12px));
    box-shadow: var(--glass-shadow, 0 8px 32px rgba(0, 0, 0, 0.4));
    overflow: hidden;
    margin: var(--sp-sm, 8px) 0;
  }

  .queue-header {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    width: 100%;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: none;
    border: none;
    cursor: pointer;
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-sm-size, 0.8125rem);
    min-height: 44px;
    text-align: left;
  }

  .queue-label { flex: 1; }

  .clear-btn {
    background: none;
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-pill, 9999px);
    color: var(--text-secondary, #999999);
    font-size: var(--t-label-size, 0.75rem);
    padding: 2px var(--sp-sm, 8px);
    cursor: pointer;
    white-space: nowrap;
  }

  .clear-btn:hover { background: var(--bg-surface-hover, #2E2E2E); }

  .queue-items {
    border-top: 1px solid var(--border, #2E2E2E);
    max-height: 220px;
    overflow-y: auto;
  }

  .queue-item {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-xs, 4px) var(--sp-md, 16px);
    min-height: 44px;
  }

  .queue-item.error { background: var(--danger-muted, #3D1F1F); }
  .queue-item.done { opacity: 0.6; }
  .queue-item.paused { background: rgba(255, 255, 255, 0.03); }

  .item-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .item-name {
    font-size: var(--t-body-sm-size, 0.8125rem);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--text-primary, #EDEDED);
  }

  .item-error {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--danger, #D64545);
  }

  .item-meta {
    display: flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    flex-wrap: wrap;
  }

  .item-phase {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-secondary, #999999);
  }

  .item-bytes {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
    font-variant-numeric: tabular-nums;
  }

  .item-bytes::before { content: '·'; margin-right: 4px; }

  .item-right {
    display: flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    flex-shrink: 0;
  }

  .item-progress {
    width: 60px;
    height: 4px;
    background: var(--bg-input, #212121);
    border-radius: 2px;
    overflow: hidden;
  }

  .progress-bar {
    height: 100%;
    background: var(--accent, #2EB860);
    border-radius: 2px;
    transition: width 300ms ease-out;
  }

  .action-btn {
    background: none;
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-pill, 9999px);
    color: var(--text-secondary, #999999);
    cursor: pointer;
    padding: 3px 5px;
    display: flex;
    align-items: center;
    min-width: 26px;
    min-height: 26px;
    justify-content: center;
  }

  .action-btn:hover { background: var(--bg-surface-hover, #2E2E2E); color: var(--text-primary, #EDEDED); }

  .action-btn--resume { border-color: var(--accent, #2EB860); color: var(--accent, #2EB860); }
  .action-btn--resume:hover { background: var(--accent-muted, rgba(46, 184, 96, 0.12)); }

  .action-btn--retry { border-color: var(--accent-warm, #E0A320); color: var(--accent-warm, #E0A320); }
  .action-btn--retry:hover { background: var(--accent-warm-muted, rgba(224, 163, 32, 0.12)); }

  /* iOS-only buffered-save CTA. Filled pill so it reads as the primary
     action in the row — the user's tap is the gesture navigator.share
     is waiting on. */
  .action-btn--save {
    background: var(--accent, #2EB860);
    border-color: var(--accent, #2EB860);
    color: #fff;
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 600;
    padding: 3px 10px;
    min-width: unset;
  }
  .action-btn--save:hover { opacity: 0.92; background: var(--accent, #2EB860); color: #fff; }

  .remove-btn {
    background: none;
    border: none;
    color: var(--text-disabled, #616161);
    cursor: pointer;
    padding: 2px;
    display: flex;
    align-items: center;
  }

  .remove-btn:hover { color: var(--text-secondary, #999999); }
</style>
