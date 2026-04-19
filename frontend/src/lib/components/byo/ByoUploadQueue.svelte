<script lang="ts">
  import { slide, fly, fade } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import {
    byoUploadQueue,
    isByoUploading,
    byoUploadCompletedCount,
    byoUploadErrorCount,
  } from '../../byo/stores/byoUploadQueue';
  import type { ByoUploadItem } from '../../byo/stores/byoUploadQueue';
  import { byoToast } from '../../byo/stores/byoToasts';
  import { playSealThunk } from '../../byo/soundFx';
  import Icon from '../Icons.svelte';

  let expanded = false;
  // Items currently showing the upload-seal animation (§29.3.2)
  let sealingItems = new Set<string>();
  let prevStatuses = new Map<string, string>();
  const reducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  $: if ($isByoUploading && !expanded) expanded = true;
  $: items = $byoUploadQueue.items as ByoUploadItem[];
  $: totalCount = items.length;
  $: completedCount = $byoUploadCompletedCount;
  $: errorCount = $byoUploadErrorCount;
  $: inProgressCount = items.filter((i) => i.status === 'uploading' || i.status === 'encrypting' || i.phase === 'paused').length;
  $: overallProgress = totalCount > 0
    ? Math.round(items.reduce((s, i) => s + (i.status === 'completed' ? 100 : i.progress), 0) / totalCount)
    : 0;

  // Detect uploading → completed transitions and trigger the seal animation
  // + fire a global seal toast (§29.3.2): shield completes, then toast appears.
  $: {
    const liveIds = new Set(items.map((i) => i.id));
    for (const item of items) {
      const prev = prevStatuses.get(item.id);
      const isNowComplete = item.status === 'completed';
      const wasInProgress = prev === 'uploading' || prev === 'encrypting';
      if (isNowComplete && wasInProgress) {
        // Optional audio cue (§29.6) — no-op unless user enabled sounds.
        playSealThunk();
        if (!reducedMotion) {
          sealingItems = new Set([...sealingItems, item.id]);
          setTimeout(() => {
            sealingItems = new Set([...sealingItems].filter((id) => id !== item.id));
          }, 1200); // 200 scale-in + 200 checkmark + 800 hold
          // Toast appears after the shield has held for a moment — matches
          // the "completion ritual" in §29.3.2 step 5.
          const name = item.overrideName || item.file.name;
          setTimeout(() => {
            byoToast.show(`Encrypted & saved · ${name}`, { icon: 'seal' });
          }, 900);
        } else {
          const name = item.overrideName || item.file.name;
          byoToast.show(`Encrypted & saved · ${name}`, { icon: 'seal' });
        }
      }
      prevStatuses.set(item.id, item.status);
    }
    // Prune entries for items removed from the queue (clearCompleted,
    // removeItem) so the status-shadow map doesn't leak across long
    // sessions.
    for (const id of prevStatuses.keys()) {
      if (!liveIds.has(id)) prevStatuses.delete(id);
    }
  }

  function statusIcon(item: ByoUploadItem): string {
    if (item.status === 'completed') return 'check';
    if (item.status === 'error') return 'error';
    if (item.phase === 'paused') return 'pause';
    return 'upload';
  }

  function formatBytes(bytes: number): string {
    if (bytes <= 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function formatEta(item: ByoUploadItem): string {
    if (!item.startedAt || item.bytesDone <= 0 || item.bytesTotal <= 0) return '';
    const elapsed = Date.now() - item.startedAt;
    if (elapsed < 2000) return ''; // too early for meaningful ETA
    const speed = item.bytesDone / elapsed; // bytes/ms
    if (speed <= 0) return '';
    const remaining = item.bytesTotal - item.bytesDone;
    if (remaining <= 0) return '';
    const etaMs = remaining / speed;
    if (etaMs < 10000) return '< 10s';
    if (etaMs < 60000) return `~${Math.round(etaMs / 1000)}s left`;
    return `~${Math.round(etaMs / 60000)}m left`;
  }

  function phaseLabel(item: ByoUploadItem): string {
    if (item.phase === 'paused') return 'Paused';
    if (item.phase === 'encrypting' || item.status === 'encrypting') return 'Encrypting…';
    if (item.phase === 'uploading' || item.status === 'uploading') return 'Uploading…';
    return '';
  }

  function isActiveUpload(item: ByoUploadItem): boolean {
    return item.status === 'uploading' || item.status === 'encrypting' || item.phase === 'paused';
  }
</script>

{#if items.length > 0}
  <div class="upload-queue" transition:slide={{ duration: reducedMotion ? 0 : 200 }}>
    <!-- Header / toggle -->
    <button class="queue-header" on:click={() => expanded = !expanded}>
      <Icon name="upload" size={16} />
      <span class="queue-label">
        {#if inProgressCount > 0}
          Uploading {inProgressCount} file{inProgressCount !== 1 ? 's' : ''}…
        {:else if errorCount > 0}
          {errorCount} upload error{errorCount !== 1 ? 's' : ''}
        {:else}
          {completedCount} / {totalCount} uploaded
        {/if}
      </span>
      {#if inProgressCount > 0}
        <span class="queue-progress">{overallProgress}%</span>
      {/if}
      <button class="clear-btn" on:click|stopPropagation={() => byoUploadQueue.clearCompleted()}>
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
            class:done={item.status === 'completed'}
            class:paused={item.phase === 'paused'}
            in:fly={{ y: reducedMotion ? 0 : 12, duration: reducedMotion ? 0 : 220, delay: reducedMotion ? 0 : Math.min(i * 30, 200), easing: quintOut }}
            out:fade={{ duration: reducedMotion ? 0 : 150 }}
          >
            <div class="item-info">
              <span class="item-name">{item.overrideName || item.file.name}</span>
              {#if item.status === 'error'}
                <span class="item-error">{item.error}</span>
              {:else if isActiveUpload(item)}
                <span class="item-meta">
                  <span class="item-phase">{phaseLabel(item)}</span>
                  {#if item.bytesTotal > 0 && (item.phase === 'uploading' || item.phase === 'paused')}
                    <span class="item-bytes">{formatBytes(item.bytesDone)} / {formatBytes(item.bytesTotal)}</span>
                  {/if}
                  {#if item.phase === 'uploading'}
                    {@const eta = formatEta(item)}
                    {#if eta}<span class="item-eta">{eta}</span>{/if}
                  {/if}
                </span>
              {/if}
            </div>

            <div class="item-right">
              {#if item.status === 'uploading' || item.status === 'encrypting' || item.phase === 'paused'}
                {#if item.phase !== 'paused'}
                  <!-- Progress bar + pause button -->
                  <div class="item-progress">
                    <div class="progress-bar" style="width: {item.progress}%"></div>
                  </div>
                  <button
                    class="action-btn"
                    on:click|stopPropagation={() => byoUploadQueue.pauseUpload(item.id)}
                    aria-label="Pause upload"
                    title="Pause"
                  >
                    <Icon name="pause" size={14} />
                  </button>
                {:else}
                  <!-- Resume button -->
                  <button
                    class="action-btn action-btn--resume"
                    on:click|stopPropagation={() => byoUploadQueue.resumeUpload(item.id)}
                    aria-label="Resume upload"
                    title="Resume"
                  >
                    <Icon name="play" size={14} />
                  </button>
                {/if}
              {:else if sealingItems.has(item.id)}
                <!-- Upload-Seal animation (§29.3.2): scale-in → checkmark → fade-out -->
                <div class="seal-anim" aria-hidden="true">
                  <svg width="24" height="24" viewBox="0 0 48 48" fill="none">
                    <path d="M24 4 L40 14 L40 34 L24 44 L8 34 L8 14 Z"
                      fill="var(--accent-muted,rgba(46,184,96,0.15))"
                      stroke="var(--accent,#2EB860)" stroke-width="2" stroke-linejoin="round"/>
                    <polyline points="15,24 22,31 33,17"
                      stroke="var(--accent,#2EB860)" stroke-width="3"
                      stroke-linecap="round" stroke-linejoin="round" fill="none"
                      class="seal-check"/>
                  </svg>
                </div>
              {:else if item.status === 'error'}
                <button
                  class="action-btn action-btn--retry"
                  on:click|stopPropagation={() => byoUploadQueue.retryUpload(item.id)}
                  aria-label="Retry upload"
                  title="Retry"
                >
                  <Icon name="retry" size={14} />
                </button>
              {:else}
                <Icon name={statusIcon(item)} size={16} />
              {/if}
              <button class="remove-btn" on:click={() => byoUploadQueue.removeItem(item.id)} aria-label="Remove">
                <Icon name="close" size={14} />
              </button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

<style>
  .upload-queue {
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

  .queue-progress {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--accent-text, #5FDB8A);
    font-weight: 600;
  }

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

  .item-eta {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
    font-variant-numeric: tabular-nums;
  }

  .item-eta::before { content: '·'; margin-right: 4px; }

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
  .action-btn--resume:hover { background: rgba(46, 184, 96, 0.12); }

  .action-btn--retry { border-color: var(--accent-warm, #E89C3A); color: var(--accent-warm, #E89C3A); }
  .action-btn--retry:hover { background: rgba(232, 156, 58, 0.12); }

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

  /* Upload-Seal micro-interaction (§29.3.2) */
  .seal-anim {
    width: 24px;
    height: 24px;
    animation: sealLifecycle 1.2s ease-out forwards;
  }
  .seal-check {
    stroke-dasharray: 30;
    stroke-dashoffset: 30;
    animation: drawCheck 200ms ease-out 200ms forwards;
  }
  @keyframes sealLifecycle {
    0%   { transform: scale(0); opacity: 1; }
    17%  { transform: scale(1); opacity: 1; }
    83%  { transform: scale(1); opacity: 1; }
    100% { transform: scale(1); opacity: 0; }
  }
  @keyframes drawCheck {
    to { stroke-dashoffset: 0; }
  }
  @media (prefers-reduced-motion: reduce) {
    .seal-anim { animation: none; opacity: 0; }
    .seal-check { animation: none; stroke-dashoffset: 0; }
  }
</style>
