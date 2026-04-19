<script lang="ts">
  /**
   * OfflineBanner — amber advisory shown inside an offline provider tab.
   *
   * Complements the ambient encryption strip (§29.4 offline = dashed grey),
   * which already signals offline state app-wide. This banner adds retry
   * affordance + provider name. Styled as an advisory (amber), not an
   * alert (red), because the flow is retry-driven and recovery is expected.
   */
  import { slide } from 'svelte/transition';
  import { createEventDispatcher } from 'svelte';
  import CloudSlash from 'phosphor-svelte/lib/CloudSlash';

  export let providerName: string;
  export let retrying = false;

  const dispatch = createEventDispatcher<{ retry: void }>();
</script>

<div class="offline-banner" role="status" aria-live="polite" transition:slide={{ duration: 200 }}>
  <CloudSlash size={16} weight="regular" />
  <span class="banner-text">
    <strong>{providerName}</strong> is offline. Showing cached files; read-only until reconnected.
  </span>
  <button
    class="retry-btn"
    disabled={retrying}
    on:click={() => dispatch('retry')}
    aria-label="Retry connection to {providerName}"
  >
    {retrying ? 'Retrying…' : 'Retry'}
  </button>
</div>

<style>
  .offline-banner {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--accent-warm-muted, #3D2E10);
    border-bottom: 1px solid color-mix(in srgb, var(--accent-warm, #E0A320) 40%, transparent);
    color: var(--accent-warm-text, #F0C04A);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .banner-text {
    flex: 1;
    line-height: 1.4;
  }

  .banner-text strong {
    color: var(--accent-warm-text, #F0C04A);
    font-weight: 600;
  }

  .retry-btn {
    flex-shrink: 0;
    min-height: 28px;
    padding: 4px var(--sp-md, 16px);
    border-radius: var(--r-pill, 9999px);
    border: 1px solid var(--accent-warm, #E0A320);
    background: transparent;
    color: var(--accent-warm-text, #F0C04A);
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 600;
    cursor: pointer;
    transition: background 120ms;
  }

  .retry-btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--accent-warm, #E0A320) 18%, transparent);
  }

  .retry-btn:disabled {
    opacity: 0.6;
    cursor: default;
  }
</style>
