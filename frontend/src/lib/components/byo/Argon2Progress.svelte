<script lang="ts">
  import Cloud from 'phosphor-svelte/lib/Cloud';
  import CloudCheck from 'phosphor-svelte/lib/CloudCheck';

  interface Props {
    done?: boolean;
    memoryMb?: number;
    /** Optional one-line status to show after Argon2 completes (e.g.
     * "Writing device slot…"). When set, replaces the static sublabel
     * so the user has a sense of which late-unlock phase is running. */
    phase?: string;
  }

  let { done = false, memoryMb = 128, phase = '' }: Props = $props();

  // No fake timer — show honest indeterminate shimmer until done.
  let label = $derived(done ? 'Vault unlocked' : 'Unlocking vault…');
</script>

<div
  class="argon2-progress"
  role="status"
  aria-live="polite"
  aria-busy={!done}
  aria-label={label}
>
  <div class="icon-wrap" aria-hidden="true">
    {#if done}
      <CloudCheck size={36} weight="duotone" color="var(--accent, #2EB860)" />
    {:else}
      <div class="cloud-pulse">
        <Cloud size={36} weight="duotone" color="var(--accent, #2EB860)" />
      </div>
    {/if}
  </div>
  <div class="content">
    <p class="label">{done ? 'Keys derived' : 'Deriving encryption keys…'}</p>
    <p class="sublabel">
      {#if done && phase}{phase}{:else}Using {memoryMb} MB of memory · This takes a few seconds{/if}
    </p>
    <div class="bar-track" role="progressbar" aria-valuenow={done ? 100 : undefined} aria-valuemin={0} aria-valuemax={100}>
      {#if done}
        <div class="bar-fill done-fill"></div>
      {:else}
        <div class="bar-shimmer"></div>
      {/if}
    </div>
    <p class="percent">{done ? '100%' : ''}</p>
  </div>
</div>

<style>
  .argon2-progress {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
    align-items: center;
    padding: var(--sp-lg, 24px);
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
  }

  .icon-wrap {
    flex-shrink: 0;
    width: 48px;
    height: 48px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  /* Pulsing cloud — subtle breathe between 90% and 100% scale so the
     motion reads as "in progress" without looking like a loading bar.
     Replaces the border-spinner with the project's cloud motif. */
  .cloud-pulse {
    display: inline-flex;
    animation: cloud-pulse 1.6s ease-in-out infinite;
    transform-origin: center;
  }

  @keyframes cloud-pulse {
    0%, 100% { transform: scale(0.9); opacity: 0.7; }
    50%      { transform: scale(1); opacity: 1; }
  }

  @media (prefers-reduced-motion: reduce) {
    .cloud-pulse { animation: none; transform: none; opacity: 1; }
  }

  .content {
    width: 100%;
    min-width: 0;
    text-align: center;
  }

  .label {
    margin: 0 0 var(--sp-xs, 4px);
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }

  .sublabel {
    margin: 0 0 var(--sp-sm, 8px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
  }

  .bar-track {
    width: 100%;
    height: 6px;
    background: var(--bg-input, #212121);
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: var(--sp-xs, 4px);
    position: relative;
  }

  /* Indeterminate shimmer */
  .bar-shimmer {
    position: absolute;
    inset: 0;
    background: linear-gradient(
      90deg,
      transparent 0%,
      var(--accent, #2EB860) 40%,
      var(--accent-text, #5FDB8A) 50%,
      var(--accent, #2EB860) 60%,
      transparent 100%
    );
    background-size: 200% 100%;
    animation: shimmer 1.6s ease-in-out infinite;
    border-radius: 3px;
  }

  @keyframes shimmer {
    0% { background-position: 200% center; }
    100% { background-position: -200% center; }
  }

  @media (prefers-reduced-motion: reduce) {
    .bar-shimmer {
      animation: none;
      background: var(--accent-muted, rgba(46, 184, 96, 0.35));
    }
  }

  /* Snap to full when done */
  .bar-fill.done-fill {
    height: 100%;
    width: 100%;
    background: var(--accent, #2EB860);
    border-radius: 3px;
  }

  .percent {
    margin: 0;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
    text-align: center;
    min-height: 1em;
  }
</style>
