<script lang="ts">
  export let done = false;
  export let memoryMb = 128;

  // No fake timer — show honest indeterminate shimmer until done.
  $: label = done ? 'Vault unlocked' : 'Unlocking vault…';
</script>

<div
  class="argon2-progress"
  role="status"
  aria-live="polite"
  aria-busy={!done}
  aria-label={label}
>
  <div class="icon-wrap" aria-hidden="true">
    <div class="spinner" class:done></div>
  </div>
  <div class="content">
    <p class="label">{done ? 'Keys derived' : 'Deriving encryption keys…'}</p>
    <p class="sublabel">Using {memoryMb} MB of memory · This takes a few seconds</p>
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
    gap: var(--sp-md, 16px);
    align-items: flex-start;
    padding: var(--sp-lg, 24px);
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
  }

  .icon-wrap {
    flex-shrink: 0;
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .spinner {
    width: 36px;
    height: 36px;
    border: 3px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    transition: border-color 300ms ease;
  }

  .spinner.done {
    border-color: var(--accent, #2EB860);
    animation: none;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  @media (prefers-reduced-motion: reduce) {
    .spinner { animation: none; border-top-color: var(--accent, #2EB860); }
  }

  .content {
    flex: 1;
    min-width: 0;
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
    text-align: right;
    min-height: 1em;
  }
</style>
