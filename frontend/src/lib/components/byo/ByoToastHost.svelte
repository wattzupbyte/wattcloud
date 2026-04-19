<!--
  ByoToastHost — renders the single active toast from the byoToast store.
  DESIGN.md §20 + §31.3 (toast gets glass treatment).
-->
<script lang="ts">
  import { fade, fly } from 'svelte/transition';
  import { byoToast } from '../../byo/stores/byoToasts';
  import HexShield from '../HexShield.svelte';

  const reducedMotion = typeof window !== 'undefined'
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
</script>

{#if $byoToast}
  {@const t = $byoToast}
  <div
    class="byo-toast"
    role="status"
    aria-live="polite"
    in:fly={{ y: reducedMotion ? 0 : 12, duration: reducedMotion ? 0 : 200 }}
    out:fade={{ duration: reducedMotion ? 0 : 200 }}
  >
    {#if t.icon === 'seal'}
      <HexShield size={18} variant="check" color="var(--accent, #2EB860)" fillColor="var(--accent-muted, #1B3627)" />
    {:else if t.icon === 'warn'}
      <HexShield size={18} variant="outline" color="var(--accent-warm-text, #F0C04A)" />
    {/if}
    <span class="toast-text">{t.text}</span>
    <button class="toast-dismiss" on:click={byoToast.dismiss} aria-label="Dismiss">×</button>
  </div>
{/if}

<style>
  .byo-toast {
    position: fixed;
    left: 50%;
    transform: translateX(-50%);
    bottom: calc(12px + env(safe-area-inset-bottom, 0px) + var(--bottom-nav-height, 56px) + 16px);
    z-index: var(--z-toast, 60);
    display: inline-flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    min-height: 48px;
    max-width: 400px;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    /* §31.3 toasts get glass-blur-light */
    background: var(--glass-bg, rgba(28, 28, 28, 0.82));
    backdrop-filter: var(--glass-blur-light, blur(12px));
    -webkit-backdrop-filter: var(--glass-blur-light, blur(12px));
    border: var(--glass-border, 1px solid rgba(255, 255, 255, 0.08));
    border-radius: var(--r-pill, 9999px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-sm-size, 0.8125rem);
    box-shadow: var(--glass-shadow, 0 8px 32px rgba(0, 0, 0, 0.4));
  }

  @supports not (backdrop-filter: blur(1px)) {
    .byo-toast {
      background: var(--bg-surface-raised, #262626);
    }
  }

  @media (min-width: 600px) {
    .byo-toast {
      /* No floating bottom nav on desktop — sit 24dp from bottom. */
      bottom: 24px;
    }
  }

  .toast-text {
    flex: 1;
    line-height: 1.4;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .toast-dismiss {
    flex-shrink: 0;
    margin-left: var(--sp-xs, 4px);
    width: 24px;
    height: 24px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: none;
    border: none;
    color: var(--text-secondary, #999);
    font-size: 1rem;
    line-height: 1;
    cursor: pointer;
    border-radius: 50%;
    transition: background 120ms, color 120ms;
  }

  .toast-dismiss:hover {
    background: var(--bg-surface-hover, #2E2E2E);
    color: var(--text-primary, #EDEDED);
  }
</style>
