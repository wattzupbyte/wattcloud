<!--
  ByoToastHost — renders the single active toast from the byoToast store.
  DESIGN.md §20 + §31.3 (toast gets glass treatment).
-->
<script lang="ts">
  import { fade, fly } from 'svelte/transition';
  import { byoToast } from '../../byo/stores/byoToasts';
  import CheckCircle from 'phosphor-svelte/lib/CheckCircle';
  import Warning from 'phosphor-svelte/lib/Warning';
  import WarningCircle from 'phosphor-svelte/lib/WarningCircle';

  const reducedMotion = typeof window !== 'undefined'
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
</script>

{#if $byoToast}
  {@const t = $byoToast}
  <div
    class="byo-toast"
    class:is-danger={t.icon === 'danger'}
    role={t.icon === 'danger' ? 'alert' : 'status'}
    aria-live={t.icon === 'danger' ? 'assertive' : 'polite'}
    in:fly={{ y: reducedMotion ? 0 : 12, duration: reducedMotion ? 0 : 200 }}
    out:fade={{ duration: reducedMotion ? 0 : 200 }}
  >
    {#if t.icon === 'seal'}
      <CheckCircle size={20} weight="fill" color="var(--accent, #2EB860)" />
    {:else if t.icon === 'warn'}
      <Warning size={20} weight="fill" color="var(--accent-warm-text, #F0C04A)" />
    {:else if t.icon === 'danger'}
      <WarningCircle size={20} weight="fill" color="var(--danger, #D64545)" />
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
    /* Top-align the icon + dismiss with the first line so wrapped body
       text sits flush to the left on subsequent lines. */
    display: inline-flex;
    /* Single-line toasts are the common case; centering keeps the icon,
       text and dismiss on the same optical baseline. For 2+ line toasts
       the icon/dismiss center against the text block, which reads better
       than sticking them at the top of a long error. */
    align-items: center;
    gap: var(--sp-sm, 8px);
    /* Set width (not just max-width) so short errors on mobile still span
       the page-content width — DESIGN.md §24 says mobile toast = screen
       width − 32dp. At ≥512px viewport this caps at the 480px desktop max. */
    width: min(480px, calc(100vw - 32px));
    /* Padding drives the height so single-line toasts stay compact while
       multi-line error toasts grow naturally. */
    padding: var(--sp-sm, 10px) var(--sp-md, 16px);
    /* §31.3 toasts get glass-blur-light. The pill border-radius below
       gracefully degrades to a stadium when the text wraps — r-card would
       look boxier for short messages. */
    background: var(--glass-bg, rgba(28, 28, 28, 0.82));
    backdrop-filter: var(--glass-blur-light, blur(12px));
    -webkit-backdrop-filter: var(--glass-blur-light, blur(12px));
    border: var(--glass-border, 1px solid rgba(255, 255, 255, 0.08));
    border-radius: var(--r-card, 16px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-sm-size, 0.8125rem);
    box-shadow: var(--glass-shadow, 0 8px 32px rgba(0, 0, 0, 0.4));
  }

  .byo-toast.is-danger {
    border-color: color-mix(in srgb, var(--danger, #D64545) 35%, transparent);
    background: color-mix(in srgb, var(--danger, #D64545) 12%, var(--glass-bg, rgba(28, 28, 28, 0.82)));
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
    /* Allow multiline — error messages in particular can be long and
       must be readable in full, not truncated with an ellipsis. */
    white-space: pre-wrap;
    overflow-wrap: anywhere;
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
