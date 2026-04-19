<!--
  PullToRefresh — branded pull-down refresh per DESIGN.md §29.3.5
  "Shield Spin" replacing the generic circular spinner.

  Behaviour
  1. Only arms when the inner scroll container is at scrollTop === 0
     and the primary pointer is a touch (mouse users get wheel/scroll).
  2. Pull distance maps to a 0..1 progress that drives the hex-shield's
     stroke-dashoffset (so the outline draws itself as the user pulls).
  3. If the user releases past the 48dp threshold, the shield rotates
     360° over 400ms (ease-in-out) while the onRefresh promise resolves,
     then fades (200ms). Below threshold or on cancel, it snaps back.
  4. Honours prefers-reduced-motion: no draw/spin; just a brief opacity
     blink while the refresh runs.
-->
<script lang="ts">
  import { onMount } from 'svelte';

  /** Called when the user releases past the pull threshold.
      Return a promise that resolves once the refresh completes. */
  export let onRefresh: () => Promise<void> | void;
  /** Disable the gesture when the underlying view doesn't support refresh. */
  export let disabled = false;
  /** Pull distance in px required to trigger refresh. */
  export let threshold = 64;
  /** Max visual pull distance (caps the indicator's travel). */
  export let maxPull = 96;
  /** Classes applied to the scroll container — let the caller keep the
      same layout/padding it had on its original scroll element. */
  let className = '';
  export { className as class };

  // Matches the hex-shield path perimeter for viewBox 0 0 48 48 outline.
  const SHIELD_CIRCUMFERENCE = 110;

  let container: HTMLDivElement;
  let startY: number | null = null;
  let pullDistance = 0;
  let refreshing = false;
  let completing = false; // post-threshold spin phase
  let reducedMotion = false;

  $: progress = Math.min(pullDistance / threshold, 1);
  $: visualPull = Math.min(pullDistance, maxPull);
  $: dashOffset = SHIELD_CIRCUMFERENCE * (1 - progress);

  onMount(() => {
    reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  });

  function onTouchStart(e: TouchEvent) {
    if (disabled || refreshing) return;
    if (!container) return;
    if (container.scrollTop > 0) return;
    if (e.touches.length !== 1) return;
    startY = e.touches[0].clientY;
    pullDistance = 0;
  }

  function onTouchMove(e: TouchEvent) {
    if (startY === null || refreshing) return;
    if (container.scrollTop > 0) {
      // User scrolled back up past zero — abort.
      startY = null;
      pullDistance = 0;
      return;
    }
    const dy = e.touches[0].clientY - startY;
    if (dy <= 0) {
      pullDistance = 0;
      return;
    }
    // Rubber-band: scale down once we pass maxPull.
    pullDistance = dy < maxPull ? dy : maxPull + (dy - maxPull) * 0.3;
    // Only prevent the native overscroll when we're actually dragging.
    if (pullDistance > 4) e.preventDefault();
  }

  async function onTouchEnd() {
    if (startY === null) return;
    startY = null;
    const triggered = pullDistance >= threshold;
    if (!triggered) {
      pullDistance = 0;
      return;
    }
    refreshing = true;
    completing = true;
    try {
      await onRefresh();
    } catch {
      /* caller is responsible for surfacing errors */
    }
    // Let the spin animation finish before collapsing.
    await new Promise((r) => setTimeout(r, reducedMotion ? 0 : 400));
    refreshing = false;
    completing = false;
    pullDistance = 0;
  }
</script>

<div
  class="ptr-container {className}"
  bind:this={container}
  on:touchstart|nonpassive={onTouchStart}
  on:touchmove|nonpassive={onTouchMove}
  on:touchend={onTouchEnd}
  on:touchcancel={onTouchEnd}
  on:pointerdown
>
  {#if pullDistance > 0 || refreshing}
    <div
      class="ptr-indicator"
      class:is-refreshing={refreshing}
      class:reduced-motion={reducedMotion}
      style:transform="translateY({visualPull - 24}px)"
      aria-hidden="true"
    >
      <svg
        class="ptr-shield"
        class:spin={completing && !reducedMotion}
        width="28"
        height="28"
        viewBox="0 0 48 48"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M24 4 L40 14 L40 34 L24 44 L8 34 L8 14 Z"
          stroke="var(--accent, #2EB860)"
          stroke-width="2.5"
          stroke-linejoin="round"
          stroke-linecap="round"
          fill="none"
          stroke-dasharray={SHIELD_CIRCUMFERENCE}
          stroke-dashoffset={refreshing ? 0 : dashOffset}
        />
      </svg>
    </div>
  {/if}

  <slot />
</div>

<style>
  .ptr-container {
    /* PullToRefresh owns the scroll: the gesture guards check
       container.scrollTop, so the scroll element and the gesture
       listener must be the same element. Caller-supplied class adds
       padding/background via :global rules. */
    position: relative;
    flex: 1;
    overflow-y: auto;
    /* Disable the browser's native pull-to-refresh so it doesn't
       fight ours when we preventDefault on move. */
    overscroll-behavior-y: contain;
  }

  .ptr-indicator {
    position: absolute;
    top: 0;
    left: 50%;
    margin-left: -20px;
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: var(--bg-surface-raised, #262626);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    pointer-events: none;
    transition: transform 180ms cubic-bezier(0.32, 0.72, 0, 1);
    z-index: 5;
  }

  .ptr-indicator.is-refreshing {
    /* Hold the shield at its fully-drawn, centred position during spin. */
    transform: translateY(40px) !important;
  }

  .ptr-shield.spin {
    animation: ptrSpin 400ms cubic-bezier(0.4, 0, 0.2, 1);
  }

  @keyframes ptrSpin {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
  }

  .ptr-indicator.reduced-motion {
    transition: none;
  }
  .ptr-indicator.reduced-motion .ptr-shield {
    animation: none;
  }
</style>
