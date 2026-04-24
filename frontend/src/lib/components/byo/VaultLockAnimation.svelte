<!--
  VaultLockAnimation — §29.3.1 "The Vault Lock"
  Plays on cold unlock: cloud outline draws (600ms) → fade-out (200ms).
  Skipped if sessionStorage['sc-byo-unlocked-within-5min'] is set.
  prefers-reduced-motion: instant fade only.

  Per DESIGN.md §29.1, the cloud is never drawn with another icon inside
  it — no bolt, no padlock, no check. The draw-on itself is the moment.
-->
<script lang="ts">
  import { onMount, createEventDispatcher } from 'svelte';

  const dispatch = createEventDispatcher<{ done: void }>();

  const SESSION_KEY = 'sc-byo-unlocked-within-5min';
  // pathLength=100 normalises the cloud path length; dasharray/dashoffset
  // animate 100→0 to draw it on screen regardless of its real length.
  const SHIELD_CIRCUMFERENCE = 100;

  let visible = false;
  let shieldProgress = 0;
  let fading = false;
  let reducedMotion = false;

  onMount(() => {
    reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const alreadyUnlocked = sessionStorage.getItem(SESSION_KEY);
    if (alreadyUnlocked) {
      dispatch('done');
      return;
    }

    sessionStorage.setItem(SESSION_KEY, Date.now().toString());
    setTimeout(() => sessionStorage.removeItem(SESSION_KEY), 5 * 60 * 1000);

    if (reducedMotion) {
      visible = true;
      setTimeout(() => { fading = true; setTimeout(() => { visible = false; dispatch('done'); }, 200); }, 100);
      return;
    }

    visible = true;

    const startTime = performance.now();
    function animShield(now: number) {
      const t = Math.min((now - startTime) / 600, 1);
      shieldProgress = easeInOut(t);
      if (t < 1) {
        requestAnimationFrame(animShield);
      } else {
        shieldProgress = 1;
        // Hold the completed cloud briefly, then fade out.
        setTimeout(() => {
          fading = true;
          setTimeout(() => {
            visible = false;
            dispatch('done');
          }, 200);
        }, 300);
      }
    }
    requestAnimationFrame(animShield);
  });

  function easeInOut(t: number): number {
    return t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
  }

  $: dashOffset = SHIELD_CIRCUMFERENCE * (1 - shieldProgress);
</script>

{#if visible}
  <div
    class="vault-lock-overlay"
    class:fading
    role="presentation"
    aria-hidden="true"
  >
    <div class="vault-lock-content">
      <svg
        class="vault-shield"
        width="96"
        height="96"
        viewBox="0 0 48 48"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <!-- Tinted body appears once the outline is ~halfway drawn,
             so the cloud fills in as it seals. -->
        {#if shieldProgress > 0.5}
          <path
            d="M30 7.5 a16.5 16.5 0 0 0 -14.76 9.13 A12 12 0 1 0 13.5 40.5 H30 a16.5 16.5 0 0 0 0 -33 Z"
            fill="var(--accent-muted, #1B3627)"
            style="opacity: {(shieldProgress - 0.5) / 0.5 * 0.45}"
          />
        {/if}
        <path
          d="M30 7.5 a16.5 16.5 0 0 0 -14.76 9.13 A12 12 0 1 0 13.5 40.5 H30 a16.5 16.5 0 0 0 0 -33 Z"
          pathLength="100"
          stroke="var(--accent, #2EB860)"
          stroke-width="2.5"
          stroke-linejoin="round"
          stroke-linecap="round"
          fill="none"
          stroke-dasharray={SHIELD_CIRCUMFERENCE}
          stroke-dashoffset={dashOffset}
        />
      </svg>
    </div>
  </div>
{/if}

<style>
  .vault-lock-overlay {
    position: fixed;
    inset: 0;
    background: var(--bg-base, #121212);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
    opacity: 1;
    transition: opacity 200ms ease-out;
  }

  .vault-lock-overlay.fading {
    opacity: 0;
  }

  .vault-lock-content {
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .vault-shield {
    filter: drop-shadow(0 0 12px rgba(46, 184, 96, 0.4));
  }
</style>
