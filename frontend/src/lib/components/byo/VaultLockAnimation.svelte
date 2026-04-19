<!--
  VaultLockAnimation — §29.3.1 "The Vault Lock"
  Plays on cold unlock: hex-shield draws (600ms) → bolt slides (200ms) → fade-out (200ms).
  Skipped if sessionStorage['sc-byo-unlocked-within-5min'] is set.
  prefers-reduced-motion: instant fade only.
-->
<script lang="ts">
  import { onMount, createEventDispatcher } from 'svelte';
  import { fade } from 'svelte/transition';

  const dispatch = createEventDispatcher<{ done: void }>();

  const SESSION_KEY = 'sc-byo-unlocked-within-5min';
  const SHIELD_CIRCUMFERENCE = 258; // approximate SVG path length for the hex

  let visible = false;
  let shieldProgress = 0;  // 0→1 drives stroke-dashoffset
  let boltOpen = false;
  let fading = false;
  let reducedMotion = false;

  onMount(() => {
    reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const alreadyUnlocked = sessionStorage.getItem(SESSION_KEY);
    if (alreadyUnlocked) {
      dispatch('done');
      return;
    }

    // Mark session so the animation doesn't replay within 5 minutes
    sessionStorage.setItem(SESSION_KEY, Date.now().toString());
    setTimeout(() => sessionStorage.removeItem(SESSION_KEY), 5 * 60 * 1000);

    if (reducedMotion) {
      // Skip animation; just flash and done
      visible = true;
      setTimeout(() => { fading = true; setTimeout(() => { visible = false; dispatch('done'); }, 200); }, 100);
      return;
    }

    visible = true;

    // Phase 1: draw hex-shield over 600ms
    const startTime = performance.now();
    function animShield(now: number) {
      const t = Math.min((now - startTime) / 600, 1);
      shieldProgress = easeInOut(t);
      if (t < 1) {
        requestAnimationFrame(animShield);
      } else {
        shieldProgress = 1;
        // Phase 2: bolt slides open over 200ms
        boltOpen = true;
        setTimeout(() => {
          // Phase 3: fade out over 200ms
          fading = true;
          setTimeout(() => {
            visible = false;
            dispatch('done');
          }, 200);
        }, 200);
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
        <!-- Hex shield outline drawn via stroke-dashoffset animation -->
        <path
          d="M24 4 L40 14 L40 34 L24 44 L8 34 L8 14 Z"
          stroke="var(--accent, #2EB860)"
          stroke-width="2.5"
          stroke-linejoin="round"
          stroke-linecap="round"
          fill="none"
          stroke-dasharray={SHIELD_CIRCUMFERENCE}
          stroke-dashoffset={dashOffset}
        />
        <!-- Lock bolt: horizontal bar that slides right when boltOpen -->
        <line
          class="bolt"
          class:bolt-open={boltOpen}
          x1="18"
          y1="24"
          x2={boltOpen ? '30' : '24'}
          y2="24"
          stroke="var(--accent, #2EB860)"
          stroke-width="2.5"
          stroke-linecap="round"
        />
        <!-- Lock body circle -->
        {#if shieldProgress > 0.7}
          <circle
            cx="24"
            cy="24"
            r="5"
            stroke="var(--accent, #2EB860)"
            stroke-width="2"
            fill="none"
            style="opacity: {(shieldProgress - 0.7) / 0.3}"
          />
        {/if}
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

  .bolt {
    transition: x2 200ms ease-out;
  }
</style>
