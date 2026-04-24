<script lang="ts">
  import { createEventDispatcher, onDestroy } from 'svelte';
  import { fade } from 'svelte/transition';
  import Copy from 'phosphor-svelte/lib/Copy';
  import Check from 'phosphor-svelte/lib/Check';
  import ArrowRight from 'phosphor-svelte/lib/ArrowRight';
  import Lock from 'phosphor-svelte/lib/Lock';

  export let recoveryKey: string;
  export let onConfirmed: () => void;
  export let embedded: boolean = false;

  const dispatch = createEventDispatcher();

  let confirmed = false;
  let copied = false;
  let displayKey = '';

  $: {
    if (recoveryKey) {
      const clean = recoveryKey.replace(/[-\s]/g, '');
      const groups: string[] = [];
      for (let i = 0; i < clean.length; i += 8) groups.push(clean.slice(i, i + 8));
      displayKey = groups.join(' ');
    } else {
      displayKey = '';
    }
  }

  async function copyToClipboard() {
    try {
      await navigator.clipboard.writeText(recoveryKey.replace(/[-\s]/g, ''));
      copied = true;
      setTimeout(() => { copied = false; }, 2000);
    } catch (e) {
      console.error('Failed to copy:', e);
    }
  }

  function handleContinue() {
    if (!confirmed) return;
    dispatch('confirmed');
    onConfirmed?.();
  }

  onDestroy(() => {
    displayKey = '';
    recoveryKey = '';
    confirmed = false;
  });
</script>

<div class="rkd" class:rkd-standalone={!embedded}>
  <div class="rkd-inner">
    <div class="rkd-hex" aria-hidden="true">
      <Lock size={72} weight="regular" color="var(--accent, #2EB860)" />
    </div>

    <p class="rkd-warn">
      This key is the only way to recover your vault if you forget your passphrase
      and lose every enrolled device. Nobody — not even the server — can recover it.
      Store it offline in a password manager or on paper.
    </p>

    <div class="rkd-key-field">
      <code class="rkd-key-code" aria-label="Your recovery key">{displayKey}</code>
      <button
        type="button"
        class="rkd-copy"
        on:click={copyToClipboard}
        aria-label={copied ? 'Copied' : 'Copy recovery key'}
      >
        {#if copied}
          <Check size={18} />
          <span in:fade={{ duration: 120 }}>Copied</span>
        {:else}
          <Copy size={18} />
          <span>Copy</span>
        {/if}
      </button>
    </div>

    <label class="rkd-confirm">
      <input type="checkbox" bind:checked={confirmed} />
      <span class="rkd-check" aria-hidden="true"></span>
      <span>I've saved this key somewhere safe. I understand that losing both my passphrase and this key means my files can't be recovered.</span>
    </label>

    <button
      class="btn btn-primary rkd-continue"
      on:click={handleContinue}
      disabled={!confirmed}
    >
      <span>Continue</span>
      <ArrowRight size={18} weight="bold" />
    </button>
  </div>
</div>

<style>
  .rkd {
    width: 100%;
  }
  .rkd-standalone {
    min-height: 100vh;
    min-height: 100dvh;
    background-color: var(--bg-base);
    padding: var(--sp-xl) var(--sp-md);
    display: flex;
    justify-content: center;
  }

  .rkd-inner {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md);
    width: 100%;
    max-width: 420px;
  }

  .rkd-standalone .rkd-inner {
    background: var(--bg-surface);
    border-radius: var(--r-card);
    padding: var(--sp-xl) var(--sp-lg);
  }

  .rkd-hex {
    align-self: center;
    margin-bottom: var(--sp-xs);
    color: var(--accent);
    filter: drop-shadow(0 0 10px rgba(46, 184, 96, 0.25));
  }

  .rkd-warn {
    margin: 0;
    padding: var(--sp-md);
    background: var(--accent-warm-muted);
    border: 1px solid var(--accent-warm);
    border-radius: var(--r-input);
    color: var(--accent-warm-text);
    font-size: var(--t-body-sm-size);
    line-height: 1.5;
  }

  .rkd-key-field {
    display: flex;
    align-items: stretch;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--r-input);
    overflow: hidden;
  }
  .rkd-key-field:focus-within {
    border-color: var(--accent);
  }

  .rkd-key-code {
    flex: 1;
    min-width: 0;
    padding: var(--sp-sm) var(--sp-md);
    font-family: var(--font-mono);
    font-size: var(--t-body-sm-size);
    line-height: 1.5;
    color: var(--text-primary);
    word-break: break-all;
    user-select: all;
  }

  .rkd-copy {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs);
    padding: 0 var(--sp-md);
    background: transparent;
    border: none;
    border-left: 1px solid var(--border);
    color: var(--text-secondary);
    font-size: var(--t-body-sm-size);
    font-weight: 500;
    cursor: pointer;
    transition: color var(--duration-normal) ease,
                background var(--duration-normal) ease;
    min-width: 88px;
  }
  .rkd-copy:hover {
    color: var(--accent-text);
    background: var(--bg-surface-hover);
  }

  .rkd-confirm {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-sm);
    padding: var(--sp-md);
    background: var(--bg-surface-raised);
    border: 1px solid var(--border);
    border-radius: var(--r-input);
    cursor: pointer;
    font-size: var(--t-body-sm-size);
    color: var(--text-primary);
    line-height: 1.5;
    transition: border-color var(--duration-normal) ease;
  }
  .rkd-confirm:hover { border-color: var(--accent); }

  .rkd-confirm input[type="checkbox"] {
    position: absolute;
    opacity: 0;
    width: 0;
    height: 0;
  }

  .rkd-check {
    flex-shrink: 0;
    width: 20px;
    height: 20px;
    border: 1.5px solid var(--border);
    border-radius: 4px;
    background: var(--bg-input);
    margin-top: 1px;
    position: relative;
    transition: background var(--duration-normal) ease,
                border-color var(--duration-normal) ease;
  }
  .rkd-confirm input:checked + .rkd-check {
    background: var(--accent);
    border-color: var(--accent);
  }
  .rkd-confirm input:checked + .rkd-check::after {
    content: '';
    position: absolute;
    left: 6px;
    top: 2px;
    width: 4px;
    height: 9px;
    border: solid var(--text-inverse);
    border-width: 0 2px 2px 0;
    transform: rotate(45deg);
  }

  .rkd-continue {
    width: 100%;
    margin-top: var(--sp-xs);
  }
</style>
