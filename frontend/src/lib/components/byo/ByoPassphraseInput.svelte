<script lang="ts">
  import { onMount } from 'svelte';

  
  interface Props {
    /**
   * BYO passphrase input with entropy enforcement.
   *
   * Modes:
   *   create / change — two fields (passphrase + confirm) + zxcvbn entropy >= 60 gate
   *   unlock          — single field, min 16 chars only
   *
   * Security: passphrase is passed to the caller via `on:submit` as a string
   * and must be zeroized by the caller after use.
   */
    mode?: 'create' | 'unlock' | 'change';
    label?: any;
    submitLabel?: any;
    disabled?: boolean;
  onSubmit?: (...args: any[]) => void;
  }

  let {
    mode = 'create',
    label = mode === 'unlock' ? 'Passphrase' : 'New passphrase',
    submitLabel = mode === 'unlock' ? 'Unlock' : mode === 'change' ? 'Change Passphrase' : 'Continue',
    disabled = false,
    onSubmit
  }: Props = $props();
const MIN_LENGTH = 16;
  const MIN_ENTROPY = 60;

  let passphrase = $state('');
  let confirm = $state('');
  let showPass = $state(false);
  let showConfirm = $state(false);
  let error = $state('');
  let entropyBits = $state(0);
  let _entropyScore = $state(0);
  let entropyLoaded = false;
  let entropyLoading = false;
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  // Lazy-load zxcvbn on first input to keep initial bundle small
  type ZxcvbnResult = { guessesLog10: number; score: 0 | 1 | 2 | 3 | 4 };
  let zxcvbn: ((pw: string) => ZxcvbnResult) | null = $state(null);

  async function loadZxcvbn() {
    if (zxcvbn || entropyLoading) return;
    entropyLoading = true;
    try {
      const [core, langEn] = await Promise.all([
        import('@zxcvbn-ts/core'),
        import('@zxcvbn-ts/language-en'),
      ]);
      core.zxcvbnOptions.setOptions({
        translations: langEn.translations,
        graphs: (langEn as any).adjacencyGraphs,
        dictionary: langEn.dictionary,
      });
      zxcvbn = core.zxcvbn as unknown as (pw: string) => ZxcvbnResult;
      entropyLoaded = true;
      // Run initial check if passphrase already entered
      if (passphrase) checkEntropy(passphrase);
    } catch (e) {
      console.error('[ByoPassphraseInput] zxcvbn load failed:', e);
    } finally {
      entropyLoading = false;
    }
  }

  function checkEntropy(pw: string) {
    if (!zxcvbn || !pw) { entropyBits = 0; _entropyScore = 0; return; }
    const result = zxcvbn(pw);
    // guessesLog10 in bits: log2(10^guessesLog10) = guessesLog10 * log2(10) ≈ * 3.322
    entropyBits = Math.round(result.guessesLog10 * 3.322);
    _entropyScore = result.score;
  }

  function onPassphraseInput() {
    error = '';
    if (mode !== 'unlock') {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        if (!entropyLoaded && !entropyLoading) loadZxcvbn();
        else checkEntropy(passphrase);
      }, 150);
    }
  }

  onMount(() => {
    if (mode !== 'unlock') loadZxcvbn();
  });

  // Reactive entropy check when zxcvbn loads
  $effect(() => {
    if (zxcvbn && passphrase && mode !== 'unlock') checkEntropy(passphrase);
  });

  function validate(): string | null {
    if (passphrase.length < MIN_LENGTH) {
      return `Passphrase must be at least ${MIN_LENGTH} characters.`;
    }
    if (mode !== 'unlock') {
      if (entropyBits < MIN_ENTROPY) {
        return `Passphrase is too weak (${entropyBits} bits). Add more words or symbols to reach ${MIN_ENTROPY} bits.`;
      }
      if (passphrase !== confirm) {
        return 'Passphrases do not match.';
      }
    }
    return null;
  }

  function handleSubmit() {
    error = validate() || '';
    if (error) return;
    onSubmit?.(passphrase);
    // Caller is responsible for zeroizing after use.
    // Clear local state immediately.
    passphrase = '';
    confirm = '';
    entropyBits = 0;
    _entropyScore = 0;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') handleSubmit();
  }

  // Entropy bar color
  function entropyColor(bits: number): string {
    if (bits < 30) return 'var(--danger, #D64545)';
    if (bits < 50) return '#E89C3A';
    if (bits < MIN_ENTROPY) return '#C5B830';
    return 'var(--accent, #2EB860)';
  }

  let entropyPct = $derived(Math.min(100, Math.round((entropyBits / 100) * 100)));
  let isStrong = $derived(mode === 'unlock' || entropyBits >= MIN_ENTROPY);
  let canSubmit = $derived(passphrase.length >= MIN_LENGTH && isStrong && !disabled &&
    (mode === 'unlock' || passphrase === confirm));
</script>

<div class="passphrase-input">
  <div class="field">
    <label for="byo-passphrase">{label}</label>
    <div class="input-wrap">
      <input
        id="byo-passphrase"
        type={showPass ? 'text' : 'password'}
        value={passphrase}
        oninput={(e) => { passphrase = e.currentTarget.value; onPassphraseInput(); }}
        onkeydown={handleKeydown}
        placeholder="At least {MIN_LENGTH} characters"
        autocomplete={mode === 'unlock' ? 'current-password' : 'new-password'}
        {disabled}
        class="input"
        class:input-error={!!error}
      />
      <button
        type="button"
        class="toggle-vis"
        onclick={() => showPass = !showPass}
        aria-label={showPass ? 'Hide passphrase' : 'Show passphrase'}
        tabindex="-1"
      >
        {#if showPass}
          <!-- Eye-off icon -->
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
            <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
            <line x1="1" y1="1" x2="23" y2="23"/>
          </svg>
        {:else}
          <!-- Eye icon -->
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
            <circle cx="12" cy="12" r="3"/>
          </svg>
        {/if}
      </button>
    </div>
  </div>

  {#if mode !== 'unlock' && passphrase.length > 0}
    <div class="entropy-bar-wrap">
      <div class="bar-track">
        <div
          class="bar-fill"
          style="width: {entropyPct}%; background: {entropyColor(entropyBits)};"
        ></div>
      </div>
      <span class="entropy-label" style="color: {entropyColor(entropyBits)};">
        {#if entropyBits === 0}
          Checking…
        {:else if entropyBits < MIN_ENTROPY}
          {entropyBits} bits — too weak (need {MIN_ENTROPY})
        {:else}
          {entropyBits} bits — strong
        {/if}
      </span>
    </div>
  {/if}

  {#if mode !== 'unlock'}
    <div class="field">
      <label for="byo-confirm">Confirm passphrase</label>
      <div class="input-wrap">
        <input
          id="byo-confirm"
          type={showConfirm ? 'text' : 'password'}
          value={confirm}
          oninput={(e) => { confirm = e.currentTarget.value; }}
          onkeydown={handleKeydown}
          placeholder="Re-enter passphrase"
          autocomplete="new-password"
          {disabled}
          class="input"
          class:input-error={!!error && passphrase !== confirm}
        />
        <button
          type="button"
          class="toggle-vis"
          onclick={() => showConfirm = !showConfirm}
          aria-label={showConfirm ? 'Hide passphrase' : 'Show passphrase'}
          tabindex="-1"
        >
          {#if showConfirm}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
              <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
              <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
              <line x1="1" y1="1" x2="23" y2="23"/>
            </svg>
          {:else}
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
          {/if}
        </button>
      </div>
    </div>
  {/if}

  {#if error}
    <p class="error-msg" role="alert">{error}</p>
  {/if}

  <button
    class="btn btn-primary submit-btn"
    onclick={handleSubmit}
    disabled={!canSubmit}
  >
    {submitLabel}
  </button>
</div>

<style>
  .passphrase-input {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  label {
    /* §13.1: field labels are --t-body-sm weight 500, not uppercase. */
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 500;
    color: var(--text-secondary, #999999);
  }

  .input-wrap {
    position: relative;
    display: flex;
    align-items: center;
  }

  .input {
    width: 100%;
    padding-right: 44px;
  }

  .input.input-error {
    border-color: var(--danger, #D64545);
  }

  .toggle-vis {
    position: absolute;
    right: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 44px;
    height: 44px;
    background: none;
    border: none;
    color: var(--text-disabled, #616161);
    cursor: pointer;
    border-radius: 4px;
    transition: color 150ms;
  }

  .toggle-vis:hover { color: var(--text-secondary, #999999); }

  .entropy-bar-wrap {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .bar-track {
    width: 100%;
    height: 4px;
    background: var(--bg-input, #212121);
    border-radius: 2px;
    overflow: hidden;
  }

  .bar-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 250ms ease-out, background 250ms ease;
  }

  .entropy-label {
    font-size: var(--t-label-size, 0.75rem);
    transition: color 250ms ease;
  }

  .error-msg {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--danger, #D64545);
  }

  .submit-btn {
    width: 100%;
    min-height: 48px;
  }
</style>
