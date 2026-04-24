<!--
  PasswordInput — a password <input> with a right-aligned show/hide eye
  toggle. Shared primitive so every password-style field in the app has
  the same reveal affordance.

  Visual design is owned by this component, not by the caller. Svelte's
  CSS scoping means a consumer's `.field-input` / `.input` rule would
  not match an element rendered inside a different component, so this
  primitive styles the input itself using the shared design tokens
  (--bg-surface, --border, --accent, --r-input, …). Callers can tweak
  via booleans (`error`, `mono`, `sm`) rather than by passing a class
  that wouldn't apply anyway.
-->
<script lang="ts">
  export let value: string = '';
  export let id: string | undefined = undefined;
  export let name: string | undefined = undefined;
  export let placeholder: string = '';
  export let autocomplete: string = 'current-password';
  export let required: boolean = false;
  export let disabled: boolean = false;
  export let spellcheck: boolean = false;
  /** Red error border — matches .input-error / .danger border in surrounding forms. */
  export let error: boolean = false;
  /** Monospace + wider letter-spacing — for recovery keys and similar codes. */
  export let mono: boolean = false;
  /** Small variant — smaller font-size (matches --t-body-sm-size surfaces). */
  export let sm: boolean = false;
  /** aria-label when the toggle would reveal text. */
  export let showLabel: string = 'Show';
  /** aria-label when the toggle would hide text. */
  export let hideLabel: string = 'Hide';

  let shown = false;

  function handleInput(e: Event) {
    const target = e.currentTarget as HTMLInputElement;
    value = target.value;
  }
</script>

<span class="pw-wrap" class:is-disabled={disabled}>
  <!-- Dynamic `type` + Svelte's `bind:value` are incompatible (the compiler
       refuses because bind:value infers the JS type from the HTML type).
       Both text and password yield strings, so the two-way binding is
       wired manually: render `value` as an attribute, update it in
       on:input. Parents using `<PasswordInput bind:value={x} />` still
       get the expected two-way behaviour. -->
  <input
    {id}
    {name}
    {placeholder}
    {autocomplete}
    {required}
    {disabled}
    {spellcheck}
    type={shown ? 'text' : 'password'}
    class="pw-input"
    class:is-error={error}
    class:is-mono={mono}
    class:is-sm={sm}
    {value}
    on:input={handleInput}
    on:keydown
    on:keyup
    on:focus
    on:blur
  />
  <button
    type="button"
    class="pw-toggle"
    aria-label={shown ? hideLabel : showLabel}
    aria-pressed={shown}
    on:click={() => (shown = !shown)}
    tabindex="-1"
  >
    {#if shown}
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
        <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
        <line x1="1" y1="1" x2="23" y2="23"/>
      </svg>
    {:else}
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>
    {/if}
  </button>
</span>

<style>
  .pw-wrap {
    position: relative;
    display: flex;
    align-items: stretch;
    width: 100%;
  }

  .pw-input {
    flex: 1;
    width: 100%;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    padding-right: 44px;
    background: var(--bg-surface, #161616);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-size, 0.9375rem);
    font-family: inherit;
    box-sizing: border-box;
    transition: border-color 120ms ease;
  }
  .pw-input::placeholder { color: var(--text-disabled, #5A5A5A); }
  .pw-input:focus { outline: none; border-color: var(--accent, #2EB860); }
  .pw-input.is-error { border-color: var(--danger, #D64545); }
  .pw-input.is-error:focus { border-color: var(--danger, #D64545); }
  .pw-input.is-mono {
    font-family: var(--font-mono, ui-monospace, 'SF Mono', 'JetBrains Mono', Consolas, monospace);
    letter-spacing: 0.05em;
  }
  .pw-input.is-sm { font-size: var(--t-body-sm-size, 0.8125rem); }
  .pw-wrap.is-disabled .pw-input { opacity: 0.6; cursor: not-allowed; }

  .pw-toggle {
    position: absolute;
    right: 4px;
    top: 50%;
    transform: translateY(-50%);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    padding: 0;
    background: transparent;
    border: none;
    border-radius: var(--r-button, 8px);
    color: var(--text-tertiary, var(--text-secondary, #7A7A7A));
    cursor: pointer;
    transition: color 120ms ease, background-color 120ms ease;
  }
  .pw-toggle:hover,
  .pw-toggle:focus-visible {
    color: var(--text-primary, #EDEDED);
    background: var(--bg-surface-hover, rgba(255, 255, 255, 0.05));
    outline: none;
  }
  .pw-wrap.is-disabled .pw-toggle { pointer-events: none; opacity: 0.4; }
</style>
