<script lang="ts">
  /**
   * ShareLinkSheet — §11.2 bottom sheet for creating E2E share links.
   *
   * Supports all four variants:
   *   A  — raw content_key in URL fragment (provider public link)
   *   A+ — password-gated (Argon2id-wrapped fragment)
   *   B1 — time-bounded presigned URL via relay
   *   B2 — upload to relay blob store (SFTP / no public link)
   *
   * ZK invariants:
   *   - content_key never leaves this component; shared only via fragment (#...)
   *   - fragment stays client-side; never POSTed to any server
   *   - password never transmitted; used only to derive share_key in WASM worker
   */

  import { createEventDispatcher, onMount } from 'svelte';
  import { fly, fade } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import { getContext } from 'svelte';
  import type { DataProvider, FileEntry, ShareVariant, ShareEntry } from '../../byo/DataProvider';
  import type { StorageProvider } from '@secure-cloud/byo';
  import { SHARE_EXPLAINER_ITEMS, SHARE_EXPLAINER_HEADER } from '../../byo/copy/share-explainer';
  import ShieldCheck from 'phosphor-svelte/lib/ShieldCheck';
  import Link from 'phosphor-svelte/lib/Link';
  import Lock from 'phosphor-svelte/lib/Lock';
  import Globe from 'phosphor-svelte/lib/Globe';
  import Clock from 'phosphor-svelte/lib/Clock';
  import UploadSimple from 'phosphor-svelte/lib/UploadSimple';
  import Copy from 'phosphor-svelte/lib/Copy';
  import X from 'phosphor-svelte/lib/X';
  import CaretDown from 'phosphor-svelte/lib/CaretDown';
  import CaretUp from 'phosphor-svelte/lib/CaretUp';
  import QrCode from 'phosphor-svelte/lib/QrCode';
  import QrDisplay from './QrDisplay.svelte';

  const dispatch = createEventDispatcher<{ close: void }>();

  export let file: FileEntry;

  const dataProvider = getContext<DataProvider>('byo:dataProvider');
  const storageProvider = getContext<StorageProvider>('byo:storageProvider');

  // Only S3-compatible providers issue native presigned URLs (B1).
  // GDrive, Dropbox, OneDrive, Box, pCloud, WebDAV, and SFTP do not.
  $: supportsB1 = storageProvider?.type === 's3';

  type Variant = 'A' | 'A+' | 'B1' | 'B2';

  let selectedVariant: Variant = 'A';
  let password = '';
  let confirmPassword = '';
  let ttlChoice: 3600 | 86400 | 604800 | 2592000 = 86400; // 1 day default

  let generating = false;
  let generatedFragment = '';
  let generatedEntry: ShareEntry | null = null;
  let copyToast = false;
  let error = '';
  let showExplainer = false;
  let showQr = false;

  // Password strength
  $: strength = passwordStrength(password);
  $: strengthLabel = ['', 'Weak', 'Fair', 'Good', 'Strong'][strength];
  $: strengthColor = ['', 'var(--danger)', 'var(--accent-warm, #E0A320)', 'var(--accent)', 'var(--accent)'][strength];

  function passwordStrength(p: string): 0 | 1 | 2 | 3 | 4 {
    if (!p) return 0;
    let score = 0;
    if (p.length >= 12) score++;
    if (p.length >= 20) score++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) score++;
    if (/[0-9]/.test(p) || /[^A-Za-z0-9]/.test(p)) score++;
    return Math.min(score, 4) as 0 | 1 | 2 | 3 | 4;
  }

  const variants: { id: Variant; label: string; icon: any; desc: string; requiresPresign?: true }[] = [
    { id: 'A',  label: 'Public',    icon: Globe,        desc: 'Key in link fragment' },
    { id: 'A+', label: 'Password',  icon: Lock,         desc: 'Argon2id-protected' },
    { id: 'B1', label: 'Timed',     icon: Clock,        desc: 'Presigned URL', requiresPresign: true },
    { id: 'B2', label: 'Relayed',   icon: UploadSimple, desc: 'Via SecureCloud relay' },
  ];

  const ttlOptions = [
    { label: '1 hour',  value: 3600 as const },
    { label: '1 day',   value: 86400 as const },
    { label: '7 days',  value: 604800 as const },
    { label: '30 days', value: 2592000 as const },
  ];

  function shareUrl(fragment: string): string {
    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    return `${origin}/s/${generatedEntry?.share_id ?? ''}#${fragment}`;
  }

  async function generate() {
    if (selectedVariant === 'A+') {
      if (!password) { error = 'Enter a password'; return; }
      if (password !== confirmPassword) { error = 'Passwords do not match'; return; }
      if (strength < 2) { error = 'Password is too weak'; return; }
    }
    error = '';
    generating = true;
    try {
      const opts: { password?: string; ttlSeconds?: number } = {};
      if (selectedVariant === 'A+') opts.password = password;
      if (selectedVariant === 'B1' || selectedVariant === 'B2') opts.ttlSeconds = ttlChoice;

      const result = await dataProvider.createShareLink(file.id, selectedVariant as ShareVariant, opts);
      generatedFragment = result.fragment;
      generatedEntry = result.entry;
    } catch (e: any) {
      error = e.message || 'Failed to generate share link';
    } finally {
      generating = false;
    }
  }

  async function copyLink() {
    const url = shareUrl(generatedFragment);
    await navigator.clipboard.writeText(url);
    copyToast = true;
    setTimeout(() => { copyToast = false; }, 2000);
  }

  async function copyPasswordText() {
    await navigator.clipboard.writeText(password);
    copyToast = true;
    setTimeout(() => { copyToast = false; }, 2000);
  }

  async function revoke() {
    if (!generatedEntry) return;
    await dataProvider.revokeShare(generatedEntry.share_id);
    generatedFragment = '';
    generatedEntry = null;
  }

  function close() {
    dispatch('close');
  }
</script>

<!-- Overlay — role=dialog makes this interactive, but Svelte's linter
     still flags mouse/keyboard listeners on a plain <div>. -->
<!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Share file"
  on:click|self={close}
  on:keydown={(e) => { if (e.key === 'Escape') close(); }}
  tabindex="-1"
  transition:fade={{ duration: 200 }}
>
  <!-- Sheet -->
  <div
    class="sheet"
    transition:fly={{ y: 80, duration: 300, easing: quintOut }}
  >
    <!-- Drag handle -->
    <div class="drag-handle" aria-hidden="true" />

    <!-- Header -->
    <div class="sheet-header">
      <div>
        <h2 class="sheet-title">Share '{file.decrypted_name}'</h2>
        <p class="sheet-subtitle">Generate a link anyone can open in a browser — no account required.</p>
      </div>
      <button class="close-btn" on:click={close} aria-label="Close">
        <X size={20} />
      </button>
    </div>

    <!-- Trust banner (§29.1 hex-shield motif) -->
    <div class="trust-banner" role="note">
      <ShieldCheck size={24} weight="fill" class="trust-icon" aria-hidden="true" />
      <span class="trust-text">End-to-end encrypted share</span>
    </div>

    {#if !generatedEntry}
      <!-- Variant selector -->
      <div class="variant-selector" role="tablist" aria-label="Share variant">
        {#each variants as v}
          {@const isDisabled = v.requiresPresign && !supportsB1}
          <button
            class="variant-chip"
            class:active={selectedVariant === v.id}
            class:disabled={isDisabled}
            role="tab"
            aria-selected={selectedVariant === v.id}
            aria-disabled={isDisabled}
            disabled={isDisabled}
            on:click={() => { if (!isDisabled) selectedVariant = v.id; }}
            title={isDisabled ? 'This provider does not issue presigned links' : v.desc}
          >
            <svelte:component this={v.icon} size={16} aria-hidden="true" />
            <span>{v.label}</span>
          </button>
        {/each}
      </div>

      <!-- Variant-specific form -->
      <div class="variant-form">
        {#if selectedVariant === 'A'}
          <p class="form-hint">A link with the decryption key embedded in the fragment. The key never reaches any server.</p>

        {:else if selectedVariant === 'A+'}
          <div class="field">
            <label for="share-pwd" class="field-label">Password</label>
            <input
              id="share-pwd"
              type="password"
              class="input"
              bind:value={password}
              placeholder="Choose a strong password"
              aria-describedby="share-pwd-strength"
              autocomplete="new-password"
            />
            {#if password}
              <div
                class="strength-bar"
                role="meter"
                aria-label="Password strength: {strengthLabel}"
                aria-valuenow={strength}
                aria-valuemin="0"
                aria-valuemax="4"
                id="share-pwd-strength"
              >
                {#each [1,2,3,4] as n}
                  <div
                    class="strength-segment"
                    style="background: {n <= strength ? strengthColor : 'var(--border)'}"
                  />
                {/each}
                <span class="strength-label" aria-live="polite" style="color: {strengthColor}">{strengthLabel}</span>
              </div>
            {/if}
          </div>
          <div class="field">
            <label for="share-pwd-confirm" class="field-label">Confirm password</label>
            <input
              id="share-pwd-confirm"
              type="password"
              class="input"
              class:input-error={confirmPassword && password !== confirmPassword}
              bind:value={confirmPassword}
              placeholder="Repeat the password"
              autocomplete="new-password"
            />
            {#if confirmPassword && password !== confirmPassword}
              <span class="field-error">Passwords do not match</span>
            {/if}
          </div>
          <p class="form-hint">This password is never sent to any server. Share it with the recipient separately (e.g. via Signal).</p>

        {:else if selectedVariant === 'B1' || selectedVariant === 'B2'}
          <div class="field">
            <p class="field-label">Expires in</p>
            <div class="ttl-chips" role="group" aria-label="Link expiry">
              {#each ttlOptions as opt}
                <button
                  class="ttl-chip"
                  class:active={ttlChoice === opt.value}
                  on:click={() => ttlChoice = opt.value}
                  aria-pressed={ttlChoice === opt.value}
                >{opt.label}</button>
              {/each}
            </div>
          </div>
          {#if selectedVariant === 'B2'}
            <p class="form-hint">Your encrypted file will be uploaded to SecureCloud's relay so recipients without provider access can still download it. The relay never sees the encryption key.</p>
          {/if}
        {/if}

        {#if error}
          <div class="form-error" role="alert">{error}</div>
        {/if}
      </div>

      <!-- Generate CTA -->
      <button class="btn-primary" on:click={generate} disabled={generating} aria-busy={generating}>
        {#if generating}
          <span class="spinner-sm" aria-hidden="true" />
          Generating…
        {:else}
          Generate link
        {/if}
      </button>

    {:else}
      <!-- Post-generation state -->
      <div class="generated">
        <div class="url-row">
          <input
            type="text"
            class="url-input"
            readonly
            value={shareUrl(generatedFragment)}
            aria-label="Share URL"
          />
          <button
            class="icon-btn"
            on:click={() => showQr = !showQr}
            aria-label={showQr ? 'Hide QR code' : 'Show QR code'}
            aria-expanded={showQr}
            title={showQr ? 'Hide QR' : 'Show QR'}
          >
            <QrCode size={18} />
          </button>
          <button class="icon-btn" on:click={copyLink} aria-label="Copy link" title="Copy link">
            <Copy size={18} />
          </button>
        </div>

        {#if showQr}
          <!-- Hand-off via QR — the fragment stays in the URL, so scanning
               transfers the content key too. (§29.1 — branded surface.) -->
          <div class="qr-panel" transition:fly={{ y: -8, duration: 200 }}>
            <QrDisplay data={shareUrl(generatedFragment)} ariaLabel="QR code for share link" />
            <p class="qr-hint">Scan to open on another device.</p>
          </div>
        {/if}

        {#if copyToast}
          <p class="toast-inline" role="status" aria-live="polite">Copied!</p>
        {/if}

        {#if selectedVariant === 'A+'}
          <button class="btn-secondary" on:click={copyPasswordText} style="margin-top: var(--sp-sm)">
            <Copy size={16} aria-hidden="true" />
            Copy password
          </button>
        {/if}

        <button class="btn-ghost btn-danger-text" on:click={revoke} style="margin-top: var(--sp-sm)">
          Revoke link
        </button>
      </div>
    {/if}

    <!-- "How does this work?" accordion -->
    <div class="explainer">
      <button
        class="explainer-toggle"
        on:click={() => showExplainer = !showExplainer}
        aria-expanded={showExplainer}
      >
        <span>How does this work?</span>
        {#if showExplainer}
          <CaretUp size={16} aria-hidden="true" />
        {:else}
          <CaretDown size={16} aria-hidden="true" />
        {/if}
      </button>

      {#if showExplainer}
        <div class="explainer-body" transition:fly={{ y: -8, duration: 200 }}>
          <p class="explainer-header">{SHARE_EXPLAINER_HEADER}</p>
          {#each SHARE_EXPLAINER_ITEMS as item}
            <div class="explainer-item">
              <ShieldCheck size={16} weight="fill" class="explainer-icon" aria-hidden="true" />
              <div>
                <strong>{item.heading}</strong>
                <span> {item.body}</span>
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: flex-end;
    justify-content: center;
    z-index: 500;
    padding: 0 var(--sp-sm, 8px);
  }

  .sheet {
    background: var(--surface-2, #1E1E1E);
    border: 1px solid var(--border, #2E2E2E);
    border-bottom: none;
    border-radius: var(--r-card, 16px) var(--r-card, 16px) 0 0;
    width: 100%;
    max-width: 480px;
    max-height: 85vh;
    overflow-y: auto;
    padding: var(--sp-sm, 8px) var(--sp-lg, 24px) var(--sp-xl, 32px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
  }

  .drag-handle {
    width: 40px;
    height: 4px;
    background: var(--border, #2E2E2E);
    border-radius: 2px;
    margin: 0 auto var(--sp-xs, 4px);
    flex-shrink: 0;
  }

  .sheet-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: var(--sp-sm, 8px);
  }

  .sheet-title {
    margin: 0;
    font-size: var(--t-h2-size, 1rem);
    font-weight: 600;
    color: var(--text-primary, #ededed);
  }

  .sheet-subtitle {
    margin: 4px 0 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.5;
  }

  .close-btn {
    background: none;
    border: none;
    color: var(--text-secondary, #999);
    cursor: pointer;
    padding: 4px;
    border-radius: 8px;
    flex-shrink: 0;
  }

  .qr-panel {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-sm, 8px);
    margin-top: var(--sp-sm, 8px);
  }

  .qr-hint {
    margin: 0;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-secondary, #999);
    text-align: center;
  }

  .close-btn:hover { color: var(--text-primary, #ededed); }

  /* Trust banner (§29.1) */
  .trust-banner {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    background: var(--accent-muted, rgba(46, 184, 96, 0.12));
    border-radius: var(--r-card, 16px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
  }

  .trust-banner :global(.trust-icon) { color: var(--accent, #2EB860); }
  .trust-text {
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 500;
    color: var(--accent-text, #5FDB8A);
  }

  /* Variant selector */
  .variant-selector {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: var(--sp-xs, 4px);
  }

  .variant-chip {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    padding: var(--sp-sm, 8px) var(--sp-xs, 4px);
    border-radius: var(--r-input, 12px);
    border: 1px solid var(--border, #2E2E2E);
    background: var(--bg-surface-raised, #1E1E1E);
    color: var(--text-secondary, #999);
    font-size: 0.7rem;
    cursor: pointer;
    transition: background 150ms, color 150ms, border-color 150ms;
  }

  .variant-chip.active {
    background: var(--accent-muted, rgba(46, 184, 96, 0.12));
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
  }

  .variant-chip.disabled {
    opacity: 0.38;
    cursor: not-allowed;
  }

  /* Form fields */
  .variant-form {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
  }

  .field { display: flex; flex-direction: column; gap: 6px; }
  .field-label { font-size: var(--t-body-sm-size, 0.8125rem); color: var(--text-secondary, #999); }

  .input {
    background: var(--surface-1, #121212);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    color: var(--text-primary, #ededed);
    font-size: var(--t-body-sm-size, 0.8125rem);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    width: 100%;
    box-sizing: border-box;
  }

  .input:focus { outline: none; border-color: var(--accent, #2EB860); }
  .input.input-error { border-color: var(--danger, #D64545); }

  .field-error {
    font-size: 0.75rem;
    color: var(--danger, #D64545);
  }

  .strength-bar {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .strength-segment {
    height: 3px;
    flex: 1;
    border-radius: 2px;
    transition: background 200ms;
  }

  .strength-label {
    font-size: 0.7rem;
    font-weight: 600;
    width: 40px;
    text-align: right;
  }

  .form-hint {
    font-size: 0.75rem;
    color: var(--text-secondary, #999);
    margin: 0;
    line-height: 1.5;
  }

  .form-error {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--danger, #D64545);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border-radius: var(--r-input, 12px);
  }

  /* TTL chips */
  .ttl-chips {
    display: flex;
    gap: var(--sp-xs, 4px);
    flex-wrap: wrap;
  }

  .ttl-chip {
    padding: 4px 12px;
    border-radius: var(--r-pill, 9999px);
    border: 1px solid var(--border, #2E2E2E);
    background: var(--bg-surface-raised, #1E1E1E);
    color: var(--text-secondary, #999);
    font-size: 0.75rem;
    cursor: pointer;
    transition: background 150ms, color 150ms, border-color 150ms;
  }

  .ttl-chip.active {
    background: var(--accent-muted, rgba(46, 184, 96, 0.12));
    border-color: var(--accent, #2EB860);
    color: var(--accent-text, #5FDB8A);
  }

  /* Buttons (§12 pill) */
  .btn-primary {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-xs, 4px);
    width: 100%;
    padding: 12px;
    border-radius: var(--r-pill, 9999px);
    border: none;
    background: var(--accent, #2EB860);
    color: #fff;
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 600;
    cursor: pointer;
    transition: opacity 150ms;
  }

  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }

  .btn-secondary {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    padding: 8px 16px;
    border-radius: var(--r-pill, 9999px);
    border: 1px solid var(--border, #2E2E2E);
    background: transparent;
    color: var(--text-primary, #ededed);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
  }

  .btn-ghost {
    background: none;
    border: none;
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    padding: 4px 0;
  }

  .btn-danger-text { color: var(--danger, #D64545); }

  /* Generated state */
  .generated {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .url-row {
    display: flex;
    gap: var(--sp-xs, 4px);
    align-items: center;
  }

  .url-input {
    flex: 1;
    background: var(--surface-1, #121212);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    color: var(--text-primary, #ededed);
    font-size: 0.75rem;
    font-family: monospace;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
  }

  .icon-btn {
    width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: var(--r-pill, 9999px);
    border: 1px solid var(--border, #2E2E2E);
    background: var(--bg-surface-raised, #1E1E1E);
    color: var(--text-primary, #ededed);
    cursor: pointer;
    flex-shrink: 0;
  }

  .toast-inline {
    font-size: 0.75rem;
    color: var(--accent-text, #5FDB8A);
    margin: 0;
  }

  /* Spinner */
  .spinner-sm {
    width: 16px;
    height: 16px;
    border: 2px solid rgba(255,255,255,0.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  /* Explainer accordion */
  .explainer {
    border-top: 1px solid var(--border, #2E2E2E);
    padding-top: var(--sp-sm, 8px);
  }

  .explainer-toggle {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    background: none;
    border: none;
    color: var(--text-secondary, #999);
    font-size: var(--t-body-sm-size, 0.8125rem);
    cursor: pointer;
    padding: 4px 0;
  }

  .explainer-body {
    padding: var(--sp-sm, 8px) 0;
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
  }

  .explainer-header {
    font-weight: 600;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #ededed);
    margin: 0 0 var(--sp-xs, 4px);
  }

  .explainer-item {
    display: flex;
    gap: var(--sp-sm, 8px);
    align-items: flex-start;
    font-size: 0.75rem;
    color: var(--text-secondary, #999);
    line-height: 1.5;
  }

  .explainer-item :global(.explainer-icon) {
    color: var(--accent, #2EB860);
    flex-shrink: 0;
    margin-top: 2px;
  }
</style>
