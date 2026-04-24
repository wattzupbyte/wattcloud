<script lang="ts">
  /**
   * ShareLinkSheet — one-flow share creator.
   *
   * Every share is uploaded to the Wattcloud relay as encrypted ciphertext.
   * The recipient doesn't need your provider. The fragment carries the
   * decryption key — raw by default, Argon2id-wrapped when the optional
   * password toggle is on. This is the only path; the former A/A+/B1/B2
   * variant picker is gone (A/A+ called provider public-link APIs nobody
   * implemented; B1 worked only on S3).
   *
   * ZK invariants:
   *   - content_key never leaves WASM (creator + recipient both use
   *     worker-side decryption of the V7 header).
   *   - fragment stays client-side; never POSTed to any server.
   *   - password never transmitted; Argon2id 128 MiB / 3 iter / 4 parallel
   *     wraps the key inside WASM.
   *
   * For folder / collection shares (phase 3b) a different entry point will
   * open the same sheet with a "source" prop; the shape of the sheet is
   * identical, only the underlying dataProvider method changes.
   */

  import { createEventDispatcher } from 'svelte';
  import { fly, fade } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import { getContext } from 'svelte';
  import type { DataProvider, FileEntry, FolderEntry, CollectionEntry, ShareEntry } from '../../byo/DataProvider';
  import { SHARE_EXPLAINER_ITEMS, SHARE_EXPLAINER_HEADER } from '../../byo/copy/share-explainer';
  import { isShareLimitError } from '../../byo/shareLimitCopy';
  import ShieldCheck from 'phosphor-svelte/lib/ShieldCheck';
  import PasswordInput from '../common/PasswordInput.svelte';
  import Copy from 'phosphor-svelte/lib/Copy';
  import X from 'phosphor-svelte/lib/X';
  import CaretDown from 'phosphor-svelte/lib/CaretDown';
  import CaretUp from 'phosphor-svelte/lib/CaretUp';
  import QrCode from 'phosphor-svelte/lib/QrCode';
  import QrDisplay from './QrDisplay.svelte';

  const dispatch = createEventDispatcher<{ close: void }>();

  /**
   * One of four mutually exclusive sources:
   *   - { kind: 'file', file }              — single-blob share
   *   - { kind: 'folder', folder }          — folder bundle (all descendant files)
   *   - { kind: 'collection', collection }  — photo-collection bundle
   *   - { kind: 'files', files }            — multi-file selection bundle (flat)
   *
   * Svelte disallows `export type` in component script blocks, so consumers
   * use a structural literal type matching this shape.
   */
  type ShareSource =
    | { kind: 'file'; file: FileEntry }
    | { kind: 'folder'; folder: FolderEntry }
    | { kind: 'collection'; collection: CollectionEntry }
    | { kind: 'files'; files: FileEntry[] };

  export let source: ShareSource;

  const dataProvider = getContext<{ current: DataProvider }>('byo:dataProvider').current;

  $: sourceName = source.kind === 'file'
    ? source.file.decrypted_name
    : source.kind === 'folder'
      ? source.folder.decrypted_name
      : source.kind === 'collection'
        ? source.collection.decrypted_name
        : `${source.files.length} files`;
  $: sourceLabelTitle = source.kind === 'file'
    ? `Share '${sourceName}'`
    : source.kind === 'folder'
      ? `Share folder '${sourceName}'`
      : source.kind === 'collection'
        ? `Share collection '${sourceName}'`
        : `Share ${sourceName}`;
  $: bundleHint = source.kind === 'file'
    ? ''
    : source.kind === 'folder'
      ? 'Every file in this folder (and its subfolders) will be uploaded to the relay.'
      : source.kind === 'collection'
        ? 'Every photo in this collection will be uploaded to the relay.'
        : 'The selected files will be uploaded to the relay and delivered as one zip archive.';

  type Ttl = 3600 | 86400 | 604800 | 2592000;
  const ttlOptions: Array<{ label: string; value: Ttl }> = [
    { label: '1 hour', value: 3600 },
    { label: '1 day', value: 86400 },
    { label: '7 days', value: 604800 },
    { label: '30 days', value: 2592000 },
  ];

  let passwordOn = false;
  let password = '';
  let confirmPassword = '';
  let ttlChoice: Ttl = 86400;

  let generating = false;
  let generatedFragment = '';
  let generatedEntry: ShareEntry | null = null;
  let progressDone = 0;
  let progressTotal = 0;
  let copyToast = false;
  let error = '';
  let showExplainer = false;
  let showQr = false;

  // Password strength meter (only shown when password toggle is on).
  $: strength = passwordStrength(password);
  $: strengthLabel = ['', 'Weak', 'Fair', 'Good', 'Strong'][strength];
  $: strengthColor = [
    '',
    'var(--danger)',
    'var(--accent-warm, #E0A320)',
    'var(--accent)',
    'var(--accent)',
  ][strength];

  function passwordStrength(p: string): 0 | 1 | 2 | 3 | 4 {
    if (!p) return 0;
    let score = 0;
    if (p.length >= 12) score++;
    if (p.length >= 20) score++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) score++;
    if (/[0-9]/.test(p) || /[^A-Za-z0-9]/.test(p)) score++;
    return Math.min(score, 4) as 0 | 1 | 2 | 3 | 4;
  }

  function shareUrl(fragment: string): string {
    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    return `${origin}/s/${generatedEntry?.share_id ?? ''}#${fragment}`;
  }

  async function generate() {
    error = '';
    if (passwordOn) {
      if (!password) {
        error = 'Enter a password';
        return;
      }
      if (password !== confirmPassword) {
        error = 'Passwords do not match';
        return;
      }
      if (strength < 2) {
        error = 'Password is too weak';
        return;
      }
    }
    generating = true;
    progressDone = 0;
    progressTotal = 0;
    try {
      const commonOpts = {
        password: passwordOn ? password : undefined,
        ttlSeconds: ttlChoice,
      };
      let result: { entry: ShareEntry; fragment: string };
      if (source.kind === 'file') {
        result = await dataProvider.createShareLink(source.file.id, {
          ...commonOpts,
          filename: source.file.decrypted_name,
        });
      } else if (source.kind === 'folder') {
        result = await dataProvider.createFolderShare(source.folder.id, {
          ...commonOpts,
          onProgress: (done, total) => {
            progressDone = done;
            progressTotal = total;
          },
        });
      } else if (source.kind === 'collection') {
        result = await dataProvider.createCollectionShare(source.collection.id, {
          ...commonOpts,
          onProgress: (done, total) => {
            progressDone = done;
            progressTotal = total;
          },
        });
      } else {
        result = await dataProvider.createFilesShare(
          source.files.map((f) => f.id),
          {
            ...commonOpts,
            onProgress: (done, total) => {
              progressDone = done;
              progressTotal = total;
            },
          },
        );
      }
      generatedFragment = result.fragment;
      generatedEntry = result.entry;
    } catch (e: any) {
      // Abuse-protection errors arrive with a structured message already;
      // surface them verbatim so the user sees specific copy
      // ("You've hit the hourly share-creation limit…") rather than a
      // generic "Failed to generate share link".
      if (isShareLimitError(e)) {
        error = e.message;
      } else {
        error = e?.message || 'Failed to generate share link';
      }
    } finally {
      generating = false;
    }
  }

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(shareUrl(generatedFragment));
      copyToast = true;
      setTimeout(() => {
        copyToast = false;
      }, 2000);
    } catch {
      error = 'Could not copy to clipboard. Select the link and copy it manually.';
    }
  }

  async function copyPasswordText() {
    try {
      await navigator.clipboard.writeText(password);
      copyToast = true;
      setTimeout(() => {
        copyToast = false;
      }, 2000);
    } catch {
      error = 'Could not copy to clipboard.';
    }
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

<!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Share"
  on:click|self={close}
  on:keydown={(e) => {
    if (e.key === 'Escape') close();
  }}
  tabindex="-1"
  transition:fade={{ duration: 200 }}
>
  <div class="sheet" transition:fly={{ y: 80, duration: 300, easing: quintOut }}>
    <div class="drag-handle" aria-hidden="true" />

    <div class="sheet-header">
      <div>
        <h2 class="sheet-title">{sourceLabelTitle}</h2>
        <p class="sheet-subtitle">
          Your encrypted content uploads to the relay server. Anyone with the
          link can download it — and only they can read it. The relay sees
          ciphertext only.
          {#if bundleHint}<br />{bundleHint}{/if}
        </p>
      </div>
      <button class="close-btn" on:click={close} aria-label="Close">
        <X size={20} />
      </button>
    </div>

    <div class="trust-banner" role="note">
      <ShieldCheck size={24} weight="fill" class="trust-icon" aria-hidden="true" />
      <span class="trust-text">End-to-end encrypted share</span>
    </div>

    {#if !generatedEntry}
      <div class="form">
        <div class="field">
          <p class="field-label">Link expires after</p>
          <div class="ttl-chips" role="group" aria-label="Link expiry">
            {#each ttlOptions as opt}
              <button
                type="button"
                class="ttl-chip"
                class:active={ttlChoice === opt.value}
                on:click={() => (ttlChoice = opt.value)}
                aria-pressed={ttlChoice === opt.value}
              >
                {opt.label}
              </button>
            {/each}
          </div>
        </div>

        <label class="toggle-row">
          <span class="toggle-text">Require a password</span>
          <input
            type="checkbox"
            class="toggle-switch"
            bind:checked={passwordOn}
            aria-label="Require a password"
          />
        </label>

        {#if passwordOn}
          <div class="field" transition:fly={{ y: -8, duration: 180 }}>
            <label for="share-pwd" class="field-label">Password</label>
            <PasswordInput
              id="share-pwd"
              sm
              bind:value={password}
              placeholder="Choose a strong password"
              autocomplete="new-password"
              showLabel="Show password"
              hideLabel="Hide password"
            />
            {#if password}
              <div
                class="strength-bar"
                role="meter"
                aria-label={`Password strength: ${strengthLabel}`}
                aria-valuenow={strength}
                aria-valuemin="0"
                aria-valuemax="4"
              >
                {#each [1, 2, 3, 4] as n}
                  <div
                    class="strength-segment"
                    style={`background: ${n <= strength ? strengthColor : 'var(--border)'}`}
                  />
                {/each}
                <span class="strength-label" aria-live="polite" style={`color: ${strengthColor}`}
                  >{strengthLabel}</span
                >
              </div>
            {/if}
          </div>

          <div class="field">
            <label for="share-pwd-confirm" class="field-label">Confirm password</label>
            <PasswordInput
              id="share-pwd-confirm"
              sm
              error={!!(confirmPassword && password !== confirmPassword)}
              bind:value={confirmPassword}
              placeholder="Repeat the password"
              autocomplete="new-password"
              showLabel="Show password"
              hideLabel="Hide password"
            />
            {#if confirmPassword && password !== confirmPassword}
              <span class="field-error">Passwords do not match</span>
            {/if}
          </div>
          <p class="form-hint">
            The password is never sent to any server. Share it with the recipient
            separately (e.g. via Signal).
          </p>
        {/if}

        {#if error}
          <div class="form-error" role="alert">{error}</div>
        {/if}
      </div>

      <button
        class="btn-primary"
        on:click={generate}
        disabled={generating}
        aria-busy={generating}
      >
        {#if generating}
          <span class="spinner-sm" aria-hidden="true" />
          {#if progressTotal > 0}
            Uploading {progressDone} / {progressTotal}…
          {:else}
            Uploading to relay…
          {/if}
        {:else}
          Create link
        {/if}
      </button>
    {:else}
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
            on:click={() => (showQr = !showQr)}
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
          <div class="qr-panel" transition:fly={{ y: -8, duration: 200 }}>
            <QrDisplay data={shareUrl(generatedFragment)} ariaLabel="QR code for share link" />
            <p class="qr-hint">Scan to open on another device.</p>
          </div>
        {/if}

        {#if copyToast}
          <p class="toast-inline" role="status" aria-live="polite">Copied!</p>
        {/if}

        {#if passwordOn}
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

    <div class="explainer">
      <button
        class="explainer-toggle"
        on:click={() => (showExplainer = !showExplainer)}
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
    background: var(--bg-surface-raised, #262626);
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
  .sheet-title { margin: 0; font-size: var(--t-h2-size, 1rem); font-weight: 600; color: var(--text-primary, #ededed); }
  .sheet-subtitle { margin: 4px 0 0; font-size: var(--t-body-sm-size, 0.8125rem); color: var(--text-secondary, #999); line-height: 1.5; }
  .close-btn { background: none; border: none; color: var(--text-secondary, #999); cursor: pointer; padding: 4px; border-radius: 8px; flex-shrink: 0; }
  .close-btn:hover { color: var(--text-primary, #ededed); }
  .qr-panel { display: flex; flex-direction: column; align-items: center; gap: var(--sp-sm, 8px); margin-top: var(--sp-sm, 8px); }
  .qr-hint { margin: 0; font-size: var(--t-label-size, 0.75rem); color: var(--text-secondary, #999); text-align: center; }

  .trust-banner {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    background: var(--accent-muted, rgba(46, 184, 96, 0.12));
    border-radius: var(--r-card, 16px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
  }
  .trust-banner :global(.trust-icon) { color: var(--accent, #2EB860); }
  .trust-text { font-size: var(--t-body-sm-size, 0.8125rem); font-weight: 500; color: var(--accent-text, #5FDB8A); }

  .form { display: flex; flex-direction: column; gap: var(--sp-sm, 8px); }
  .field { display: flex; flex-direction: column; gap: 6px; }
  .field-label { font-size: var(--t-body-sm-size, 0.8125rem); color: var(--text-secondary, #999); margin: 0; }

  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-xs, 4px) 0;
    cursor: pointer;
    min-height: 28px;
  }
  .toggle-text {
    color: var(--text-primary, #ededed);
    font-size: var(--t-body-sm-size, 0.8125rem);
    flex: 1 1 auto;
    min-width: 0;
  }
  .toggle-switch {
    appearance: none;
    -webkit-appearance: none;
    width: 40px;
    height: 22px;
    background: var(--bg-surface-hover, #2E2E2E);
    border-radius: 9999px;
    position: relative;
    cursor: pointer;
    transition: background 160ms ease;
    flex-shrink: 0;
    margin: 0;
    padding: 0;
    border: none;
    outline: none;
  }
  .toggle-switch::after {
    content: '';
    position: absolute;
    top: 2px;
    left: 2px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--text-primary, #EDEDED);
    transition: transform 160ms ease, background 160ms ease;
  }
  .toggle-switch:checked {
    background: var(--accent, #2EB860);
  }
  .toggle-switch:checked::after {
    transform: translateX(18px);
    background: var(--text-inverse, #121212);
  }
  .toggle-switch:focus-visible {
    outline: 2px solid var(--accent, #2EB860);
    outline-offset: 2px;
  }

  .field-error { font-size: 0.75rem; color: var(--danger, #D64545); }
  .strength-bar { display: flex; align-items: center; gap: 4px; }
  .strength-segment { height: 3px; flex: 1; border-radius: 2px; transition: background 200ms; }
  .strength-label { font-size: 0.7rem; font-weight: 600; width: 40px; text-align: right; }
  .form-hint { font-size: 0.75rem; color: var(--text-secondary, #999); margin: 0; line-height: 1.5; }
  .form-error {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--danger, #D64545);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border-radius: var(--r-input, 12px);
  }

  .ttl-chips { display: flex; gap: var(--sp-xs, 4px); flex-wrap: wrap; }
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
  .btn-ghost { background: none; border: none; font-size: var(--t-body-sm-size, 0.8125rem); cursor: pointer; padding: 4px 0; }
  .btn-danger-text { color: var(--danger, #D64545); }

  .generated { display: flex; flex-direction: column; gap: var(--sp-xs, 4px); }
  .url-row { display: flex; gap: var(--sp-xs, 4px); align-items: center; }
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
  .toast-inline { font-size: 0.75rem; color: var(--accent-text, #5FDB8A); margin: 0; }

  .spinner-sm {
    width: 16px;
    height: 16px;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .explainer { border-top: 1px solid var(--border, #2E2E2E); padding-top: var(--sp-sm, 8px); }
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
  .explainer-body { padding: var(--sp-sm, 8px) 0; display: flex; flex-direction: column; gap: var(--sp-sm, 8px); }
  .explainer-header { font-weight: 600; font-size: var(--t-body-sm-size, 0.8125rem); color: var(--text-primary, #ededed); margin: 0 0 var(--sp-xs, 4px); }
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
