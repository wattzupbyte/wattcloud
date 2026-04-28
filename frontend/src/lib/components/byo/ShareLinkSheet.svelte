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
  import { fly, fade } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';
  import { getContext } from 'svelte';
  import type { DataProvider, FileEntry, FolderEntry, CollectionEntry, ShareEntry } from '../../byo/DataProvider';
  import { SHARE_EXPLAINER_ITEMS, SHARE_EXPLAINER_HEADER } from '../../byo/copy/share-explainer';
  import { isShareLimitError } from '../../byo/shareLimitCopy';
  import { supportsRequestStreams } from '../../byo/shareUploadStreaming';
  import ShieldCheck from 'phosphor-svelte/lib/ShieldCheck';
  import PasswordInput from '../common/PasswordInput.svelte';
  import Copy from 'phosphor-svelte/lib/Copy';
  import X from 'phosphor-svelte/lib/X';
  import CaretDown from 'phosphor-svelte/lib/CaretDown';
  import CaretUp from 'phosphor-svelte/lib/CaretUp';
  import QrCode from 'phosphor-svelte/lib/QrCode';
  import Warning from 'phosphor-svelte/lib/Warning';
  import QrDisplay from './QrDisplay.svelte';
/**
   * One of five mutually exclusive sources:
   *   - { kind: 'file', file }              — single-blob share
   *   - { kind: 'folder', folder }          — folder bundle (all descendant files)
   *   - { kind: 'collection', collection }  — photo-collection bundle
   *   - { kind: 'files', files }            — multi-file selection bundle (flat)
   *   - { kind: 'mixed', folders, files }   — folders + loose files in one link
   *
   * Svelte disallows `export type` in component script blocks, so consumers
   * use a structural literal type matching this shape.
   */
  type ShareSource =
    | { kind: 'file'; file: FileEntry }
    | { kind: 'folder'; folder: FolderEntry }
    | { kind: 'collection'; collection: CollectionEntry }
    | { kind: 'files'; files: FileEntry[] }
    | { kind: 'mixed'; folders: FolderEntry[]; files: FileEntry[] };

  interface Props {
    source: ShareSource;
  onClose?: (...args: any[]) => void;
  }

  let { source,
  onClose }: Props = $props();

  const dataProvider = getContext<{ current: DataProvider }>('byo:dataProvider').current;


  type Ttl = 3600 | 86400 | 604800 | 2592000;
  const ttlOptions: Array<{ label: string; value: Ttl }> = [
    { label: '1 hour', value: 3600 },
    { label: '1 day', value: 86400 },
    { label: '7 days', value: 604800 },
    { label: '30 days', value: 2592000 },
  ];

  let passwordOn = $state(false);
  let password = $state('');
  let confirmPassword = $state('');
  let ttlChoice: Ttl = $state(86400);
  /** User-supplied display name. Surfaces both in Settings → Active
   *  shares (creator side) and on the recipient's landing page (carried
   *  in the fragment as &n=). When blank, both ends fall back to the
   *  inferred default (filename, folder name, "N items", etc.). */
  let shareLabel = $state('');

  let generating = $state(false);
  let generatedFragment = $state('');
  let generatedEntry: ShareEntry | null = $state(null);
  let progressDone = $state(0);
  let progressTotal = $state(0);
  let copyToast = $state(false);
  let error = $state('');
  let showExplainer = $state(false);
  let showQr = $state(false);

  // ── Buffer-fallback hint (Firefox-default browsers) ──────────────────────────
  // The share upload path uses fetch() with a ReadableStream body to avoid
  // materialising multi-GB ciphertext in JS heap. Firefox gates that feature
  // behind `network.fetch.upload_streams`, so by default it falls back to
  // buffer-and-forward. Surface a one-time hint before the first share so the
  // user knows about the heap cost and can flip the pref if they want.
  // Regular file uploads (StorageProvider.upload_stream) chunk through WASM
  // with bounded per-POST bodies, so this prompt does NOT apply there.
  const STREAMING_HINT_KEY = 'sc-byo-streaming-upload-hint-dismissed';
  let streamingHintOpen = $state(false);
  let streamingHintDontShowAgain = $state(false);
  let streamingHintFlagCopied = $state(false);
  let streamingHintAboutCopied = $state(false);
  // Cache the capability check so the hint decision is consistent within
  // this sheet's lifetime even though `supportsRequestStreams` is itself
  // memoised.
  const browserStreams = supportsRequestStreams();
  function streamingHintDismissed(): boolean {
    if (typeof localStorage === 'undefined') return false;
    return localStorage.getItem(STREAMING_HINT_KEY) === '1';
  }
  async function copyToClipboard(text: string): Promise<boolean> {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }


  async function handleStreamingHintConfirm() {
    if (streamingHintDontShowAgain && typeof localStorage !== 'undefined') {
      localStorage.setItem(STREAMING_HINT_KEY, '1');
    }
    streamingHintOpen = false;
    await runGenerate();
  }

  function handleStreamingHintCancel() {
    if (streamingHintDontShowAgain && typeof localStorage !== 'undefined') {
      localStorage.setItem(STREAMING_HINT_KEY, '1');
    }
    streamingHintOpen = false;
  }

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
    // Buffer-fallback hint: pause before the actual upload so the user can
    // see the memory tradeoff and flip the Firefox pref if they want. The
    // hint only fires when (a) the browser doesn't support fetch upload
    // streams, AND (b) the user hasn't dismissed it permanently.
    if (!browserStreams && !streamingHintDismissed()) {
      streamingHintDontShowAgain = false;
      streamingHintFlagCopied = false;
      streamingHintAboutCopied = false;
      streamingHintOpen = true;
      return;
    }
    await runGenerate();
  }

  async function runGenerate() {
    generating = true;
    progressDone = 0;
    progressTotal = 0;
    try {
      const trimmedLabel = shareLabel.trim();
      const commonOpts = {
        password: passwordOn ? password : undefined,
        ttlSeconds: ttlChoice,
        label: trimmedLabel || undefined,
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
      } else if (source.kind === 'mixed') {
        result = await dataProvider.createMixedShare(
          {
            folderIds: source.folders.map((f) => f.id),
            fileIds: source.files.map((f) => f.id),
          },
          {
            ...commonOpts,
            onProgress: (done, total) => {
              progressDone = done;
              progressTotal = total;
            },
          },
        );
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
    onClose?.();
  }
  let sourceName = $derived(
    source.kind === 'file'
      ? source.file.decrypted_name
      : source.kind === 'folder'
        ? source.folder.decrypted_name
        : source.kind === 'collection'
          ? source.collection.decrypted_name
          : source.kind === 'mixed'
            ? `${source.folders.length + source.files.length} items`
            : `${source.files.length} files`,
  );
  let sourceLabelTitle = $derived(
    source.kind === 'file'
      ? `Share '${sourceName}'`
      : source.kind === 'folder'
        ? `Share folder '${sourceName}'`
        : source.kind === 'collection'
          ? `Share collection '${sourceName}'`
          : `Share ${sourceName}`,
  );
  let bundleHint = $derived(
    source.kind === 'file'
      ? ''
      : source.kind === 'folder'
        ? 'Every file in this folder (and its subfolders) will be uploaded to the relay.'
        : source.kind === 'collection'
          ? 'Every photo in this collection will be uploaded to the relay.'
          : source.kind === 'mixed'
            ? 'Every selected folder (with its subfolders) and loose file will be uploaded to the relay and delivered as one zip archive.'
            : 'The selected files will be uploaded to the relay and delivered as one zip archive.',
  );
  // Password strength meter (only shown when password toggle is on).
  let strength = $derived(passwordStrength(password));
  let strengthLabel = $derived(['', 'Weak', 'Fair', 'Good', 'Strong'][strength]);
  let strengthColor = $derived([
    '',
    'var(--danger)',
    'var(--accent-warm, #E0A320)',
    'var(--accent)',
    'var(--accent)',
  ][strength]);
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-label="Share"
  onclick={(e) => { if (e.target === e.currentTarget) close(); }}
  onkeydown={(e) => {
    if (e.key === 'Escape') close();
  }}
  tabindex="-1"
  transition:fade={{ duration: 200 }}
>
  <div class="sheet" transition:fly={{ y: 80, duration: 300, easing: quintOut }}>
    <div class="drag-handle" aria-hidden="true"></div>

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
      <button class="close-btn" onclick={close} aria-label="Close">
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
          <label for="share-label-input" class="field-label">Share name <span class="field-label-optional">(optional)</span></label>
          <input
            id="share-label-input"
            class="field-input"
            type="text"
            bind:value={shareLabel}
            placeholder={sourceName}
            maxlength="120"
            autocomplete="off"
          />
          <p class="field-hint">
            Surfaces in Settings → Active shares and on the recipient's
            landing page. Leave blank to use the default
            (<span class="mono-text">{sourceName}</span>).
          </p>
        </div>

        <div class="field">
          <p class="field-label">Link expires after</p>
          <div class="ttl-chips" role="group" aria-label="Link expiry">
            {#each ttlOptions as opt}
              <button
                type="button"
                class="ttl-chip"
                class:active={ttlChoice === opt.value}
                onclick={() => (ttlChoice = opt.value)}
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
></div>
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
        onclick={generate}
        disabled={generating}
        aria-busy={generating}
      >
        {#if generating}
          <span class="spinner-sm" aria-hidden="true"></span>
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
            onclick={() => (showQr = !showQr)}
            aria-label={showQr ? 'Hide QR code' : 'Show QR code'}
            aria-expanded={showQr}
            title={showQr ? 'Hide QR' : 'Show QR'}
          >
            <QrCode size={18} />
          </button>
          <button class="icon-btn" onclick={copyLink} aria-label="Copy link" title="Copy link">
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
          <button class="btn-secondary" onclick={copyPasswordText} style="margin-top: var(--sp-sm)">
            <Copy size={16} aria-hidden="true" />
            Copy password
          </button>
        {/if}

        <button class="btn-ghost btn-danger-text" onclick={revoke} style="margin-top: var(--sp-sm)">
          Revoke link
        </button>
      </div>
    {/if}

    <div class="explainer">
      <button
        class="explainer-toggle"
        onclick={() => (showExplainer = !showExplainer)}
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

{#if streamingHintOpen}
  <!-- Sits on top of ShareLinkSheet's z-index:500 overlay. Hard-coded
       z-index because the design-system tokens (z-overlay/z-sheet) cap
       at 60 — ConfirmModal/BottomSheet would render behind. -->
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="streaming-hint-overlay"
    role="dialog"
    aria-modal="true"
    aria-labelledby="streaming-hint-title"
    onclick={(e) => { if (e.target === e.currentTarget) handleStreamingHintCancel(); }}
    onkeydown={(e) => { if (e.key === 'Escape') handleStreamingHintCancel(); }}
    tabindex="-1"
    transition:fade={{ duration: 150 }}
  >
    <div
      class="streaming-hint-sheet"
      transition:fly={{ y: 40, duration: 220, easing: quintOut }}
    >
      <h3 class="streaming-hint-title" id="streaming-hint-title">
        Streaming uploads are off in this browser
      </h3>

      <div class="streaming-hint-callout" role="note">
        <span class="streaming-hint-icon" aria-hidden="true">
          <Warning size={18} weight="regular" />
        </span>
        <p>
          The share will work, but the encrypted ciphertext sits in this tab's
          memory while it uploads. For shares of a few hundred MB or less, you
          won't notice. Larger shares may use significant RAM until the
          upload finishes.
        </p>
      </div>

      <details class="streaming-hint-details">
        <summary>
          <CaretDown size={14} weight="bold" class="streaming-hint-summary-caret" />
          <span>Make Firefox stream uploads instead</span>
        </summary>
        <p class="streaming-hint-explainer">
          Firefox supports streaming uploads but ships with the feature off
          by default. Browsers can't open <code>about:</code> pages from a
          regular tab — copy the values below and paste them in:
        </p>
        <ol class="streaming-hint-steps">
          <li>
            Open a new tab and paste:
            <button
              type="button"
              class="streaming-hint-copy"
              onclick={async () => {
                streamingHintAboutCopied = await copyToClipboard('about:config');
                if (streamingHintAboutCopied) {
                  setTimeout(() => { streamingHintAboutCopied = false; }, 2000);
                }
              }}
            >
              <code>about:config</code>
              <Copy size={14} weight="regular" />
              {#if streamingHintAboutCopied}
                <span class="streaming-hint-copied">Copied</span>
              {/if}
            </button>
          </li>
          <li>
            Accept the warning, then search for:
            <button
              type="button"
              class="streaming-hint-copy"
              onclick={async () => {
                streamingHintFlagCopied = await copyToClipboard('network.fetch.upload_streams');
                if (streamingHintFlagCopied) {
                  setTimeout(() => { streamingHintFlagCopied = false; }, 2000);
                }
              }}
            >
              <code>network.fetch.upload_streams</code>
              <Copy size={14} weight="regular" />
              {#if streamingHintFlagCopied}
                <span class="streaming-hint-copied">Copied</span>
              {/if}
            </button>
          </li>
          <li>Toggle the value to <strong>true</strong>.</li>
          <li>Reload this page and create your share.</li>
        </ol>
        <p class="streaming-hint-note">
          Other browsers (Chrome, Edge, Safari 17.4+) ship streaming on by
          default — no flag needed.
        </p>
      </details>

      <label class="streaming-hint-dontshow">
        <input type="checkbox" bind:checked={streamingHintDontShowAgain} />
        <span>Don't show this again on this device</span>
      </label>

      <div class="streaming-hint-actions">
        <button type="button" class="btn btn-ghost" onclick={handleStreamingHintCancel}>
          Cancel
        </button>
        <button type="button" class="btn btn-primary" onclick={handleStreamingHintConfirm}>
          Continue anyway
        </button>
      </div>
    </div>
  </div>
{/if}

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
  .field-label-optional { color: var(--text-disabled, #616161); font-weight: 400; }
  .field-input {
    width: 100%;
    box-sizing: border-box;
    padding: 8px 12px;
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    color: var(--text-primary, #ededed);
    font-size: var(--t-body-size, 0.9375rem);
  }
  .field-input::placeholder { color: var(--text-disabled, #616161); }
  .field-input:focus {
    outline: none;
    border-color: var(--accent, #2EB860);
  }
  .field-hint {
    margin: 0;
    font-size: 0.6875rem;
    color: var(--text-disabled, #616161);
    line-height: 1.4;
  }
  .field-hint .mono-text { font-family: var(--font-mono, ui-monospace, monospace); color: var(--text-secondary, #999); }

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

  /* ── Streaming-fallback hint modal ─────────────────────────────────── */
  .streaming-hint-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    /* Must clear ShareLinkSheet's z-index:500 — the hint is launched
       *from inside* that sheet so it has to render above it. */
    z-index: 600;
    padding: var(--sp-md, 16px);
  }
  .streaming-hint-sheet {
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
    width: 100%;
    max-width: 520px;
    max-height: calc(100vh - var(--sp-xl, 32px));
    overflow-y: auto;
    padding: var(--sp-lg, 24px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
    color: var(--text-primary, #EDEDED);
    line-height: 1.5;
    font-size: var(--t-body-sm-size, 0.8125rem);
  }
  .streaming-hint-title {
    margin: 0;
    font-size: var(--t-title-size, 1.0625rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }
  .streaming-hint-sheet p { margin: 0; }
  .streaming-hint-callout {
    display: flex;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--accent-warm-muted, #3D2F10);
    border: 1px solid color-mix(in srgb, var(--accent-warm, #E0A320) 35%, transparent);
    border-radius: var(--r-input, 12px);
    color: var(--accent-warm, #E0A320);
  }
  .streaming-hint-callout p {
    color: var(--text-primary, #EDEDED);
    flex: 1;
  }
  .streaming-hint-icon {
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
    margin-top: 2px;
  }
  .streaming-hint-details > summary {
    cursor: pointer;
    color: var(--text-primary, #ededed);
    font-weight: 500;
    list-style: none;
    user-select: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 10px;
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    background: var(--bg-surface, #1C1C1C);
    transition: background 150ms;
  }
  .streaming-hint-details > summary:hover {
    background: var(--bg-surface-raised, #1E1E1E);
  }
  .streaming-hint-details > summary::-webkit-details-marker { display: none; }
  .streaming-hint-details > summary :global(.streaming-hint-summary-caret) {
    transition: transform 200ms ease;
    color: var(--text-secondary, #999);
  }
  .streaming-hint-details[open] > summary :global(.streaming-hint-summary-caret) {
    transform: rotate(180deg);
  }
  .streaming-hint-explainer {
    margin: var(--sp-sm, 8px) 0 var(--sp-sm, 8px) !important;
    color: var(--text-secondary, #999);
  }
  .streaming-hint-steps {
    margin: 0;
    padding-left: var(--sp-md, 16px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
    color: var(--text-primary, #EDEDED);
  }
  .streaming-hint-steps li { line-height: 1.6; }
  .streaming-hint-steps code {
    font-family: var(--font-mono, ui-monospace, monospace);
    font-size: 0.8125rem;
    background: var(--bg-surface, #1C1C1C);
    padding: 1px 6px;
    border-radius: 4px;
  }
  .streaming-hint-copy {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 8px;
    margin-left: 4px;
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: 6px;
    color: var(--text-primary, #EDEDED);
    cursor: pointer;
    font-size: inherit;
    line-height: 1;
    vertical-align: baseline;
  }
  .streaming-hint-copy:hover { background: var(--bg-surface-hover, #2E2E2E); }
  .streaming-hint-copy code { background: transparent; padding: 0; }
  .streaming-hint-copied {
    color: var(--accent-text, #5FDB8A);
    font-size: 0.6875rem;
    margin-left: 4px;
  }
  .streaming-hint-note {
    margin: var(--sp-sm, 8px) 0 0 !important;
    color: var(--text-disabled, #616161);
    font-size: 0.75rem;
  }
  .streaming-hint-dontshow {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--text-secondary, #999);
    font-size: 0.8125rem;
    cursor: pointer;
  }
  .streaming-hint-dontshow input { cursor: pointer; }
  .streaming-hint-actions {
    display: flex;
    gap: var(--sp-sm, 8px);
    justify-content: flex-end;
    margin-top: var(--sp-sm, 8px);
  }
  .streaming-hint-actions .btn { min-width: 110px; }
</style>
