<script lang="ts">
  /**
   * AddProviderSheet — bottom sheet (DESIGN.md §11.2) for adding a storage provider.
   *
   * Two modes:
   *   firstRun=false (default): adds a second provider to an already-open vault.
   *     Fires `on:added` with the new provider_id. Used from ByoDashboard.
   *   firstRun=true: first-run flow; vault is not open yet.
   *     Fires `on:selected` with the initialized provider instance + config.
   *     Used from ByoApp instead of the now-deleted ProviderPicker.
   */
  import { createEventDispatcher, getContext } from 'svelte';
  import type { StorageProvider, ProviderType, ProviderConfig } from '@wattcloud/sdk';
  import { createProvider, SftpProvider } from '@wattcloud/sdk';
  import * as byoWorker from '@wattcloud/sdk';
  import { addProvider, getPrimaryProviderId } from '../../byo/VaultLifecycle';
  import { initiateOAuthFlow } from '@wattcloud/sdk';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import HexShield from '../HexShield.svelte';

  /** Set to true when used as the first-run provider selection screen. */
  export let firstRun = false;

  const dispatch = createEventDispatcher<{
    added: { providerId: string };
    selected: { provider: StorageProvider; config: ProviderConfig };
    close: void;
  }>();

  // ── Provider list ──────────────────────────────────────────────────────────

  const PROVIDERS: Array<{
    type: ProviderType;
    name: string;
    description: string;
    mode: 'oauth' | 'inline';
  }> = [
    { type: 'gdrive',   name: 'Google Drive',  description: '15 GB free',             mode: 'oauth' },
    { type: 'dropbox',  name: 'Dropbox',        description: '2 GB free',              mode: 'oauth' },
    { type: 'onedrive', name: 'OneDrive',       description: '5 GB free',             mode: 'oauth' },
    { type: 'box',      name: 'Box',            description: '10 GB free',            mode: 'oauth' },
    { type: 'pcloud',   name: 'pCloud',         description: 'EU/US regions',         mode: 'oauth' },
    { type: 'webdav',   name: 'WebDAV',          description: 'Nextcloud, ownCloud…',  mode: 'inline' },
    { type: 'sftp',     name: 'SFTP',            description: 'Any SSH server',        mode: 'inline' },
    { type: 's3',       name: 'S3 / R2 / Wasabi / MinIO', description: 'Any S3-compatible bucket', mode: 'inline' },
  ];

  // ── State ──────────────────────────────────────────────────────────────────

  let activeInline: ProviderType | null = null;
  let oauthLoading: ProviderType | null = null;
  let connecting = false;
  let error = '';

  // WebDAV form
  let wdavUrl = ''; let wdavUser = ''; let wdavPass = '';
  // SFTP form
  let sftpHost = ''; let sftpPort = 22; let sftpUser = '';
  let sftpPass = ''; let sftpKey = ''; let sftpPassphrase = '';
  // pCloud region
  let pcloudRegion: 'us' | 'eu' = 'us';

  // S3 form
  let s3Endpoint = ''; let s3Region = ''; let s3Bucket = '';
  let s3AccessKeyId = ''; let s3SecretAccessKey = '';
  let s3PathStyle = false; let s3ShowSecret = false; let s3CorsError = false;

  type S3Service = 'cloudflare-r2' | 'wasabi' | 'minio' | null;
  function detectS3Service(ep: string): S3Service {
    if (!ep) return null;
    if (ep.includes('r2.cloudflarestorage.com')) return 'cloudflare-r2';
    if (ep.includes('wasabisys.com')) return 'wasabi';
    if (ep.includes('minio') || /:[0-9]{4,5}$/.test(ep)) return 'minio';
    return null;
  }
  $: s3Detected = detectS3Service(s3Endpoint);
  $: if (s3Detected === 'minio' || s3Detected === 'wasabi') s3PathStyle = true;
  $: if (s3Detected === 'cloudflare-r2') s3PathStyle = false;

  const S3_CORS_JSON = JSON.stringify({
    CORSRules: [{ AllowedOrigins: ['*'], AllowedMethods: ['GET', 'PUT', 'HEAD', 'DELETE'],
      AllowedHeaders: ['*'], ExposeHeaders: ['ETag'], MaxAgeSeconds: 3600 }]
  }, null, 2);

  async function submitS3() {
    s3CorsError = false; error = '';
    if (!s3Bucket)          { error = 'Bucket name is required'; return; }
    if (!s3AccessKeyId)     { error = 'Access key ID is required'; return; }
    if (!s3SecretAccessKey) { error = 'Secret access key is required'; return; }
    await connectProvider('s3', {
      type: 's3',
      s3Endpoint: s3Endpoint || undefined,
      s3Region:   s3Region || undefined,
      s3Bucket,
      s3AccessKeyId,
      s3SecretAccessKey,
      s3PathStyle: s3PathStyle || undefined,
    });
    if (error && (error.toLowerCase().includes('cors') || error.toLowerCase().includes('network'))) {
      s3CorsError = true;
    }
  }

  function copyS3CorsJson() {
    navigator.clipboard.writeText(S3_CORS_JSON);
  }

  // SSH TOFU confirmation
  let pendingHostKey: { fingerprint: string; resolve: (v: boolean) => void } | null = null;

  // ── OAuth providers ────────────────────────────────────────────────────────

  async function connectOAuth(type: ProviderType) {
    error = '';
    oauthLoading = type;
    try {
      const result = await initiateOAuthFlow(type as 'gdrive' | 'dropbox' | 'onedrive' | 'box' | 'pcloud');
      const config: ProviderConfig = {
        type,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        tokenExpiry: Date.now() + result.expiresIn * 1000,
      };
      await connectProvider(type, config);
    } catch (e: any) {
      error = e.message || 'Authentication failed';
    } finally {
      oauthLoading = null;
    }
  }

  // ── Inline forms ───────────────────────────────────────────────────────────

  async function submitWebDAV() {
    if (!wdavUrl) { error = 'Server URL is required'; return; }
    if (!wdavUser) { error = 'Username is required'; return; }
    await connectProvider('webdav', { type: 'webdav', serverUrl: wdavUrl, username: wdavUser, password: wdavPass || undefined });
  }

  async function submitSFTP() {
    if (!sftpHost) { error = 'Hostname is required'; return; }
    if (!sftpUser) { error = 'Username is required'; return; }
    if (!sftpPass && !sftpKey) { error = 'Password or private key is required'; return; }
    error = '';
    let credHandle: number;
    try {
      credHandle = await byoWorker.Worker.sftpStoreCredential(
        sftpPass || undefined,
        sftpKey || undefined,
        sftpPassphrase || undefined,
      );
    } catch (e: any) {
      error = e.message || 'Failed to store credentials';
      return;
    }
    // Zero sensitive form vars immediately after moving to worker.
    sftpPass = ''; sftpKey = ''; sftpPassphrase = '';
    await connectProvider('sftp', {
      type: 'sftp',
      sftpHost,
      sftpPort,
      sftpUsername: sftpUser,
    }, credHandle);
  }

  // ── Connect & register ─────────────────────────────────────────────────────

  async function connectProvider(type: ProviderType, config: ProviderConfig, sftpCredHandle?: number) {
    error = '';
    connecting = true;
    try {
      const instance = createProvider(type);

      if (instance instanceof SftpProvider) {
        if (sftpCredHandle === undefined) throw new Error('SFTP connection requires credential handle');
        instance.onFirstHostKey = (fp: string) =>
          new Promise<boolean>(resolve => { pendingHostKey = { fingerprint: fp, resolve }; });
        instance.credHandle = sftpCredHandle;
        instance.credUsername = config.sftpUsername || '';
      }

      await instance.init(config);

      if (firstRun) {
        // First-run: vault not open yet — hand the ready instance + config to ByoApp
        dispatch('selected', { provider: instance, config });
      } else {
        // Dashboard: vault is open — register the provider and notify the tab switcher
        const providerId = await addProvider(instance, config);
        dispatch('added', { providerId });
      }
    } catch (e: any) {
      error = e.message || 'Failed to connect';
      // Clean up worker-side SFTP credential on connection failure.
      if (sftpCredHandle !== undefined) {
        byoWorker.Worker.sftpClearCredential(sftpCredHandle).catch(() => {});
      }
    } finally {
      connecting = false;
    }
  }
</script>

<!-- First-run: full-page view (no overlay, role=region).                   -->
<!-- Dashboard "add provider": bottom sheet (DESIGN.md §11.2, role=dialog). -->
<!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
<div
  class:inline-page={firstRun}
  class:sheet-overlay={!firstRun}
  on:click={firstRun ? undefined : (e) => { if (e.target === e.currentTarget) dispatch('close'); }}
>
  <div
    class:inline-content={firstRun}
    class:sheet={!firstRun}
    role={firstRun ? 'region' : 'dialog'}
    aria-modal={firstRun ? undefined : 'true'}
    aria-label={firstRun ? 'Choose storage provider' : 'Add storage provider'}
  >
    {#if !firstRun}
      <div class="drag-handle" aria-hidden="true"></div>
    {/if}

    {#if firstRun}
      <div class="first-run-brand">
        <HexShield size={64} variant="check" color="var(--accent, #2EB860)" fillColor="var(--accent-muted, #1B3627)" />
        <h1 class="first-run-title">Wattcloud</h1>
        <p class="first-run-sub">Your files stay encrypted — only you hold the keys.</p>
      </div>
    {/if}

    <div class="sheet-header">
      <h2 class="sheet-title">{firstRun ? 'Choose your storage' : 'Add storage'}</h2>
      <p class="sheet-subtitle">{firstRun ? 'Pick the cloud you already use. We never see your plaintext.' : 'Connect a cloud provider to your vault'}</p>
    </div>

    {#if !firstRun}
      <!-- Trust banner — hex-shield motif (DESIGN.md §29.1) -->
      <div class="trust-banner">
        <HexShield size={24} variant="check" color="var(--accent-text, #5FDB8A)" fillColor="transparent" />
        <span>End-to-end encrypted on all providers</span>
      </div>
    {/if}

    {#if error}
      <div class="error-banner" role="alert">{error}</div>
    {/if}

    <!-- Provider list (DESIGN.md §14.1 — 48dp rows) -->
    <div class="provider-list">
      {#each PROVIDERS as p}
        <div class="provider-row">
          {#if p.mode === 'oauth'}
            <button
              class="provider-btn"
              class:loading={oauthLoading === p.type}
              disabled={connecting || !!oauthLoading}
              on:click={() => connectOAuth(p.type)}
            >
              <span class="provider-name">{p.name}</span>
              <span class="provider-desc">{p.description}</span>
              {#if oauthLoading === p.type}
                <span class="spinner-sm" aria-label="Connecting…"></span>
              {:else}
                <svg class="chevron" viewBox="0 0 16 16" aria-hidden="true">
                  <path d="M6 3l5 5-5 5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
                </svg>
              {/if}
            </button>
          {:else}
            <button
              class="provider-btn"
              class:active={activeInline === p.type}
              disabled={connecting}
              on:click={() => { activeInline = activeInline === p.type ? null : p.type; error = ''; }}
            >
              <span class="provider-name">{p.name}</span>
              <span class="provider-desc">{p.description}</span>
              <svg class="chevron" class:rotated={activeInline === p.type} viewBox="0 0 16 16" aria-hidden="true">
                <path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              </svg>
            </button>

            {#if activeInline === 'webdav' && p.type === 'webdav'}
              <form class="inline-form" on:submit|preventDefault={submitWebDAV}>
                <label class="field-label">Server URL
                  <input class="field-input" type="url" bind:value={wdavUrl} placeholder="https://cloud.example.com" required autocomplete="off"/>
                </label>
                <label class="field-label">Username
                  <input class="field-input" type="text" bind:value={wdavUser} required autocomplete="username"/>
                </label>
                <label class="field-label">Password
                  <input class="field-input" type="password" bind:value={wdavPass} autocomplete="current-password"/>
                </label>
                <button type="submit" class="btn-primary" disabled={connecting}>
                  {connecting ? 'Connecting…' : 'Connect'}
                </button>
              </form>
            {/if}

            {#if activeInline === 'sftp' && p.type === 'sftp'}
              <form class="inline-form" on:submit|preventDefault={submitSFTP}>
                <label class="field-label">Hostname
                  <input class="field-input" type="text" bind:value={sftpHost} required autocomplete="off"/>
                </label>
                <div class="row-2">
                  <label class="field-label">Port
                    <input class="field-input" type="number" bind:value={sftpPort} min="1" max="65535"/>
                  </label>
                  <label class="field-label">Username
                    <input class="field-input" type="text" bind:value={sftpUser} required autocomplete="username"/>
                  </label>
                </div>
                <label class="field-label">Password
                  <input class="field-input" type="password" bind:value={sftpPass} autocomplete="current-password"/>
                </label>
                <label class="field-label">Private key (PEM)
                  <textarea class="field-input field-textarea" bind:value={sftpKey} rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
                </label>
                <button type="submit" class="btn-primary" disabled={connecting}>
                  {connecting ? 'Connecting…' : 'Connect'}
                </button>
              </form>
            {/if}

            {#if activeInline === 's3' && p.type === 's3'}
              <form class="inline-form" on:submit|preventDefault={submitS3}>
                {#if s3Detected}
                  <div class="detect-chip">
                    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                      <path d="M8 1l1.5 3 3.5.5-2.5 2.5.5 3.5L8 9l-3 1.5.5-3.5L3 4.5 6.5 4z" fill="currentColor"/>
                    </svg>
                    Detected {s3Detected === 'cloudflare-r2' ? 'Cloudflare R2' : s3Detected === 'wasabi' ? 'Wasabi' : 'MinIO'}{s3Detected !== 'cloudflare-r2' ? ' — path-style auto-enabled' : ''}
                  </div>
                {/if}
                <label class="field-label">Endpoint URL
                  <input class="field-input" type="url" bind:value={s3Endpoint} placeholder="Leave blank for AWS S3 (or https://…)" autocomplete="off"/>
                </label>
                <div class="row-2">
                  <label class="field-label">Region
                    <input class="field-input" type="text" bind:value={s3Region} placeholder="us-east-1" autocomplete="off"/>
                  </label>
                  <label class="field-label">Bucket
                    <input class="field-input" type="text" bind:value={s3Bucket} placeholder="my-bucket" required autocomplete="off"/>
                  </label>
                </div>
                <label class="field-label">Access Key ID
                  <input class="field-input" type="text" bind:value={s3AccessKeyId} required autocomplete="off" spellcheck="false"/>
                </label>
                <label class="field-label">Secret Access Key
                  <div class="secret-row">
                    {#if s3ShowSecret}
                      <input class="field-input secret-input" type="text" bind:value={s3SecretAccessKey} required autocomplete="new-password" spellcheck="false"/>
                    {:else}
                      <input class="field-input secret-input" type="password" bind:value={s3SecretAccessKey} required autocomplete="new-password" spellcheck="false"/>
                    {/if}
                    <button type="button" class="eye-btn" aria-label={s3ShowSecret ? 'Hide secret key' : 'Show secret key'} on:click={() => s3ShowSecret = !s3ShowSecret}>
                      {#if s3ShowSecret}
                        <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
                          <path d="M1 10s3-6 9-6 9 6 9 6-3 6-9 6-9-6-9-6z"/>
                          <circle cx="10" cy="10" r="3"/>
                          <line x1="2" y1="2" x2="18" y2="18" stroke-linecap="round"/>
                        </svg>
                      {:else}
                        <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
                          <path d="M1 10s3-6 9-6 9 6 9 6-3 6-9 6-9-6-9-6z"/>
                          <circle cx="10" cy="10" r="3"/>
                        </svg>
                      {/if}
                    </button>
                  </div>
                </label>
                <label class="toggle-label">
                  <input type="checkbox" class="toggle-input" bind:checked={s3PathStyle}/>
                  <span class="toggle-text">Force path-style URLs (MinIO, Backblaze B2)</span>
                </label>
                {#if s3CorsError}
                  <div class="cors-card" role="alert">
                    <p class="cors-title">CORS not configured on this bucket</p>
                    <p class="cors-body">Add this CORS rule to your bucket, then try again.</p>
                    <button type="button" class="btn-copy" on:click={copyS3CorsJson}>Copy CORS JSON</button>
                  </div>
                {/if}
                <button type="submit" class="btn-primary" disabled={connecting}>
                  {connecting ? 'Connecting…' : 'Test & Connect'}
                </button>
              </form>
            {/if}
          {/if}
        </div>
      {/each}
    </div>

    {#if firstRun}
      <!-- First-run: amber trust line at the bottom (§29.2 secondary accent) -->
      <p class="first-run-footer">
        <HexShield size={16} variant="outline" color="var(--accent-warm-text, #F0C04A)" />
        <span>Zero-knowledge — we never receive your files or keys.</span>
      </p>
    {:else}
      <button class="btn-ghost" on:click={() => dispatch('close')}>Cancel</button>
    {/if}
  </div>
</div>

<!-- SSH host-key TOFU confirmation -->
{#if pendingHostKey}
  <div class="tofu-overlay" role="dialog" aria-modal="true" aria-label="SSH host key verification">
    <div class="tofu-dialog">
      <h3>Verify SSH Host Key</h3>
      <p>First connection to this SFTP server. Confirm the fingerprint before trusting it.</p>
      <div class="fp-box">{pendingHostKey.fingerprint}</div>
      <div class="tofu-actions">
        <button class="btn-danger-sm" on:click={() => { pendingHostKey?.resolve(false); pendingHostKey = null; }}>Reject</button>
        <button class="btn-primary-sm" on:click={() => { pendingHostKey?.resolve(true); pendingHostKey = null; }}>Trust &amp; Connect</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .sheet-overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,.55);
    display: flex; align-items: flex-end; justify-content: center;
    z-index: 900;
  }

  .sheet {
    background: var(--bg-surface-raised, #1E1E1E);
    border-radius: var(--r-card, 16px) var(--r-card, 16px) 0 0;
    width: 100%; max-width: 600px;
    max-height: 85vh;
    overflow-y: auto;
    padding: var(--sp-sm, 8px) var(--sp-lg, 24px) var(--sp-xl, 32px);
    display: flex; flex-direction: column; gap: var(--sp-md, 16px);
    animation: slideUp 300ms cubic-bezier(.32,.72,0,1);
  }

  /* First-run: full-page layout, no sheet overlay, no drag handle. (§B4) */
  .inline-page {
    flex: 1;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: var(--sp-lg, 24px) var(--sp-md, 16px);
    overflow-y: auto;
  }

  .inline-content {
    width: 100%;
    max-width: 480px;
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
  }

  .first-run-brand {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-sm, 8px);
    text-align: center;
    padding: var(--sp-lg, 24px) 0 var(--sp-md, 16px);
  }

  .first-run-title {
    margin: 0;
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--text-primary, #EDEDED);
  }

  .first-run-sub {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    max-width: 320px;
    line-height: 1.5;
  }

  .first-run-footer {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-sm, 8px);
    margin: var(--sp-sm, 8px) 0 0;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
    text-align: center;
  }

  @keyframes slideUp { from { transform: translateY(100%); } }

  .drag-handle {
    width: 36px; height: 4px;
    background: var(--border, #2E2E2E);
    border-radius: 2px;
    align-self: center; margin-bottom: var(--sp-xs, 4px);
  }

  .sheet-title {
    margin: 0;
    font-size: var(--t-h2-size, 1.125rem);
    font-weight: 600; color: var(--text-primary, #EDEDED);
  }
  .sheet-subtitle {
    margin: 0;
    font-size: var(--t-body-sm-size, .8125rem);
    color: var(--text-secondary, #999);
  }

  /* Trust banner — hex-shield green+amber pairing (§29.1, §29.2) */
  .trust-banner {
    display: flex; align-items: center; gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--accent-muted, #1A3D2B);
    border-radius: var(--r-card, 16px);
    color: var(--accent-text, #5FDB8A);
    font-size: var(--t-body-sm-size, .8125rem);
  }
  .trust-banner :global(svg) { flex-shrink: 0; }

  .error-banner {
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 12px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, .8125rem);
  }

  .provider-list { display: flex; flex-direction: column; gap: 1px; }

  .provider-row { display: flex; flex-direction: column; }

  /* 48dp provider row (§14.1) */
  .provider-btn {
    display: flex; align-items: center; gap: var(--sp-sm, 8px);
    min-height: 48px; width: 100%;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--bg-surface, #161616);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    color: var(--text-primary, #EDEDED);
    cursor: pointer; text-align: left;
    transition: background 120ms;
  }
  .provider-btn:hover:not(:disabled) { background: var(--bg-surface-raised, #1E1E1E); }
  .provider-btn.active { border-color: var(--accent, #2EB860); }

  .provider-name { font-weight: 500; flex: 1; }
  .provider-desc { font-size: var(--t-body-sm-size, .8125rem); color: var(--text-secondary, #999); }

  .chevron { width: 16px; height: 16px; flex-shrink: 0; transition: transform 200ms; }
  .chevron.rotated { transform: rotate(180deg); }

  /* Inline forms */
  .inline-form {
    display: flex; flex-direction: column; gap: var(--sp-sm, 8px);
    padding: var(--sp-md, 16px);
    background: var(--bg-canvas, #121212);
    border: 1px solid var(--border, #2E2E2E);
    border-top: none;
    border-radius: 0 0 var(--r-card, 16px) var(--r-card, 16px);
  }

  .row-2 { display: grid; grid-template-columns: 80px 1fr; gap: var(--sp-sm, 8px); }

  .field-label {
    display: flex; flex-direction: column; gap: 4px;
    font-size: var(--t-body-sm-size, .8125rem);
    color: var(--text-secondary, #999);
  }
  .field-input {
    width: 100%;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--bg-surface, #161616);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-size, .9375rem);
    box-sizing: border-box;
  }
  .field-textarea { resize: vertical; min-height: 72px; font-family: monospace; }

  /* Pill buttons (DESIGN.md §12) */
  .btn-primary {
    padding: var(--sp-sm, 10px) var(--sp-xl, 24px);
    border-radius: var(--r-pill, 9999px);
    border: none; background: var(--accent, #2EB860);
    color: var(--text-inverse, #000); font-size: var(--t-body-size, .9375rem);
    font-weight: 600; cursor: pointer; align-self: flex-end;
  }
  .btn-primary:disabled { opacity: .5; cursor: not-allowed; }

  .btn-ghost {
    padding: var(--sp-sm, 10px) var(--sp-xl, 24px);
    border-radius: var(--r-pill, 9999px);
    border: 1px solid var(--border, #2E2E2E);
    background: transparent;
    color: var(--text-secondary, #999);
    font-size: var(--t-body-size, .9375rem);
    cursor: pointer; width: 100%;
  }

  .spinner-sm {
    width: 16px; height: 16px;
    border: 2px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    display: inline-block;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* S3 auto-detect chip (amber, §29.2) */
  .detect-chip {
    display: flex; align-items: center; gap: 6px;
    padding: 6px 12px;
    background: var(--accent-warm-muted, #3D2F10);
    border-radius: var(--r-input, 12px);
    color: var(--accent-warm-text, #F5A623);
    font-size: var(--t-body-sm-size, .8125rem);
  }

  /* Secret access key row with eye toggle */
  .secret-row { display: flex; gap: 6px; align-items: center; }
  .secret-input { flex: 1; }
  .eye-btn {
    flex-shrink: 0; width: 36px; height: 36px;
    display: flex; align-items: center; justify-content: center;
    background: var(--bg-surface, #161616);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    color: var(--text-secondary, #999);
    cursor: pointer;
  }
  .eye-btn:hover { color: var(--text-primary, #EDEDED); }

  /* Path-style toggle */
  .toggle-label {
    display: flex; align-items: center; gap: 8px;
    font-size: var(--t-body-sm-size, .8125rem);
    color: var(--text-secondary, #999);
    cursor: pointer;
  }
  .toggle-input { width: 16px; height: 16px; accent-color: var(--accent, #2EB860); cursor: pointer; }
  .toggle-text { user-select: none; }

  /* CORS error card */
  .cors-card {
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--accent-warm-muted, #3D2F10);
    border: 1px solid var(--accent-warm, #F5A623);
    border-radius: var(--r-input, 12px);
    display: flex; flex-direction: column; gap: 6px;
  }
  .cors-title { margin: 0; font-size: .8125rem; font-weight: 600; color: var(--accent-warm-text, #F5A623); }
  .cors-body  { margin: 0; font-size: .75rem; color: var(--text-secondary, #999); }
  .btn-copy {
    align-self: flex-start;
    padding: 4px 12px; border-radius: 8px;
    border: 1px solid var(--accent-warm, #F5A623);
    background: transparent; color: var(--accent-warm-text, #F5A623);
    font-size: .75rem; cursor: pointer;
  }

  /* TOFU overlay */
  .tofu-overlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,.75);
    display: flex; align-items: center; justify-content: center;
    z-index: 1000; padding: var(--sp-lg, 24px);
  }
  .tofu-dialog {
    background: var(--bg-surface-raised, #1E1E1E);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    padding: var(--sp-xl, 32px);
    max-width: 480px; width: 100%;
    display: flex; flex-direction: column; gap: var(--sp-md, 16px);
  }
  .tofu-dialog h3 { margin: 0; font-size: 1rem; color: var(--text-primary, #ededed); }
  .tofu-dialog p  { margin: 0; font-size: .8125rem; color: var(--text-secondary, #999); }
  .fp-box {
    font-family: monospace; font-size: .8125rem;
    background: var(--bg-canvas, #121212);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    word-break: break-all;
  }
  .tofu-actions { display: flex; gap: var(--sp-sm, 8px); justify-content: flex-end; }
  .btn-danger-sm {
    padding: 8px 16px; border-radius: 10px;
    border: 1px solid var(--danger, #D64545);
    background: transparent; color: var(--danger, #D64545);
    font-size: .8125rem; cursor: pointer;
  }
  .btn-primary-sm {
    padding: 8px 16px; border-radius: 10px;
    border: none; background: var(--accent, #2EB860);
    color: #fff; font-size: .8125rem; cursor: pointer;
  }
</style>
