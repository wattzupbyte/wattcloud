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
  import type { ProviderType, ProviderConfig } from '@wattcloud/sdk';
  import { createProvider, SftpProvider } from '@wattcloud/sdk';
  import * as byoWorker from '@wattcloud/sdk';
  import { addProvider } from '../../byo/VaultLifecycle';
  import { initiateOAuthFlow } from '@wattcloud/sdk';
  import CloudBadge from '../CloudBadge.svelte';
  import Lock from 'phosphor-svelte/lib/Lock';
  import PasswordInput from '../common/PasswordInput.svelte';
  import { byoToast } from '../../byo/stores/byoToasts';
  import CloudArrowUp from 'phosphor-svelte/lib/CloudArrowUp';
  import CloudCheck from 'phosphor-svelte/lib/CloudCheck';
  import HardDrives from 'phosphor-svelte/lib/HardDrives';
  import Terminal from 'phosphor-svelte/lib/Terminal';
  import Database from 'phosphor-svelte/lib/Database';
  import Key from 'phosphor-svelte/lib/Key';
  import ArrowSquareOut from 'phosphor-svelte/lib/ArrowSquareOut';
  import CaretDown from 'phosphor-svelte/lib/CaretDown';
  import DeviceMobile from 'phosphor-svelte/lib/DeviceMobile';
  import type { ComponentType } from 'svelte';

  
  interface Props {
    /** Set to true when used as the first-run provider selection screen. */
    firstRun?: boolean;
  onSelected?: (...args: any[]) => void;
  onAdded?: (...args: any[]) => void;
  onLinkDevice?: (...args: any[]) => void;
  onClose?: (...args: any[]) => void;
  }

  let { firstRun = false,
  onSelected,
  onAdded,
  onLinkDevice,
  onClose }: Props = $props();
// ── Provider list ──────────────────────────────────────────────────────────

  const PROVIDERS: Array<{
    type: ProviderType;
    name: string;
    description: string;
    mode: 'oauth' | 'inline';
    icon: ComponentType;
  }> = [
    // OAuth cloud accounts — deferred. Keep rows commented out (not deleted)
    // so re-enabling is a one-line change once the OAuth flow is shipped.
    /*
    { type: 'gdrive',   name: 'Google Drive',            description: 'Connect your Google account',       mode: 'oauth',  icon: GoogleDriveLogo },
    { type: 'dropbox',  name: 'Dropbox',                 description: 'Connect your Dropbox',               mode: 'oauth',  icon: DropboxLogo     },
    { type: 'onedrive', name: 'OneDrive',                description: 'Connect your Microsoft account',     mode: 'oauth',  icon: Cloud           },
    { type: 'box',      name: 'Box',                     description: 'Connect your Box account',           mode: 'oauth',  icon: Package         },
    { type: 'pcloud',   name: 'pCloud',                  description: 'Connect pCloud — EU or US',          mode: 'oauth',  icon: CloudCheck      },
    */
    // Bring your own endpoint — inline-form credentials, no provider console needed.
    { type: 'webdav',   name: 'WebDAV',                  description: 'Nextcloud, ownCloud, Synology, …',   mode: 'inline', icon: HardDrives      },
    { type: 'sftp',     name: 'SFTP',                    description: 'Any SSH server you control',         mode: 'inline', icon: Terminal        },
    { type: 's3',       name: 'S3 / R2 / Wasabi / MinIO',description: 'AWS, R2, Wasabi, MinIO, Backblaze',  mode: 'inline', icon: Database        },
  ];
  const INLINE_PROVIDERS = PROVIDERS.filter((p) => p.mode === 'inline');

  // ── State ──────────────────────────────────────────────────────────────────

  let activeInline: ProviderType | null = $state(null);
  let oauthLoading: ProviderType | null = $state(null);
  let connecting = $state(false);
  let error = $state('');

  // Surface an error to the user via the global toast host — replaces the
  // old top-of-sheet banner that users couldn't see when scrolled down to
  // the inline forms. `error` is still tracked so submitS3 can inspect the
  // message for CORS/network substrings after a failed connect.
  function showError(msg: string) {
    error = msg;
    byoToast.show(msg, { icon: 'danger' });
  }

  // WebDAV form
  let wdavUrl = $state(''); let wdavUser = $state(''); let wdavPass = $state('');
  // SFTP form
  let sftpHost = $state(''); let sftpPort = $state(22); let sftpUser = $state('');
  let sftpPass = $state(''); let sftpKey = $state(''); let sftpPassphrase = '';
  /** Optional server-absolute directory the vault lives under (e.g. `/wattcloud`). */
  let sftpBasePath = $state('');
  // S3 form
  let s3Endpoint = $state(''); let s3Region = $state(''); let s3Bucket = $state('');
  let s3AccessKeyId = $state(''); let s3SecretAccessKey = $state('');
  let s3PathStyle = $state(false); let s3CorsError = $state(false);
  /** Optional in-bucket prefix. Non-empty → vault at `{bucket}/{prefix}/WattcloudVault/`. */
  let s3BasePath = $state('');

  type S3Service = 'cloudflare-r2' | 'wasabi' | 'minio' | null;
  function detectS3Service(ep: string): S3Service {
    if (!ep) return null;
    if (ep.includes('r2.cloudflarestorage.com')) return 'cloudflare-r2';
    if (ep.includes('wasabisys.com')) return 'wasabi';
    if (ep.includes('minio') || /:[0-9]{4,5}$/.test(ep)) return 'minio';
    return null;
  }
  let s3Detected = $derived(detectS3Service(s3Endpoint));
  $effect(() => {
    if (s3Detected === 'minio' || s3Detected === 'wasabi') s3PathStyle = true;
  });
  $effect(() => {
    if (s3Detected === 'cloudflare-r2') s3PathStyle = false;
  });

  const S3_CORS_JSON = JSON.stringify({
    CORSRules: [{ AllowedOrigins: ['*'], AllowedMethods: ['GET', 'PUT', 'HEAD', 'DELETE'],
      AllowedHeaders: ['*'], ExposeHeaders: ['ETag'], MaxAgeSeconds: 3600 }]
  }, null, 2);

  async function submitS3() {
    s3CorsError = false; error = '';
    if (!s3Endpoint)        { showError('Endpoint URL is required'); return; }
    if (!s3Bucket)          { showError('Bucket name is required'); return; }
    if (!s3AccessKeyId)     { showError('Access key ID is required'); return; }
    if (!s3SecretAccessKey) { showError('Secret access key is required'); return; }
    await connectProvider('s3', {
      type: 's3',
      s3Endpoint,
      s3Region:   s3Region || undefined,
      s3Bucket,
      s3AccessKeyId,
      s3SecretAccessKey,
      s3PathStyle:  s3PathStyle || undefined,
      s3BasePath:   s3BasePath.trim() || undefined,
    });
    if (error && (error.toLowerCase().includes('cors') || error.toLowerCase().includes('network'))) {
      s3CorsError = true;
    }
  }

  function copyS3CorsJson() {
    navigator.clipboard.writeText(S3_CORS_JSON);
  }

  // SSH TOFU confirmation
  let pendingHostKey: { fingerprint: string; resolve: (v: boolean) => void } | null = $state(null);

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
      showError(e.message || 'Authentication failed');
    } finally {
      oauthLoading = null;
    }
  }

  // ── Inline forms ───────────────────────────────────────────────────────────

  async function submitWebDAV() {
    if (!wdavUrl) { showError('Server URL is required'); return; }
    if (!wdavUser) { showError('Username is required'); return; }
    await connectProvider('webdav', { type: 'webdav', serverUrl: wdavUrl, username: wdavUser, password: wdavPass || undefined });
  }

  // Parse a user-pasted SFTP host: strip scheme, userinfo, port, path, and
  // surrounding whitespace so DNS sees a clean label.  When the paste
  // includes a path (e.g. `sftp://user@host.example.com:22/wattcloud`) we
  // return it as `basePath` so the SFTP provider can nest the vault there
  // instead of silently dropping it.
  function parseSftpHost(raw: string): { host: string; basePath: string } {
    let h = raw.trim();
    h = h.replace(/^[a-z]+:\/\//i, '');  // scheme
    h = h.replace(/^[^@/]*@/, '');        // userinfo
    let path = '';
    const slash = h.indexOf('/');
    if (slash >= 0) {
      path = h.slice(slash);               // includes leading /
      h = h.slice(0, slash);
    }
    const colon = h.lastIndexOf(':');
    if (colon >= 0 && /^\d+$/.test(h.slice(colon + 1))) h = h.slice(0, colon);
    // Drop a trailing slash on the captured path so we never end up with
    // `//WattcloudVault` after concatenation with the vault root.
    const basePath = path.replace(/\/+$/, '');
    return { host: h, basePath };
  }

  async function submitSFTP() {
    const { host: cleanHost, basePath: extractedBase } = parseSftpHost(sftpHost);
    if (!cleanHost) { showError('Hostname is required'); return; }
    // Hostname must be a single DNS label sequence — no slashes, spaces, etc.
    if (!/^[a-zA-Z0-9.-]+$/.test(cleanHost) || cleanHost.length > 253) {
      showError(`"${sftpHost}" is not a valid hostname. Enter just the server, e.g. "u12345.your-storagebox.de".`);
      return;
    }
    // Reflect the cleaned value back into the input so the user sees what we
    // will actually connect to (and so re-submits don't mutate silently).
    // If the paste bundled `host/path`, promote the path into the Base
    // path field unless the user already typed something there.
    if (cleanHost !== sftpHost) sftpHost = cleanHost;
    if (extractedBase && !sftpBasePath) sftpBasePath = extractedBase;
    if (!sftpUser) { showError('Username is required'); return; }
    if (!sftpPass && !sftpKey) { showError('Password or private key is required'); return; }
    error = '';
    let credHandle: number;
    try {
      credHandle = await byoWorker.Worker.sftpStoreCredential(
        sftpPass || undefined,
        sftpKey || undefined,
        sftpPassphrase || undefined,
      );
    } catch (e: any) {
      showError(e.message || 'Failed to store credentials');
      return;
    }
    // Note: the WASM-side credential (credHandle) is the canonical copy used
    // for the live session; the plaintext copies below are persisted alongside
    // the rest of the ProviderConfig — encrypted in the manifest body
    // (BYO-ZK-3) and wrapped under the per-device non-extractable CryptoKey
    // in IDB (BYO-ZK-12). SECURITY.md §12 permits this for SFTP for parity
    // with the OAuth refresh-token and WebDAV-password flows.
    const ok = await connectProvider('sftp', {
      type: 'sftp',
      sftpHost,
      sftpPort,
      sftpUsername: sftpUser,
      sftpBasePath: sftpBasePath.trim() || undefined,
      sftpPassword: sftpPass || undefined,
      sftpPrivateKey: sftpKey || undefined,
      sftpPassphrase: sftpPassphrase || undefined,
    }, credHandle);
    if (ok) {
      sftpPass = ''; sftpKey = ''; sftpPassphrase = '';
    }
  }

  // ── Connect & register ─────────────────────────────────────────────────────

  async function connectProvider(type: ProviderType, config: ProviderConfig, sftpCredHandle?: number): Promise<boolean> {
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
        onSelected?.({ provider: instance, config });
      } else {
        // Dashboard: vault is open — register the provider and notify the tab switcher
        const providerId = await addProvider(instance, config);
        onAdded?.({ providerId });
      }
      return true;
    } catch (e: any) {
      console.error(`[AddProviderSheet] ${type} connect failed`, e);
      const detail = e?.message || e?.toString?.() || e?.name || 'Unknown error';
      let msg = `Failed to connect: ${detail}`;
      // SFTP: "No such file" on mkdir points at a write-permission issue on
      // the remote root — nudge the user toward the actionable fix.
      if (type === 'sftp' && /no such file/i.test(msg)) {
        msg += ' — your SFTP account may not have write access where Wattcloud wants to create the vault. Either create a "WattcloudVault" directory manually at the right location, or set a Base path above that points at a directory you can write to.';
      }
      showError(msg);
      // Clean up worker-side SFTP credential on connection failure.
      if (sftpCredHandle !== undefined) {
        byoWorker.Worker.sftpClearCredential(sftpCredHandle).catch(() => {});
      }
      return false;
    } finally {
      connecting = false;
    }
  }
</script>

<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
{#if firstRun}
  <!-- First-run: tile grid (DESIGN.md §14.2 – 2 cols mobile / 3 cols desktop). -->
  <div class="fr-page" role="region" aria-label="Choose storage provider">
    <div class="fr-hero">
      <CloudBadge size={56} variant="outline" color="var(--accent, #2EB860)" />
      <h1 class="fr-title">Connect your storage</h1>
      <p class="fr-sub">Bring your own storage. Wattcloud encrypts before anything leaves your device.</p>
    </div>

    <!-- How it works — 3-step flow. Mobile stacks vertically; ≥600px
         lays out horizontally. Chevron separators are real DOM siblings
         with aria-hidden so they don't pollute the listitem enumeration. -->
    <div class="fr-how" role="list" aria-label="How Wattcloud works">
      <div class="fr-how-step" role="listitem">
        <span class="fr-how-icon" aria-hidden="true"><CloudArrowUp size={22} weight="regular" /></span>
        <span class="fr-how-label">Bring your storage</span>
      </div>
      <div class="fr-how-sep" aria-hidden="true">›</div>
      <div class="fr-how-step" role="listitem">
        <span class="fr-how-icon" aria-hidden="true"><Lock size={22} weight="regular" /></span>
        <span class="fr-how-label">Encrypt on device</span>
      </div>
      <div class="fr-how-sep" aria-hidden="true">›</div>
      <div class="fr-how-step" role="listitem">
        <span class="fr-how-icon" aria-hidden="true"><CloudCheck size={22} weight="regular" /></span>
        <span class="fr-how-label">Only ciphertext leaves</span>
      </div>
    </div>

    <div class="tile-grid">
      {#each INLINE_PROVIDERS as p (p.type)}
        <button
          class="tile"
          class:active={activeInline === p.type}
          disabled={connecting}
          onclick={() => { activeInline = p.type; error = ''; }}
          aria-label={`Connect ${p.name}`}
        >
          <span class="tile-logo" aria-hidden="true">
            <p.icon size={32} weight="regular" />
          </span>
          <span class="tile-name">{p.name}</span>
        </button>
      {/each}
    </div>

    <!-- OAuth cloud accounts — deferred. Keep the block commented out
         (not deleted) so re-enabling is a markup toggle once the OAuth
         flow is shipped. -->
    <!--
    <h2 class="fr-section-label">Cloud accounts</h2>
    <div class="tile-grid">
      {#each OAUTH_PROVIDERS as p (p.type)}
        <button
          class="tile"
          class:loading={oauthLoading === p.type}
          disabled={connecting || !!oauthLoading}
          onclick={() => connectOAuth(p.type)}
          aria-label={`Connect ${p.name}`}
        >
          <span class="tile-logo" aria-hidden="true">
            {#if oauthLoading === p.type}
              <span class="spinner-sm"></span>
            {:else}
              <svelte:component this={p.icon} size={32} weight="regular" />
            {/if}
          </span>
          <span class="tile-name">{p.name}</span>
        </button>
      {/each}
    </div>
    -->

    <!-- Help expander — surfaces a short "what's the difference" guide
         for users who don't already know their storage type. Native
         <details> keeps keyboard + screen-reader semantics free. -->
    <details class="fr-learn">
      <summary class="fr-learn-summary">
        <span>Not sure which to pick?</span>
        <CaretDown size={14} weight="bold" />
      </summary>
      <ul class="fr-learn-list">
        <li class="fr-learn-row">
          <span class="fr-learn-icon" aria-hidden="true"><HardDrives size={18} weight="regular" /></span>
          <div class="fr-learn-text">
            <span class="fr-learn-name">WebDAV</span>
            <span class="fr-learn-desc">Nextcloud, ownCloud, or Synology. Paste a server URL, username, password.</span>
          </div>
        </li>
        <li class="fr-learn-row">
          <span class="fr-learn-icon" aria-hidden="true"><Terminal size={18} weight="regular" /></span>
          <div class="fr-learn-text">
            <span class="fr-learn-name">SFTP</span>
            <span class="fr-learn-desc">Any SSH server you control. Good fit if you already log in with <code>ssh</code>.</span>
          </div>
        </li>
        <li class="fr-learn-row">
          <span class="fr-learn-icon" aria-hidden="true"><Database size={18} weight="regular" /></span>
          <div class="fr-learn-text">
            <span class="fr-learn-name">S3 / R2 / Wasabi / MinIO</span>
            <span class="fr-learn-desc">Pay-per-GB object storage. Cheapest at scale, widest provider choice.</span>
          </div>
        </li>
      </ul>
    </details>

    <!-- Feature row — three value props. Promoted from a single-line
         trust card to three equal columns so the guarantees read as the
         product's foundation, not a footer afterthought. CloudBadge
         preserves §29.1 brand motif in the first cell. -->
    <ul class="fr-features" aria-label="Core guarantees">
      <li class="fr-feature">
        <span class="fr-feature-icon" aria-hidden="true">
          <CloudBadge size={22} variant="solid" color="var(--accent-text, #5FDB8A)" />
        </span>
        <span class="fr-feature-name">Zero-knowledge</span>
        <span class="fr-feature-desc">No server ever sees plaintext.</span>
      </li>
      <li class="fr-feature">
        <span class="fr-feature-icon" aria-hidden="true"><Key size={22} weight="regular" color="var(--accent-text, #5FDB8A)" /></span>
        <span class="fr-feature-name">You own the keys</span>
        <span class="fr-feature-desc">Lose them, lose access — but so does everyone else.</span>
      </li>
      <li class="fr-feature">
        <span class="fr-feature-icon" aria-hidden="true"><HardDrives size={22} weight="regular" color="var(--accent-text, #5FDB8A)" /></span>
        <span class="fr-feature-name">Any storage</span>
        <span class="fr-feature-desc">Switch provider anytime without re-encrypting.</span>
      </li>
    </ul>

    <!-- Secondary path: join a vault that already exists on another device.
         Demoted from a pill to a small text link so it doesn't compete with
         the tile grid as a primary action. -->
    <button class="link-device-link" onclick={() => onLinkDevice?.()}>
      <DeviceMobile size={14} weight="regular" />
      <span>Already enrolled? Link this device</span>
    </button>
  </div>

  <!-- Child form sheet (DESIGN.md §11.2 form sheet) — self-hosted credentials. -->
  {#if activeInline}
    <div
      class="sheet-overlay"
      role="presentation"
      onclick={(e) => { if (e.target === e.currentTarget) activeInline = null; }}
    >
      <div class="sheet" role="dialog" aria-modal="true" aria-label={`Connect ${activeInline}`}>
        <div class="drag-handle" aria-hidden="true"></div>
        {#if activeInline === 'webdav'}
          <div class="sheet-header">
            <h2 class="sheet-title">WebDAV</h2>
            <p class="sheet-subtitle">Nextcloud, ownCloud, Synology, or any WebDAV-compatible server.</p>
          </div>
          <form class="inline-form borderless" onsubmit={(e) => { e.preventDefault(); submitWebDAV(); }}>
            <label class="field-label">Server URL
              <input class="field-input" type="url" bind:value={wdavUrl} placeholder="https://cloud.example.com" required autocomplete="off"/>
              <span class="field-hint">The vault folder is always named <code>WattcloudVault/</code> and is created directly under this URL. Point the URL at a subfolder to nest the vault inside it. Your vault will land at <code>{(wdavUrl.trim() || 'https://cloud.example.com').replace(/\/+$/, '')}/WattcloudVault/</code>.</span>
            </label>
            <label class="field-label">Username
              <input class="field-input" type="text" bind:value={wdavUser} required autocomplete="username"/>
            </label>
            <!-- svelte-ignore a11y_label_has_associated_control -->
            <label class="field-label">Password
              <PasswordInput
                bind:value={wdavPass}
                autocomplete="current-password"
                showLabel="Show password"
                hideLabel="Hide password"
              />
            </label>
            <div class="form-actions">
              <button type="button" class="btn-ghost" onclick={() => { activeInline = null; }}>Cancel</button>
              <button type="submit" class="btn-primary" disabled={connecting}>
                {connecting ? 'Connecting…' : 'Connect'}
              </button>
            </div>
          </form>
        {:else if activeInline === 'sftp'}
          <div class="sheet-header">
            <h2 class="sheet-title">SFTP</h2>
            <p class="sheet-subtitle">Any SSH server you control.</p>
          </div>
          <form class="inline-form borderless" onsubmit={(e) => { e.preventDefault(); submitSFTP(); }}>
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
            <label class="field-label">
              <span class="field-label-text">Base path <span class="optional">(optional)</span></span>
              <input class="field-input" type="text" bind:value={sftpBasePath} placeholder="/MyFolder" autocomplete="off"/>
              <span class="field-hint">Optional. The vault folder is always named <code>WattcloudVault/</code>. Setting a base path prefixes where it's created. Leave empty to place it at the SFTP session root. Your vault will land at <code>{(sftpBasePath.trim() || '').replace(/\/+$/, '')}/WattcloudVault/</code>.</span>
            </label>
            <!-- svelte-ignore a11y_label_has_associated_control -->
            <label class="field-label">Password
              <PasswordInput
                bind:value={sftpPass}
                autocomplete="current-password"
                showLabel="Show password"
                hideLabel="Hide password"
              />
            </label>
            <label class="field-label">Private key (PEM)
              <textarea class="field-input field-textarea" bind:value={sftpKey} rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
            </label>
            <div class="form-actions">
              <button type="button" class="btn-ghost" onclick={() => { activeInline = null; }}>Cancel</button>
              <button type="submit" class="btn-primary" disabled={connecting}>
                {connecting ? 'Connecting…' : 'Connect'}
              </button>
            </div>
          </form>
        {:else if activeInline === 's3'}
          <div class="sheet-header">
            <h2 class="sheet-title">S3 / R2 / Wasabi / MinIO</h2>
            <p class="sheet-subtitle">AWS, Cloudflare R2, Wasabi, MinIO, Backblaze B2, or any S3-compatible endpoint.</p>
          </div>
          <form class="inline-form borderless" onsubmit={(e) => { e.preventDefault(); submitS3(); }}>
            {#if s3Detected}
              <div class="detect-chip">
                <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                  <path d="M8 1l1.5 3 3.5.5-2.5 2.5.5 3.5L8 9l-3 1.5.5-3.5L3 4.5 6.5 4z" fill="currentColor"/>
                </svg>
                Detected {s3Detected === 'cloudflare-r2' ? 'Cloudflare R2' : s3Detected === 'wasabi' ? 'Wasabi' : 'MinIO'}{s3Detected !== 'cloudflare-r2' ? ' — path-style auto-enabled' : ''}
              </div>
            {/if}
            <label class="field-label">Endpoint URL
              <input class="field-input" type="url" bind:value={s3Endpoint} placeholder="https://s3.example.com" required autocomplete="off"/>
              <span class="field-hint">The URL of your S3-compatible endpoint (AWS S3, Cloudflare R2, Wasabi, MinIO, Backblaze B2, …).</span>
            </label>
            <div class="row-2">
              <label class="field-label">Region
                <input class="field-input" type="text" bind:value={s3Region} placeholder="us-east-1" autocomplete="off"/>
              </label>
              <label class="field-label">Bucket
                <input class="field-input" type="text" bind:value={s3Bucket} placeholder="my-bucket" required autocomplete="off"/>
              </label>
            </div>
            <label class="field-label">
              <span class="field-label-text">Bucket path prefix <span class="optional">(optional)</span></span>
              <input class="field-input" type="text" bind:value={s3BasePath} placeholder="MyFolder" autocomplete="off"/>
              <span class="field-hint">Optional. The vault folder is named <code>WattcloudVault/</code> and appends your bucket path prefix. Leave empty to place it at the bucket root. Your vault will land at <code>{s3Bucket || 'my-bucket'}/{s3BasePath.trim().replace(/^\/+|\/+$/g, '') ? `${s3BasePath.trim().replace(/^\/+|\/+$/g, '')}/` : ''}WattcloudVault/</code>.</span>
            </label>
            <label class="field-label">Access Key ID
              <input class="field-input" type="text" bind:value={s3AccessKeyId} required autocomplete="off" spellcheck="false"/>
            </label>
            <!-- svelte-ignore a11y_label_has_associated_control -->
            <label class="field-label">Secret Access Key
              <PasswordInput
                bind:value={s3SecretAccessKey}
                required
                autocomplete="new-password"
                showLabel="Show secret key"
                hideLabel="Hide secret key"
              />
            </label>
            <label class="toggle-label">
              <input type="checkbox" class="toggle-input" bind:checked={s3PathStyle}/>
              <span class="toggle-text">Force path-style URLs (MinIO, Backblaze B2)</span>
            </label>
            {#if s3CorsError}
              <div class="cors-card" role="alert">
                <p class="cors-title">CORS not configured on this bucket</p>
                <p class="cors-body">Add this CORS rule to your bucket, then try again.</p>
                <button type="button" class="btn-copy" onclick={copyS3CorsJson}>Copy CORS JSON</button>
              </div>
            {/if}
            <div class="form-actions">
              <button type="button" class="btn-ghost" onclick={() => { activeInline = null; }}>Cancel</button>
              <button type="submit" class="btn-primary" disabled={connecting}>
                {connecting ? 'Connecting…' : 'Test & Connect'}
              </button>
            </div>
          </form>
        {/if}
      </div>
    </div>
  {/if}
{:else}
  <!-- Dashboard "add provider": bottom sheet (DESIGN.md §11.2, role=dialog). -->
  <div
    class="sheet-overlay"
    role="presentation"
    onclick={(e) => { if (e.target === e.currentTarget) onClose?.(); }}
  >
    <div class="sheet" role="dialog" aria-modal="true" aria-label="Add storage provider" tabindex="-1">
      <div class="drag-handle" aria-hidden="true"></div>

      <div class="sheet-header">
        <h2 class="sheet-title">Add storage</h2>
        <p class="sheet-subtitle">Connect a cloud provider to your vault</p>
      </div>

      <!-- Trust banner — cloud-badge motif (DESIGN.md §29.1) -->
      <div class="trust-banner">
        <Lock size={22} weight="regular" color="var(--accent-text, #5FDB8A)" />
        <span>End-to-end encrypted on all providers</span>
      </div>

      <!-- Provider list (DESIGN.md §14.1 — 48dp rows).
           OAuth providers are temporarily hidden (PROVIDERS array has them
           commented out) so the list collapses to a single self-hosted group
           and captions would be redundant — captions kept in comments for
           when OAuth ships. -->
      <div class="provider-list">
        {#each PROVIDERS as p (p.type)}
          <!--
          {#if i === FIRST_INLINE_INDEX}
            <p class="group-caption">Bring your own endpoint</p>
          {/if}
          -->
          <div class="provider-row">
            {#if p.mode === 'oauth'}
              <button
                class="provider-btn"
                class:loading={oauthLoading === p.type}
                disabled={connecting || !!oauthLoading}
                onclick={() => connectOAuth(p.type)}
              >
                <span class="provider-icon" aria-hidden="true">
                  <p.icon size={22} weight="regular" />
                </span>
                <span class="provider-name">{p.name}</span>
                <span class="provider-desc">{p.description}</span>
                {#if oauthLoading === p.type}
                  <span class="spinner-sm" aria-label="Connecting…"></span>
                {:else}
                  <span class="trailing" aria-hidden="true">
                    <ArrowSquareOut size={16} weight="regular" />
                  </span>
                {/if}
              </button>
            {:else}
              <button
                class="provider-btn"
                class:active={activeInline === p.type}
                disabled={connecting}
                onclick={() => { activeInline = activeInline === p.type ? null : p.type; error = ''; }}
              >
                <span class="provider-icon" aria-hidden="true">
                  <p.icon size={22} weight="regular" />
                </span>
                <span class="provider-name">{p.name}</span>
                <span class="provider-desc">{p.description}</span>
                <span class="trailing" class:rotated={activeInline === p.type} aria-hidden="true">
                  <CaretDown size={14} weight="bold" />
                </span>
              </button>

              {#if activeInline === 'webdav' && p.type === 'webdav'}
                <form class="inline-form" onsubmit={(e) => { e.preventDefault(); submitWebDAV(); }}>
                  <label class="field-label">Server URL
                    <input class="field-input" type="url" bind:value={wdavUrl} placeholder="https://cloud.example.com" required autocomplete="off"/>
                    <span class="field-hint">The vault folder is always named <code>WattcloudVault/</code> and is created directly under this URL. Point the URL at a subfolder to nest the vault inside it. Your vault will land at <code>{(wdavUrl.trim() || 'https://cloud.example.com').replace(/\/+$/, '')}/WattcloudVault/</code>.</span>
                  </label>
                  <label class="field-label">Username
                    <input class="field-input" type="text" bind:value={wdavUser} required autocomplete="username"/>
                  </label>
                  <!-- svelte-ignore a11y_label_has_associated_control -->
                  <label class="field-label">Password
                    <PasswordInput
                      bind:value={wdavPass}
                      autocomplete="current-password"
                      showLabel="Show password"
                      hideLabel="Hide password"
                    />
                  </label>
                  <button type="submit" class="btn-primary" disabled={connecting}>
                    {connecting ? 'Connecting…' : 'Connect'}
                  </button>
                </form>
              {/if}

              {#if activeInline === 'sftp' && p.type === 'sftp'}
                <form class="inline-form" onsubmit={(e) => { e.preventDefault(); submitSFTP(); }}>
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
                  <label class="field-label">
                    <span class="field-label-text">Base path <span class="optional">(optional)</span></span>
                    <input class="field-input" type="text" bind:value={sftpBasePath} placeholder="/MyFolder" autocomplete="off"/>
                    <span class="field-hint">Optional. The vault folder is always named <code>WattcloudVault/</code>. Setting a base path prefixes where it's created. Leave empty to place it at the SFTP session root. Your vault will land at <code>{(sftpBasePath.trim() || '').replace(/\/+$/, '')}/WattcloudVault/</code>.</span>
                  </label>
                  <!-- svelte-ignore a11y_label_has_associated_control -->
                  <label class="field-label">Password
                    <PasswordInput
                      bind:value={sftpPass}
                      autocomplete="current-password"
                      showLabel="Show password"
                      hideLabel="Hide password"
                    />
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
                <form class="inline-form" onsubmit={(e) => { e.preventDefault(); submitS3(); }}>
                  {#if s3Detected}
                    <div class="detect-chip">
                      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
                        <path d="M8 1l1.5 3 3.5.5-2.5 2.5.5 3.5L8 9l-3 1.5.5-3.5L3 4.5 6.5 4z" fill="currentColor"/>
                      </svg>
                      Detected {s3Detected === 'cloudflare-r2' ? 'Cloudflare R2' : s3Detected === 'wasabi' ? 'Wasabi' : 'MinIO'}{s3Detected !== 'cloudflare-r2' ? ' — path-style auto-enabled' : ''}
                    </div>
                  {/if}
                  <label class="field-label">Endpoint URL
                    <input class="field-input" type="url" bind:value={s3Endpoint} placeholder="https://s3.example.com" required autocomplete="off"/>
                    <span class="field-hint">The URL of your S3-compatible endpoint (AWS S3, Cloudflare R2, Wasabi, MinIO, Backblaze B2, …).</span>
                  </label>
                  <div class="row-2">
                    <label class="field-label">Region
                      <input class="field-input" type="text" bind:value={s3Region} placeholder="us-east-1" autocomplete="off"/>
                    </label>
                    <label class="field-label">Bucket
                      <input class="field-input" type="text" bind:value={s3Bucket} placeholder="my-bucket" required autocomplete="off"/>
                    </label>
                  </div>
                  <label class="field-label">
                    <span class="field-label-text">Bucket path prefix <span class="optional">(optional)</span></span>
                    <input class="field-input" type="text" bind:value={s3BasePath} placeholder="MyFolder" autocomplete="off"/>
                    <span class="field-hint">Optional. The vault folder is named <code>WattcloudVault/</code> and appends your bucket path prefix. Leave empty to place it at the bucket root. Your vault will land at <code>{s3Bucket || 'my-bucket'}/{s3BasePath.trim().replace(/^\/+|\/+$/g, '') ? `${s3BasePath.trim().replace(/^\/+|\/+$/g, '')}/` : ''}WattcloudVault/</code>.</span>
                  </label>
                  <label class="field-label">Access Key ID
                    <input class="field-input" type="text" bind:value={s3AccessKeyId} required autocomplete="off" spellcheck="false"/>
                  </label>
                  <!-- svelte-ignore a11y_label_has_associated_control -->
                  <label class="field-label">Secret Access Key
                    <PasswordInput
                      bind:value={s3SecretAccessKey}
                      required
                      autocomplete="new-password"
                      showLabel="Show secret key"
                      hideLabel="Hide secret key"
                    />
                  </label>
                  <label class="toggle-label">
                    <input type="checkbox" class="toggle-input" bind:checked={s3PathStyle}/>
                    <span class="toggle-text">Force path-style URLs (MinIO, Backblaze B2)</span>
                  </label>
                  {#if s3CorsError}
                    <div class="cors-card" role="alert">
                      <p class="cors-title">CORS not configured on this bucket</p>
                      <p class="cors-body">Add this CORS rule to your bucket, then try again.</p>
                      <button type="button" class="btn-copy" onclick={copyS3CorsJson}>Copy CORS JSON</button>
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

      <button class="btn-ghost" onclick={() => onClose?.()}>Cancel</button>
    </div>
  </div>
{/if}

<!-- SSH host-key TOFU confirmation -->
{#if pendingHostKey}
  <div class="tofu-overlay" role="dialog" aria-modal="true" aria-label="SSH host key verification">
    <div class="tofu-dialog">
      <h3>Verify SSH Host Key</h3>
      <p>First connection to this SFTP server. Confirm the fingerprint before trusting it.</p>
      <div class="fp-box">{pendingHostKey.fingerprint}</div>
      <div class="tofu-actions">
        <button class="btn btn-secondary btn-sm" onclick={() => { pendingHostKey?.resolve(false); pendingHostKey = null; }}>Reject</button>
        <button class="btn btn-primary btn-sm" onclick={() => { pendingHostKey?.resolve(true); pendingHostKey = null; }}>Trust &amp; Connect</button>
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
    /* Respect iOS notch insets in landscape — without these the overlay
       covers the reserved area but the centered sheet appears shifted
       because it's centered to the full viewport, not the visible area. */
    padding-left:  env(safe-area-inset-left,  0px);
    padding-right: env(safe-area-inset-right, 0px);
    box-sizing: border-box;
  }

  .sheet {
    /* Take the sheet out of the global `.sheet { position: fixed; left: 0; right: 0 }`
       (component-classes.css §sheet) — at ≥600px that rule pushes `left` by
       --drawer-current-width (default 280px) to avoid the desktop drawer.
       On first-run there IS no drawer, and on landscape mobile the same rule
       fires because landscape width crosses the 600px breakpoint, shifting
       this sheet visibly to the right. Using flex-end centering on the
       overlay with a relatively-positioned sheet avoids the shift without
       touching the shared desktop behaviour. */
    position: relative;
    left: auto; right: auto; bottom: auto;
    margin: 0;
    background: var(--bg-surface-raised, #1E1E1E);
    border-radius: var(--r-card, 16px) var(--r-card, 16px) 0 0;
    width: 100%; max-width: 600px;
    max-height: 85vh;
    overflow-y: auto;
    padding: var(--sp-sm, 8px) var(--sp-lg, 24px) var(--sp-xl, 32px);
    display: flex; flex-direction: column; gap: var(--sp-md, 16px);
    animation: slideUp 300ms cubic-bezier(.32,.72,0,1);
  }

  /* ── First-run page ─────────────────────────────────────────────────── */
  /* DESIGN.md §14.2 tile grid: 2 cols mobile, 4 cols desktop at ≥600px.   */

  .fr-page {
    flex: 1;
    width: 100%;
    max-width: 560px;
    margin: 0 auto;
    padding: var(--sp-lg, 24px) var(--sp-md, 16px) var(--sp-2xl, 48px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
    overflow-y: auto;
  }

  .fr-hero {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-sm, 8px);
    text-align: center;
    padding: var(--sp-lg, 24px) 0 var(--sp-sm, 8px);
  }
  .fr-title {
    margin: var(--sp-xs, 4px) 0 0;
    font-size: var(--t-h1-size, 1.5rem);
    font-weight: var(--t-h1-weight, 700);
    line-height: var(--t-h1-lh, 1.3);
    letter-spacing: var(--t-h1-ls, -0.02em);
    color: var(--text-primary, #EDEDED);
  }
  .fr-sub {
    margin: 0;
    max-width: 340px;
    font-size: var(--t-body-sm-size, 0.8125rem);
    line-height: var(--t-body-sm-lh, 1.45);
    color: var(--text-secondary, #999);
  }


  .tile-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: var(--sp-sm, 8px);
  }
  /* With an odd tile count on mobile (2-col), the last tile lands alone in
     a new row and leaves an empty cell next to it. Span the orphan tile
     across both columns so the grid reads as a complete shape. At ≥600px
     (3-col) this doesn't fire because the only odd-count in play (3 tiles)
     fills the first row exactly — but we gate the rule to mobile anyway
     so future additions can't regress the desktop layout. */
  @media (max-width: 599px) {
    .tile-grid > .tile:last-child:nth-child(odd) { grid-column: span 2; }
  }
  @media (min-width: 600px) {
    .tile-grid { grid-template-columns: repeat(3, 1fr); }
  }

  .tile {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--sp-sm, 8px);
    min-height: 104px;
    padding: var(--sp-md, 16px) var(--sp-sm, 8px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    color: var(--text-primary, #EDEDED);
    cursor: pointer;
    transition: background 120ms ease, border-color 120ms ease, transform 100ms ease;
  }
  .tile:hover:not(:disabled) {
    background: var(--bg-surface-hover, #2E2E2E);
    border-color: var(--accent, #2EB860);
  }
  .tile:active:not(:disabled) { transform: scale(0.97); }
  .tile:focus-visible {
    outline: none;
    border-color: var(--accent, #2EB860);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent, #2EB860) 25%, transparent);
  }
  .tile:disabled { opacity: 0.5; cursor: not-allowed; }
  .tile.active { border-color: var(--accent, #2EB860); }

  .tile-logo {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    color: var(--text-primary, #EDEDED);
  }
  .tile:hover:not(:disabled) .tile-logo,
  .tile.active .tile-logo { color: var(--accent, #2EB860); }

  .tile-name {
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 500;
    line-height: 1.2;
    text-align: center;
  }

  /* ── How it works — 3-step flow ───────────────────────────────────────
     Mobile: stack vertically inside a single bordered container.
     ≥600px: three equal columns separated by CSS-drawn chevrons.
     Low-visual-weight surface so the tile grid remains the primary focus. */
  .fr-how {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-md, 16px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
  }
  .fr-how-step {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: var(--sp-sm, 10px);
    min-width: 0;
  }
  .fr-how-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    flex-shrink: 0;
    color: var(--accent-text, #5FDB8A);
    background: var(--accent-muted, #1B3627);
    border-radius: 50%;
  }
  .fr-how-label {
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 500;
    color: var(--text-primary, #EDEDED);
    line-height: 1.35;
  }
  /* Chevron separators are always rendered but hidden on mobile (the
     flow reads top-to-bottom there, no connector needed). ≥600px they
     become the visual hinge between steps. */
  .fr-how-sep {
    display: none;
  }
  @media (min-width: 600px) {
    .fr-how {
      flex-direction: row;
      align-items: center;
      padding: var(--sp-md, 16px) var(--sp-lg, 24px);
      gap: var(--sp-xs, 6px);
    }
    .fr-how-step {
      flex: 1;
      flex-direction: column;
      text-align: center;
      gap: var(--sp-xs, 6px);
      padding: 0 var(--sp-sm, 8px);
    }
    .fr-how-sep {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      color: var(--text-disabled, #616161);
      font-size: 1.25rem;
      line-height: 1;
      flex-shrink: 0;
      user-select: none;
    }
    .fr-how-label {
      font-size: var(--t-body-sm-size, 0.8125rem);
    }
  }

  /* ── "Not sure which to pick?" expander ───────────────────────────────
     Native <details> so keyboard + screen-reader semantics come for free.
     Open state rotates the trailing chevron 180°. Rows mimic the dashboard
     provider-row layout but tuned for first-run density (no trailing
     chevron, description wraps to two lines on mobile). */
  .fr-learn {
    background: transparent;
    border-radius: var(--r-card, 16px);
  }
  .fr-learn-summary {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: var(--sp-xs, 6px) var(--sp-sm, 10px);
    margin: 0 auto;
    font-size: var(--t-body-sm-size, .8125rem);
    color: var(--text-secondary, #999);
    cursor: pointer;
    list-style: none;
    user-select: none;
  }
  /* Hide the default disclosure marker across browsers. */
  .fr-learn-summary::-webkit-details-marker { display: none; }
  .fr-learn-summary :global(svg) {
    flex-shrink: 0;
    transition: transform 200ms ease;
    color: var(--text-disabled, #616161);
  }
  .fr-learn[open] .fr-learn-summary :global(svg) { transform: rotate(180deg); }
  .fr-learn-summary:hover,
  .fr-learn-summary:focus-visible {
    color: var(--text-primary, #EDEDED);
    outline: none;
  }

  .fr-learn-list {
    list-style: none;
    margin: var(--sp-xs, 4px) 0 0;
    padding: var(--sp-xs, 6px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
  }
  .fr-learn-row {
    display: grid;
    grid-template-columns: 32px 1fr;
    align-items: start;
    gap: var(--sp-sm, 10px);
    padding: var(--sp-sm, 10px) var(--sp-sm, 10px);
    border-radius: var(--r-input, 12px);
  }
  .fr-learn-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    color: var(--text-secondary, #999);
    background: var(--bg-surface-raised, #262626);
    border-radius: 50%;
    grid-row: span 2;
    align-self: center;
  }
  .fr-learn-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .fr-learn-name {
    font-size: var(--t-body-size, .9375rem);
    font-weight: 500;
    color: var(--text-primary, #EDEDED);
    line-height: 1.25;
  }
  .fr-learn-desc {
    font-size: var(--t-body-sm-size, .8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.45;
  }
  .fr-learn-desc :global(code) {
    font-family: var(--font-mono, ui-monospace, SFMono-Regular, monospace);
    font-size: 0.9em;
    padding: 1px 4px;
    background: var(--bg-surface-raised, #262626);
    border-radius: 4px;
    color: var(--text-primary, #EDEDED);
  }

  /* ── Feature row — three value props ──────────────────────────────────
     Replaces the old single-line trust card. Three equal columns so the
     guarantees read as the product's foundation. First column keeps the
     CloudBadge (§29.1 brand motif); the other two use plain Phosphor
     icons accent-tinted to carry the green thread without re-cloud-ing. */
  .fr-features {
    list-style: none;
    margin: var(--sp-sm, 8px) 0 0;
    padding: var(--sp-md, 16px);
    display: grid;
    grid-template-columns: 1fr;
    gap: var(--sp-md, 16px);
    background: var(--accent-muted, #1B3627);
    border-radius: var(--r-card, 16px);
  }
  .fr-feature {
    display: grid;
    grid-template-columns: 32px 1fr;
    grid-template-rows: auto auto;
    column-gap: var(--sp-sm, 10px);
    row-gap: 2px;
    min-width: 0;
  }
  .fr-feature-icon {
    grid-row: span 2;
    align-self: center;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    flex-shrink: 0;
  }
  .fr-feature-name {
    font-size: var(--t-body-size, .9375rem);
    font-weight: 600;
    color: var(--accent-text, #5FDB8A);
    line-height: 1.25;
  }
  .fr-feature-desc {
    font-size: var(--t-body-sm-size, .8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.4;
  }
  @media (min-width: 600px) {
    .fr-features {
      grid-template-columns: repeat(3, 1fr);
      gap: var(--sp-lg, 24px);
      padding: var(--sp-md, 16px) var(--sp-lg, 24px);
    }
    .fr-feature {
      grid-template-columns: 1fr;
      grid-template-rows: 32px auto auto;
      row-gap: var(--sp-xs, 4px);
      text-align: center;
      justify-items: center;
    }
    .fr-feature-icon {
      grid-row: auto;
    }
  }

  /* Secondary path — demoted from pill to inline text link so the
     already-enrolled flow stays discoverable without competing with
     the tile grid. Amber tint at rest signals the warm/alt role. */
  .link-device-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin: var(--sp-sm, 8px) auto 0;
    padding: 6px 10px;
    background: transparent;
    border: none;
    color: var(--accent-warm-text, #F0C04A);
    font-size: var(--t-body-sm-size, .8125rem);
    font-weight: 500;
    cursor: pointer;
    text-decoration: underline;
    text-decoration-color: transparent;
    text-underline-offset: 4px;
    transition: text-decoration-color 120ms ease, color 120ms ease;
  }
  .link-device-link:hover,
  .link-device-link:focus-visible {
    text-decoration-color: currentColor;
    outline: none;
  }

  /* Form-sheet variant of .inline-form — no card border (sheet is the frame). */
  .inline-form.borderless {
    padding: 0;
    background: transparent;
    border: none;
    border-radius: 0;
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

  /* Trust banner — cloud-badge green+amber pairing (§29.1, §29.2) */
  .trust-banner {
    display: flex; align-items: center; gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--accent-muted, #1A3D2B);
    border-radius: var(--r-card, 16px);
    color: var(--accent-text, #5FDB8A);
    font-size: var(--t-body-sm-size, .8125rem);
  }
  .trust-banner :global(svg) { flex-shrink: 0; }

  .provider-list { display: flex; flex-direction: column; gap: 4px; }

  .provider-row { display: flex; flex-direction: column; }

  /* 48dp provider row (§14.1): leading icon · primary label · secondary label · trailing */
  .provider-btn {
    display: grid;
    grid-template-columns: 28px 1fr auto 16px;
    align-items: center;
    gap: var(--sp-md, 12px);
    min-height: 52px; width: 100%;
    padding: var(--sp-sm, 10px) var(--sp-md, 14px);
    background: var(--bg-surface, #161616);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    color: var(--text-primary, #EDEDED);
    cursor: pointer; text-align: left;
    transition: background 120ms, border-color 120ms;
  }
  .provider-btn:hover:not(:disabled) { background: var(--bg-surface-raised, #1E1E1E); }
  .provider-btn:focus-visible {
    outline: none;
    border-color: var(--accent, #2EB860);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent, #2EB860) 25%, transparent);
  }
  .provider-btn.active { border-color: var(--accent, #2EB860); }

  .provider-icon {
    display: inline-flex; align-items: center; justify-content: center;
    color: var(--text-secondary, #999);
  }
  .provider-btn:hover:not(:disabled) .provider-icon,
  .provider-btn.active .provider-icon { color: var(--accent, #2EB860); }

  .provider-name { font-weight: 500; }
  .provider-desc {
    font-size: var(--t-body-sm-size, .8125rem);
    color: var(--text-secondary, #999);
    justify-self: end;
    text-align: right;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  .trailing {
    display: inline-flex; align-items: center; justify-content: center;
    width: 16px; height: 16px; flex-shrink: 0;
    color: var(--text-tertiary, var(--text-secondary, #7A7A7A));
    transition: transform 200ms;
  }
  .trailing.rotated { transform: rotate(180deg); }

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
  .field-hint {
    font-size: var(--t-caption-size, .75rem);
    line-height: 1.4;
    color: var(--text-tertiary, var(--text-secondary, #7A7A7A));
    margin-top: 2px;
  }

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

  /* Form-action row — Cancel + Connect inline at equal widths. Overrides
     the single-button defaults (.btn-primary align-self:flex-end,
     .btn-ghost width:100%) so both fill their flex slot uniformly. */
  .form-actions {
    display: flex;
    gap: var(--sp-sm, 8px);
    margin-top: var(--sp-sm, 8px);
  }
  .form-actions > .btn-primary,
  .form-actions > .btn-ghost {
    flex: 1;
    width: auto;
    align-self: auto;
    padding-left: 0;
    padding-right: 0;
    text-align: center;
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
</style>
