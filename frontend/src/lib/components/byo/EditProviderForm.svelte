<script lang="ts">
  /**
   * EditProviderForm — pre-filled edit form for an existing provider's settings.
   *
   * Used from ProviderContextSheet (live providers) and ByoSettings orphan rows.
   * Renders SFTP / WebDAV / S3 fields with the current values; on submit, hands
   * a freshly-built ProviderConfig back to the caller via `onSubmit`. The
   * caller is responsible for the test-connect + manifest/IDB updates.
   *
   * Credential fields (passwords, private keys, S3 secret key) start blank and
   * are treated as "keep existing if empty" — so the user can fix a typo in
   * the host without re-typing every secret.
   */
  import type { ProviderType, ProviderConfig } from '@wattcloud/sdk';
  import PasswordInput from '../common/PasswordInput.svelte';

  interface Props {
    type: ProviderType;
    currentConfig: ProviderConfig;
    displayName?: string;
    submitting?: boolean;
    submitLabel?: string;
    onSubmit: (newConfig: ProviderConfig) => void;
    onCancel: () => void;
  }

  let {
    type,
    currentConfig,
    displayName,
    submitting = false,
    submitLabel = 'Save & connect',
    onSubmit,
    onCancel,
  }: Props = $props();

  // Local form state, initialised from currentConfig. svelte-ignore the
  // referenced-locally lints — the form is meant to take a snapshot, not to
  // re-bind on prop changes mid-edit.

  // ── SFTP ──────────────────────────────────────────────────────────────────
  // svelte-ignore state_referenced_locally
  let sftpHost = $state(currentConfig.sftpHost ?? '');
  // svelte-ignore state_referenced_locally
  let sftpPort = $state(currentConfig.sftpPort ?? 22);
  // svelte-ignore state_referenced_locally
  let sftpUser = $state(currentConfig.sftpUsername ?? '');
  // svelte-ignore state_referenced_locally
  let sftpBasePath = $state(currentConfig.sftpBasePath ?? '');
  let sftpPass = $state('');
  let sftpKey = $state('');
  let sftpPassphrase = $state('');

  // ── WebDAV ────────────────────────────────────────────────────────────────
  // svelte-ignore state_referenced_locally
  let wdavUrl = $state(currentConfig.serverUrl ?? '');
  // svelte-ignore state_referenced_locally
  let wdavUser = $state(currentConfig.username ?? '');
  let wdavPass = $state('');

  // ── S3 ────────────────────────────────────────────────────────────────────
  // svelte-ignore state_referenced_locally
  let s3Endpoint = $state(currentConfig.s3Endpoint ?? '');
  // svelte-ignore state_referenced_locally
  let s3Region = $state(currentConfig.s3Region ?? '');
  // svelte-ignore state_referenced_locally
  let s3Bucket = $state(currentConfig.s3Bucket ?? '');
  // svelte-ignore state_referenced_locally
  let s3AccessKeyId = $state(currentConfig.s3AccessKeyId ?? '');
  let s3SecretAccessKey = $state('');
  // svelte-ignore state_referenced_locally
  let s3PathStyle = $state(currentConfig.s3PathStyle ?? false);
  // svelte-ignore state_referenced_locally
  let s3BasePath = $state(currentConfig.s3BasePath ?? '');

  let validationError = $state('');

  function buildSftpConfig(): ProviderConfig | null {
    const cleanHost = sftpHost.trim();
    if (!cleanHost) { validationError = 'Hostname is required'; return null; }
    if (!/^[a-zA-Z0-9.-]+$/.test(cleanHost) || cleanHost.length > 253) {
      validationError = `"${sftpHost}" is not a valid hostname.`;
      return null;
    }
    if (!sftpUser.trim()) { validationError = 'Username is required'; return null; }

    // "Keep existing" semantics for credentials: pull from current config when
    // the form field is blank, so the user can edit just the host.
    const password = sftpPass || currentConfig.sftpPassword;
    const privateKey = sftpKey || currentConfig.sftpPrivateKey;
    // Passphrase is meaningful only when a private key is in play.
    const passphrase = privateKey
      ? (sftpPassphrase || currentConfig.sftpPassphrase)
      : undefined;
    if (!password && !privateKey) {
      validationError = 'Provide a password or private key.';
      return null;
    }
    return {
      type: 'sftp',
      sftpHost: cleanHost,
      sftpPort,
      sftpUsername: sftpUser.trim(),
      // Base path is read-only in Edit; preserve the existing value.
      sftpBasePath: currentConfig.sftpBasePath || undefined,
      sftpPassword: password || undefined,
      sftpPrivateKey: privateKey || undefined,
      sftpPassphrase: passphrase || undefined,
      sftpHostKeyFingerprint: currentConfig.sftpHostKeyFingerprint,
    };
  }

  function buildWebdavConfig(): ProviderConfig | null {
    if (!wdavUrl.trim()) { validationError = 'Server URL is required'; return null; }
    if (!wdavUser.trim()) { validationError = 'Username is required'; return null; }
    const password = wdavPass || currentConfig.password;
    return {
      type: 'webdav',
      serverUrl: wdavUrl.trim(),
      username: wdavUser.trim(),
      password: password || undefined,
    };
  }

  function buildS3Config(): ProviderConfig | null {
    if (!s3Endpoint.trim()) { validationError = 'Endpoint URL is required'; return null; }
    if (!s3Bucket.trim()) { validationError = 'Bucket name is required'; return null; }
    if (!s3AccessKeyId.trim()) { validationError = 'Access key ID is required'; return null; }
    const secret = s3SecretAccessKey || currentConfig.s3SecretAccessKey;
    if (!secret) { validationError = 'Secret access key is required'; return null; }
    return {
      type: 's3',
      s3Endpoint: s3Endpoint.trim(),
      s3Region: s3Region.trim() || undefined,
      s3Bucket: s3Bucket.trim(),
      s3AccessKeyId: s3AccessKeyId.trim(),
      s3SecretAccessKey: secret,
      s3PathStyle: s3PathStyle || undefined,
      // Base path is read-only in Edit; preserve the existing value.
      s3BasePath: currentConfig.s3BasePath || undefined,
    };
  }

  function handleSubmit(e: Event) {
    e.preventDefault();
    validationError = '';
    let cfg: ProviderConfig | null = null;
    if (type === 'sftp') cfg = buildSftpConfig();
    else if (type === 'webdav') cfg = buildWebdavConfig();
    else if (type === 's3') cfg = buildS3Config();
    else { validationError = `Editing not supported for provider type: ${type}`; return; }
    if (cfg) onSubmit(cfg);
  }
</script>

<form class="edit-form" onsubmit={handleSubmit}>
  {#if displayName}
    <p class="form-hint">Edit settings for <strong>{displayName}</strong>. Leave credential fields blank to keep the existing values.</p>
  {/if}

  {#if type === 'sftp'}
    <label class="field-label">Host
      <input class="field-input" type="text" bind:value={sftpHost} placeholder="u12345.your-storagebox.de" autocomplete="off" required />
    </label>
    <label class="field-label">Port
      <input class="field-input" type="number" bind:value={sftpPort} min="1" max="65535" required />
    </label>
    <label class="field-label">Username
      <input class="field-input" type="text" bind:value={sftpUser} autocomplete="username" required />
    </label>
    <div class="field-readonly">
      <span class="field-readonly-label">Base path</span>
      <span class="field-readonly-value">{sftpBasePath || '— (vault at server root)'}</span>
      <span class="field-readonly-hint">Locked after enrollment — changing this orphans your existing files on the server. Forget &amp; re-add the provider if it really needs to move.</span>
    </div>
    <!-- svelte-ignore a11y_label_has_associated_control -->
    <label class="field-label">Password
      <PasswordInput bind:value={sftpPass} autocomplete="new-password" placeholder="Leave blank to keep existing" showLabel="Show password" hideLabel="Hide password" />
    </label>
    <label class="field-label">Private key (optional, PEM)
      <textarea class="field-input field-textarea" bind:value={sftpKey} rows="3" placeholder="Leave blank to keep existing"></textarea>
    </label>
    {#if sftpKey || currentConfig.sftpPrivateKey}
      <!-- svelte-ignore a11y_label_has_associated_control -->
      <label class="field-label">Key passphrase (optional)
        <PasswordInput bind:value={sftpPassphrase} autocomplete="off" placeholder="Leave blank to keep existing" showLabel="Show passphrase" hideLabel="Hide passphrase" />
      </label>
    {/if}
  {:else if type === 'webdav'}
    <label class="field-label">Server URL
      <input class="field-input" type="url" bind:value={wdavUrl} placeholder="https://nextcloud.example.com/remote.php/dav" autocomplete="off" required />
    </label>
    <label class="field-label">Username
      <input class="field-input" type="text" bind:value={wdavUser} autocomplete="username" required />
    </label>
    <!-- svelte-ignore a11y_label_has_associated_control -->
    <label class="field-label">Password
      <PasswordInput bind:value={wdavPass} autocomplete="new-password" placeholder="Leave blank to keep existing" showLabel="Show password" hideLabel="Hide password" />
    </label>
  {:else if type === 's3'}
    <label class="field-label">Endpoint URL
      <input class="field-input" type="url" bind:value={s3Endpoint} placeholder="https://s3.region.amazonaws.com" autocomplete="off" required />
    </label>
    <label class="field-label">Region
      <input class="field-input" type="text" bind:value={s3Region} placeholder="us-east-1" autocomplete="off" />
    </label>
    <label class="field-label">Bucket
      <input class="field-input" type="text" bind:value={s3Bucket} autocomplete="off" required />
    </label>
    <label class="field-label">Access key ID
      <input class="field-input" type="text" bind:value={s3AccessKeyId} autocomplete="off" required />
    </label>
    <!-- svelte-ignore a11y_label_has_associated_control -->
    <label class="field-label">Secret access key
      <PasswordInput bind:value={s3SecretAccessKey} autocomplete="new-password" placeholder="Leave blank to keep existing" showLabel="Show key" hideLabel="Hide key" />
    </label>
    <label class="field-label-row">
      <input type="checkbox" bind:checked={s3PathStyle} /> Force path-style addressing (MinIO / Wasabi)
    </label>
    <div class="field-readonly">
      <span class="field-readonly-label">Base path</span>
      <span class="field-readonly-value">{s3BasePath || '— (vault at bucket root)'}</span>
      <span class="field-readonly-hint">Locked after enrollment — changing this orphans your existing objects in the bucket. Forget &amp; re-add the provider if it really needs to move.</span>
    </div>
  {:else}
    <p class="form-hint form-hint-warn">Editing isn't available for {type} providers yet.</p>
  {/if}

  {#if validationError}
    <p class="form-error">{validationError}</p>
  {/if}

  <div class="form-actions">
    <button type="button" class="btn-ghost-sm" onclick={onCancel} disabled={submitting}>Cancel</button>
    <button type="submit" class="btn-primary-sm" disabled={submitting || (type !== 'sftp' && type !== 'webdav' && type !== 's3')}>
      {submitting ? 'Connecting…' : submitLabel}
    </button>
  </div>
</form>

<style>
  .edit-form { display: flex; flex-direction: column; gap: 8px; }
  .form-hint {
    margin: 0 0 4px;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.45;
  }
  .form-hint-warn { color: var(--danger, #D64545); }
  .field-label {
    display: flex; flex-direction: column; gap: 4px;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-secondary, #999);
  }
  .field-label-row {
    display: flex; align-items: center; gap: 8px;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    padding: 4px 0;
  }
  .field-input {
    width: 100%;
    padding: 8px 12px;
    background: var(--bg-surface, #161616);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-body-size, 0.9375rem);
    box-sizing: border-box;
  }
  .field-textarea { resize: vertical; font-family: monospace; font-size: 0.8125rem; }
  .field-readonly {
    display: flex; flex-direction: column; gap: 4px;
    padding: 8px 12px;
    background: var(--bg-surface, #161616);
    border: 1px dashed var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
  }
  .field-readonly-label {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-secondary, #999);
  }
  .field-readonly-value {
    font-family: monospace;
    font-size: var(--t-body-sm-size, 0.875rem);
    color: var(--text-primary, #EDEDED);
  }
  .field-readonly-hint {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #757575);
    line-height: 1.4;
  }
  .form-error {
    margin: 4px 0 0;
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }
  .form-actions {
    display: flex; gap: 8px; justify-content: flex-end; margin-top: 8px;
  }
  .btn-primary-sm, .btn-ghost-sm {
    padding: 8px 16px;
    border-radius: 10px;
    font-size: var(--t-body-sm-size, 0.875rem);
    cursor: pointer;
  }
  .btn-primary-sm {
    border: none;
    background: var(--accent, #2EB860);
    color: #fff;
  }
  .btn-primary-sm:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-ghost-sm {
    border: 1px solid var(--border, #2E2E2E);
    background: transparent;
    color: var(--text-secondary, #999);
  }
  .btn-ghost-sm:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
