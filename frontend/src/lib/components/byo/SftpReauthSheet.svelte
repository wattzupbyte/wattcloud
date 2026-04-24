<script lang="ts">
  /**
   * SftpReauthSheet — re-collect SFTP credentials for a legacy vault.
   *
   * New vaults persist SFTP credentials in the ProviderConfig (encrypted in
   * the manifest body and wrapped under the per-device CryptoKey in IDB, see
   * SECURITY.md §12) and never hit this sheet. It only fires for vaults
   * created before the credential-persistence change; after a successful
   * reauth, the caller writes the freshly-entered creds back to the store
   * so the next reload also skips the sheet.
   *
   * Host/port/basePath come from the stored config and are surfaced
   * read-only for confirmation.
   */
  import { createEventDispatcher } from 'svelte';
  import type { ProviderConfig } from '@wattcloud/sdk';
  import PasswordInput from '../common/PasswordInput.svelte';
  import Lock from 'phosphor-svelte/lib/Lock';

  export let config: ProviderConfig;
  export let vaultLabel: string = '';
  export let busy: boolean = false;
  export let error: string = '';

  const dispatch = createEventDispatcher<{
    submit: { username: string; password: string; privateKey: string; passphrase: string };
    cancel: void;
  }>();

  let username = config.sftpUsername ?? '';
  let password = '';
  let privateKey = '';
  let passphrase = '';

  $: host = config.sftpHost ?? '';
  $: port = config.sftpPort ?? 22;
  $: basePath = config.sftpBasePath ?? '';
  $: canSubmit = username.trim().length > 0 && (password.length > 0 || privateKey.length > 0) && !busy;

  function handleSubmit() {
    if (!canSubmit) return;
    dispatch('submit', { username: username.trim(), password, privateKey, passphrase });
  }
</script>

<div class="reauth">
  <div class="hero">
    <Lock size={56} weight="regular" color="var(--accent-warm, #E0A320)" />
    <h2 class="title">Re-enter SFTP credentials</h2>
    <p class="sub">
      {#if vaultLabel}
        This vault was created before credentials were saved on-device.
        Enter the credentials for <strong>{vaultLabel}</strong> to open
        it — they'll be remembered from now on.
      {:else}
        This vault was created before credentials were saved on-device.
        Enter the credentials to open it — they'll be remembered from now on.
      {/if}
    </p>
  </div>

  <dl class="known">
    <div class="known-row">
      <dt>Host</dt>
      <dd><code>{host}{port !== 22 ? `:${port}` : ''}</code></dd>
    </div>
    {#if basePath}
      <div class="known-row">
        <dt>Base path</dt>
        <dd><code>{basePath}</code></dd>
      </div>
    {/if}
  </dl>

  <form class="form" on:submit|preventDefault={handleSubmit}>
    <label class="field">
      <span class="label-text">Username</span>
      <input
        class="input"
        type="text"
        bind:value={username}
        autocomplete="username"
        required
      />
    </label>

    <label class="field">
      <span class="label-text">Password</span>
      <PasswordInput
        bind:value={password}
        autocomplete="current-password"
        showLabel="Show password"
        hideLabel="Hide password"
      />
    </label>

    <div class="or">or</div>

    <label class="field">
      <span class="label-text">Private key (PEM)</span>
      <textarea
        class="input textarea"
        bind:value={privateKey}
        rows="3"
        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
        autocomplete="off"
        spellcheck="false"
      ></textarea>
    </label>

    {#if privateKey}
      <label class="field">
        <span class="label-text">Key passphrase <span class="field-optional">(optional)</span></span>
        <PasswordInput
          bind:value={passphrase}
          autocomplete="new-password"
          showLabel="Show passphrase"
          hideLabel="Hide passphrase"
        />
      </label>
    {/if}

    {#if error}
      <p class="error" role="alert">{error}</p>
    {/if}

    <div class="actions">
      <button type="button" class="btn btn-ghost" on:click={() => dispatch('cancel')} disabled={busy}>
        Cancel
      </button>
      <button type="submit" class="btn btn-primary" disabled={!canSubmit}>
        {busy ? 'Connecting…' : 'Unlock'}
      </button>
    </div>
  </form>
</div>

<style>
  .reauth {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xl, 32px);
    width: 100%;
    max-width: 480px;
    margin: 0 auto;
    padding: var(--sp-lg, 24px) var(--sp-md, 16px);
  }

  .hero {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-sm, 8px);
    text-align: center;
  }

  .title {
    margin: 0;
    font-size: var(--t-title-size, 1.25rem);
    font-weight: 700;
    color: var(--text-primary, #EDEDED);
  }

  .sub {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    line-height: 1.5;
    max-width: 36ch;
  }

  .known {
    margin: 0;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--bg-surface, #232323);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .known-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: var(--sp-md, 16px);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .known-row dt {
    margin: 0;
    color: var(--text-disabled, #616161);
  }

  .known-row dd {
    margin: 0;
    color: var(--text-primary, #EDEDED);
    overflow-wrap: anywhere;
  }

  .known-row code {
    font-family: var(--font-mono, ui-monospace, monospace);
    font-size: 0.8125rem;
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .label-text {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-secondary, #999999);
    font-weight: 500;
  }

  .field-optional {
    color: var(--text-disabled, #616161);
    font-weight: 400;
  }

  .textarea {
    font-family: var(--font-mono, ui-monospace, monospace);
    font-size: 0.75rem;
    resize: vertical;
  }

  .or {
    text-align: center;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  .error {
    margin: 0;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--accent-danger-muted, #3D1010);
    border: 1px solid var(--accent-danger, #D04040);
    border-radius: var(--r-input, 12px);
    color: var(--accent-danger-text, #F08080);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .actions {
    display: flex;
    justify-content: space-between;
    gap: var(--sp-sm, 8px);
    margin-top: var(--sp-sm, 8px);
  }

  .actions .btn { flex: 1; }
</style>
