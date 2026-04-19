<script lang="ts">
  /**
   * ByoApp — top-level BYO state machine.
   *
   * State:
   *   provider-select → check-vault → {new-user-setup | unlock}
   *   unlock → dashboard
   *   dashboard → {settings | trash | link-device | use-recovery}
   *   link-device → dashboard (back)
   *   use-recovery → dashboard (after recovery + unlock)
   *   settings → dashboard (back)
   *   trash → dashboard (back)
   *   Lock → provider-select
   */

  import { setContext, onMount } from 'svelte';
  import type { StorageProvider, ProviderType, ProviderConfig } from '@secure-cloud/byo';
  import { createProvider, MockProvider, initStatsClient } from '@secure-cloud/byo';
  import * as byoWorker from '@secure-cloud/byo';
  import { unlockVault, lockVault, getProviders, getPrimaryProviderId } from '../../byo/VaultLifecycle';
  import { ByoDataProvider } from '../../byo/ByoDataProvider';
  import { setByoSearchDataProvider } from '../../byo/stores/byoSearch';
  import { setByoPhotosDataProvider } from '../../byo/stores/byoPhotos';
  import { vaultStore } from '../../byo/stores/vaultStore';

  import AddProviderSheet from './AddProviderSheet.svelte';
  import ByoSetup from './ByoSetup.svelte';
  import ByoUnlock from './ByoUnlock.svelte';
  import ByoDashboard from './ByoDashboard.svelte';
  import ByoSettings from './ByoSettings.svelte';
  import ByoTrash from './ByoTrash.svelte';
  import DeviceEnrollment from './DeviceEnrollment.svelte';
  import ByoRecovery from './ByoRecovery.svelte';
  import VaultLockAnimation from './VaultLockAnimation.svelte';
  import ByoToastHost from './ByoToastHost.svelte';
  import { playLockClick } from '../../byo/soundFx';

  type AppState =
    | 'provider-select'
    | 'check-vault'
    | 'new-user-setup'
    | 'unlock'
    | 'link-device'
    | 'use-recovery'
    | 'dashboard'
    | 'settings'
    | 'trash';

  let state: AppState = 'provider-select';
  let provider: StorageProvider | null = null;
  let providerConfig: ProviderConfig | null = null;
  let dataProvider: ByoDataProvider | null = null;
  let checkVaultError = '';
  let showLockAnimation = false;

  onMount(() => {
    // Kick off stats initialisation in the background — fire-and-forget.
    initStatsClient().catch(() => {});
  });

  // ── Provider selected ──────────────────────────────────────────────────

  // AddProviderSheet (firstRun=true) fires on:selected with an already-initialized
  // provider instance — no need to re-create or re-init here.
  async function handleAddSheetSelected(
    event: CustomEvent<{ provider: StorageProvider; config: ProviderConfig }>,
  ) {
    checkVaultError = '';
    state = 'check-vault';
    const { provider: readyProvider, config } = event.detail;

    try {
      provider = readyProvider;
      providerConfig = config;

      // Check whether vault_manifest.sc exists on this provider (R6 vault format)
      let vaultExists = false;
      try {
        await provider.getVersion('SecureCloud/vault_manifest.sc');
        vaultExists = true;
      } catch {
        vaultExists = false;
      }

      state = vaultExists ? 'unlock' : 'new-user-setup';
    } catch (e: any) {
      checkVaultError = e.message ?? 'Failed to connect to provider';
      state = 'provider-select';
    }
  }

  // ── Setup complete ─────────────────────────────────────────────────────

  function handleSetupComplete() {
    // Vault is freshly created — go to unlock
    state = 'unlock';
  }

  // ── Unlocked ───────────────────────────────────────────────────────────

  function handleUnlocked(payload: { db: import('sql.js').Database; sessionId: string }) {
    if (!provider) return;
    const { db, sessionId } = payload;

    // activeProviderId is set in vaultStore by unlockVault(); read it back.
    const activeProviderId = getPrimaryProviderId();

    // Create DataProvider and expose via Svelte context
    dataProvider = new ByoDataProvider(db, provider, activeProviderId, sessionId);
    setContext('byo:dataProvider', dataProvider);
    setContext('byo:storageProvider', provider);

    // Wire BYO stores to the DataProvider
    setByoSearchDataProvider(dataProvider);
    setByoPhotosDataProvider(dataProvider);

    // Optional audio cue (§29.6) — no-op unless user enabled sounds.
    playLockClick();

    // Play vault-lock animation FIRST (§29.3.1 — shield draws, bolt slides,
    // then UI fades in beneath it). Skipped within a 5-min session by
    // VaultLockAnimation itself — in that case its `done` fires synchronously.
    showLockAnimation = true;
  }

  function handleLockAnimationDone() {
    showLockAnimation = false;
    // Only navigate after unlock path — not when locking.
    if (dataProvider && state === 'unlock') state = 'dashboard';
  }

  // ── Lock ───────────────────────────────────────────────────────────────

  function handleLock() {
    lockVault();
    dataProvider = null;
    provider = null;

    // Reset store wiring
    setByoSearchDataProvider(null as any);
    setByoPhotosDataProvider(null as any);

    state = 'provider-select';
  }

  // ── Navigation ─────────────────────────────────────────────────────────

  function goToDashboard() {
    state = 'dashboard';
  }

  async function handleTestProvider(e: CustomEvent) {
    checkVaultError = '';
    state = 'check-vault';
    try {
      provider = e.detail;
      await provider!.init();
      providerConfig = provider!.getConfig();
      let vaultExists = false;
      try { await provider!.getVersion('SecureCloud/vault_manifest.sc'); vaultExists = true; } catch { vaultExists = false; }
      state = vaultExists ? 'unlock' : 'new-user-setup';
    } catch (err: any) {
      checkVaultError = err?.message ?? 'Failed to initialize test provider';
      state = 'provider-select';
    }
  }
</script>

<div class="byo-app">
  {#if state === 'provider-select' || state === 'check-vault'}
    <div class="byo-shell">
      {#if state === 'check-vault'}
        <div class="byo-centered">
          <div class="checking">
            <div class="spinner"></div>
            <p>Connecting to provider…</p>
          </div>
        </div>
      {:else}
        {#if checkVaultError}
          <div class="error-banner-wrap">
            <div class="error-banner">{checkVaultError}</div>
          </div>
        {/if}
        <AddProviderSheet
          firstRun={true}
          on:selected={handleAddSheetSelected}
          on:testProvider={handleTestProvider}
        />
      {/if}
    </div>

  {:else if state === 'new-user-setup'}
    {#if provider}
      <ByoSetup
        {provider}
        on:complete={handleSetupComplete}
        on:cancel={() => { state = 'provider-select'; }}
      />
    {/if}

  {:else if state === 'unlock'}
    {#if provider}
      <ByoUnlock
        {provider}
        on:unlocked={(e) => handleUnlocked(e.detail)}
        on:use-recovery={() => { state = 'use-recovery'; }}
        on:link-device={() => { state = 'link-device'; }}
        on:cancel={() => { state = 'provider-select'; }}
      />
    {/if}

  {:else if state === 'link-device'}
    {#if provider}
      <div class="byo-shell">
        <DeviceEnrollment
          role="new"
          shard=""
          {provider}
          on:complete={goToDashboard}
          on:cancel={() => { state = 'unlock'; }}
        />
      </div>
    {/if}

  {:else if state === 'use-recovery'}
    {#if provider}
      <!-- After re-keying, send user to unlock with new passphrase -->
      <ByoRecovery
        {provider}
        on:complete={() => { state = 'unlock'; }}
        on:cancel={() => { state = 'unlock'; }}
      />
    {/if}

  {:else if state === 'dashboard'}
    <ByoDashboard
      onLock={handleLock}
      onSettings={() => { state = 'settings'; }}
      onTrash={() => { state = 'trash'; }}
    />

  {:else if state === 'settings'}
    <ByoSettings
      onBack={goToDashboard}
      onEnrollDevice={() => { state = 'link-device'; }}
      onUseRecovery={() => { state = 'use-recovery'; }}
    />

  {:else if state === 'trash'}
    <ByoTrash onBack={goToDashboard} />
  {/if}

  {#if showLockAnimation}
    <VaultLockAnimation on:done={handleLockAnimationDone} />
  {/if}

  <!-- Global toast host (§20 + §31.3) — single active toast, glass-pill. -->
  <ByoToastHost />
</div>

<style>
  .byo-app {
    width: 100%;
    height: 100%;
    min-height: 100dvh;
    background: var(--bg-base, #1A1A1A);
    color: var(--text-primary, #EDEDED);
    display: flex;
    flex-direction: column;
  }

  .byo-shell {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .byo-centered {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: var(--sp-2xl, 48px) var(--sp-md, 16px);
    gap: var(--sp-xl, 32px);
    max-width: 480px;
    margin: 0 auto;
    width: 100%;
    flex: 1;
  }

  .checking {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-xl, 32px);
    color: var(--text-secondary, #999999);
  }

  .checking p { margin: 0; font-size: var(--t-body-sm-size, 0.8125rem); }

  .spinner {
    width: 32px;
    height: 32px;
    border: 2px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .error-banner-wrap {
    padding: var(--sp-md, 16px) var(--sp-md, 16px) 0;
    max-width: 480px;
    margin: 0 auto;
    width: 100%;
  }

  .error-banner {
    width: 100%;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 12px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
    text-align: center;
  }

</style>
