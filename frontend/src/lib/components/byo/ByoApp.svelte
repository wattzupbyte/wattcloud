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
  import { get } from 'svelte/store';
  import type { StorageProvider, ProviderType, ProviderConfig } from '@wattcloud/sdk';
  import { createProvider, MockProvider, initStatsClient } from '@wattcloud/sdk';
  import * as byoWorker from '@wattcloud/sdk';
  import {
    unlockVault,
    lockVault,
    getProviders,
    getPrimaryProviderId,
    getProviderConfig,
    exportCurrentShard,
    getVaultId,
  } from '../../byo/VaultLifecycle';
  import { ByoDataProvider } from '../../byo/ByoDataProvider';
  import { setByoSearchDataProvider } from '../../byo/stores/byoSearch';
  import { setByoPhotosDataProvider, initByoPhotoFolderFilter } from '../../byo/stores/byoPhotos';
  import { setByoCollectionsDataProvider, resetByoCollections, initByoCollectionsOrder } from '../../byo/stores/byoCollections';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import {
    listPersistedVaults,
    loadProvidersForVault,
    deleteVaultProviderConfigs,
    type PersistedVaultSummary,
    type HydratedProviderConfig,
  } from '../../byo/ProviderConfigStore';
  import {
    hydrateProvider,
    providerNeedsReauth,
    type SftpCredentials,
  } from '../../byo/ProviderHydrate';
  import { getWebAuthnRecord } from '../../byo/DeviceKeyStore';
  import { unlockVaultKeyViaPasskey } from '../../byo/WebAuthnGate';

  import AddProviderSheet from './AddProviderSheet.svelte';
  import ByoSetup from './ByoSetup.svelte';
  import ByoUnlock from './ByoUnlock.svelte';
  import ByoDashboard from './ByoDashboard.svelte';
  import ByoSettings from './ByoSettings.svelte';
  import ByoTrash from './ByoTrash.svelte';
  import DeviceEnrollment from './DeviceEnrollment.svelte';
  import ByoRecovery from './ByoRecovery.svelte';
  import VaultLockAnimation from './VaultLockAnimation.svelte';
  import VaultsListScreen from './VaultsListScreen.svelte';
  import VaultContextSheet from './VaultContextSheet.svelte';
  import SftpReauthSheet from './SftpReauthSheet.svelte';
  import ByoToastHost from './ByoToastHost.svelte';
  import ByoCredProtectionOffer from './ByoCredProtectionOffer.svelte';
  import ConfirmModal from '../ConfirmModal.svelte';
  import Drawer from '../Drawer.svelte';
  import BottomNav from '../BottomNav.svelte';
  import { byoSelectionMode } from '../../byo/stores/byoFileStore';
  import { drawerOpen, drawerCollapsed } from '../../stores/drawer';
  import { storageUsage, resetStorageUsage } from '../../stores/storageUsage';
  import {
    byoShareStats,
    byoRelayHeadroom,
    refreshShareStats,
    fetchRelayHeadroom,
    resetShareStats,
  } from '../../byo/stores/byoShareStats';
  import { byoToast } from '../../byo/stores/byoToasts';
  import { playLockClick } from '../../byo/soundFx';

  type AppState =
    | 'vault-list'
    | 'sftp-reauth'
    | 'provider-select'
    | 'check-vault'
    | 'new-user-setup'
    | 'unlock'
    | 'link-device'
    | 'link-device-source'
    | 'link-device-sink'
    | 'use-recovery'
    | 'dashboard'
    | 'settings'
    | 'trash';

  let state: AppState = 'vault-list';
  let provider: StorageProvider | null = null;
  let providerConfig: ProviderConfig | null = null;
  let dataProvider: ByoDataProvider | null = null;
  let showLockAnimation = false;

  // Persisted-vault state
  let persistedVaults: PersistedVaultSummary[] = [];
  let currentVaultId: string | null = null;
  let menuVault: PersistedVaultSummary | null = null;
  let menuOpen = false;

  // SFTP re-auth prompt (used when the selected vault's primary provider
  // needs credentials that aren't persisted — currently SFTP only).
  let reauthPending: { primary: HydratedProviderConfig; vaultLabel: string } | null = null;
  let reauthBusy = false;
  let reauthError = '';

  // Self-heal modal: non-null when the tapped vault has persisted provider
  // rows but every one failed to decrypt — usually the residue of an
  // interrupted device-key migration. The user's only productive path out
  // is "forget this vault on this device and re-add the provider"; the
  // data on the remote storage is untouched.
  let unopenableVault:
    | { vault_id: string; vault_label: string; failed_count: number }
    | null = null;
  let unopenableBusy = false;

  // Set when the user tapped "Enable" in the one-shot credential-protection
  // offer on the dashboard. Passed to ByoSettings so it auto-expands the
  // Credential Protection row (single tap → row visible → Enable button
  // ready). Reset when leaving settings so a later manual visit doesn't
  // pre-expand the section.
  let openCredProtectionOnSettings = false;
  /** Drawer → Active shares tap sets this so ByoSettings opens with the
   *  sharing section pre-expanded. */
  let openSharesOnSettings = false;

  // Dashboard's current subview — owned here so the shared Drawer
  // (hoisted out of ByoDashboard to avoid unmounting on every state
  // change) can highlight the active link, and so routing from Settings
  // back to Dashboard lands on the tab the user picked. `bind:view` on
  // ByoDashboard keeps this in sync when the user taps the bottom nav
  // inside the dashboard.
  let dashboardView: 'files' | 'photos' | 'favorites' = 'files';

  // Chrome visibility: DashboardHeader + shared Drawer render while the
  // user is inside a vault (dashboard / settings / trash). Excluded from
  // pre-unlock states so the login/provider-select screens stay clean.
  const SHELL_STATES: ReadonlyArray<AppState> = ['dashboard', 'settings', 'trash'];
  $: inShell = SHELL_STATES.includes(state);

  // The highlight in the drawer tracks the logical location: dashboard
  // view when on dashboard, else the state name.
  $: drawerCurrentView = state === 'dashboard' ? dashboardView : state;
  /** Subset accepted by BottomNav's ViewType — falls back to 'files' for
      init-flow states (check-vault, unlock, …) so the nav never breaks. */
  $: bottomNavView = (
    drawerCurrentView === 'photos' || drawerCurrentView === 'favorites' || drawerCurrentView === 'settings'
      ? drawerCurrentView
      : 'files'
  ) as 'files' | 'photos' | 'favorites' | 'settings';

  // Enrollment source-side state: the existing device re-decrypts its shard
  // so DeviceEnrollment can forward it. Kept in local scope with an empty
  // default so the stringly-typed `shard` prop never leaks stale bytes
  // between sessions.
  let sourceShard = '';
  let sourcePrimaryConfig: ProviderConfig | null = null;
  let sourcePrimaryLabel = '';
  let sourceError = '';

  /**
   * Svelte `setContext` can only run during component initialization, but
   * `dataProvider` and `storageProvider` aren't knowable until the user
   * unlocks the vault (much later, inside an async event handler). We
   * register *mutable holders* at init time and mutate `.current` in
   * `handleUnlocked`; consumer components dereference `.current` at their
   * own init time, which always happens after unlock (child screens mount
   * only once `state` transitions past 'unlock').
   */
  type DataProviderHolder = { current: ByoDataProvider | null };
  type StorageProviderHolder = { current: StorageProvider | null };
  const dataProviderHolder: DataProviderHolder = { current: null };
  const storageProviderHolder: StorageProviderHolder = { current: null };
  setContext<DataProviderHolder>('byo:dataProvider', dataProviderHolder);
  setContext<StorageProviderHolder>('byo:storageProvider', storageProviderHolder);

  onMount(async () => {
    // Kick off stats initialisation in the background — fire-and-forget.
    initStatsClient().catch(() => {});
    // Ask the browser not to evict our IDB under storage pressure. Best-effort
    // — a rejection is non-fatal (user can re-enter credentials on loss).
    if (typeof navigator !== 'undefined' && navigator.storage?.persist) {
      navigator.storage.persist().catch(() => {});
    }
    // Hydrate the list of previously-saved vaults. If any exist, show the
    // vault-list landing page; otherwise fall through to provider-select.
    try {
      persistedVaults = await listPersistedVaults();
    } catch (e) {
      console.warn('[ByoApp] failed to list persisted vaults', e);
      persistedVaults = [];
    }
    state = persistedVaults.length > 0 ? 'vault-list' : 'provider-select';
  });

  async function refreshPersistedVaults() {
    try {
      persistedVaults = await listPersistedVaults();
    } catch {
      persistedVaults = [];
    }
  }

  /**
   * Handler for VaultsListScreen `open` event: user tapped a persisted vault.
   * Hydrates every provider for the vault, then routes through check-vault
   * → unlock with the primary provider. Legacy SFTP vaults whose stored
   * config predates credential persistence (see SECURITY.md §12) detour
   * through the re-auth sheet first and self-upgrade after one re-entry.
   */
  async function handleVaultListOpen(event: CustomEvent<{ vault_id: string }>) {
    const { vault_id } = event.detail;
    currentVaultId = vault_id;
    reauthError = '';

    // Passkey-unlock fast path (SECURITY.md §12 "Passkey replaces passphrase").
    // When the vault has the opt-in flag on, do the WebAuthn touch right
    // here — the single prompt (a) primes the device-key session cache so
    // `loadProvidersForVault` below doesn't re-enter the WebAuthn gate to
    // unwrap the provider config rows, and (b) returns a pre-opened WASM
    // vault session so we can call `unlockVault` directly and skip the
    // ByoUnlock passphrase screen entirely. Before this change the user
    // saw two authenticator prompts back-to-back (one from the gate during
    // row hydration, one from the unlock button) even though both were
    // driven by the same PRF salt.
    let preopenedSessionId: number | undefined;
    try {
      const record = await getWebAuthnRecord(vault_id);
      const fastPath =
        record?.mode === 'prf' &&
        !!record?.passkey_unlocks_vault &&
        record.credentials.some((c) => !!c.wrapped_vault_key);
      if (fastPath) {
        try {
          preopenedSessionId = await unlockVaultKeyViaPasskey(vault_id);
        } catch (err: any) {
          const msg: string = err?.message ?? String(err);
          if (!/cancel|NotAllowedError/i.test(msg)) {
            byoToast.show(
              `Passkey unlock failed: ${msg}. Falling back to passphrase.`,
              { icon: 'warn' },
            );
          }
          preopenedSessionId = undefined;
        }
      }
    } catch {
      // Gate-record lookup failed — fall through to the passphrase flow.
    }

    try {
      const { hydrated, failed } = await loadProvidersForVault(vault_id);

      // Systematic decrypt failure: we have rows on disk for this vault
      // but the device key doesn't unwrap any of them. Offer the self-heal
      // instead of the opaque "no saved providers" dead end.
      if (hydrated.length === 0 && failed.length > 0) {
        if (preopenedSessionId !== undefined) {
          await byoWorker.Worker.byoVaultClose(preopenedSessionId).catch(() => {});
          preopenedSessionId = undefined;
        }
        const summary = persistedVaults.find((v) => v.vault_id === vault_id);
        unopenableVault = {
          vault_id,
          vault_label: summary?.vault_label ?? failed[0]!.display_name,
          failed_count: failed.length,
        };
        currentVaultId = null;
        return;
      }

      if (hydrated.length === 0) {
        if (preopenedSessionId !== undefined) {
          await byoWorker.Worker.byoVaultClose(preopenedSessionId).catch(() => {});
        }
        throw new Error('No saved providers for this vault on this device.');
      }

      // Partial failure: some rows loaded, some didn't. Surface a soft
      // warning so the user knows a provider is missing from this vault
      // and can re-add it from Settings.
      if (failed.length > 0) {
        byoToast.show(
          `${failed.length} saved provider${failed.length === 1 ? '' : 's'} ` +
            "for this vault couldn't be unlocked on this device and will be " +
            'skipped. Re-add from Settings.',
          { icon: 'warn', durationMs: 6000 },
        );
      }

      // Primary first; if none flagged, pick the most recent.
      const primaryRow =
        hydrated.find((r) => r.is_primary) ??
        hydrated.slice().sort((a, b) => b.saved_at.localeCompare(a.saved_at))[0];
      if (!primaryRow) throw new Error('Could not determine primary provider.');

      if (providerNeedsReauth(primaryRow.config)) {
        // SFTP credentials missing — we still need the user to re-enter
        // them. Close the preopened session; the reauth flow owns its own
        // unlock path (and will route through ByoUnlock if needed).
        if (preopenedSessionId !== undefined) {
          await byoWorker.Worker.byoVaultClose(preopenedSessionId).catch(() => {});
          preopenedSessionId = undefined;
        }
        const summary = persistedVaults.find((v) => v.vault_id === vault_id);
        reauthPending = {
          primary: primaryRow,
          vaultLabel: summary?.vault_label ?? primaryRow.display_name,
        };
        state = 'sftp-reauth';
        return;
      }

      // Fast path complete: skip ByoUnlock, unlock the vault right now.
      if (preopenedSessionId !== undefined) {
        const sessionToClose = preopenedSessionId;
        state = 'check-vault';
        try {
          const instance = await hydrateProvider(primaryRow.config);
          provider = instance;
          providerConfig = primaryRow.config;

          let vaultExists = false;
          try {
            await instance.getVersion(instance.manifestRef());
            vaultExists = true;
          } catch {
            vaultExists = false;
          }

          if (!vaultExists) {
            // Persisted config points at a vault that's no longer on the
            // provider. Close the preopened session and fall through to
            // the new-user-setup flow — the user probably deleted the
            // remote manifest and wants to re-create.
            await byoWorker.Worker.byoVaultClose(sessionToClose).catch(() => {});
            preopenedSessionId = undefined;
            state = 'new-user-setup';
            return;
          }

          const sid = crypto.randomUUID();
          const db = await unlockVault(instance, {
            passphrase: '',
            keySessionId: sid,
            vaultId: vault_id,
            preopenedSessionId: sessionToClose,
          });
          // `handleLockAnimationDone` only advances the state machine to
          // 'dashboard' when it observes `state === 'unlock'` (the
          // passphrase path always goes check-vault → unlock → animation
          // → dashboard). Without this flip the fast path would leave
          // state stuck on 'check-vault' after the animation fires and
          // the UI would stay on "Connecting to provider…" forever.
          state = 'unlock';
          await handleUnlocked({ db, sessionId: sid });
          return;
        } catch (unlockErr: any) {
          // Unlock failed after a successful passkey touch — close the
          // preopened session and fall through to ByoUnlock so the user
          // has a passphrase retry surface.
          await byoWorker.Worker.byoVaultClose(sessionToClose).catch(() => {});
          preopenedSessionId = undefined;
          byoToast.show(
            unlockErr?.message ?? 'Vault unlock failed — try the passphrase.',
            { icon: 'warn' },
          );
        }
      }

      state = 'check-vault';
      await completeVaultOpen(primaryRow);
    } catch (e: any) {
      if (preopenedSessionId !== undefined) {
        await byoWorker.Worker.byoVaultClose(preopenedSessionId).catch(() => {});
      }
      byoToast.show(e?.message ?? 'Failed to hydrate saved vault', { icon: 'danger' });
      currentVaultId = null;
      state = 'vault-list';
    }
  }

  /**
   * User chose "Forget & re-add" from the unopenable-vault dialog. Drops
   * every provider_configs row for this vault on this device (remote vault
   * data untouched) and returns them to the provider-select flow so they
   * can re-enter credentials. The new rows will be wrapped under the
   * current device key, self-healing whichever migration crashed mid-way.
   */
  async function handleForgetUnopenable() {
    if (!unopenableVault || unopenableBusy) return;
    unopenableBusy = true;
    const { vault_id, vault_label } = unopenableVault;
    try {
      await deleteVaultProviderConfigs(vault_id);
      await refreshPersistedVaults();
      byoToast.show(`"${vault_label}" forgotten on this device. Re-add the provider to reconnect.`);
      unopenableVault = null;
      state = persistedVaults.length > 0 ? 'vault-list' : 'provider-select';
    } catch (e: any) {
      byoToast.show(e?.message ?? 'Failed to forget vault on this device.', { icon: 'danger' });
    } finally {
      unopenableBusy = false;
    }
  }

  function handleCancelUnopenable() {
    if (unopenableBusy) return;
    unopenableVault = null;
  }

  /**
   * Shared tail of the vault-open flow: hydrate the primary, probe for an
   * existing manifest, and route to unlock / new-user-setup. `creds` is
   * supplied by the reauth sheet for SFTP; other providers pass undefined.
   */
  async function completeVaultOpen(
    primaryRow: HydratedProviderConfig,
    creds?: SftpCredentials,
  ) {
    const instance = await hydrateProvider(primaryRow.config, creds);
    provider = instance;
    providerConfig = primaryRow.config;

    // Probe vault existence using the provider's own canonical manifest
    // ref — providers whose real storage layout diverges from the logical
    // MANIFEST_FILE path (SFTP writes under `{vaultRoot}/data/`) would
    // otherwise miss an existing vault and collide with it on setup.
    let vaultExists = false;
    try {
      await instance.getVersion(instance.manifestRef());
      vaultExists = true;
    } catch {
      vaultExists = false;
    }
    state = vaultExists ? 'unlock' : 'new-user-setup';
  }

  async function handleSftpReauthSubmit(
    event: CustomEvent<{ username: string; password: string; privateKey: string; passphrase: string }>,
  ) {
    if (!reauthPending) return;
    reauthBusy = true;
    reauthError = '';
    const { username, password, privateKey, passphrase } = event.detail;
    // Splice the re-entered username back into the config so `init()` uses
    // the fresh value (the user may have corrected a typo from the original
    // setup); everything else is read-only in the sheet.
    const configWithUser: ProviderConfig = {
      ...reauthPending.primary.config,
      sftpUsername: username,
    };
    // Legacy-vault upgrade path: once reauth succeeds we persist the
    // freshly-entered creds back to ProviderConfigStore so the next page
    // reload skips the sheet entirely. New vaults created after this
    // change already include creds in the manifest config_json and never
    // land here. See SECURITY.md §12 for the storage model.
    const configWithCreds: ProviderConfig = {
      ...configWithUser,
      sftpPassword: password || undefined,
      sftpPrivateKey: privateKey || undefined,
      sftpPassphrase: passphrase || undefined,
    };
    try {
      await completeVaultOpen(
        { ...reauthPending.primary, config: configWithUser },
        { password: password || undefined, privateKey: privateKey || undefined, passphrase: passphrase || undefined },
      );
      try {
        const { saveProviderConfig } = await import('../../byo/ProviderConfigStore');
        const primary = reauthPending.primary;
        await saveProviderConfig(
          {
            provider_id: primary.provider_id,
            vault_id: primary.vault_id,
            vault_label: primary.vault_label,
            type: primary.type,
            display_name: primary.display_name,
            is_primary: primary.is_primary,
            saved_at: new Date().toISOString(),
          },
          configWithCreds,
        );
      } catch (persistErr) {
        // Non-fatal — user just has to re-enter creds next reload.
        console.warn('[ByoApp] post-reauth saveProviderConfig failed', persistErr);
      }
      reauthPending = null;
    } catch (e: any) {
      console.error('[ByoApp] SFTP reauth/hydrate failed', e);
      reauthError = e?.message ?? 'Failed to connect — check credentials and try again.';
    } finally {
      reauthBusy = false;
    }
  }

  function handleSftpReauthCancel() {
    reauthPending = null;
    reauthBusy = false;
    reauthError = '';
    currentVaultId = null;
    state = 'vault-list';
  }

  function handleVaultListMenu(event: CustomEvent<{ vault_id: string }>) {
    const v = persistedVaults.find((x) => x.vault_id === event.detail.vault_id);
    if (!v) return;
    menuVault = v;
    menuOpen = true;
  }

  function handleVaultListAddNew() {
    state = 'provider-select';
  }

  /**
   * Receiver entry from the start screen: user wants to join a vault that
   * already exists on another device, without adding a provider here first.
   * DeviceEnrollment (role='new', no provider) will receive the primary
   * ProviderConfig from the source and hydrate on the fly.
   */
  function handleVaultListLinkFromOtherDevice() {
    provider = null;
    providerConfig = null;
    currentVaultId = null;
    state = 'link-device-sink';
  }

  /**
   * Sender entry from the settings page: user wants to show the QR to a new
   * device. We re-export the current device's shard on demand so the
   * plaintext only lives in a short-lived buffer inside DeviceEnrollment.
   */
  async function handleEnrollNewDevice() {
    sourceError = '';
    try {
      sourceShard = await exportCurrentShard();
      const primaryId = getPrimaryProviderId();
      sourcePrimaryConfig = primaryId ? getProviderConfig(primaryId) : null;
      const summary = currentVaultId
        ? persistedVaults.find((v) => v.vault_id === currentVaultId)
        : null;
      sourcePrimaryLabel = summary?.vault_label ?? '';
      state = 'link-device-source';
    } catch (e: any) {
      byoToast.show(e?.message ?? 'Could not prepare device enrollment.', { icon: 'danger' });
    }
  }

  function resetSourceEnrollment() {
    sourceShard = '';
    sourcePrimaryConfig = null;
    sourcePrimaryLabel = '';
    sourceError = '';
  }

  async function handleVaultForgotten(event: CustomEvent<{ vault_id: string }>) {
    byoToast.show('Vault forgotten on this device.');
    await refreshPersistedVaults();
    if (persistedVaults.length === 0) state = 'provider-select';
  }

  // ── Provider selected ──────────────────────────────────────────────────

  // AddProviderSheet (firstRun=true) fires on:selected with an already-initialized
  // provider instance — no need to re-create or re-init here.
  async function handleAddSheetSelected(
    event: CustomEvent<{ provider: StorageProvider; config: ProviderConfig }>,
  ) {
    state = 'check-vault';
    const { provider: readyProvider, config } = event.detail;

    try {
      provider = readyProvider;
      providerConfig = config;

      // Check whether vault_manifest.sc exists on this provider (R6 vault
      // format). Uses the provider's canonical manifest ref — see
      // handleVaultListOpen for the reasoning.
      let vaultExists = false;
      try {
        await provider.getVersion(provider.manifestRef());
        vaultExists = true;
      } catch {
        vaultExists = false;
      }

      state = vaultExists ? 'unlock' : 'new-user-setup';
    } catch (e: any) {
      byoToast.show(e.message ?? 'Failed to connect to provider', { icon: 'danger' });
      state = 'provider-select';
    }
  }

  // ── Setup complete ─────────────────────────────────────────────────────

  function handleSetupComplete() {
    // Vault is freshly created — go to unlock
    state = 'unlock';
  }

  // ── Unlocked ───────────────────────────────────────────────────────────

  async function handleUnlocked(payload: { db: import('sql.js').Database; sessionId: string }) {
    if (!provider) return;
    const { db, sessionId } = payload;

    // activeProviderId is set in vaultStore by unlockVault(); read it back.
    const activeProviderId = getPrimaryProviderId();

    // Create DataProvider and expose via the context holders (registered at
    // component init — see dataProviderHolder / storageProviderHolder above).
    dataProvider = new ByoDataProvider(db, provider, activeProviderId, sessionId);
    dataProviderHolder.current = dataProvider;
    storageProviderHolder.current = provider;

    // Wire BYO stores to the DataProvider
    setByoSearchDataProvider(dataProvider);
    setByoPhotosDataProvider(dataProvider);
    setByoCollectionsDataProvider(dataProvider);

    // Warm the drawer's share-stats readout: pull local totals from the
    // vault immediately, fetch relay headroom in the background.
    refreshShareStats(dataProvider);
    fetchRelayHeadroom().catch(() => {});
    {
      const vId = get(vaultStore).vaultId;
      if (vId) {
        initByoPhotoFolderFilter(vId);
        initByoCollectionsOrder(vId);
      }
    }

    // Optional audio cue (§29.6) — no-op unless user enabled sounds.
    playLockClick();

    // Persist the provider config on this device. Belt-and-braces: covers
    // the case where the user connected a provider whose vault already
    // existed (second-device flow) — ByoSetup wouldn't have run, so the
    // save hook there didn't fire. Skipped on hydrate-from-IDB because the
    // row already exists (saveProviderConfig is an upsert).
    const vaultId = get(vaultStore).vaultId ?? null;
    if (vaultId && provider && providerConfig) {
      try {
        const { saveProviderConfig } = await import('../../byo/ProviderConfigStore');
        await saveProviderConfig(
          {
            provider_id: activeProviderId,
            vault_id: vaultId,
            vault_label: provider.displayName,
            type: provider.type,
            display_name: provider.displayName,
            is_primary: true,
            saved_at: new Date().toISOString(),
          },
          providerConfig,
        );
      } catch (e) {
        console.warn('[ByoApp] post-unlock saveProviderConfig failed', e);
      }
    }

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

  async function handleLock() {
    lockVault();
    dataProvider = null;
    provider = null;
    currentVaultId = null;

    // Reset store wiring
    setByoSearchDataProvider(null as any);
    setByoPhotosDataProvider(null as any);
    resetByoCollections();
    resetStorageUsage();
    resetShareStats();
    $drawerOpen = false;

    // Refresh the persisted list so the start screen reflects the just-locked
    // vault (and any others added while unlocked). Prefer the list view
    // when entries exist so the user doesn't repeat provider selection.
    await refreshPersistedVaults();
    state = persistedVaults.length > 0 ? 'vault-list' : 'provider-select';
  }

  // ── Navigation ─────────────────────────────────────────────────────────

  function goToDashboard() {
    state = 'dashboard';
  }

  // Drawer is hoisted here so it persists across dashboard/settings/trash.
  // "Files/Photos/Favorites" in the drawer always return to dashboard with
  // the matching subview; "Settings" opens the settings screen.
  function handleDrawerNavigate(e: CustomEvent<{ view: string }>) {
    const v = e.detail?.view;
    $drawerOpen = false;
    if (v === 'files' || v === 'photos' || v === 'favorites') {
      dashboardView = v;
      openCredProtectionOnSettings = false;
      openSharesOnSettings = false;
      state = 'dashboard';
    } else if (v === 'settings') {
      state = 'settings';
    }
  }

  function openSharesSettings() {
    openCredProtectionOnSettings = false;
    openSharesOnSettings = true;
    state = 'settings';
  }

  async function handleTestProvider(e: CustomEvent) {
    state = 'check-vault';
    try {
      provider = e.detail;
      await provider!.init();
      providerConfig = provider!.getConfig();
      let vaultExists = false;
      try { await provider!.getVersion(provider!.manifestRef()); vaultExists = true; } catch { vaultExists = false; }
      state = vaultExists ? 'unlock' : 'new-user-setup';
    } catch (err: any) {
      byoToast.show(err?.message ?? 'Failed to initialize test provider', { icon: 'danger' });
      state = 'provider-select';
    }
  }
</script>

<div class="byo-app">
  {#if state === 'vault-list'}
    <div class="byo-shell">
      <VaultsListScreen
        vaults={persistedVaults}
        on:open={handleVaultListOpen}
        on:menu={handleVaultListMenu}
        on:addNew={handleVaultListAddNew}
        on:linkDevice={handleVaultListLinkFromOtherDevice}
      />
    </div>

  {:else if state === 'sftp-reauth' && reauthPending}
    <div class="byo-shell">
      <SftpReauthSheet
        config={reauthPending.primary.config}
        vaultLabel={reauthPending.vaultLabel}
        busy={reauthBusy}
        error={reauthError}
        on:submit={handleSftpReauthSubmit}
        on:cancel={handleSftpReauthCancel}
      />
    </div>

  {:else if state === 'provider-select' || state === 'check-vault'}
    <div class="byo-shell">
      {#if state === 'check-vault'}
        <div class="byo-centered">
          <div class="checking">
            <div class="spinner"></div>
            <p>Connecting to provider…</p>
          </div>
        </div>
      {:else}
        <AddProviderSheet
          firstRun={true}
          on:selected={handleAddSheetSelected}
          on:testProvider={handleTestProvider}
          on:linkDevice={handleVaultListLinkFromOtherDevice}
        />
      {/if}
    </div>

  {:else if state === 'new-user-setup'}
    {#if provider}
      <ByoSetup
        {provider}
        providerConfig={providerConfig}
        configJson={providerConfig ? JSON.stringify(providerConfig) : '{}'}
        on:complete={handleSetupComplete}
        on:cancel={() => { state = 'provider-select'; }}
      />
    {/if}

  {:else if state === 'unlock'}
    {#if provider}
      <ByoUnlock
        {provider}
        vaultIdHint={currentVaultId}
        on:unlocked={(e) => handleUnlocked(e.detail)}
        on:use-recovery={() => { state = 'use-recovery'; }}
        on:link-device={() => { state = 'link-device'; }}
        on:cancel={() => {
          currentVaultId = null;
          state = persistedVaults.length > 0 ? 'vault-list' : 'provider-select';
        }}
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

  {:else if state === 'link-device-source'}
    <div class="byo-shell">
      <DeviceEnrollment
        role="existing"
        shard={sourceShard}
        primaryConfig={sourcePrimaryConfig}
        primaryLabel={sourcePrimaryLabel}
        on:complete={() => {
          resetSourceEnrollment();
          state = 'dashboard';
        }}
        on:cancel={() => {
          resetSourceEnrollment();
          state = 'settings';
        }}
      />
    </div>

  {:else if state === 'link-device-sink'}
    <div class="byo-shell">
      <DeviceEnrollment
        role="new"
        shard=""
        provider={null}
        on:enrolled={(e) => {
          provider = e.detail.provider;
          providerConfig = e.detail.config;
          handleUnlocked({ db: e.detail.db, sessionId: e.detail.sessionId });
        }}
        on:complete={goToDashboard}
        on:cancel={() => {
          state = persistedVaults.length > 0 ? 'vault-list' : 'provider-select';
        }}
      />
    </div>

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
      bind:view={dashboardView}
      onLock={handleLock}
      onSettings={() => { state = 'settings'; }}
      onTrash={() => { state = 'trash'; }}
    />
    <ByoCredProtectionOffer
      vaultId={getVaultId()}
      on:openSettings={() => { openCredProtectionOnSettings = true; state = 'settings'; }}
    />


  {:else if state === 'settings'}
    <ByoSettings
      onEnrollDevice={handleEnrollNewDevice}
      onUseRecovery={() => { state = 'use-recovery'; }}
      openCredProtection={openCredProtectionOnSettings}
      openShares={openSharesOnSettings}
    />

  {:else if state === 'trash'}
    <ByoTrash onBack={goToDashboard} />
  {/if}

  <!-- Shared Drawer — hoisted here so it persists across dashboard /
       settings / trash without unmount+remount when `state` changes.
       Subscribing to the same stores as DashboardHeader means the
       collapse/open controls in the per-screen header drive the single
       Drawer instance rendered at this level. -->
  {#if inShell}
    <Drawer
      open={$drawerOpen}
      bind:collapsed={$drawerCollapsed}
      showLogout={false}
      currentView={drawerCurrentView}
      onClose={() => $drawerOpen = false}
      on:close={() => $drawerOpen = false}
      storageUsedBytes={$storageUsage.used}
      storageQuotaBytes={$storageUsage.quota ?? 0}
      shareCount={dataProvider ? $byoShareStats.count : null}
      shareBytes={dataProvider ? $byoShareStats.bytes : null}
      relayHeadroomFreeBytes={$byoRelayHeadroom?.freeBytes ?? null}
      on:navigate={handleDrawerNavigate}
      on:lock-vault={handleLock}
      on:shares-click={openSharesSettings}
    />

    <!-- Bottom nav — hoisted to ByoApp so it shows on dashboard, settings,
         and trash alike (ByoSettings was missing it entirely). Hidden
         while selection mode is active on Files/Photos. -->
    <div class="bottom-nav-wrap" class:nav-hidden={$byoSelectionMode} aria-hidden={$byoSelectionMode}>
      <BottomNav
        activeView={bottomNavView}
        on:navigate={handleDrawerNavigate}
      />
    </div>
  {/if}

  {#if showLockAnimation}
    <VaultLockAnimation on:done={handleLockAnimationDone} />
  {/if}

  <VaultContextSheet
    open={menuOpen}
    vault={menuVault}
    on:close={() => { menuOpen = false; menuVault = null; }}
    on:open={handleVaultListOpen}
    on:forgotten={handleVaultForgotten}
    on:renamed={refreshPersistedVaults}
  />

  <ConfirmModal
    isOpen={unopenableVault !== null}
    title="Can't unlock this vault on this device"
    confirmText="Forget & re-add"
    confirmClass="btn-danger"
    loading={unopenableBusy}
    on:confirm={handleForgetUnopenable}
    on:cancel={handleCancelUnopenable}
  >
    {#if unopenableVault}
      <p>
        <strong>"{unopenableVault.vault_label}"</strong> has
        {unopenableVault.failed_count} saved
        provider{unopenableVault.failed_count === 1 ? '' : 's'} on this
        device, but the device key can no longer unwrap
        {unopenableVault.failed_count === 1 ? 'it' : 'them'} — usually the
        residue of an interrupted device-key migration.
      </p>
      <p>
        "Forget & re-add" will drop the local entries for this vault on
        this device. Your vault data on the remote storage is not
        touched; you'll re-enter the provider credentials, and new entries
        will be written under the current device key.
      </p>
    {/if}
  </ConfirmModal>

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

  /* Bottom-nav wrapper — slides down + fades when BYO selection mode is on
     (matches what ByoDashboard used to do before the hoist). */
  .bottom-nav-wrap {
    transition: transform 200ms ease-in, opacity 200ms ease-in;
  }
  .bottom-nav-wrap.nav-hidden {
    transform: translateY(calc(var(--bottom-nav-height, 56px) + 12px + env(safe-area-inset-bottom, 0px)));
    opacity: 0;
    pointer-events: none;
  }
  @media (prefers-reduced-motion: reduce) {
    .bottom-nav-wrap { transition: none; }
    .bottom-nav-wrap.nav-hidden { transform: none; opacity: 0; }
  }
</style>
