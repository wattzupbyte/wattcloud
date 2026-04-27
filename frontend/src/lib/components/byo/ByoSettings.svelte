<script lang="ts">
  import { getContext, onMount } from 'svelte';
  import type { DataProvider, StorageUsage } from '../../byo/DataProvider';
  import type { StorageProvider } from '@wattcloud/sdk';
  import * as byoWorker from '@wattcloud/sdk';
  import {
    getDb,
    getVaultSessionId,
    getVaultId,
    getProvider,
    markDirty,
    addProvider,
    bytesToBase64,
    base64ToBytes,
  } from '../../byo/VaultLifecycle';
  import { getDeviceRecord } from '../../byo/DeviceKeyStore';
  import {
    loadProvidersForVault,
    deleteProviderConfig,
    type HydratedProviderConfig,
  } from '../../byo/ProviderConfigStore';
  import { hydrateProvider } from '../../byo/ProviderHydrate';
  import { vaultStore, sortedProviders } from '../../byo/stores/vaultStore';
  import type { ProviderMeta } from '../../byo/stores/vaultStore';
  import { queryRows } from '../../byo/ConflictResolver';
  import ByoPassphraseInput from './ByoPassphraseInput.svelte';
  import Argon2Progress from './Argon2Progress.svelte';
  import Icon from '../Icons.svelte';
  import ConfirmModal from '../ConfirmModal.svelte';
  import ActiveSharesList from './ActiveSharesList.svelte';
  import ProviderContextSheet from './ProviderContextSheet.svelte';
  import AddProviderSheet from './AddProviderSheet.svelte';
  import EditProviderForm from './EditProviderForm.svelte';
  import ByoCredentialProtection from './ByoCredentialProtection.svelte';
  import AccessControlPanel from './AccessControlPanel.svelte';
  import DashboardHeader from '../DashboardHeader.svelte';
  import { storageUsage as storageUsageStore } from '../../stores/storageUsage';
  import { byoSoundEnabled, setByoSoundEnabled, playSealThunk } from '../../byo/soundFx';
  import { byoToast } from '../../byo/stores/byoToasts';

  

  
  interface Props {
    onEnrollDevice: () => void;
    onUseRecovery?: (() => void) | undefined;
    /**
   * When true (arrived here from the "Enable credential protection" offer),
   * auto-expand the Credential Protection row so the user sees the Enable
   * button without a second tap. Not true-autostart — launching
   * `navigator.credentials.create()` requires a fresh user gesture from
   * inside the settings screen, so we still surface the button.
   */
    openCredProtection?: boolean;
    /** When the user taps the drawer's "Active shares" row, the parent sets
   *  this so the Sharing section expands on mount and scrolls into view. */
    openShares?: boolean;
  }

  let {
    onEnrollDevice,
    onUseRecovery = undefined,
    openCredProtection = false,
    openShares = false
  }: Props = $props();

  const dataProvider = getContext<{ current: DataProvider }>('byo:dataProvider').current;
  const storageProvider = getContext<{ current: StorageProvider }>('byo:storageProvider').current;

  // ── Vault header byte offsets (vault_format.rs, v2 format) ───────────────
  const SLOT_COUNT = 8;
  const SLOT_SIZE = 125;
  const DEVICE_SLOTS_OFFSET = 191;
  const NUM_SLOTS_OFFSET = 190;
  const HEADER_SIZE = 1227;
  const HMAC_OFFSET = 1195;
  const MASTER_SALT_OFFSET = 22;
  const PASS_WRAP_IV_OFFSET = 70;
  const PASS_WRAPPED_VAULT_KEY_OFFSET = 82;

  // ── State ──────────────────────────────────────────────────────────────

  // Devices
  interface EnrolledDevice {
    device_id: string;
    device_name: string;
    enrolled_at: string;
  }
  let enrolledDevices: EnrolledDevice[] = $state([]);
  let currentDeviceId = $state('');
  let devicesLoading = $state(true);

  // Passphrase section
  let passphraseExpanded = $state(false);
  let passphraseStep: 'input' | 'changing' | 'done' = $state('input');
  let argonDone = $state(false);
  let passphraseError = $state('');

  // Sharing section
  let sharesExpanded = $state(false);
  let credProtectionExpanded = $state(false);
  let accessControlExpanded = $state(false);

  // Guard the credential-protection block: all three props must resolve to
  // non-null before the child component renders (otherwise its migration
  // calls would operate on a closed/missing vault session).
  let credProtectionSessionId = $derived(getVaultSessionId());
  let credProtectionVaultId = $derived(getVaultId());
  let credProtectionProvider = $derived(storageProvider);
  let credProtectionReady =
    $derived(credProtectionSessionId !== null &&
    credProtectionVaultId !== '' &&
    credProtectionProvider !== null);

  // Browser-sync warning toggle
  let syncWarningAck = $state(typeof localStorage !== 'undefined'
    ? localStorage.getItem('sc-byo-sync-warning-ack') === '1'
    : false);

  // Provider context sheet
  let contextProvider: ProviderMeta | null = $state(null);
  let showAddProvider = $state(false);

  // Orphan providers — `provider_configs` IDB rows for this vault whose
  // provider_id isn't in the live manifest. Typically left behind when a
  // post-addProvider save crashed before the manifest reached the primary;
  // also useful when a remote was wiped and the local row points nowhere.
  // Includes rows whose decrypt failed — those still take up space and
  // need a removal path even though Retry/Edit can't operate on them.
  type OrphanRow = HydratedProviderConfig | (import('../../byo/ProviderConfigStore').ProviderConfigMeta & { config: null });
  let orphanProviders: OrphanRow[] = $state([]);
  let retryingOrphanId: string | null = $state(null);
  let editingOrphanId: string | null = $state(null);
  let savingOrphanEdit = $state(false);

  // About
  let storageUsage: StorageUsage | null = $state(null);
  let fileCount = $state(0);
  let vaultVersion = $state('');
  let vaultId = $state('');
  let aboutLoading = $state(true);
  let downloadingBackup = $state(false);
  let backupError = $state('');

  // Confirm modal
  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmMessage = $state('');
  let confirmAction: (() => Promise<void>) | null = $state(null);
  let confirmDanger = $state(false);

  function showGlobalError(msg: string) {
    byoToast.show(msg, { icon: 'danger' });
  }

  onMount(async () => {
    if (openCredProtection) credProtectionExpanded = true;
    if (openShares) {
      sharesExpanded = true;
      // Defer one frame so the row is in the DOM before we scroll to it.
      requestAnimationFrame(() => {
        document.getElementById('settings-sharing-anchor')?.scrollIntoView({
          behavior: 'smooth',
          block: 'start',
        });
      });
    }
    await loadDevices();
    loadAbout(); // fire-and-forget; aboutLoading covers the spinner
  });

  async function loadDevices() {
    devicesLoading = true;
    try {
      const db = getDb();
      if (!db) return;
      const rows = queryRows(db, "SELECT value FROM vault_meta WHERE key = 'enrolled_devices'");
      if (rows.length > 0) {
        enrolledDevices = JSON.parse(rows[0]['value'] as string) as EnrolledDevice[];
      }
      const vaultHexId = getVaultId();
      const record = await getDeviceRecord(vaultHexId);
      currentDeviceId = record?.device_id ?? '';
    } catch (e: any) {
      showGlobalError(e.message ?? 'Failed to load devices');
    } finally {
      devicesLoading = false;
    }
  }

  async function loadAbout() {
    aboutLoading = true;
    try {
      const db = getDb();
      if (!db) return;
      const countRows = queryRows(db, 'SELECT COUNT(*) as cnt FROM files');
      fileCount = (countRows[0]?.['cnt'] as number) ?? 0;
      const vRows = queryRows(db, "SELECT value FROM vault_meta WHERE key = 'vault_version'");
      vaultVersion = (vRows[0]?.['value'] as string) ?? '—';
      vaultId = getVaultId();
      storageUsage = await dataProvider.getStorageUsage();
      // Keep the shared store in sync so the hoisted Drawer shows the
      // same numbers without re-fetching.
      storageUsageStore.set({ used: storageUsage.used, quota: storageUsage.quota });
    } catch (e: any) {
      showGlobalError(e.message ?? 'Failed to load vault info');
    } finally {
      aboutLoading = false;
    }
  }

  // ── Device revocation ──────────────────────────────────────────────────

  function confirmRevokeDevice(device: EnrolledDevice) {
    if (device.device_id === currentDeviceId) {
      showGlobalError('Cannot revoke the current device.');
      return;
    }
    showConfirm(
      'Revoke Device',
      `Revoke access for "${device.device_name}"? This device will no longer be able to unlock the vault.`,
      () => doRevokeDevice(device.device_id),
      true,
    );
  }

  async function doRevokeDevice(deviceId: string) {
    const provider = getProvider();
    const vaultSessionId = getVaultSessionId();
    if (!provider || vaultSessionId === null) { showGlobalError('Vault not unlocked'); return; }

    try {
      const { data: vaultBytes } = await provider.download('WattcloudVault/vault_manifest.sc');
      const header = new Uint8Array(vaultBytes.slice(0, HEADER_SIZE));

      for (let i = 0; i < SLOT_COUNT; i++) {
        const offset = DEVICE_SLOTS_OFFSET + i * SLOT_SIZE;
        if (header[offset] !== 0x01) continue;
        const slotDeviceId = Array.from(header.slice(offset + 1, offset + 17))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
        if (slotDeviceId === deviceId) {
          header.fill(0, offset, offset + SLOT_SIZE);
          if (header[NUM_SLOTS_OFFSET] > 0) header[NUM_SLOTS_OFFSET]--;
          break;
        }
      }

      const headerPrefixB64 = bytesToBase64(header.slice(0, HMAC_OFFSET));
      const { hmac } = await byoWorker.Worker.byoVaultComputeHeaderHmac(vaultSessionId, headerPrefixB64);
      header.set(base64ToBytes(hmac), HMAC_OFFSET);

      const body = vaultBytes.slice(HEADER_SIZE);
      const assembled = new Uint8Array(header.length + body.length);
      assembled.set(header, 0);
      assembled.set(body, header.length);
      await provider.upload('WattcloudVault/vault_manifest.sc', 'vault_manifest.sc', assembled);

      const db = getDb();
      if (db) {
        const updated = enrolledDevices.filter((d) => d.device_id !== deviceId);
        db.run(
          "UPDATE vault_meta SET value = ? WHERE key = 'enrolled_devices'",
          [JSON.stringify(updated)],
        );
        markDirty();
        enrolledDevices = updated;
      }
    } catch (e: any) {
      showGlobalError(e.message ?? 'Revoke failed');
    }
  }

  // ── Passphrase change ──────────────────────────────────────────────────

  async function handlePassphraseSubmit(newPassphrase: string) {
    const provider = getProvider();
    const vaultSessionId = getVaultSessionId();
    if (!provider || vaultSessionId === null) { passphraseError = 'Vault not unlocked'; return; }

    passphraseStep = 'changing';
    argonDone = false;
    passphraseError = '';

    try {
      const passSlot = await byoWorker.Worker.byoVaultRewrapWithPassphrase(
        vaultSessionId,
        newPassphrase,
        131072, 3, 4,
      );
      argonDone = true;

      const { data: vaultBytes } = await provider.download('WattcloudVault/vault_manifest.sc');
      const header = new Uint8Array(vaultBytes.slice(0, HEADER_SIZE));
      header.set(base64ToBytes(passSlot.masterSaltB64), MASTER_SALT_OFFSET);
      header.set(base64ToBytes(passSlot.wrapIvB64), PASS_WRAP_IV_OFFSET);
      header.set(base64ToBytes(passSlot.wrappedKeyB64), PASS_WRAPPED_VAULT_KEY_OFFSET);

      const headerPrefixB64 = bytesToBase64(header.slice(0, HMAC_OFFSET));
      const { hmac } = await byoWorker.Worker.byoVaultComputeHeaderHmac(vaultSessionId, headerPrefixB64);
      header.set(base64ToBytes(hmac), HMAC_OFFSET);

      const body = vaultBytes.slice(HEADER_SIZE);
      const assembled = new Uint8Array(header.length + body.length);
      assembled.set(header, 0);
      assembled.set(body, header.length);
      await provider.upload('WattcloudVault/vault_manifest.sc', 'vault_manifest.sc', assembled);

      passphraseStep = 'done';
    } catch (e: any) {
      passphraseError = e.message ?? 'Passphrase change failed';
      passphraseStep = 'input';
    }
  }

  // ── Backup download ────────────────────────────────────────────────────

  async function handleDownloadBackup() {
    const provider = getProvider();
    if (!provider) { backupError = 'Vault not unlocked'; return; }

    downloadingBackup = true;
    backupError = '';
    try {
      const { data } = await provider.download('WattcloudVault/vault_manifest.sc');
      const blob = new Blob([data as unknown as BlobPart], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vault-manifest-backup-${new Date().toISOString().slice(0, 10)}.sc`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      backupError = e.message ?? 'Download failed';
    } finally {
      downloadingBackup = false;
    }
  }

  // ── Confirm modal helpers ──────────────────────────────────────────────

  function showConfirm(
    title: string,
    message: string,
    action: () => Promise<void>,
    danger = false,
  ) {
    confirmTitle = title;
    confirmMessage = message;
    confirmAction = action;
    confirmDanger = danger;
    confirmOpen = true;
  }

  async function handleConfirm() {
    confirmOpen = false;
    if (confirmAction) {
      try {
        await confirmAction();
      } catch (e: any) {
        showGlobalError(e.message ?? 'Operation failed');
      }
      confirmAction = null;
    }
  }

  // ── Provider helpers ───────────────────────────────────────────────────

  function providerIcon(type: string): string {
    const icons: Record<string, string> = {
      gdrive: 'G', dropbox: 'D', onedrive: 'O', webdav: 'W', sftp: 'S', box: 'B', pcloud: 'P', s3: 'S3',
    };
    return icons[type] ?? '?';
  }

  function statusLabel(status: ProviderMeta['status']): string {
    const labels: Record<string, string> = {
      connected: 'Connected', syncing: 'Syncing', offline: 'Offline',
      offline_os: 'No network', error: 'Error', unauthorized: 'Token expired',
    };
    return labels[status] ?? status;
  }

  function statusDotColor(status: ProviderMeta['status']): string {
    if (status === 'connected') return 'var(--accent, #2EB860)';
    if (status === 'syncing') return 'var(--accent-warm, #E0A320)';
    if (status === 'error' || status === 'unauthorized') return 'var(--danger, #D64545)';
    return 'var(--text-disabled, #616161)';
  }

  async function loadOrphans() {
    const vid = getVaultId();
    if (!vid) { orphanProviders = []; return; }
    try {
      const { hydrated, failed } = await loadProvidersForVault(vid);
      const live = new Set($vaultStore.providers.map((p) => p.providerId));
      const orphans: OrphanRow[] = [];
      for (const o of hydrated) {
        if (!live.has(o.provider_id)) orphans.push(o);
      }
      // Rows we couldn't decrypt are still IDB rows the user can see in the
      // Your Vaults provider count. They can't be Retried / Edited (we have
      // no plaintext config) but we still surface them so Remove is reachable.
      for (const f of failed) {
        if (!live.has(f.provider_id)) orphans.push({ ...f, config: null });
      }
      orphanProviders = orphans;
    } catch {
      orphanProviders = [];
    }
  }

  function removeOrphan(o: { provider_id: string; display_name: string }) {
    showConfirm(
      'Remove saved provider',
      `Remove the saved credentials for "${o.display_name}" on this device? ` +
        "This doesn't touch any files on the remote storage.",
      async () => {
        await deleteProviderConfig(o.provider_id);
        await loadOrphans();
      },
      true,
    );
  }

  async function retryOrphan(o: HydratedProviderConfig) {
    retryingOrphanId = o.provider_id;
    try {
      // Pin providerId to the orphan row's id so addProvider re-adds the
      // manifest entry under the SAME id the IDB row carries. Without this
      // pin, configs persisted by older code paths (no providerId in the
      // encrypted blob) cause addProvider to mint a fresh UUID — manifest
      // gets the new id, IDB keeps the old id, and the row stays orphaned
      // forever despite the toast saying "reconnected". Also reuses the
      // existing vault_<id>.sc body on the remote instead of leaving a
      // second copy behind.
      const cfgWithId = { ...o.config, providerId: o.provider_id };
      const instance = await hydrateProvider(cfgWithId);
      // addProvider force-saves inline so the new manifest entry survives
      // an immediate reload — no need to await saveVault separately here.
      await addProvider(instance, cfgWithId, o.display_name);
      // Re-persist the IDB row with the (now guaranteed) providerId in the
      // encrypted config too, so future reloads / device-enrollments don't
      // hit the same legacy gap.
      const vid = getVaultId();
      if (vid) {
        const { saveProviderConfig } = await import('../../byo/ProviderConfigStore');
        await saveProviderConfig(
          {
            provider_id: o.provider_id,
            vault_id: vid,
            vault_label: o.vault_label,
            type: o.type,
            display_name: o.display_name,
            is_primary: o.is_primary,
            saved_at: new Date().toISOString(),
          },
          cfgWithId,
        );
      }
      byoToast.show(`${o.display_name} reconnected.`, { icon: 'seal' });
      await loadOrphans();
    } catch (e: any) {
      showGlobalError(
        `Couldn't reconnect ${o.display_name}: ${e?.message ?? e}. ` +
          'Use Edit to fix the credentials, or Remove and add the provider fresh.',
      );
    } finally {
      retryingOrphanId = null;
    }
  }

  /** Persist edits made via the EditProviderForm against an orphan row, then
   *  re-attempt the connect+addProvider with the fresh config. The new
   *  config carries the same providerId so the orphaned vault body on the
   *  remote (if any) gets reused. */
  async function saveOrphanEdit(o: HydratedProviderConfig, newConfig: import('@wattcloud/sdk').ProviderConfig) {
    savingOrphanEdit = true;
    try {
      const vid = getVaultId();
      if (!vid) throw new Error('Vault not unlocked');
      const cfgWithId = { ...newConfig, providerId: o.provider_id };
      // Test-connect first so a typo doesn't overwrite a working IDB row with
      // garbage that the next reload will fail to hydrate.
      const instance = await hydrateProvider(cfgWithId);
      // Persist the corrected config to IDB (upsert by provider_id).
      const { saveProviderConfig } = await import('../../byo/ProviderConfigStore');
      await saveProviderConfig(
        {
          provider_id: o.provider_id,
          vault_id: vid,
          vault_label: o.vault_label,
          type: o.type,
          display_name: o.display_name,
          is_primary: o.is_primary,
          saved_at: new Date().toISOString(),
        },
        cfgWithId,
      );
      // Re-attach into the live manifest. addProvider force-saves inline
      // so the new entry persists across reload.
      await addProvider(instance, cfgWithId, o.display_name);
      byoToast.show(`${o.display_name} reconnected with updated settings.`, { icon: 'seal' });
      editingOrphanId = null;
      await loadOrphans();
    } catch (e: any) {
      showGlobalError(`Couldn't apply: ${e?.message ?? e}`);
    } finally {
      savingOrphanEdit = false;
    }
  }

  $effect(() => {
    // Re-derive orphans whenever the live provider list changes (e.g.
    // after an orphan retry succeeds and shifts a row into the live list).
    void $vaultStore.providers;
    loadOrphans();
  });

  function statusTooltip(p: ProviderMeta): string {
    if (p.status === 'connected' || p.status === 'syncing') return '';
    if (p.status === 'offline_os') return 'Reconnect when your network is back.';
    if (p.status === 'unauthorized') {
      const agoMs = p.lastPingTs ? Date.now() - p.lastPingTs : 0;
      const agoH = Math.floor(agoMs / 3_600_000);
      return agoH > 0 ? `Token expired ${agoH}h ago — tap to reconnect.` : 'Token expired — tap to reconnect.';
    }
    if (p.status === 'offline' && p.failCount > 0) {
      // Compute approximate next retry delay (1.5^failCount, capped at 5 min).
      const backoffFactor = Math.min(p.failCount, 6);
      const intervalMs = Math.min(30_000 * Math.pow(1.5, backoffFactor), 300_000);
      const elapsed = p.lastPingTs ? Date.now() - p.lastPingTs : 0;
      const remainingMs = Math.max(0, intervalMs - elapsed);
      if (remainingMs < 10_000) return 'Retrying…';
      const remainingSec = Math.round(remainingMs / 1_000);
      return `Retry in ${remainingSec}s (attempt ${p.failCount}).`;
    }
    return '';
  }

  function toggleSyncWarning() {
    syncWarningAck = !syncWarningAck;
    if (syncWarningAck) {
      localStorage.setItem('sc-byo-sync-warning-ack', '1');
    } else {
      localStorage.removeItem('sc-byo-sync-warning-ack');
    }
  }

  function toggleSounds() {
    const next = !$byoSoundEnabled;
    setByoSoundEnabled(next);
    // On enable: audition the thunk so the user hears what they signed up
    // for and the AudioContext unlocks under this click gesture.
    if (next) playSealThunk();
  }

  // ── Formatters ─────────────────────────────────────────────────────────

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        month: 'short', day: 'numeric', year: 'numeric',
      });
    } catch {
      return iso;
    }
  }
</script>

<div class="byo-settings">
  <!-- Same chrome as the dashboard — drawer toggle drives the shared
       drawer stores directly; search button is hidden because Settings
       has nothing to search. -->
  <DashboardHeader currentView="settings" hideSearch={true} />

  <div class="settings-scroll">

    <!-- ── Devices ── -->
    <div class="settings-group">
      <h3 class="group-title">Devices</h3>
      <div class="group-body">
        <button class="settings-row" onclick={onEnrollDevice}>
          <span class="row-icon"><Icon name="plus" size={16} /></span>
          <span class="row-label">Enroll New Device</span>
          <span class="row-chevron"><Icon name="chevronRight" size={14} /></span>
        </button>
        {#if devicesLoading}
          <div class="loading-inline"><div class="spinner-sm"></div></div>
        {:else if enrolledDevices.length === 0}
          <p class="group-empty">No enrolled devices.</p>
        {:else}
          {#each enrolledDevices as device (device.device_id)}
            <div class="device-row" class:current={device.device_id === currentDeviceId}>
              <div class="device-icon-wrap"><Icon name="device" size={18} /></div>
              <div class="device-info">
                <span class="device-name">
                  {device.device_name}
                  {#if device.device_id === currentDeviceId}
                    <span class="current-badge">This device</span>
                  {/if}
                </span>
                <span class="device-meta">Enrolled {formatDate(device.enrolled_at)}</span>
              </div>
              {#if device.device_id !== currentDeviceId}
                <button
                  class="revoke-btn"
                  onclick={() => confirmRevokeDevice(device)}
                  aria-label="Revoke {device.device_name}"
                >Revoke</button>
              {/if}
            </div>
          {/each}
        {/if}
      </div>
    </div>

    <!-- ── Providers ── -->
    <div class="settings-group">
      <h3 class="group-title">Providers</h3>
      <div class="group-body">
        {#each $sortedProviders as p (p.providerId)}
          <button
            class="settings-row"
            onclick={() => contextProvider = p}
            aria-label="Manage {p.displayName}"
            title={statusTooltip(p)}
          >
            <span class="prow-icon" aria-hidden="true">{providerIcon(p.type)}</span>
            <span class="row-label">
              {p.displayName}
              {#if p.isPrimary}<span class="primary-badge">Primary</span>{/if}
            </span>
            {#if p.status !== 'offline_os' && p.status !== 'offline'}
              <!-- 'offline' is suppressed here: the per-provider OfflineBanner
                   on the dashboard already calls the user's attention to the
                   condition; surfacing the same status as a row badge is
                   redundant and visually noisy. Other states (connected,
                   syncing, error, unauthorized) still show. -->
              <span class="status-dot" style:background-color={statusDotColor(p.status)} aria-hidden="true"></span>
              <span class="status-label" style:color={statusDotColor(p.status)}>{statusLabel(p.status)}</span>
            {/if}
            <span class="row-chevron"><Icon name="chevronRight" size={14} /></span>
          </button>
        {/each}
        {#if $vaultStore.providers.some((p) => p.status === 'offline_os')}
          <div class="offline-os-banner" role="status">
            You're offline — changes will sync when your network is back.
          </div>
        {/if}
        {#if $vaultStore.providers.length === 0}
          <p class="group-empty">No providers connected.</p>
        {/if}
        {#if orphanProviders.length > 0}
          <div class="orphans-block">
            <p class="orphans-help">
              Saved on this device but not in the vault — usually left over from a connect that didn't finish.
              Retry to attach, or remove the saved credentials.
            </p>
            {#each orphanProviders as o (o.provider_id)}
              {@const decrypted = o.config !== null}
              <div class="orphan-row" title="{o.type.toUpperCase()} · saved {formatDate(o.saved_at)}{decrypted ? '' : ' · decrypt failed'}">
                <span class="prow-icon" aria-hidden="true">{providerIcon(o.type)}</span>
                <span class="row-label">
                  {o.display_name}
                  <span class="orphan-meta">
                    {o.type.toUpperCase()} · saved {formatDate(o.saved_at)}
                    {#if !decrypted} · can't decrypt on this device{/if}
                  </span>
                </span>
                {#if decrypted}
                  <button
                    class="orphan-btn"
                    disabled={retryingOrphanId !== null || editingOrphanId !== null}
                    onclick={() => retryOrphan(o as HydratedProviderConfig)}
                  >
                    {retryingOrphanId === o.provider_id ? 'Retrying…' : 'Retry'}
                  </button>
                  <button
                    class="orphan-btn"
                    disabled={retryingOrphanId !== null || editingOrphanId !== null}
                    onclick={() => editingOrphanId = (editingOrphanId === o.provider_id ? null : o.provider_id)}
                  >Edit</button>
                {/if}
                <button
                  class="orphan-btn orphan-danger"
                  disabled={retryingOrphanId !== null || editingOrphanId !== null}
                  onclick={() => removeOrphan(o)}
                >Remove</button>
              </div>
              {#if editingOrphanId === o.provider_id && o.config !== null}
                <div class="orphan-edit">
                  <EditProviderForm
                    type={o.type}
                    currentConfig={o.config}
                    displayName={o.display_name}
                    submitting={savingOrphanEdit}
                    submitLabel="Save & retry"
                    onSubmit={(cfg) => saveOrphanEdit(o as HydratedProviderConfig, cfg)}
                    onCancel={() => editingOrphanId = null}
                  />
                </div>
              {/if}
            {/each}
          </div>
        {/if}
        <button class="settings-row" onclick={() => showAddProvider = true}>
          <span class="row-icon"><Icon name="plus" size={16} /></span>
          <span class="row-label">Add another provider</span>
          <span class="row-chevron"><Icon name="chevronRight" size={14} /></span>
        </button>
      </div>
    </div>

    <!-- ── Sharing ── -->
    <div class="settings-group" id="settings-sharing-anchor">
      <h3 class="group-title">Sharing</h3>
      <div class="group-body">
        <button
          class="settings-row"
          onclick={() => sharesExpanded = !sharesExpanded}
          aria-expanded={sharesExpanded}
        >
          <span class="row-icon"><Icon name="share" size={16} /></span>
          <span class="row-label">Active shares</span>
          <span class="row-chevron" class:rotated={sharesExpanded}><Icon name="chevronRight" size={14} /></span>
        </button>
        {#if sharesExpanded}
          <div class="row-content">
            <ActiveSharesList />
          </div>
        {/if}
      </div>
    </div>

    <!-- ── Security ── -->
    <div class="settings-group">
      <h3 class="group-title">Security</h3>
      <div class="group-body">
        <!-- Change Passphrase -->
        <button
          class="settings-row"
          onclick={() => { passphraseExpanded = !passphraseExpanded; passphraseStep = 'input'; passphraseError = ''; }}
          aria-expanded={passphraseExpanded}
        >
          <span class="row-icon"><Icon name="lock" size={16} /></span>
          <span class="row-label">Change Passphrase</span>
          <span class="row-chevron" class:rotated={passphraseExpanded}><Icon name="chevronRight" size={14} /></span>
        </button>
        {#if passphraseExpanded}
          <div class="row-content">
            {#if passphraseStep === 'input'}
              {#if passphraseError}
                <div class="inline-error">{passphraseError}</div>
              {/if}
              <p class="row-desc">Enter a new passphrase. All enrolled devices will continue to work.</p>
              <ByoPassphraseInput mode="change" onSubmit={handlePassphraseSubmit} />
            {:else if passphraseStep === 'changing'}
              <Argon2Progress done={argonDone} />
              {#if argonDone}<p class="status-msg">Updating vault…</p>{/if}
            {:else if passphraseStep === 'done'}
              <div class="success-card">
                <Icon name="check" size={20} />
                <div>
                  <p class="success-title">Passphrase updated</p>
                  <p class="success-desc">Your vault is now protected by the new passphrase.</p>
                </div>
              </div>
              <button class="primary-btn" onclick={() => passphraseStep = 'input'}>Change Again</button>
            {/if}
          </div>
        {/if}

        <!-- Rotate Recovery Key -->
        {#if onUseRecovery}
          <button class="settings-row" onclick={onUseRecovery}>
            <span class="row-icon"><Icon name="key" size={16} /></span>
            <span class="row-label">Rotate Recovery Key</span>
            <span class="row-chevron"><Icon name="chevronRight" size={14} /></span>
          </button>
        {:else}
          <div class="settings-row settings-row-disabled" title="Recovery key rotation is available from the login screen">
            <span class="row-icon"><Icon name="key" size={16} /></span>
            <span class="row-label">Rotate Recovery Key</span>
            <span class="row-value">Log out to use</span>
          </div>
        {/if}

        <!-- Credential Protection (WebAuthn gate) -->
        <button
          class="settings-row"
          onclick={() => (credProtectionExpanded = !credProtectionExpanded)}
          aria-expanded={credProtectionExpanded}
        >
          <span class="row-icon"><Icon name="shield" size={16} /></span>
          <span class="row-label">Credential Protection</span>
          <span class="row-chevron" class:rotated={credProtectionExpanded}><Icon name="chevronRight" size={14} /></span>
        </button>
        {#if credProtectionExpanded}
          <div class="row-content">
            {#if credProtectionReady && credProtectionSessionId !== null && credProtectionProvider !== null}
              <ByoCredentialProtection
                vaultId={credProtectionVaultId}
                vaultLabel="Wattcloud vault"
                provider={credProtectionProvider}
                vaultSessionId={credProtectionSessionId}
              />
            {:else}
              <p class="row-desc">Unlock the vault to manage credential protection.</p>
            {/if}
          </div>
        {/if}

        <!-- Access Control (restricted enrollment gate) -->
        <button
          class="settings-row"
          onclick={() => (accessControlExpanded = !accessControlExpanded)}
          aria-expanded={accessControlExpanded}
        >
          <span class="row-icon"><Icon name="shield" size={16} /></span>
          <span class="row-label">Access Control</span>
          <span class="row-chevron" class:rotated={accessControlExpanded}><Icon name="chevronRight" size={14} /></span>
        </button>
        {#if accessControlExpanded}
          <div class="row-content">
            <AccessControlPanel />
          </div>
        {/if}

        <!-- Browser-sync warning toggle -->
        <label class="settings-row settings-row-label">
          <span class="row-icon"><Icon name="warning" size={16} /></span>
          <span class="row-text">
            <span class="row-label">Browser Sync Warning</span>
            <span class="row-desc-inline">Shown before saving if acknowledgement expired</span>
          </span>
          <button
            class="toggle-btn"
            class:active={syncWarningAck}
            role="switch"
            aria-checked={syncWarningAck}
            aria-label="Browser sync warning"
            onclick={toggleSyncWarning}
          >
            <span class="toggle-knob"></span>
          </button>
        </label>

        <!-- Vault sounds toggle (§29.6 — opt-in audio identity) -->
        <label class="settings-row settings-row-label">
          <span class="row-icon"><Icon name="bell" size={16} /></span>
          <span class="row-text">
            <span class="row-label">Vault sounds</span>
            <span class="row-desc-inline">Soft click on unlock; thunk on seal</span>
          </span>
          <button
            class="toggle-btn"
            class:active={$byoSoundEnabled}
            role="switch"
            aria-checked={$byoSoundEnabled}
            aria-label="Vault sounds"
            onclick={toggleSounds}
          >
            <span class="toggle-knob"></span>
          </button>
        </label>
      </div>
    </div>

    <!-- ── About ── -->
    <div class="settings-group">
      <h3 class="group-title">About</h3>
      <div class="group-body">
        {#if aboutLoading}
          <div class="loading-inline"><div class="spinner-sm"></div></div>
        {:else}
          <div class="info-row">
            <span class="info-label">Vault ID</span>
            <span class="info-value mono">{vaultId ? vaultId.slice(0, 16) + '…' : '—'}</span>
          </div>
          <div class="info-row">
            <span class="info-label">Vault Version</span>
            <span class="info-value">{vaultVersion}</span>
          </div>
          <div class="info-row">
            <span class="info-label">File Count</span>
            <span class="info-value">{fileCount.toLocaleString()}</span>
          </div>
          {#if storageUsage}
            <div class="info-row">
              <span class="info-label">Storage Used</span>
              <span class="info-value">{formatBytes(storageUsage.used)}</span>
            </div>
            {#if storageUsage.quota}
              <div class="info-row">
                <span class="info-label">Quota</span>
                <span class="info-value">{formatBytes(storageUsage.quota)}</span>
              </div>
            {/if}
          {/if}
        {/if}

        <div class="about-actions">
          <button
            class="primary-btn"
            onclick={handleDownloadBackup}
            disabled={downloadingBackup}
          >
            <Icon name="download" size={14} />
            {downloadingBackup ? 'Downloading…' : 'Download Vault Backup'}
          </button>
          {#if backupError}
            <div class="inline-error">{backupError}</div>
          {/if}
          <p class="row-desc">
            A vault backup is the encrypted vault_manifest.sc file. Restore it by selecting
            the same provider and using your passphrase or recovery key.
          </p>
        </div>
      </div>
    </div>

  </div>
  <!-- Drawer is rendered once at the ByoApp level (shared with the
       dashboard/trash screens) so switching into Settings no longer
       causes it to unmount and flash. -->
</div>

{#if contextProvider}
  <ProviderContextSheet
    provider={contextProvider}
    isOnlyProvider={$vaultStore.providers.length <= 1}
    onClose={() => contextProvider = null}
    onChange={() => { contextProvider = null; }}
  />
{/if}

{#if showAddProvider}
  <AddProviderSheet
    onAdded={() => showAddProvider = false}
    onClose={() => showAddProvider = false}
  />
{/if}

<ConfirmModal
  isOpen={confirmOpen}
  title={confirmTitle}
  message={confirmMessage}
  confirmText={confirmDanger ? 'Revoke' : 'Confirm'}
  confirmClass={confirmDanger ? 'btn-danger' : 'btn-primary'}
  onConfirm={handleConfirm}
  onCancel={() => { confirmOpen = false; confirmAction = null; }}
/>

<style>
  .byo-settings {
    display: flex;
    flex-direction: column;
    height: 100%;
    overflow: hidden;
    box-sizing: border-box;
  }

  /* Desktop: shift content right of the fixed drawer sidebar so settings
     sits next to the drawer instead of underneath it. Top-padding clears
     the fixed DashboardHeader. */
  .byo-settings {
    padding-top: var(--header-height, 56px);
  }
  @media (min-width: 600px) {
    .byo-settings {
      padding-left: var(--drawer-current-width, var(--drawer-width));
      transition: padding-left 0.2s ease;
    }
  }

  /* ── Scroll container ── */
  .settings-scroll {
    flex: 1;
    overflow-y: auto;
    padding: var(--sp-md, 16px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-lg, 24px);
  }

  /* ── Group ── */
  .settings-group {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .group-title {
    font-size: var(--t-label-size, 0.75rem);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--text-secondary, #999999);
    /* §18.1: 32dp top margin, 8dp bottom, 16dp left padding. */
    margin: 0 0 var(--sp-sm, 8px);
    padding: 0 var(--sp-md, 16px);
  }

  .settings-group:first-child .group-title { margin-top: 0; }

  .group-body {
    display: flex;
    flex-direction: column;
    /* §18.1: grouped rows share a container with --r-card; dividers
       between rows are 1px --border, inset from the left. */
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    overflow: hidden;
  }

  .group-empty {
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-disabled, #616161);
    margin: 0;
  }

  /* ── Settings row (§18.1 — fixed 56dp height) ── */
  .settings-row {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    /* Vertical centering via flex; min-height 56dp per spec. */
    padding: 0 var(--sp-md, 16px);
    min-height: 56px;
    background: none;
    border: none;
    border-top: 1px solid var(--border, #2E2E2E);
    color: var(--text-primary, #EDEDED);
    cursor: pointer;
    text-align: left;
    width: 100%;
    transition: background 120ms;
  }
  .settings-row:first-child { border-top: none; }
  .settings-row:hover { background: var(--bg-surface-hover, #2E2E2E); }
  .settings-row-disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .settings-row-disabled:hover { background: none; }
  .settings-row-label {
    cursor: pointer;
  }

  .row-icon {
    display: flex;
    align-items: center;
    color: var(--text-secondary, #999999);
    flex-shrink: 0;
    width: 20px;
    justify-content: center;
  }

  .row-label {
    flex: 1;
    /* §18.1: Label uses --t-body (default body), not body-sm. */
    font-size: var(--t-body-size, 0.9375rem);
    color: var(--text-primary, #EDEDED);
  }

  /* Wraps label+inline-desc so they can sit side-by-side on desktop and
     stack on mobile (narrow rows were wrapping the label to 3 lines
     because .row-desc-inline was flex-shrink:0). */
  .row-text {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
  }
  .row-text .row-label {
    flex: 0 1 auto;
  }
  @media (max-width: 599px) {
    .row-text {
      flex-direction: column;
      align-items: flex-start;
      gap: 2px;
    }
    .row-text .row-desc-inline {
      white-space: normal;
      text-align: left;
    }
  }

  .row-value {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    flex-shrink: 0;
  }

  .row-desc-inline {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
    flex-shrink: 0;
  }

  .row-chevron {
    display: flex;
    align-items: center;
    color: var(--text-disabled, #616161);
    flex-shrink: 0;
    transition: transform 200ms;
  }
  .row-chevron.rotated { transform: rotate(90deg); }

  .row-content {
    padding: var(--sp-sm, 8px) var(--sp-md, 16px) var(--sp-md, 16px);
    border-top: 1px solid var(--border, #2E2E2E);
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
  }

  .row-desc {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    line-height: 1.5;
  }

  /* ── Provider rows ── */
  .prow-icon {
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 6px;
    background: var(--bg-surface, rgba(255,255,255,0.06));
    font-size: 0.65rem;
    font-weight: 700;
    flex-shrink: 0;
    color: var(--text-secondary, #999);
  }

  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .status-label {
    font-size: var(--t-label-size, 0.75rem);
    flex-shrink: 0;
  }

  .offline-os-banner {
    margin: var(--sp-xs, 4px) var(--sp-sm, 8px);
    padding: var(--sp-xs, 4px) var(--sp-sm, 8px);
    border-radius: var(--r-input, 12px);
    background: var(--bg-surface-raised, #262626);
    color: var(--text-secondary, #999999);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .primary-badge {
    font-size: var(--t-label-size, 0.75rem);
    background: var(--accent-muted, #1B3627);
    border: 1px solid var(--accent, #2EB860);
    border-radius: var(--r-pill, 9999px);
    color: var(--accent-text, #5FDB8A);
    padding: 1px 6px;
    margin-left: var(--sp-xs, 4px);
  }

  /* ── Orphan provider rows ── */
  .orphans-block {
    border-top: 1px solid var(--border, #2E2E2E);
    background: var(--bg-surface, rgba(255,255,255,0.03));
  }
  .orphans-help {
    margin: 0;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px) 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.45;
  }
  .orphan-row {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    min-height: 48px;
  }
  .orphan-row .row-label {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }
  .orphan-meta {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #757575);
  }
  .orphan-btn {
    flex-shrink: 0;
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    background: transparent;
    color: var(--text-primary, #EDEDED);
    font-size: var(--t-label-size, 0.75rem);
    padding: 4px 10px;
    cursor: pointer;
    transition: background 120ms ease, border-color 120ms ease;
  }
  .orphan-btn:hover:not(:disabled) {
    background: var(--bg-surface-hover, #2E2E2E);
  }
  .orphan-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .orphan-btn.orphan-danger {
    color: var(--danger, #D64545);
    border-color: var(--danger, #D64545);
  }
  .orphan-btn.orphan-danger:hover:not(:disabled) {
    background: rgba(214, 69, 69, 0.1);
  }
  .orphan-edit {
    padding: var(--sp-sm, 8px) var(--sp-md, 16px) var(--sp-md, 16px);
    border-top: 1px solid var(--border, #2E2E2E);
    background: var(--bg-surface-raised, #1E1E1E);
  }

  /* ── Device rows (§18.1) ── */
  .device-row {
    display: flex;
    align-items: center;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    border-top: 1px solid var(--border, #2E2E2E);
    min-height: 56px;
  }
  .device-row:first-child { border-top: none; }

  .device-icon-wrap {
    color: var(--text-disabled, #616161);
    flex-shrink: 0;
  }

  .device-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .device-name {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #EDEDED);
    display: flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    flex-wrap: wrap;
  }

  .current-badge {
    font-size: var(--t-label-size, 0.75rem);
    background: var(--accent-muted, #1B3627);
    border: 1px solid var(--accent, #2EB860);
    border-radius: var(--r-pill, 9999px);
    color: var(--accent-text, #5FDB8A);
    padding: 1px 6px;
  }

  .device-meta {
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-disabled, #616161);
  }

  .revoke-btn {
    padding: 4px var(--sp-sm, 8px);
    background: none;
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-pill, 9999px);
    color: var(--danger, #D64545);
    font-size: var(--t-label-size, 0.75rem);
    cursor: pointer;
    flex-shrink: 0;
    min-height: 28px;
    transition: all 150ms;
  }
  .revoke-btn:hover { background: var(--danger-muted, #3D1F1F); }

  /* ── Toggle button ── */
  .toggle-btn {
    position: relative;
    width: 40px;
    height: 24px;
    background: var(--border, #2E2E2E);
    border: none;
    border-radius: 12px;
    cursor: pointer;
    flex-shrink: 0;
    transition: background 200ms;
    padding: 0;
  }
  .toggle-btn.active { background: var(--accent, #2EB860); }

  .toggle-knob {
    position: absolute;
    top: 3px;
    left: 3px;
    width: 18px;
    height: 18px;
    background: #fff;
    border-radius: 50%;
    transition: transform 200ms;
    pointer-events: none;
  }
  .toggle-btn.active .toggle-knob { transform: translateX(16px); }

  /* ── About ── */
  .info-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--sp-xs, 4px) var(--sp-md, 16px);
    border-top: 1px solid var(--border, #2E2E2E);
    min-height: 40px;
  }
  .info-row:first-child { border-top: none; }

  .info-label {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
  }

  .info-value {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-primary, #EDEDED);
  }

  .info-value.mono {
    font-family: var(--font-mono, monospace);
    font-size: var(--t-label-size, 0.75rem);
  }

  .about-actions {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px) var(--sp-md, 16px);
    border-top: 1px solid var(--border, #2E2E2E);
  }

  /* ── Shared ── */
  .inline-error {
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 12px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
  }

  .status-msg {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    text-align: center;
  }

  .success-card {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-sm, 8px);
    padding: var(--sp-md, 16px);
    background: var(--accent-muted, #1B3627);
    border: 1px solid var(--accent, #2EB860);
    border-radius: var(--r-input, 12px);
    color: var(--accent-text, #5FDB8A);
  }

  .success-title {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 600;
    color: var(--accent-text, #5FDB8A);
  }

  .success-desc {
    margin: 2px 0 0;
    font-size: var(--t-label-size, 0.75rem);
    color: var(--text-secondary, #999999);
  }

  .primary-btn {
    display: inline-flex;
    align-items: center;
    gap: var(--sp-xs, 4px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--accent, #2EB860);
    border: none;
    border-radius: var(--r-pill, 9999px);
    color: var(--text-inverse, #000);
    font-size: var(--t-body-sm-size, 0.8125rem);
    font-weight: 600;
    cursor: pointer;
    transition: all 150ms;
    width: fit-content;
  }
  .primary-btn:hover:not(:disabled) { background: var(--accent-hover, #3DD870); }
  .primary-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .loading-inline {
    display: flex;
    justify-content: center;
    padding: var(--sp-lg, 24px);
  }

  .spinner-sm {
    width: 22px;
    height: 22px;
    border: 2px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }
</style>
