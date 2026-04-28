<script lang="ts">
  /**
   * ByoCredentialProtection — Settings UI for the WebAuthn passkey gate on
   * the per-vault device CryptoKey (SECURITY.md §12). Renders inline inside
   * the existing Security settings group, showing the gate status + enrolled
   * passkeys and providing enable / add-backup / remove / disable actions.
   *
   * Must only be rendered while the vault is unlocked — enable and disable
   * need the current device CryptoKey to decrypt the shard / provider_configs
   * and then re-encrypt them under the new key.
   */
  import { onMount } from 'svelte';
  import Icon from '../Icons.svelte';
  import ConfirmModal from '../ConfirmModal.svelte';
  import { byoToast } from '../../byo/stores/byoToasts';
  import {
    getWebAuthnRecord,
      clearWebAuthnRecord,
    readRawDeviceCryptoKey,
    setDeviceCryptoKey,
    deleteDeviceCryptoKey,
      type DeviceWebAuthnRecord,
    type WebAuthnCredentialEntry,
  } from '../../byo/DeviceKeyStore';
  import {
    enrolDeviceKey,
    addCredential as addGateCredential,
    removeCredential as removeGateCredential,
    isWebAuthnAvailable,
    evictSessionCache,
    peekSessionDeviceKeyBytes,
    enablePasskeyUnlock as enablePasskeyUnlockGate,
    disablePasskeyUnlock as disablePasskeyUnlockGate,
  } from '../../byo/WebAuthnGate';
  import { migrateDeviceKey } from '../../byo/DeviceKeyMigration';
  import type { StorageProvider } from '@wattcloud/sdk';

  interface Props {
    vaultId: string;
    vaultLabel: string;
    provider: StorageProvider;
    vaultSessionId: number;
  }

  let {
    vaultId,
    vaultLabel,
    provider,
    vaultSessionId
  }: Props = $props();

  // ── State ────────────────────────────────────────────────────────────────

  let loading = $state(true);
  let record = $state<DeviceWebAuthnRecord | null>(null);
  let busy = $state(false);
  let webauthnAvailable = $state(false);
  let confirmRemove: WebAuthnCredentialEntry | null = $state(null);
  let confirmDisable = $state(false);
  /** When true, the passkey-replaces-passphrase confirm modal is showing. */
  let confirmEnablePasskeyUnlock = $state(false);
  /** When true, the passkey-replaces-passphrase disable confirm modal is showing. */
  let confirmDisablePasskeyUnlock = $state(false);
  /**
   * The presence-fallback educational modal is async-driven: when
   * WebAuthnGate's `onPrfUnavailable` fires, it stashes a resolver here and
   * awaits the user's Enable / Cancel decision before returning.
   */
  let presenceFallbackResolve: ((accepted: boolean) => void) | null = $state(null);

  onMount(async () => {
    webauthnAvailable = isWebAuthnAvailable();
    record = await getWebAuthnRecord(vaultId);
    loading = false;
  });

  async function refresh() {
    record = await getWebAuthnRecord(vaultId);
  }

  // ── Enable ────────────────────────────────────────────────────────────────

  async function handleEnable() {
    if (busy) return;

    // Before committing to enrolment, make sure IDB is persistent on this
    // origin. If the browser has the power to silently evict our device
    // record, the gate becomes a lockout trap — eviction nukes the
    // device_webauthn row, leaving the vault openable only via the recovery
    // key. `navigator.storage.persist()` returning false is the canonical
    // signal (private mode, or the user declined the persistence prompt).
    if (typeof navigator !== 'undefined' && navigator.storage?.persist) {
      try {
        const persisted = await navigator.storage.persist();
        if (!persisted) {
          byoToast.show(
            'Browser storage is not persistent on this profile (private mode or ' +
              'a declined prompt). Credential protection will work this session, but ' +
              'your enrolment may be evicted later — keep your recovery key handy.',
            { icon: 'warn', durationMs: 8000 },
          );
        }
      } catch {
        // Persist call itself threw (headless / SSR / unusual browsers). Not fatal.
      }
    }

    busy = true;
    try {
      const oldKey = await readRawDeviceCryptoKey(vaultId);
      if (!oldKey) throw new Error('No device key found for this vault');

      const result = await enrolDeviceKey(vaultId, {
        displayName: defaultAuthenticatorLabel(),
        allowPresenceFallback: true,
        vaultLabel,
        onPrfUnavailable: () =>
          new Promise<boolean>((resolve) => {
            presenceFallbackResolve = resolve;
          }),
      });

      // PRF mode: we now own a fresh random device key; migrate everything
      // that was wrapped under `oldKey` onto it. Presence mode keeps the
      // same key and needs no migration.
      if (result.mode === 'prf') {
        try {
          await migrateDeviceKey({
            vaultId,
            provider,
            oldKey,
            newKey: result.deviceKey,
            vaultSessionId,
          });
        } catch (migrationErr) {
          // migrateDeviceKey is all-or-nothing: either nothing was
          // committed, or provider_configs were reverted to `oldKey` and
          // the manifest was never changed. Either way, roll back the
          // gate record so getDeviceCryptoKey falls through to
          // readRawDeviceCryptoKey and the vault stays openable with
          // `oldKey`.
          await clearWebAuthnRecord(vaultId).catch(() => {});
          evictSessionCache(vaultId);
          throw migrationErr;
        }
        // Best-effort cleanup of the now-orphaned raw device key row.
        // If this fails the gate still routes every read through
        // WebAuthnGate (mode='prf' ignores device_crypto_keys), so the
        // leftover row is harmless — not worth tripping the migration
        // rollback for.
        await deleteDeviceCryptoKey(vaultId).catch(() => {});
      }

      await refresh();
      const modeLabel = result.mode === 'prf' ? 'cryptographic' : 'presence-check';
      byoToast.show(`Credential protection enabled (${modeLabel} mode).`, { icon: 'seal' });
    } catch (e: any) {
      byoToast.show(e?.message ?? 'Failed to enable credential protection.', {
        icon: 'danger',
      });
    } finally {
      busy = false;
    }
  }

  // ── Add backup passkey ───────────────────────────────────────────────────

  async function handleAddBackup() {
    if (busy || !record || record.mode === 'none') return;
    busy = true;
    try {
      // For prf-mode vaults the authenticator's PRF output needs to wrap
      // the same device-key bytes the existing credential already owns.
      // The bytes were stashed by `unlockDeviceKey` the last time this
      // vault was unlocked on this tab — pull them straight from the
      // session cache.
      let deviceKeyBytes: Uint8Array | undefined;
      if (record.mode === 'prf') {
        const cached = peekSessionDeviceKeyBytes(vaultId);
        if (!cached) {
          byoToast.show(
            'The device key is not in memory — lock and unlock the vault, ' +
              'then try adding the backup passkey again.',
            { icon: 'warn' },
          );
          return;
        }
        deviceKeyBytes = cached;
      }

      await addGateCredential(vaultId, {
        displayName: defaultAuthenticatorLabel(),
        allowPresenceFallback: true,
        vaultLabel,
        deviceKeyBytes,
      });
      if (deviceKeyBytes) deviceKeyBytes.fill(0);
      await refresh();
      byoToast.show('Backup passkey added.', { icon: 'seal' });
    } catch (e: any) {
      byoToast.show(e?.message ?? 'Failed to add backup passkey.', { icon: 'danger' });
    } finally {
      busy = false;
    }
  }

  // ── Remove a single credential ───────────────────────────────────────────

  function requestRemove(entry: WebAuthnCredentialEntry) {
    if (!record) return;
    if (record.credentials.length === 1) {
      byoToast.show(
        'This is the last enrolled passkey — disable credential protection instead.',
        { icon: 'warn' },
      );
      return;
    }
    confirmRemove = entry;
  }

  async function handleConfirmRemove() {
    if (!confirmRemove) return;
    const entry = confirmRemove;
    confirmRemove = null;
    if (busy) return;
    busy = true;
    try {
      await removeGateCredential(vaultId, entry.credential_id);
      await refresh();
      byoToast.show(`Removed "${entry.display_name}".`, { icon: 'seal' });
    } catch (e: any) {
      byoToast.show(e?.message ?? 'Failed to remove passkey.', { icon: 'danger' });
    } finally {
      busy = false;
    }
  }

  // ── Disable ──────────────────────────────────────────────────────────────

  function requestDisable() {
    confirmDisable = true;
  }

  async function handleConfirmDisable() {
    confirmDisable = false;
    if (busy || !record) return;
    busy = true;
    try {
      // Current device key — via the gate so the user is prompted once more
      // (prf) or just returned (presence).
      const { getDeviceCryptoKey } = await import('../../byo/DeviceKeyStore');
      const currentKey = await getDeviceCryptoKey(vaultId);
      if (!currentKey) throw new Error('No current device key — cannot rotate.');

      // Fresh plain non-extractable key; replaces the gated path.
      const freshKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      );

      await migrateDeviceKey({
        vaultId,
        provider,
        oldKey: currentKey,
        newKey: freshKey,
        vaultSessionId,
      });
      await setDeviceCryptoKey(vaultId, freshKey);
      await clearWebAuthnRecord(vaultId);
      evictSessionCache(vaultId);

      byoToast.show('Credential protection disabled.', { icon: 'seal' });
    } catch (e: any) {
      console.error('[ByoCredentialProtection] disable failed:', e, e?.message);
      const detail = e?.message || e?.name || String(e);
      byoToast.show(`Failed to disable credential protection: ${detail}`, {
        icon: 'danger',
      });
    } finally {
      // Refresh from ground truth so the toggle reflects the actual record
      // state — on iOS, an interrupted PRF assertion or aborted IDB
      // transaction can leave the in-memory model inconsistent.
      await refresh().catch((err) => console.warn('[ByoCredentialProtection] refresh after disable failed:', err));
      busy = false;
    }
  }

  // ── Passkey-unlock toggle (SECURITY.md §12 "Passkey replaces passphrase") ─

  function requestEnablePasskeyUnlock() {
    if (busy || !record || record.mode !== 'prf') return;
    confirmEnablePasskeyUnlock = true;
  }

  async function handleConfirmEnablePasskeyUnlock() {
    confirmEnablePasskeyUnlock = false;
    if (busy) return;
    busy = true;
    try {
      const { wrappedCount, skippedCount } = await enablePasskeyUnlockGate(
        vaultId,
        vaultSessionId,
      );
      await refresh();
      if (skippedCount > 0) {
        byoToast.show(
          `Passkey unlock enabled for ${wrappedCount} of ${
            wrappedCount + skippedCount
          } passkeys. The others still need the passphrase on unlock — ` +
            'enable them one at a time from this screen.',
          { icon: 'seal', durationMs: 8000 },
        );
      } else {
        byoToast.show('Passkey now unlocks this vault without a passphrase.', {
          icon: 'seal',
        });
      }
    } catch (e: any) {
      const msg: string = e?.message ?? String(e);
      if (!/cancel|NotAllowedError/i.test(msg)) {
        byoToast.show(`Couldn't enable passkey unlock: ${msg}`, { icon: 'danger' });
      }
    } finally {
      busy = false;
    }
  }

  function requestDisablePasskeyUnlock() {
    if (busy || !record?.passkey_unlocks_vault) return;
    confirmDisablePasskeyUnlock = true;
  }

  /**
   * Toggle handler for the passkey-unlock switch. We roll the checkbox
   * back before opening the confirm modal so the visible state is always
   * whatever the record actually says — an accidental tap doesn't look
   * like a state flip until the user confirms.
   */
  function handlePasskeyUnlockToggle(ev: Event) {
    const target = ev.currentTarget as HTMLInputElement | null;
    if (target) target.checked = !!record?.passkey_unlocks_vault;
    if (record?.passkey_unlocks_vault) {
      requestDisablePasskeyUnlock();
    } else {
      requestEnablePasskeyUnlock();
    }
  }

  async function handleConfirmDisablePasskeyUnlock() {
    confirmDisablePasskeyUnlock = false;
    if (busy) return;
    busy = true;
    try {
      await disablePasskeyUnlockGate(vaultId);
      await refresh();
      byoToast.show('Passkey unlock disabled — passphrase required on next unlock.', {
        icon: 'info',
      });
    } catch (e: any) {
      byoToast.show(e?.message ?? 'Failed to disable passkey unlock.', {
        icon: 'danger',
      });
    } finally {
      busy = false;
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  function defaultAuthenticatorLabel(): string {
    const ua = navigator.userAgent;
    if (/Mac OS/.test(ua)) return 'Mac passkey';
    if (/Windows/.test(ua)) return 'Windows Hello';
    if (/iPhone|iPad/.test(ua)) return 'iPhone passkey';
    if (/Android/.test(ua)) return 'Android passkey';
    return 'Passkey';
  }

  function formatDate(iso: string): string {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  let modeLabel =
    $derived(record?.mode === 'prf'
      ? 'Cryptographic (PRF)'
      : record?.mode === 'presence'
        ? 'Presence check'
        : 'Off');
  let modeColor =
    $derived(record && record.mode !== 'none' ? 'var(--accent)' : 'var(--text-secondary)');
  let isEnabled = $derived(record !== null && record.mode !== 'none');
</script>

{#if loading}
  <div class="cp-loading"><div class="cp-spinner"></div></div>
{:else if !webauthnAvailable}
  <p class="cp-unsupported">
    WebAuthn is not available in this browser. Credential protection requires
    a browser that supports <code>navigator.credentials</code>.
  </p>
{:else}
  <div class="cp">
    <div class="cp-status">
      <span class="cp-status-label">Status</span>
      <span class="cp-status-value" style:color={modeColor}>{modeLabel}</span>
    </div>

    {#if !isEnabled}
      <p class="cp-explainer">
        Protect your saved storage-provider credentials and the device shard
        with a passkey on this device (Touch ID, Windows Hello, or a security
        key). When enabled, opening the vault requires a biometric or PIN
        confirmation.
      </p>
      <p class="cp-note">
        This is a <strong>per-device</strong> setting. Enabling it here does
        not affect other devices you've linked to this vault — you'll need
        to enable protection there separately. Enrolled passkeys never leave
        this browser's IndexedDB.
      </p>
      <button class="cp-primary" onclick={handleEnable} disabled={busy}>
        {busy ? 'Setting up…' : 'Enable Credential Protection'}
      </button>
    {:else if record}
      <p class="cp-explainer">
        {#if record.mode === 'prf'}
          A biometric is cryptographically required to open this vault on
          this device. Without it, the saved credentials cannot be decrypted.
        {:else}
          A passkey touch is required before opening the vault. Presence-only
          mode is a behavioural gate — the underlying key remains stored as
          today. Consider upgrading to PRF on a supporting authenticator.
        {/if}
      </p>

      <div class="cp-list" role="list">
        {#each record.credentials as cred (cred.credential_id)}
          <div class="cp-row" role="listitem">
            <div class="cp-row-icon"><Icon name="key" size={18} /></div>
            <div class="cp-row-body">
              <span class="cp-row-name">{cred.display_name}</span>
              <span class="cp-row-meta">
                Added {formatDate(cred.added_at)}
                {#if cred.prf_supported}
                  · PRF
                {:else}
                  · Presence only
                {/if}
              </span>
            </div>
            <button
              class="cp-remove"
              onclick={() => requestRemove(cred)}
              disabled={busy || record.credentials.length === 1}
              aria-label="Remove {cred.display_name}"
              title={record.credentials.length === 1
                ? 'Disable protection to remove the last passkey'
                : 'Remove this passkey'}
            >Remove</button>
          </div>
        {/each}
      </div>

      <button class="cp-secondary" onclick={handleAddBackup} disabled={busy}>
        <Icon name="plus" size={14} />
        <span>Add another passkey</span>
      </button>

      {#if record.mode === 'prf'}
        <div class="cp-unlock-toggle">
          <div class="cp-unlock-text">
            <span class="cp-unlock-title">Passkey unlocks this vault</span>
            <span class="cp-unlock-sub">
              When on, your passkey alone opens the vault on this device — no
              passphrase needed. When off (default), the passkey protects the
              device shard but you still enter the passphrase on unlock.
              Changes the security model: review the explainer before turning
              this on.
            </span>
          </div>
          <label class="cp-switch">
            <input
              type="checkbox"
              checked={!!record.passkey_unlocks_vault}
              onchange={handlePasskeyUnlockToggle}
              disabled={busy}
              aria-label="Passkey unlocks this vault without passphrase"
            />
            <span class="cp-switch-track" aria-hidden="true"></span>
          </label>
        </div>
      {/if}

      <button class="cp-danger" onclick={requestDisable} disabled={busy}>
        Disable Credential Protection
      </button>
    {/if}
  </div>
{/if}

{#if confirmRemove}
  <ConfirmModal
    isOpen={true}
    title="Remove passkey?"
    message={`"${confirmRemove.display_name}" will no longer be able to unlock this vault. You will not be locked out — any other enrolled passkey still works.`}
    confirmText="Remove"
    onConfirm={handleConfirmRemove}
    onCancel={() => (confirmRemove = null)}
  />
{/if}

{#if confirmDisable}
  <ConfirmModal
    isOpen={true}
    title="Disable credential protection?"
    message={"Opening this vault will no longer require a biometric. Your saved " +
      'credentials and the device shard will be re-encrypted under a fresh ' +
      'device key that any code running on this origin can access.'}
    confirmText="Disable"
    onConfirm={handleConfirmDisable}
    onCancel={() => (confirmDisable = false)}
  />
{/if}

<ConfirmModal
  isOpen={confirmEnablePasskeyUnlock}
  title="Let passkey unlock without passphrase?"
  confirmText="Enable passkey unlock"
  confirmClass="btn-danger"
  loading={busy}
  onConfirm={handleConfirmEnablePasskeyUnlock}
  onCancel={() => (confirmEnablePasskeyUnlock = false)}
>
  <p>
    You're about to collapse two unlock factors into one on this device.
  </p>
  <p>
    <strong>Default (recommended):</strong> the passkey protects the device
    shard, and the passphrase is still required on unlock. An attacker would
    need both.
  </p>
  <p>
    <strong>If you enable this:</strong> your <code>vault_key</code> gets
    wrapped under the passkey and stored on this device. Anyone who can make
    your authenticator say yes — including malware that survives on this
    device long enough to social-engineer a biometric touch, or an attacker
    who steals the device unlocked — can open the vault without knowing the
    passphrase.
  </p>
  <p>
    You'll be prompted to touch your passkey once to confirm. Only the
    passkey you touch becomes an unlock credential; other enrolled passkeys
    still need the passphrase until you enable each of them here.
  </p>
</ConfirmModal>

<ConfirmModal
  isOpen={confirmDisablePasskeyUnlock}
  title="Require passphrase on unlock again?"
  confirmText="Disable passkey unlock"
  confirmClass="btn-danger"
  loading={busy}
  onConfirm={handleConfirmDisablePasskeyUnlock}
  onCancel={() => (confirmDisablePasskeyUnlock = false)}
>
  <p>
    The wrapped <code>vault_key</code> copies stored on every enrolled passkey
    for this vault will be deleted. Opening the vault will require the
    passphrase again from the next unlock onward. No biometric touch is
    needed to disable — this is always safe.
  </p>
</ConfirmModal>

{#if presenceFallbackResolve}
  <div
    class="cp-modal-backdrop"
    role="dialog"
    aria-modal="true"
    aria-labelledby="cp-presence-title"
  >
    <div class="cp-modal">
      <h3 id="cp-presence-title" class="cp-modal-title">
        This authenticator doesn't support the strong mode
      </h3>
      <div class="cp-modal-body">
        <p>
          Your passkey was created, but the browser / authenticator didn't
          negotiate the WebAuthn <code>PRF</code> extension — which is what
          lets us cryptographically bind your device key to the biometric.
        </p>
        <p class="cp-modal-compare">
          <strong class="cp-modal-ok">Presence-only fallback</strong>
          — a biometric touch is required before opening the vault. An
          attacker with same-origin code execution (XSS, malicious extension)
          can still bypass it; someone who grabs your unlocked laptop cannot.
        </p>
        <p class="cp-modal-compare">
          <strong class="cp-modal-strong">Cryptographic (PRF) mode</strong>
          — the device key literally can't be derived without the biometric.
          Same-origin attackers are blocked too. Available on up-to-date
          Chrome, Safari, Firefox with Touch ID / Windows Hello / security
          keys supporting the extension.
        </p>
        <p>
          You can enable presence-only now and upgrade later by adding a
          PRF-capable passkey as a backup, then removing this one.
        </p>
      </div>
      <div class="cp-modal-actions">
        <button
          class="cp-modal-ghost"
          onclick={() => {
            presenceFallbackResolve?.(false);
            presenceFallbackResolve = null;
          }}
        >Cancel</button>
        <button
          class="cp-modal-primary"
          onclick={() => {
            presenceFallbackResolve?.(true);
            presenceFallbackResolve = null;
          }}
        >Enable presence-only</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .cp {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
    padding: var(--sp-md, 16px);
  }

  .cp-loading {
    display: flex;
    justify-content: center;
    padding: var(--sp-lg, 24px);
  }

  .cp-spinner {
    width: 20px;
    height: 20px;
    border: 2px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: cp-spin 1s linear infinite;
  }

  @keyframes cp-spin {
    to { transform: rotate(360deg); }
  }

  .cp-unsupported {
    margin: 0;
    padding: var(--sp-md, 16px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.5;
  }

  .cp-status {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: var(--sp-sm, 8px) 0;
    border-bottom: 1px solid var(--border, #2E2E2E);
  }

  .cp-status-label {
    font-size: var(--t-label-size, 0.75rem);
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--text-secondary, #999);
  }

  .cp-status-value {
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 600;
  }

  .cp-explainer {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.5;
  }

  .cp-note {
    margin: 0;
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-input, 12px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-disabled, #616161);
    line-height: 1.5;
  }
  .cp-note strong { color: var(--text-secondary, #999); font-weight: 600; }

  .cp-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-xs, 4px);
  }

  .cp-row {
    display: flex;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
  }

  .cp-row-icon {
    flex-shrink: 0;
    color: var(--text-secondary, #999);
    display: inline-flex;
  }

  .cp-row-body {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .cp-row-name {
    font-size: var(--t-body-size, 0.9375rem);
    color: var(--text-primary, #EDEDED);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .cp-row-meta {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
  }

  .cp-remove {
    flex-shrink: 0;
    padding: 6px 12px;
    background: transparent;
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-pill, 9999px);
    color: var(--text-secondary, #999);
    font-size: var(--t-button-size, 0.875rem);
    font-weight: 600;
    cursor: pointer;
  }

  .cp-remove:hover:not(:disabled) {
    color: var(--danger, #D64545);
    border-color: var(--danger, #D64545);
  }

  .cp-remove:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .cp-primary,
  .cp-secondary,
  .cp-danger {
    height: 44px;
    border-radius: var(--r-pill, 9999px);
    font-size: var(--t-button-size, 0.875rem);
    font-weight: 600;
    letter-spacing: 0.02em;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-xs, 4px);
  }

  .cp-primary {
    background: var(--accent, #2EB860);
    color: var(--text-inverse, #121212);
    border: none;
  }
  .cp-primary:hover:not(:disabled) { background: var(--accent-hover, #40D474); }

  .cp-secondary {
    background: transparent;
    color: var(--accent-text, #5FDB8A);
    border: 1px solid var(--border, #2E2E2E);
  }
  .cp-secondary:hover:not(:disabled) {
    border-color: var(--accent, #2EB860);
  }

  .cp-danger {
    background: transparent;
    color: var(--danger, #D64545);
    border: 1px solid var(--danger-muted, #3D1F1F);
  }
  .cp-danger:hover:not(:disabled) {
    background: var(--danger-muted, #3D1F1F);
  }

  .cp-primary:disabled,
  .cp-secondary:disabled,
  .cp-danger:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* ── Passkey-unlock toggle row ──────────────────────────────────────── */

  .cp-unlock-toggle {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-md, 16px);
    padding: var(--sp-md, 12px);
    background: var(--bg-surface, #1C1C1C);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 12px);
  }

  .cp-unlock-text {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
    flex: 1;
  }

  .cp-unlock-title {
    font-size: var(--t-body-size, 0.9375rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }

  .cp-unlock-sub {
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.45;
  }

  .cp-switch {
    position: relative;
    display: inline-block;
    flex-shrink: 0;
    width: 44px;
    height: 24px;
    cursor: pointer;
    margin-top: 2px;
  }
  .cp-switch input { opacity: 0; width: 0; height: 0; }
  .cp-switch-track {
    position: absolute;
    inset: 0;
    background: var(--bg-surface-hover, #2E2E2E);
    border-radius: 9999px;
    transition: background 160ms ease;
  }
  .cp-switch-track::after {
    content: '';
    position: absolute;
    top: 3px;
    left: 3px;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--text-primary, #EDEDED);
    transition: transform 160ms ease, background 160ms ease;
  }
  .cp-switch input:checked + .cp-switch-track {
    background: var(--accent, #2EB860);
  }
  .cp-switch input:checked + .cp-switch-track::after {
    transform: translateX(20px);
    background: var(--text-inverse, #121212);
  }
  .cp-switch input:disabled + .cp-switch-track {
    opacity: 0.5;
    cursor: not-allowed;
  }

  /* ── Presence-fallback modal ───────────────────────────────────────── */

  .cp-modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: var(--sp-md, 16px);
  }

  .cp-modal {
    max-width: 480px;
    width: 100%;
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    padding: var(--sp-lg, 24px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
  }

  .cp-modal-title {
    margin: 0;
    font-size: var(--t-h2-size, 1.125rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }

  .cp-modal-body {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
  }

  .cp-modal-body p {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.5;
  }

  .cp-modal-body code {
    font-family: var(--font-mono, ui-monospace, monospace);
    font-size: 0.75rem;
    color: var(--text-primary, #EDEDED);
    background: var(--bg-input, #212121);
    padding: 1px 4px;
    border-radius: 4px;
  }

  .cp-modal-compare {
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--bg-surface, #1C1C1C);
    border-radius: var(--r-input, 12px);
  }

  .cp-modal-ok { color: var(--accent-text, #5FDB8A); }
  .cp-modal-strong { color: var(--accent-warm-text, #F0C04A); }

  .cp-modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--sp-sm, 8px);
    margin-top: var(--sp-xs, 4px);
  }

  .cp-modal-ghost,
  .cp-modal-primary {
    height: 40px;
    padding: 0 var(--sp-md, 16px);
    border-radius: var(--r-pill, 9999px);
    font-size: var(--t-button-size, 0.875rem);
    font-weight: 600;
    cursor: pointer;
  }

  .cp-modal-ghost {
    background: transparent;
    border: 1px solid var(--border, #2E2E2E);
    color: var(--text-secondary, #999);
  }
  .cp-modal-ghost:hover { color: var(--text-primary, #EDEDED); }

  .cp-modal-primary {
    background: var(--accent, #2EB860);
    color: var(--text-inverse, #121212);
    border: none;
  }
  .cp-modal-primary:hover { background: var(--accent-hover, #40D474); }
</style>
