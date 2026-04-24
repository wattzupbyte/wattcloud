<script lang="ts">
  /**
   * ByoCredProtectionOffer — one-shot modal offered after a successful
   * vault unlock to nudge the user toward enabling the WebAuthn gate
   * (SECURITY.md §12). Conditions for showing:
   *   - WebAuthn is available in this browser.
   *   - No `device_webauthn` row exists for this vault (mode is effectively
   *     'none').
   *   - The user hasn't permanently dismissed the offer for this vault
   *     (`cred_protection_offer_dismissed_at` is unset on DeviceRecord).
   * Buttons:
   *   - **Enable** → runs the full enrolment inline (WebAuthn prompt +
   *     device-key migration). Doing it here keeps the click inside the
   *     user gesture that triggered it; routing through Settings broke
   *     the gesture chain and never launched `navigator.credentials.create()`.
   *   - **Not now** → close silently; next unlock will re-offer.
   *   - "Don't ask again" checkbox → persists the dismissal timestamp.
   */
  import { createEventDispatcher, onMount } from 'svelte';
  import Icon from '../Icons.svelte';
  import {
    getDeviceRecord,
    setDeviceRecord,
    getWebAuthnRecord,
    readRawDeviceCryptoKey,
    deleteDeviceCryptoKey,
    clearWebAuthnRecord,
    type DeviceRecord,
  } from '../../byo/DeviceKeyStore';
  import {
    isWebAuthnAvailable,
    enrolDeviceKey,
    evictSessionCache,
  } from '../../byo/WebAuthnGate';
  import { migrateDeviceKey } from '../../byo/DeviceKeyMigration';
  import { getVaultSessionId, getProvider } from '../../byo/VaultLifecycle';
  import { byoToast } from '../../byo/stores/byoToasts';

  export let vaultId: string;

  const dispatch = createEventDispatcher<{ openSettings: void }>();

  let visible = false;
  let dontAskAgain = false;
  let record: DeviceRecord | null = null;
  let busy = false;

  onMount(async () => {
    if (!vaultId) return;
    if (!isWebAuthnAvailable()) return;
    const existingGate = await getWebAuthnRecord(vaultId);
    if (existingGate && existingGate.mode !== 'none') return;
    record = await getDeviceRecord(vaultId);
    if (record?.cred_protection_offer_dismissed_at) return;
    visible = true;
  });

  async function persistDismissalIfChecked(): Promise<void> {
    if (!dontAskAgain || !record) return;
    await setDeviceRecord({
      ...record,
      cred_protection_offer_dismissed_at: new Date().toISOString(),
    });
  }

  function defaultAuthenticatorLabel(): string {
    const ua = navigator.userAgent;
    if (/Mac OS/.test(ua)) return 'Mac passkey';
    if (/Windows/.test(ua)) return 'Windows Hello';
    if (/iPhone|iPad/.test(ua)) return 'iPhone passkey';
    if (/Android/.test(ua)) return 'Android passkey';
    return 'Passkey';
  }

  /**
   * Run the full enable flow right here inside the click handler so the
   * WebAuthn `create()` call still has transient activation. A round-trip
   * through Settings went through `dispatch` + state switch + onMount
   * before the call, which consumed the gesture and silently no-op'd the
   * enrolment. If anything fails we keep the offer open so the user can
   * retry or fall back to Settings.
   */
  async function handleEnable() {
    if (busy) return;
    busy = true;

    // Best-effort request for persistent storage — otherwise a private /
    // low-disk profile could silently evict the enrolment later and turn
    // the gate into a lockout. We mirror the warning pattern the Settings
    // flow uses (SECURITY.md §12 "Storage pressure eviction").
    if (typeof navigator !== 'undefined' && navigator.storage?.persist) {
      try {
        const persisted = await navigator.storage.persist();
        if (!persisted) {
          byoToast.show(
            'Browser storage is not persistent on this profile. Credential ' +
              'protection will work this session, but the enrolment may be ' +
              'evicted later — keep your recovery key handy.',
            { icon: 'warn', durationMs: 8000 },
          );
        }
      } catch {
        /* not fatal */
      }
    }

    const provider = getProvider();
    const vaultSessionId = getVaultSessionId();
    if (!provider || vaultSessionId === null) {
      byoToast.show('Vault is not fully unlocked yet — try again in a moment.', {
        icon: 'danger',
      });
      busy = false;
      return;
    }

    try {
      const oldKey = await readRawDeviceCryptoKey(vaultId);
      if (!oldKey) throw new Error('No device key found for this vault');

      const result = await enrolDeviceKey(vaultId, {
        displayName: defaultAuthenticatorLabel(),
        allowPresenceFallback: true,
        vaultLabel: 'Wattcloud vault',
      });

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
          await clearWebAuthnRecord(vaultId).catch(() => {});
          evictSessionCache(vaultId);
          throw migrationErr;
        }
        await deleteDeviceCryptoKey(vaultId).catch(() => {});
      }

      await persistDismissalIfChecked();
      const modeLabel = result.mode === 'prf' ? 'cryptographic' : 'presence-check';
      byoToast.show(`Credential protection enabled (${modeLabel} mode).`, {
        icon: 'seal',
      });
      visible = false;
    } catch (err: any) {
      // Distinguish user cancel from real errors — cancel shouldn't look
      // like a crash. WebAuthn surfaces cancels as NotAllowedError or the
      // literal string from `enrolDeviceKey`.
      const msg: string = err?.message ?? String(err);
      const isCancel = /cancel|NotAllowedError/i.test(msg);
      if (!isCancel) {
        byoToast.show(`Couldn't enable credential protection: ${msg}`, {
          icon: 'danger',
        });
      }
    } finally {
      busy = false;
    }
  }

  async function handleDismiss() {
    if (busy) return;
    visible = false;
    await persistDismissalIfChecked();
  }

  function handleOpenSettings() {
    if (busy) return;
    visible = false;
    dispatch('openSettings');
  }
</script>

{#if visible}
  <div
    class="offer-backdrop"
    role="dialog"
    aria-modal="true"
    aria-labelledby="offer-title"
  >
    <div class="offer">
      <div class="offer-icon" aria-hidden="true">
        <Icon name="shield" size={32} />
      </div>
      <h3 id="offer-title" class="offer-title">Protect this vault on this device?</h3>
      <p class="offer-body">
        Require Touch ID, Windows Hello, or a security key before opening
        the vault on this device. Your saved provider credentials and the
        device shard get re-encrypted under a key that only a biometric
        can derive. You can change this later in
        <strong>Settings → Security → Credential Protection</strong>.
      </p>
      <p class="offer-note">
        This is a <strong>per-device</strong> setting — your other devices
        are unaffected until you enable protection there too. If you lose
        every passkey on this device, unlock with your recovery key or link
        from another device to re-enrol.
      </p>
      <label class="offer-checkbox">
        <input type="checkbox" bind:checked={dontAskAgain} disabled={busy} />
        <span>Don't ask again for this vault</span>
      </label>
      <div class="offer-actions">
        <button class="offer-ghost" on:click={handleDismiss} disabled={busy}>
          Not now
        </button>
        <button
          class="offer-primary"
          on:click={handleEnable}
          disabled={busy}
          aria-busy={busy}
        >
          {#if busy}
            <span class="offer-spinner" aria-hidden="true"></span>
            Waiting for passkey…
          {:else}
            Enable
          {/if}
        </button>
      </div>
      <button
        class="offer-settings-link"
        on:click={handleOpenSettings}
        disabled={busy}
        type="button"
      >
        Customize in Settings
      </button>
    </div>
  </div>
{/if}

<style>
  .offer-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: var(--sp-md, 16px);
    animation: offer-fade 200ms ease-out;
  }

  @keyframes offer-fade {
    from { opacity: 0; }
    to { opacity: 1; }
  }

  .offer {
    max-width: 440px;
    width: 100%;
    background: var(--bg-surface-raised, #262626);
    border: 1px solid var(--border, #2E2E2E);
    border-radius: var(--r-card, 16px);
    padding: var(--sp-lg, 24px);
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
    text-align: center;
  }

  .offer-icon {
    align-self: center;
    width: 56px;
    height: 56px;
    border-radius: 50%;
    background: var(--accent-muted, #1B3627);
    color: var(--accent-text, #5FDB8A);
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .offer-title {
    margin: 0;
    font-size: var(--t-h2-size, 1.125rem);
    font-weight: 600;
    color: var(--text-primary, #EDEDED);
  }

  .offer-body {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    line-height: 1.5;
  }
  .offer-body strong { color: var(--text-primary, #EDEDED); font-weight: 600; }

  .offer-note {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-disabled, #616161);
    line-height: 1.5;
  }
  .offer-note strong { color: var(--text-secondary, #999); font-weight: 600; }

  .offer-checkbox {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-sm, 8px);
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999);
    cursor: pointer;
    user-select: none;
  }
  .offer-checkbox input {
    width: 16px;
    height: 16px;
    accent-color: var(--accent, #2EB860);
    cursor: pointer;
  }

  .offer-actions {
    display: flex;
    justify-content: center;
    gap: var(--sp-sm, 8px);
    margin-top: var(--sp-xs, 4px);
  }

  .offer-ghost,
  .offer-primary {
    height: 44px;
    padding: 0 var(--sp-lg, 24px);
    border-radius: var(--r-pill, 9999px);
    font-size: var(--t-button-size, 0.875rem);
    font-weight: 600;
    cursor: pointer;
  }

  .offer-ghost {
    background: transparent;
    border: 1px solid var(--border, #2E2E2E);
    color: var(--text-secondary, #999);
  }
  .offer-ghost:hover { color: var(--text-primary, #EDEDED); }

  .offer-primary {
    background: var(--accent, #2EB860);
    color: var(--text-inverse, #121212);
    border: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: var(--sp-sm, 8px);
  }
  .offer-primary:hover:not([disabled]) { background: var(--accent-hover, #40D474); }
  .offer-primary[disabled],
  .offer-ghost[disabled] {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .offer-spinner {
    width: 14px;
    height: 14px;
    border: 2px solid rgba(0, 0, 0, 0.25);
    border-top-color: rgba(0, 0, 0, 0.85);
    border-radius: 50%;
    animation: offer-spin 0.8s linear infinite;
  }
  @keyframes offer-spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }

  .offer-settings-link {
    background: transparent;
    border: none;
    color: var(--text-secondary, #999);
    font-size: var(--t-body-sm-size, 0.8125rem);
    text-decoration: underline;
    cursor: pointer;
    padding: 0;
    margin-top: var(--sp-xs, 4px);
  }
  .offer-settings-link:hover:not([disabled]) { color: var(--text-primary, #EDEDED); }
  .offer-settings-link[disabled] { opacity: 0.6; cursor: not-allowed; }
</style>
