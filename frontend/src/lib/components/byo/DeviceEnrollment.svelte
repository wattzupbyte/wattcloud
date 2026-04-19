<script lang="ts">
  /**
   * DeviceEnrollment — QR-based two-role device enrollment.
   *
   * role='existing': Existing device initiates enrollment (shows QR, sends shard)
   * role='new': New device joins enrollment (scans QR, receives shard, unlocks)
   *
   * Security invariants:
   * - SAS mismatch aborts + zeroizes all ephemeral material
   * - Shard is transmitted only after SAS visual confirmation
   * - All ephemeral keys cleared on destroy / error / mismatch
   */
  import { createEventDispatcher, onDestroy } from 'svelte';
  import * as byoWorker from '@secure-cloud/byo';
  import { acquireEnrollmentRelayCookie, evictEnrollmentRelayCookieCache } from '@secure-cloud/byo';
  import type { StorageProvider } from '@secure-cloud/byo';
  import { generateDeviceCryptoKey, setDeviceRecord } from '../../byo/DeviceKeyStore';
  import { unlockVault, getVaultSessionId, MANIFEST_FILE, bytesToBase64, base64ToBytes } from '../../byo/VaultLifecycle';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import QrDisplay from './QrDisplay.svelte';
  import QrScanner from './QrScanner.svelte';
  import SasConfirmation from './SasConfirmation.svelte';
  import Argon2Progress from './Argon2Progress.svelte';
  import ByoPassphraseInput from './ByoPassphraseInput.svelte';

  export let role: 'existing' | 'new';
  /** Required for role='existing': the shard to send (base64). */
  export let shard: string = '';
  /** Required for role='new': the storage provider. */
  export let provider: StorageProvider | null = null;

  const dispatch = createEventDispatcher<{
    complete: void;
    cancel: void;
    /** New device: vault unlocked with new device enrolled. */
    enrolled: import('sql.js').Database;
  }>();

  type EnrollStep =
    | 'qr-display'      // existing: show QR
    | 'qr-scan'         // new: scan QR
    | 'waiting-peer'    // both: waiting for peer to connect
    | 'sas'             // both: show SAS code
    | 'sas-confirmed'   // existing: sending shard; new: waiting for shard
    | 'passphrase'      // new: enter passphrase after receiving shard
    | 'unlocking'       // new: Argon2id running
    | 'done'            // existing: success
    | 'error';

  let step: EnrollStep = role === 'existing' ? 'qr-display' : 'qr-scan';
  let qrData = '';
  let sasCode = '';
  let error = '';
  let argon2Done = false;

  // Relay WebSocket
  let ws: WebSocket | null = null;
  // Opaque enrollment session ID — eph_sk, enc_key, mac_key stored in WASM heap
  let enrollmentSessionId: number | null = null;

  // ── Existing device: initiate enrollment ───────────────────────────────────

  async function startExistingDeviceEnrollment() {
    try {
      // Open enrollment session — eph_sk stored in WASM, never crosses boundary
      const { ephPkB64, channelIdB64, sessionId } = await byoWorker.Worker.byoEnrollmentOpen();
      enrollmentSessionId = sessionId;

      // Build QR payload
      qrData = JSON.stringify({ v: 1, ch: channelIdB64, pk: ephPkB64 });

      // Acquire purpose-scoped relay cookie (PoW-gated, ~0.5–1 s).
      await acquireEnrollmentRelayCookie(channelIdB64);

      // Connect to relay WS
      const relayBase = window.location.origin.replace(/^http/, 'ws');
      ws = new WebSocket(`${relayBase}/relay/ws?mode=enrollment&channel=${channelIdB64}`);

      ws.onmessage = async (event) => {
        const msg = JSON.parse(event.data);

        if (msg.type === 'peer_pk') {
          // Derive session keys — eph_sk consumed, enc_key/mac_key stored in WASM session
          const { sasCode: code } = await byoWorker.Worker.byoEnrollmentDeriveKeys(sessionId, msg.pk);
          sasCode = String(code).padStart(6, '0');
          step = 'sas';
        }

        if (msg.type === 'done') {
          step = 'done';
          cleanup();
          dispatch('complete');
        }
      };

      ws.onerror = () => {
        // Evict relay cookie so the next attempt re-acquires a fresh one.
        evictEnrollmentRelayCookieCache(channelIdB64).catch(() => {/* best-effort */});
        error = 'Relay connection error. Please try again.';
        step = 'error';
        cleanup();
      };
    } catch (e: any) {
      error = e.message || 'Enrollment failed';
      step = 'error';
    }
  }

  // ── New device: scan QR ────────────────────────────────────────────────────

  async function handleQrScanned(event: CustomEvent<string>) {
    let payload: unknown;
    try {
      payload = JSON.parse(event.detail);
    } catch {
      error = 'Invalid QR code';
      step = 'error';
      return;
    }
    if (
      typeof payload !== 'object' || payload === null ||
      (payload as Record<string, unknown>).v !== 1 ||
      typeof (payload as Record<string, unknown>).ch !== 'string' ||
      typeof (payload as Record<string, unknown>).pk !== 'string'
    ) {
      error = 'Invalid QR code — not a SecureCloud enrollment code.';
      step = 'error';
      return;
    }
    const typedPayload = payload as { v: number; ch: string; pk: string };

    try {
      // Open enrollment session — eph_sk stored in WASM
      const { ephPkB64: myPk, sessionId } = await byoWorker.Worker.byoEnrollmentOpen();
      enrollmentSessionId = sessionId;
      const peerPk = typedPayload.pk;

      // Acquire purpose-scoped relay cookie (PoW-gated, ~0.5–1 s).
      await acquireEnrollmentRelayCookie(typedPayload.ch);

      // Derive session keys from existing device's public key — enc_key/mac_key stored in WASM
      const { sasCode: code } = await byoWorker.Worker.byoEnrollmentDeriveKeys(sessionId, peerPk);
      sasCode = String(code).padStart(6, '0');

      // Connect to relay WS
      const relayBase = window.location.origin.replace(/^http/, 'ws');
      ws = new WebSocket(`${relayBase}/relay/ws?mode=enrollment&channel=${typedPayload.ch}`);

      ws.onopen = () => {
        // Send our ephemeral public key to the existing device. C8: only
        // surface the SAS UI after the peer has actually received our public
        // key, so the user can't confirm "codes match" on the new device
        // before the existing device has computed its own code.
        ws!.send(JSON.stringify({ type: 'peer_pk', pk: myPk }));
        step = 'sas';
      };

      ws.onmessage = async (event) => {
        const msg = JSON.parse(event.data);

        if (msg.type === 'encrypted_shard') {
          // Verify HMAC + decrypt shard; shard stored in WASM session
          await byoWorker.Worker.byoEnrollmentSessionDecryptShard(sessionId, msg.envelope);
          step = 'passphrase';
          cleanup();
        }
      };

      ws.onerror = () => {
        // Evict relay cookie so the next attempt re-acquires a fresh one.
        evictEnrollmentRelayCookieCache(typedPayload.ch).catch(() => {/* best-effort */});
        error = 'Relay connection error.';
        step = 'error';
        cleanup();
      };

      // C8: show a transient "connecting" state while the WS completes the
      // handshake — `step = 'sas'` is set from inside ws.onopen above.
      step = 'waiting-peer';
    } catch (e: any) {
      error = e.message || 'Enrollment failed';
      step = 'error';
    }
  }

  // ── SAS confirmation ───────────────────────────────────────────────────────

  async function handleSasConfirm() {
    if (role === 'existing') {
      // Encrypt shard and send to new device using session keys (never leave WASM)
      step = 'sas-confirmed';
      try {
        if (enrollmentSessionId === null) throw new Error('No enrollment session');
        const { envelopeB64 } = await byoWorker.Worker.byoEnrollmentSessionEncryptShard(
          enrollmentSessionId,
          shard,
        );
        ws?.send(JSON.stringify({ type: 'encrypted_shard', envelope: envelopeB64 }));
      } catch (e: any) {
        error = e.message || 'Failed to send shard';
        step = 'error';
        cleanup();
      }
    }
    // For new device: SAS confirm just means they visually verified it.
    // The shard arrives via WebSocket — already handled in onmessage.
  }

  function handleSasMismatch() {
    // SECURITY: Close enrollment session (zeroizes eph_sk/enc_key/mac_key in WASM)
    if (enrollmentSessionId !== null) {
      byoWorker.Worker.byoEnrollmentClose(enrollmentSessionId).catch(() => {/* best-effort */});
      enrollmentSessionId = null;
    }
    cleanup();
    error = 'SAS codes did not match — enrollment aborted. Please try again.';
    step = 'error';
  }

  // ── New device: unlock with received shard ─────────────────────────────────

  async function handlePassphrase(event: CustomEvent<string>) {
    const passphrase = event.detail;
    step = 'unlocking';
    argon2Done = false;

    try {
      if (!provider) throw new Error('No provider');
      if (enrollmentSessionId === null) throw new Error('No enrollment session');

      const vaultKeySessionId = crypto.randomUUID();
      const db = await unlockVault(provider, { passphrase, keySessionId: vaultKeySessionId });
      argon2Done = true;

      // Consume the shard from the WASM enrollment session — briefly appears in JS
      // for the WebCrypto device-slot encryption step (accepted exception).
      const { shardB64: receivedShardB64 } = await byoWorker.Worker.byoEnrollmentSessionGetShard(enrollmentSessionId);

      // Enroll this device in the vault
      const deviceIdBytes = crypto.getRandomValues(new Uint8Array(16));
      const vaultId = $vaultStore.vaultId!;
      const deviceCryptoKey = await generateDeviceCryptoKey(vaultId);

      // Encrypt shard with device CryptoKey (non-extractable — must happen in JS)
      const slotIv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedShardBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: slotIv },
        deviceCryptoKey,
        Uint8Array.from(atob(receivedShardB64), (c) => c.charCodeAt(0)),
      );
      const encryptedShardBytes = new Uint8Array(encryptedShardBuf);

      // Write new device slot into vault_manifest.sc header.
      // Must happen before setDeviceRecord so IDB state never diverges from the header.
      const HEADER_SIZE = 1227;
      const HMAC_OFFSET = 1195;
      const DEVICE_SLOTS_OFFSET = 191;
      const SLOT_SIZE = 125;
      const MAX_SLOTS = 8;

      const { data: manifestBytes, version: currentVersion } = await provider.download(MANIFEST_FILE);
      if (manifestBytes.length < HEADER_SIZE) throw new Error('Manifest too small');

      const header = new Uint8Array(manifestBytes.slice(0, HEADER_SIZE));
      const numActiveSlots = header[190];
      if (numActiveSlots >= MAX_SLOTS) throw new Error('All device slots are full');

      const slotOffset = DEVICE_SLOTS_OFFSET + numActiveSlots * SLOT_SIZE;
      header[slotOffset] = 0x01;                                      // status Active
      header.set(deviceIdBytes, slotOffset + 1);                      // device_id [1..17]
      header.set(slotIv, slotOffset + 17);                            // wrap_iv [17..29]
      header.set(encryptedShardBytes, slotOffset + 29);               // encrypted_payload [29..77]
      // signing_key_wrapped [77..125] = zeros (not yet provisioned)
      header[190] = numActiveSlots + 1;                               // bump num_active_slots

      const vaultWasmSessionId = getVaultSessionId();
      if (vaultWasmSessionId === null) throw new Error('No active vault session for HMAC');
      const { hmac } = await byoWorker.Worker.byoVaultComputeHeaderHmac(
        vaultWasmSessionId,
        bytesToBase64(header.slice(0, HMAC_OFFSET)),
      );
      header.set(base64ToBytes(hmac), HMAC_OFFSET);

      // Re-assemble manifest (new header + existing body) and upload
      const manifestBody = manifestBytes.slice(HEADER_SIZE);
      const newManifest = new Uint8Array(HEADER_SIZE + manifestBody.length);
      newManifest.set(header, 0);
      newManifest.set(manifestBody, HEADER_SIZE);
      await provider.upload(MANIFEST_FILE, 'vault_manifest.sc', newManifest, {
        mimeType: 'application/octet-stream',
        expectedVersion: currentVersion,
      });

      // Persist IDB device record only after header upload succeeds
      const deviceIdHex = Array.from(deviceIdBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
      await setDeviceRecord({
        vault_id: vaultId,
        device_id: deviceIdHex,
        device_name: navigator.userAgent.slice(0, 64),
        last_seen_vault_version: 1,
        last_seen_manifest_version: 0,
        last_backup_prompt_at: null,
      });

      // Signal existing device that enrollment is done
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'done' }));
      }

      // Close enrollment session (zeroizes remaining material in WASM)
      byoWorker.Worker.byoEnrollmentClose(enrollmentSessionId).catch(() => {/* best-effort */});
      enrollmentSessionId = null;

      dispatch('enrolled', db);
    } catch (e: any) {
      error = e.message || 'Failed to unlock vault with received shard';
      step = 'error';
    }
  }

  // ── Cleanup ────────────────────────────────────────────────────────────────

  function cleanup() {
    if (ws && ws.readyState !== WebSocket.CLOSED) {
      ws.close();
    }
    ws = null;
  }

  onDestroy(() => {
    // Close enrollment session (zeroizes eph_sk/enc_key/mac_key/shard in WASM)
    if (enrollmentSessionId !== null) {
      byoWorker.Worker.byoEnrollmentClose(enrollmentSessionId).catch(() => {/* best-effort */});
      enrollmentSessionId = null;
    }
    cleanup();
  });

  // Start existing device enrollment on mount
  $: if (role === 'existing' && step === 'qr-display' && !qrData) {
    startExistingDeviceEnrollment();
  }
</script>

<div class="enrollment">
  {#if step === 'qr-display'}
    <h2 class="title">Enroll a new device</h2>
    <p class="subtitle">Hold this screen up to the new device to scan. Do not screenshot or share this code — enrollment must happen in person.</p>
    {#if qrData}
      <QrDisplay data={qrData} ariaLabel="QR code for device enrollment" />
    {:else}
      <div class="loading">Generating enrollment code…</div>
    {/if}
    <p class="qr-warning" role="note">
      Never send this QR code over chat or email. An attacker who scans it could attempt to enroll their device instead.
    </p>
    <button class="btn btn-secondary" on:click={() => dispatch('cancel')}>Cancel</button>

  {:else if step === 'qr-scan'}
    <h2 class="title">Scan the QR code</h2>
    <p class="subtitle">On your existing device, go to Settings → Enroll device, then scan the code here.</p>
    <QrScanner on:scanned={handleQrScanned} on:error={(e) => { error = e.detail; step = 'error'; }} />
    <button class="btn btn-secondary" on:click={() => dispatch('cancel')}>Cancel</button>

  {:else if step === 'waiting-peer'}
    <h2 class="title">Connecting…</h2>
    <div class="spinner-wrap"><div class="spinner"></div></div>
    <p class="subtitle">Waiting for the existing device to respond.</p>

  {:else if step === 'sas'}
    <h2 class="title">Verify security code</h2>
    <SasConfirmation {sasCode} on:confirm={handleSasConfirm} on:mismatch={handleSasMismatch} />

  {:else if step === 'sas-confirmed'}
    <h2 class="title">Sending credentials…</h2>
    <div class="spinner-wrap"><div class="spinner"></div></div>
    <p class="subtitle">Securely transferring vault access to the new device.</p>

  {:else if step === 'passphrase'}
    <h2 class="title">Enter your passphrase</h2>
    <p class="subtitle">Verify your identity to complete enrollment.</p>
    <ByoPassphraseInput mode="unlock" submitLabel="Complete enrollment" on:submit={handlePassphrase} />

  {:else if step === 'unlocking'}
    <h2 class="title">Unlocking vault…</h2>
    <Argon2Progress done={argon2Done} />

  {:else if step === 'done'}
    <div class="success">
      <div class="success-icon" aria-hidden="true">
        <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
          <circle cx="20" cy="20" r="18" stroke="var(--accent)" stroke-width="2"/>
          <polyline points="12 21 18 27 29 15" stroke="var(--accent)" stroke-width="2.5"
            stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <h2 class="title">Device enrolled</h2>
      <p class="subtitle">The new device now has access to your vault.</p>
      <button class="btn btn-primary" on:click={() => dispatch('complete')}>Done</button>
    </div>

  {:else if step === 'error'}
    <div class="error-state">
      <p class="error-msg" role="alert">{error}</p>
      <div class="error-actions">
        <button class="btn btn-secondary" on:click={() => {
          error = '';
          step = role === 'existing' ? 'qr-display' : 'qr-scan';
          if (role === 'existing') { qrData = ''; startExistingDeviceEnrollment(); }
        }}>Try again</button>
        <button class="btn btn-ghost" on:click={() => dispatch('cancel')}>Cancel</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .enrollment {
    display: flex;
    flex-direction: column;
    gap: var(--sp-md, 16px);
    align-items: center;
    max-width: 420px;
    margin: 0 auto;
    padding: var(--sp-lg, 24px) var(--sp-md, 16px);
    text-align: center;
  }

  .title {
    margin: 0;
    font-size: var(--t-title-size, 1.25rem);
    font-weight: 700;
    color: var(--text-primary, #EDEDED);
  }

  .subtitle {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--text-secondary, #999999);
    line-height: 1.5;
  }

  .loading {
    color: var(--text-secondary, #999999);
    font-size: var(--t-body-sm-size, 0.8125rem);
    padding: var(--sp-xl, 32px);
  }

  .qr-warning {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--warning, #E8A838);
    background: var(--warning-muted, #3A2B10);
    border: 1px solid var(--warning, #E8A838);
    border-radius: var(--r-input, 12px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    text-align: left;
    line-height: 1.5;
  }

  .spinner-wrap {
    padding: var(--sp-xl, 32px);
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 3px solid var(--border, #2E2E2E);
    border-top-color: var(--accent, #2EB860);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .success {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--sp-md, 16px);
    padding: var(--sp-xl, 32px) 0;
  }

  .error-state {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm, 8px);
  }

  .error-msg {
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    background: var(--danger-muted, #3D1F1F);
    border: 1px solid var(--danger, #D64545);
    border-radius: var(--r-input, 12px);
    color: var(--danger, #D64545);
    font-size: var(--t-body-sm-size, 0.8125rem);
    text-align: left;
  }

  .error-actions {
    display: flex;
    gap: var(--sp-sm, 8px);
    justify-content: center;
  }
</style>
