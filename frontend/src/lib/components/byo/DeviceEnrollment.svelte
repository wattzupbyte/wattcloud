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
  import { onDestroy } from 'svelte';
  import * as byoWorker from '@wattcloud/sdk';
  import { acquireEnrollmentRelayCookie, evictEnrollmentRelayCookieCache } from '@wattcloud/sdk';
  import type { StorageProvider, ProviderConfig } from '@wattcloud/sdk';
  import { generateDeviceCryptoKey, setDeviceRecord, deleteDeviceRecord, deleteDeviceCryptoKey } from '../../byo/DeviceKeyStore';
  import {
    unlockVault,
    getVaultSessionId,
    getPrimaryProviderId,
    getManifest,
    markDirty,
    bytesToBase64,
    base64ToBytes,
  } from '../../byo/VaultLifecycle';
  import { vaultStore } from '../../byo/stores/vaultStore';
  import { hydrateProvider, providerNeedsReauth, type ProviderCredentials } from '../../byo/ProviderHydrate';
  import { saveProviderConfig } from '../../byo/ProviderConfigStore';
  import { queryRows } from '../../byo/ConflictResolver';
  import { bumpEnrollmentEpoch } from '../../byo/enrollmentSync';
  import QrDisplay from './QrDisplay.svelte';
  import QrScanner from './QrScanner.svelte';
  import SasConfirmation from './SasConfirmation.svelte';
  import Argon2Progress from './Argon2Progress.svelte';
  import ByoPassphraseInput from './ByoPassphraseInput.svelte';
  import ProviderReauthSheet from './ProviderReauthSheet.svelte';
  import CheckCircle from 'phosphor-svelte/lib/CheckCircle';

  
  
  
  
  interface Props {
    role: 'existing' | 'new';
    /** Required for role='existing': the shard to send (base64). */
    shard?: string;
    /**
   * Required for role='new' when the caller already has a provider.
   * Optional when role='new' is entered from the start-screen — the provider
   * is then hydrated on the fly from the primaryConfig received over the
   * enrollment channel.
   */
    provider?: StorageProvider | null;
    /**
   * role='existing' only: the primary ProviderConfig to ship to the new
   * device alongside the shard, so the receiver does not have to add and
   * authenticate the provider from scratch. New vaults include the secret
   * (SFTP password / WebDAV password / S3 secret access key) directly in
   * this config so the receiver hydrates silently. Legacy vaults whose
   * source has no secret stored fall through to the reauth sheet on the
   * receiver.
   */
    primaryConfig?: ProviderConfig | null;
    /**
   * role='existing' only: human-readable label surfaced to the receiver
   * during the reauth prompt (e.g. "Home Storage Box"). Optional.
   */
    primaryLabel?: string;
  onComplete?: (...args: any[]) => void;
  onCancel?: (...args: any[]) => void;
  onEnrolled?: (...args: any[]) => void;
  }

  let {
    role,
    shard = '',
    provider = $bindable(null),
    primaryConfig = null,
    primaryLabel = '',
    onComplete,
    onCancel,
    onEnrolled
  }: Props = $props();
type EnrollStep =
    | 'qr-display'      // existing: show QR
    | 'qr-scan'         // new: scan QR
    | 'waiting-peer'    // both: waiting for peer to connect
    | 'sas'             // both: show SAS code
    | 'sas-confirmed'   // existing: sending shard; new: waiting for shard/config
    | 'provider-reauth' // new (start-screen): re-enter provider creds for received config
    | 'hydrating'       // new (start-screen): connecting to provider with received config
    | 'passphrase'      // new: enter passphrase after provider is ready + shard received
    | 'unlocking'       // new: Argon2id running
    | 'done'            // existing: success
    | 'error';

  // svelte-ignore state_referenced_locally
  let step: EnrollStep = $state(role === 'existing' ? 'qr-display' : 'qr-scan');
  let qrData = $state('');
  let sasCode = $state('');
  let error = $state('');
  let argon2Done = $state(false);
  let unlockPhase = $state('');

  // ── Receiver-side state for the received primary config ────────────────────
  /** Decrypted primary ProviderConfig received from the existing device. */
  let receivedConfig: ProviderConfig | null = $state(null);
  /** Display label forwarded by the existing device (for the reauth sheet). */
  let receivedLabel: string = $state('');
  /** Set once the shard envelope has been decrypted into the WASM session. */
  let shardReceived = false;
  /** Provider reauth sheet state. */
  let reauthBusy = $state(false);
  let reauthError = $state('');

  // Relay WebSocket
  let ws: WebSocket | null = null;
  // Opaque enrollment session ID — eph_sk, enc_key, mac_key stored in WASM heap
  let enrollmentSessionId: number | null = null;
  // Last CloseEvent observed on the relay WS, captured before ws.onerror fires
  // so the user-facing error string can surface the close code/reason. The
  // browser's WebSocket.onerror is opaque (no detail object), so we have to
  // read this from the close handler that fires either right before or after.
  let lastCloseEvent: { code: number; reason: string; wasClean: boolean } | null = null;
  function describeCloseEvent(): string {
    if (!lastCloseEvent) return '';
    const { code, reason, wasClean } = lastCloseEvent;
    if (code === 1000 && wasClean) return '';
    const parts = [`code ${code}`];
    if (reason) parts.push(reason);
    if (code === 1006) parts.push('upgrade refused or transport dropped');
    return ` (${parts.join(' — ')})`;
  }

  // Sender-side stall timer. Once we've handed the shard + primary config
  // off, the sender has nothing else to do but wait for the receiver's
  // `done` ack. Without a deadline the existing-device UI sits on
  // "Sending credentials…" forever if the receiver hits any error
  // downstream (SFTP connect failure, Argon2id, slot-write conflict,
  // manifest upload denial). 90 s comfortably covers Argon2id on a slow
  // device + a manifest upload; longer than that almost always means the
  // receiver bailed silently.
  const SENDER_STALL_TIMEOUT_MS = 90_000;
  let senderStallTimer: ReturnType<typeof setTimeout> | null = null;
  function clearSenderStallTimer() {
    if (senderStallTimer !== null) {
      clearTimeout(senderStallTimer);
      senderStallTimer = null;
    }
  }
  function armSenderStallTimer() {
    clearSenderStallTimer();
    senderStallTimer = setTimeout(() => {
      senderStallTimer = null;
      // Only flip to error if we're still waiting — a late `done` after
      // a real failure would otherwise overwrite the UI. The sender
      // stays in 'sas-confirmed' the whole time it's waiting, so this
      // check is the natural guard.
      if (step === 'sas-confirmed') {
        error = 'The other device didn\'t finish enrollment in time. ' +
          'Check the receiving screen — it usually surfaces the underlying error there.';
        step = 'error';
        cleanup();
      }
    }, SENDER_STALL_TIMEOUT_MS);
  }

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

        if (msg.type === 'ready_for_config') {
          // Receiver is in "start from scratch" mode — it needs the primary
          // ProviderConfig to connect before it can even fetch the manifest.
          // We only send this if the caller supplied one; otherwise the
          // receiver is expected to have its own provider (legacy flow).
          if (primaryConfig) {
            try {
              await sendPrimaryConfig();
            } catch (e: any) {
              error = e.message || 'Failed to send provider config';
              step = 'error';
              cleanup();
              return;
            }
          } else {
            // Tell the receiver so it surfaces a meaningful error instead of
            // waiting forever for a payload that will never arrive.
            ws?.send(JSON.stringify({ type: 'config_unavailable' }));
          }
        }

        if (msg.type === 'done') {
          clearSenderStallTimer();
          step = 'done';
          cleanup();
          // Tell the rest of the app an enrollment just completed so the
          // Settings → Devices list and the Access Control panel can
          // re-fetch without a full page refresh.
          bumpEnrollmentEpoch();
          onComplete?.();
        }
      };

      // onerror runs BEFORE onclose, with no useful detail (browser opacity).
      // We just record the fact so onclose can pick the right error string.
      let sawError = false;
      ws.onerror = () => { sawError = true; };
      ws.onclose = (ev) => {
        lastCloseEvent = { code: ev.code, reason: ev.reason, wasClean: ev.wasClean };
        console.info('[enrollment-ws sender]', { step, code: ev.code, reason: ev.reason, wasClean: ev.wasClean, sawError });
        if (step === 'done' || step === 'error') return;
        if (ev.wasClean && ev.code === 1000) return; // intentional cleanup
        evictEnrollmentRelayCookieCache(channelIdB64).catch(() => {/* best-effort */});
        const prefix = sawError ? 'Relay connection error' : 'Relay channel closed unexpectedly';
        error = `${prefix}${describeCloseEvent()}.`;
        step = 'error';
        cleanup();
      };
    } catch (e: any) {
      error = e.message || 'Enrollment failed';
      step = 'error';
    }
  }

  // ── New device: scan QR ────────────────────────────────────────────────────

  async function handleQrScanned(qrText: string) {
    let payload: unknown;
    try {
      payload = JSON.parse(qrText);
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
      error = 'Invalid QR code — not a Wattcloud enrollment code.';
      step = 'error';
      return;
    }
    const typedPayload = payload as { v: number; ch: string; pk: string };

    try {
      // Open enrollment session — eph_sk stored in WASM. Use the QR's
      // channel_id (typedPayload.ch) so the joiner's WASM session shares
      // the same `channel_id` as the initiator. Falling back to
      // byoEnrollmentOpen here would mint a fresh channel_id, and since
      // channel_id is mixed into the SAS-derivation HKDF info, the two
      // devices would compute *different* SAS codes — exactly the bug
      // this fixes.
      const { ephPkB64: myPk, sessionId } = await byoWorker.Worker.byoEnrollmentJoin(typedPayload.ch);
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
          try {
            // Verify HMAC + decrypt shard; shard stored in WASM session
            await byoWorker.Worker.byoEnrollmentSessionDecryptShard(sessionId, msg.envelope);
            shardReceived = true;
            await maybeAdvanceAfterTransfer();
            // The WS stays open until handlePassphrase sends `done` to the
            // sender. Closing it here (even after both shard + config are in)
            // means handlePassphrase's `ws.send({type:'done'})` later silently
            // no-ops because readyState is no longer OPEN, and the sender
            // hits its 90 s stall timeout despite a successful enrollment.
          } catch (e: any) {
            error = e.message || 'Failed to decrypt shard';
            step = 'error';
            cleanup();
          }
        }

        if (msg.type === 'primary_config') {
          try {
            await handleIncomingPrimaryConfig(msg.envelope);
          } catch (e: any) {
            error = e.message || 'Failed to decrypt provider config';
            step = 'error';
            cleanup();
          }
        }

        if (msg.type === 'config_unavailable') {
          error = 'The source device did not share its provider configuration. ' +
            'Go to that device and start enrollment from a fully-unlocked vault.';
          step = 'error';
          cleanup();
        }
      };

      // onerror runs BEFORE onclose, with no useful detail. Defer the
      // error UI to onclose so it can include the CloseEvent code/reason.
      let sawError = false;
      ws.onerror = () => { sawError = true; };
      ws.onclose = (ev) => {
        lastCloseEvent = { code: ev.code, reason: ev.reason, wasClean: ev.wasClean };
        console.info('[enrollment-ws receiver]', { step, code: ev.code, reason: ev.reason, wasClean: ev.wasClean, sawError });
        if (step === 'error' || step === 'done') return;
        // 'passphrase'/'unlocking'/'hydrating'/'provider-reauth' come after
        // the receiver intentionally closed the WS (see 'encrypted_shard'
        // handler) — leave those alone.
        const stillLive = step === 'sas' || step === 'sas-confirmed' || step === 'waiting-peer';
        if (!stillLive) return;
        if (ev.wasClean && ev.code === 1000) return; // intentional clean close
        evictEnrollmentRelayCookieCache(typedPayload.ch).catch(() => {/* best-effort */});
        const prefix = sawError ? 'Relay connection error' : 'Relay channel closed unexpectedly';
        error = `${prefix}${describeCloseEvent()}.`;
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

  // ── Source-side: send the primary ProviderConfig over the channel ──────────

  async function sendPrimaryConfig() {
    if (!primaryConfig) throw new Error('No primary config to send');
    if (enrollmentSessionId === null) throw new Error('No enrollment session');
    // The session keys (enc_key / mac_key) live in WASM; we only ever see the
    // opaque envelope bytes. A plaintext-JSON ProviderConfig fits comfortably
    // under the 64 KiB payload cap enforced in sdk-core.
    const payloadBytes = new TextEncoder().encode(JSON.stringify({
      v: 1,
      config: primaryConfig,
      label: primaryLabel || '',
    }));
    const payloadB64 = bytesToBase64(payloadBytes);
    const { envelopeB64 } = await byoWorker.Worker.byoEnrollmentSessionEncryptPayload(
      enrollmentSessionId,
      payloadB64,
    );
    ws?.send(JSON.stringify({ type: 'primary_config', envelope: envelopeB64 }));
  }

  // ── Receiver-side: handle incoming primary_config ──────────────────────────

  async function handleIncomingPrimaryConfig(envelopeB64: string) {
    if (enrollmentSessionId === null) throw new Error('No enrollment session');
    const { payloadB64 } = await byoWorker.Worker.byoEnrollmentSessionDecryptPayload(
      enrollmentSessionId,
      envelopeB64,
    );
    const payloadBytes = base64ToBytes(payloadB64);
    const payloadJson = new TextDecoder().decode(payloadBytes);
    let parsed: { v?: number; config?: ProviderConfig; label?: string };
    try {
      parsed = JSON.parse(payloadJson);
    } catch {
      throw new Error('Provider config payload was not valid JSON');
    }
    if (!parsed || parsed.v !== 1 || !parsed.config || typeof parsed.config.type !== 'string') {
      throw new Error('Unrecognized provider config payload');
    }
    receivedConfig = parsed.config;
    receivedLabel = typeof parsed.label === 'string' ? parsed.label : '';
    await maybeAdvanceAfterTransfer();
  }

  /**
   * After each incoming message (shard or primary_config), check whether we
   * now have everything we need to move the receiver forward. The two
   * messages can arrive in either order; we only act once the set is
   * complete.
   */
  async function maybeAdvanceAfterTransfer() {
    // Legacy flow: caller passed a provider, no config transfer expected.
    // The shard alone is enough to move to the passphrase step.
    if (provider && shardReceived) {
      step = 'passphrase';
      return;
    }
    // Start-screen flow: need both shard AND decrypted config.
    if (!provider && shardReceived && receivedConfig) {
      if (providerNeedsReauth(receivedConfig)) {
        step = 'provider-reauth';
      } else {
        await hydrateReceivedConfig();
      }
    }
  }

  async function hydrateReceivedConfig(creds?: ProviderCredentials) {
    if (!receivedConfig) throw new Error('No received config to hydrate');
    step = 'hydrating';
    try {
      const instance = await hydrateProvider(receivedConfig, creds);
      provider = instance;
      step = 'passphrase';
    } catch (e: any) {
      // Roll back to the reauth sheet so the user can retype credentials —
      // hydrate() rejects synchronously if the creds don't auth.
      reauthError = e?.message ?? 'Failed to connect with those credentials.';
      step = receivedConfig && providerNeedsReauth(receivedConfig) ? 'provider-reauth' : 'error';
      if (step === 'error') error = reauthError;
    }
  }

  async function handleProviderReauthSubmit(creds: {
    username?: string;
    password?: string;
    privateKey?: string;
    passphrase?: string;
    accessKeyId?: string;
    secretAccessKey?: string;
  }) {
    if (!receivedConfig) return;
    reauthBusy = true;
    reauthError = '';
    // Splice ALL freshly-entered values back into receivedConfig (identity
    // + secret) so the post-unlock saveProviderConfig at step 10 persists
    // them and the next reload skips the reauth sheet entirely.
    if (receivedConfig.type === 'sftp') {
      receivedConfig = {
        ...receivedConfig,
        sftpUsername: creds.username ?? receivedConfig.sftpUsername,
        sftpPassword: creds.password || undefined,
        sftpPrivateKey: creds.privateKey || undefined,
        sftpPassphrase: creds.passphrase || undefined,
      };
    } else if (receivedConfig.type === 'webdav') {
      receivedConfig = {
        ...receivedConfig,
        username: creds.username ?? receivedConfig.username,
        password: creds.password || undefined,
      };
    } else if (receivedConfig.type === 's3') {
      receivedConfig = {
        ...receivedConfig,
        s3AccessKeyId: creds.accessKeyId ?? receivedConfig.s3AccessKeyId,
        s3SecretAccessKey: creds.secretAccessKey || undefined,
      };
    }
    await hydrateReceivedConfig({
      password: creds.password || undefined,
      privateKey: creds.privateKey || undefined,
      passphrase: creds.passphrase || undefined,
      accessKeyId: creds.accessKeyId || undefined,
      secretAccessKey: creds.secretAccessKey || undefined,
    });
    reauthBusy = false;
  }

  function handleProviderReauthCancel() {
    // Abort the whole link-device flow — the receiver cannot proceed without
    // a working primary provider.
    cleanup();
    if (enrollmentSessionId !== null) {
      byoWorker.Worker.byoEnrollmentClose(enrollmentSessionId).catch(() => {/* best-effort */});
      enrollmentSessionId = null;
    }
    onCancel?.();
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
        armSenderStallTimer();
      } catch (e: any) {
        error = e.message || 'Failed to send shard';
        step = 'error';
        cleanup();
      }
    } else {
      // New device: we visually confirmed the SAS. If we don't already have
      // a provider (start-screen flow), ask the source to send the primary
      // ProviderConfig now. The source waits for this message before sending
      // the config so the ordering is explicit and auditable.
      step = 'sas-confirmed';
      if (!provider) {
        try {
          ws?.send(JSON.stringify({ type: 'ready_for_config' }));
        } catch (e: any) {
          error = e.message || 'Failed to request provider config';
          step = 'error';
          cleanup();
        }
      }
      // The shard arrives via WebSocket — already handled in onmessage.
    }
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

  async function handlePassphrase(passphrase: string) {
    step = 'unlocking';
    argon2Done = false;

    // vault_manifest.sc header byte offsets (vault_format.rs).
    const HEADER_SIZE = 1227;
    const HMAC_OFFSET = 1195;
    const NUM_SLOTS_OFFSET = 190;
    const DEVICE_SLOTS_OFFSET = 191;
    const SLOT_SIZE = 125;
    const MAX_SLOTS = 8;

    let preopenedSessionId: number | null = null;
    let createdDeviceKeyForVaultId: string | null = null;

    try {
      if (!provider) throw new Error('No provider');
      if (enrollmentSessionId === null) throw new Error('No enrollment session');

      // ── Step 1: download manifest + parse header ─────────────────────────
      // The receiver has no device slot yet, so it CANNOT call unlockVault
      // first — unlockVault's slot-derive step (VaultLifecycle.ts §"Step 5")
      // requires `slot.device_id === myDeviceId` to find the wrapped shard
      // and would throw "Device slot not found in vault header". The whole
      // point of enrollment is to write that slot. We therefore drive the
      // bottom half of unlockVault manually (open WASM session, derive KEK
      // from the received shard, write the slot, recompute HMAC, upload),
      // then hand the live session to unlockVault via `preopenedSessionId`
      // so it skips slot-derivation and continues with manifest decode +
      // secondary-provider fetches.
      const { data: manifestBytes, version: currentVersion } = await provider.download(
        provider.manifestRef(),
      );
      if (manifestBytes.length < HEADER_SIZE) throw new Error('Manifest too small');
      const headerBytes = new Uint8Array(manifestBytes.slice(0, HEADER_SIZE));
      const headerInfo = await byoWorker.Worker.byoParseVaultHeader(
        new Uint8Array(manifestBytes),
      );
      const vaultId: string = headerInfo.vault_id;

      // ── Step 2: open vault WASM session via passphrase (Argon2id) ────────
      preopenedSessionId = await byoWorker.Worker.byoVaultOpen(
        passphrase,
        headerInfo.master_salt,
        headerInfo.argon2_memory_kb,
        headerInfo.argon2_iterations,
        headerInfo.argon2_parallelism,
        headerInfo.pass_wrap_iv,
        headerInfo.pass_wrapped_vault_key,
      );
      argon2Done = true;

      // ── Step 3: verify header HMAC against the just-derived vault_key ────
      const headerPrefixB64 = bytesToBase64(headerBytes.slice(0, HMAC_OFFSET));
      const hmacB64 = bytesToBase64(headerBytes.slice(HMAC_OFFSET));
      const hmacResult = await byoWorker.Worker.byoVaultVerifyHeaderHmac(
        preopenedSessionId,
        headerPrefixB64,
        hmacB64,
      );
      if (!hmacResult.valid) throw new Error('Vault header HMAC verification failed');

      // ── Step 4: pull the shard from the enrollment session, derive KEK ───
      // Shard appears briefly in JS for the WebCrypto AES-GCM wrap below.
      const { shardB64: receivedShardB64 } = await byoWorker.Worker.byoEnrollmentSessionGetShard(
        enrollmentSessionId,
      );
      await byoWorker.Worker.byoVaultDeriveKek(preopenedSessionId, receivedShardB64);

      // ── Step 5: enroll this device — generate device CryptoKey + slot ────
      const deviceCryptoKey = await generateDeviceCryptoKey(vaultId);
      createdDeviceKeyForVaultId = vaultId;
      const deviceIdBytes = crypto.getRandomValues(new Uint8Array(16));
      const slotIv = crypto.getRandomValues(new Uint8Array(12));

      const shardForSlot = Uint8Array.from(atob(receivedShardB64), (c) => c.charCodeAt(0));
      const encryptedShardBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: slotIv },
        deviceCryptoKey,
        shardForSlot,
      );
      shardForSlot.fill(0);
      const encryptedShardBytes = new Uint8Array(encryptedShardBuf);

      // ── Step 6: write the new slot into the header in place ──────────────
      const numActiveSlots = headerBytes[NUM_SLOTS_OFFSET];
      if (numActiveSlots >= MAX_SLOTS) throw new Error('All device slots are full');

      const slotOffset = DEVICE_SLOTS_OFFSET + numActiveSlots * SLOT_SIZE;
      headerBytes[slotOffset] = 0x01;                                      // status Active
      headerBytes.set(deviceIdBytes, slotOffset + 1);                      // device_id [1..17]
      headerBytes.set(slotIv, slotOffset + 17);                            // wrap_iv [17..29]
      headerBytes.set(encryptedShardBytes, slotOffset + 29);               // encrypted_payload [29..77]
      // signing_key_wrapped [77..125] = zeros (not yet provisioned)
      headerBytes[NUM_SLOTS_OFFSET] = numActiveSlots + 1;

      // ── Step 7: recompute header HMAC against the (now-extended) header ──
      const newHmacResult = await byoWorker.Worker.byoVaultComputeHeaderHmac(
        preopenedSessionId,
        bytesToBase64(headerBytes.slice(0, HMAC_OFFSET)),
      );
      headerBytes.set(base64ToBytes(newHmacResult.hmac), HMAC_OFFSET);

      // ── Step 8: re-assemble + upload manifest ────────────────────────────
      const manifestBody = manifestBytes.slice(HEADER_SIZE);
      const newManifest = new Uint8Array(HEADER_SIZE + manifestBody.length);
      newManifest.set(headerBytes, 0);
      newManifest.set(manifestBody, HEADER_SIZE);
      unlockPhase = 'Writing device slot to vault…';
      await provider.upload(provider.manifestRef(), 'vault_manifest.sc', newManifest, {
        mimeType: 'application/octet-stream',
        expectedVersion: currentVersion,
      });

      // ── Step 9: persist IDB device record only after the upload succeeds ─
      const deviceIdHex = Array.from(deviceIdBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      await setDeviceRecord({
        vault_id: vaultId,
        device_id: deviceIdHex,
        device_name: navigator.userAgent.slice(0, 64),
        last_seen_vault_version: 1,
        last_seen_manifest_version: 0,
        last_backup_prompt_at: null,
      });
      console.info('[DeviceEnrollment] step 9 done — manifest uploaded, device record persisted');

      // The receiver is now functionally enrolled (slot in manifest header +
      // device key in IDB). Tell the sender so its UI can transition to
      // "Done" without waiting through Step 10 (unlockVault hydrates every
      // secondary provider over SFTP — easily 30 s+ on a multi-provider
      // vault, way past the 90 s stall but well past the user's patience).
      // The remaining steps below are local persistence that doesn't change
      // enrollment success: a refresh always recovers them.
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'done' }));
        // Let the WS flush before any further awaits steal the event loop.
        await new Promise((r) => setTimeout(r, 50));
        cleanup();
      }

      // ── Step 10: hand the preopened WASM session to unlockVault ──────────
      // unlockVault's `preopenedSessionId` path skips Argon2id AND the
      // device-shard-from-slot derivation (we already loaded the KEK at
      // step 4), so it goes straight to manifest decode + secondary-provider
      // hydration.
      unlockPhase = 'Connecting to your storage providers…';
      const vaultKeySessionId = crypto.randomUUID();
      console.info('[DeviceEnrollment] step 10 begin — unlockVault hydrating secondaries');
      const t10 = performance.now();
      const db = await unlockVault(provider, {
        passphrase: '',
        keySessionId: vaultKeySessionId,
        preopenedSessionId,
      });
      preopenedSessionId = null; // ownership transferred to unlockVault
      console.info(`[DeviceEnrollment] step 10 done in ${Math.round(performance.now() - t10)} ms`);

      // ── Step 9b: append this device to vault_meta.enrolled_devices ───────
      // The slot table in the manifest header proves this device CAN unlock,
      // but the visible "Enrolled devices" list in Settings is driven by the
      // JSON blob in vault_meta. Without this, the new device authenticates
      // fine but stays invisible in the management UI — the source can't see
      // that the enrollment landed and can't revoke later. Best-effort: a
      // failure here doesn't block the unlock, since the slot is the source
      // of truth for access.
      try {
        const existingRows = queryRows(
          db,
          "SELECT value FROM vault_meta WHERE key = 'enrolled_devices'",
        );
        let enrolled: Array<{ device_id: string; device_name: string; enrolled_at: string }> = [];
        if (existingRows.length > 0) {
          try {
            enrolled = JSON.parse(existingRows[0]['value'] as string);
          } catch {
            enrolled = [];
          }
        }
        if (!enrolled.some((d) => d.device_id === deviceIdHex)) {
          enrolled.push({
            device_id: deviceIdHex,
            device_name: navigator.userAgent.slice(0, 64),
            enrolled_at: new Date().toISOString(),
          });
          db.run(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('enrolled_devices', ?)",
            [JSON.stringify(enrolled)],
          );
          markDirty();
        }
      } catch (devListErr) {
        console.warn('[DeviceEnrollment] enrolled_devices update failed', devListErr);
      }

      // If we hydrated from a received primary_config (start-screen flow),
      // persist it so the vault now appears in the vault-list on next reload.
      // Then walk the manifest's secondary entries and persist them too —
      // their config_json carries the same credentials the source uses, so
      // the new device gets multi-provider parity without re-adding each
      // secondary by hand. Configs whose secret is missing (legacy vaults
      // that never persisted creds) still land in the store; they'll fall
      // through to the reauth sheet on next open like any legacy row.
      unlockPhase = 'Saving provider configurations…';
      console.info('[DeviceEnrollment] beginning saveProviderConfig phase', {
        hasReceivedConfig: !!receivedConfig,
        manifestProviderCount: getManifest()?.providers.length ?? 0,
      });
      const tSaves = performance.now();
      const cfgLabel = receivedConfig
        ? (receivedLabel.trim().length > 0
            ? receivedLabel
            : (provider?.displayName ?? receivedConfig.type))
        : '';

      // Race the whole phase against an 8 s timeout. The device is already
      // functionally enrolled by this point — slot in manifest header, key
      // in IDB, 'done' shipped to the sender — so a hang here (we've seen
      // saveProviderConfig sit indefinitely on some receivers, suspected
      // IDB lock contention with the markDirty-triggered saveVault) must
      // not strand the UI. On timeout the entries land on the next reload
      // by re-hydrating from the manifest, and the user just goes to the
      // dashboard.
      const persistProviderConfigs = async (): Promise<void> => {
        if (!receivedConfig) return;
        // After unlockVault returns, VaultLifecycle has parsed the manifest
        // and populated _primaryProviderId with the authoritative UUID.
        // Reusing that UUID keeps this device's ProviderConfigStore row in
        // sync with every other device's row for the same vault.
        const providerIdForLink = getPrimaryProviderId() || crypto.randomUUID();
        try {
          await saveProviderConfig(
            {
              provider_id: providerIdForLink,
              vault_id: vaultId,
              vault_label: cfgLabel,
              type: receivedConfig.type,
              display_name: provider?.displayName ?? receivedConfig.type,
              is_primary: true,
              saved_at: new Date().toISOString(),
            },
            // Persist the full config the source sent, including any SFTP
            // credentials. Symmetrical with the source side, where
            // AddProviderSheet/hydrate already store the full config in
            // ProviderConfigStore. Receiver-side reauth (provider-reauth step)
            // overwrites with the freshly-entered credentials before reaching
            // here, so the row always reflects what last actually connected.
            receivedConfig,
          );
        } catch (persistErr) {
          console.warn('[DeviceEnrollment] saveProviderConfig failed', persistErr);
        }

        // Mirror every non-tombstoned, non-primary manifest entry into the
        // per-device store so reload uses the local IDB hydrate path
        // instead of re-reading config_json. One bad entry doesn't block
        // the others.
        try {
          const manifest = getManifest();
          if (!manifest) return;
          for (const entry of manifest.providers) {
            if (entry.tombstone) continue;
            if (entry.provider_id === providerIdForLink) continue;
            let secondaryConfig: ProviderConfig;
            try {
              secondaryConfig = JSON.parse(entry.config_json) as ProviderConfig;
            } catch (parseErr) {
              console.warn('[DeviceEnrollment] secondary config_json parse failed', entry.provider_id, parseErr);
              continue;
            }
            try {
              const tSec = performance.now();
              await saveProviderConfig(
                {
                  provider_id: entry.provider_id,
                  vault_id: vaultId,
                  vault_label: cfgLabel,
                  type: secondaryConfig.type,
                  display_name: entry.display_name,
                  is_primary: false,
                  saved_at: new Date().toISOString(),
                },
                secondaryConfig,
              );
              console.info(
                `[DeviceEnrollment] saved secondary ${entry.provider_id} in ${Math.round(performance.now() - tSec)} ms`,
              );
            } catch (persistErr) {
              console.warn('[DeviceEnrollment] secondary saveProviderConfig failed', entry.provider_id, persistErr);
            }
          }
        } catch (manifestErr) {
          console.warn('[DeviceEnrollment] manifest secondaries persist failed', manifestErr);
        }
      };

      const SAVE_PHASE_TIMEOUT_MS = 8_000;
      const timedOut = await Promise.race([
        persistProviderConfigs().then(() => false),
        new Promise<true>((r) => setTimeout(() => r(true), SAVE_PHASE_TIMEOUT_MS)),
      ]);
      if (timedOut) {
        console.warn(
          '[DeviceEnrollment] saveProviderConfig phase timed out after',
          SAVE_PHASE_TIMEOUT_MS,
          'ms — proceeding to onEnrolled. Configs will be re-derived from the manifest on next load.',
        );
      }

      // ('done' was already sent and the WS cleaned up right after Step 9 —
      // see the block following setDeviceRecord above. No duplicate signal
      // here.)
      console.info(
        `[DeviceEnrollment] saveProviderConfig phase done in ${Math.round(performance.now() - tSaves)} ms`,
      );
      console.info('[DeviceEnrollment] receiver flow complete, calling onEnrolled');

      // Close enrollment session (zeroizes remaining material in WASM)
      byoWorker.Worker.byoEnrollmentClose(enrollmentSessionId).catch(() => {/* best-effort */});
      enrollmentSessionId = null;

      // Tell anyone watching enrollmentEpoch to re-fetch — covers the
      // case where the receiver lands on the dashboard then immediately
      // opens Settings.
      bumpEnrollmentEpoch();

      onEnrolled?.({
        db,
        sessionId: vaultKeySessionId,
        // At this point `provider` is guaranteed non-null — either supplied
        // by the parent (legacy flow) or hydrated above from receivedConfig.
        provider: provider!,
        config: receivedConfig ?? (provider!.getConfig?.() ?? null),
      });
    } catch (e: any) {
      // Cleanup: close any preopened WASM session so it doesn't leak.
      if (preopenedSessionId !== null) {
        await byoWorker.Worker.byoVaultClose(preopenedSessionId).catch(() => {});
        preopenedSessionId = null;
      }
      // Cleanup: if we generated a device CryptoKey for this vault but
      // failed before persisting the device record (or before the manifest
      // upload landed), drop the leftover key + record so the next attempt
      // starts clean. Without this, a retry hits getDeviceCryptoKey,
      // finds the stale key, and routes into the "Device slot not found"
      // branch instead of the fresh-enrollment path.
      if (createdDeviceKeyForVaultId !== null) {
        await deleteDeviceRecord(createdDeviceKeyForVaultId).catch(() => {});
        await deleteDeviceCryptoKey(createdDeviceKeyForVaultId).catch(() => {});
      }
      error = e.message || 'Failed to unlock vault with received shard';
      step = 'error';
    }
  }

  // ── Cleanup ────────────────────────────────────────────────────────────────

  function cleanup() {
    clearSenderStallTimer();
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
  $effect(() => {
    if (role === 'existing' && step === 'qr-display' && !qrData) {
      startExistingDeviceEnrollment();
    }
  });
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
      Never send this QR code over chat or email. Anyone who scans it could try to enroll their device instead of yours.
    </p>
    <button class="btn btn-secondary wide-btn" onclick={() => onCancel?.()}>Cancel</button>

  {:else if step === 'qr-scan'}
    <h2 class="title">Scan the QR code</h2>
    <p class="subtitle">On your existing device, open Settings → Enroll device, then scan the code here.</p>
    <QrScanner onScanned={handleQrScanned} onError={(msg) => { error = msg; step = 'error'; }} />
    <button class="btn btn-secondary wide-btn" onclick={() => onCancel?.()}>Cancel</button>

  {:else if step === 'waiting-peer'}
    <h2 class="title">Connecting…</h2>
    <div class="spinner-wrap"><div class="spinner"></div></div>
    <p class="subtitle">Waiting for the existing device to respond.</p>

  {:else if step === 'sas'}
    <h2 class="title">Verify security code</h2>
    <SasConfirmation {sasCode} onConfirm={handleSasConfirm} onMismatch={handleSasMismatch} />

  {:else if step === 'sas-confirmed'}
    <h2 class="title">{role === 'existing' ? 'Sending credentials…' : 'Receiving credentials…'}</h2>
    <div class="spinner-wrap"><div class="spinner"></div></div>
    <p class="subtitle">
      {role === 'existing'
        ? 'Securely transferring vault access to the new device.'
        : 'Waiting for the other device to finish sending.'}
    </p>

  {:else if step === 'provider-reauth' && receivedConfig}
    <ProviderReauthSheet
      config={receivedConfig}
      vaultLabel={receivedLabel}
      busy={reauthBusy}
      error={reauthError}
      onSubmit={handleProviderReauthSubmit}
      onCancel={handleProviderReauthCancel}
    />

  {:else if step === 'hydrating'}
    <h2 class="title">Connecting to provider…</h2>
    <div class="spinner-wrap"><div class="spinner"></div></div>
    <p class="subtitle">Opening the storage backend with the credentials you entered.</p>

  {:else if step === 'passphrase'}
    <h2 class="title">Enter your passphrase</h2>
    <p class="subtitle">Verify your identity to complete enrollment.</p>
    <div class="full-width">
      <ByoPassphraseInput mode="unlock" submitLabel="Complete enrollment" onSubmit={handlePassphrase} />
    </div>

  {:else if step === 'unlocking'}
    <h2 class="title">Unlocking vault…</h2>
    <Argon2Progress done={argon2Done} phase={unlockPhase} />

  {:else if step === 'done'}
    <div class="success">
      <div class="success-icon" aria-hidden="true">
        <CheckCircle size={72} weight="regular" color="var(--accent, #2EB860)" />
      </div>
      <h2 class="title">Device enrolled</h2>
      <p class="subtitle">The new device now has access to your vault.</p>
      <button class="btn btn-primary wide-btn" onclick={() => onComplete?.()}>Done</button>
    </div>

  {:else if step === 'error'}
    <div class="error-state">
      <p class="error-msg" role="alert">{error}</p>
      <div class="error-actions">
        <button class="btn btn-secondary" onclick={() => {
          error = '';
          step = role === 'existing' ? 'qr-display' : 'qr-scan';
          if (role === 'existing') { qrData = ''; startExistingDeviceEnrollment(); }
        }}>Try again</button>
        <button class="btn btn-ghost" onclick={() => onCancel?.()}>Cancel</button>
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
    justify-content: center;
    /* The byo-shell parent is a flex column with flex:1, so flex:1 here
       fills the available height and the content vertically centers
       instead of pinning to the top with a tall empty band below. */
    flex: 1;
    width: 100%;
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

  /* .enrollment is align-items:center so children narrow to their content
     width — fine for centered icons/spinners but it makes inputs look
     squished compared to the standard ByoUnlock screen, which stretches.
     Wrap the passphrase block in .full-width so it spans the column. */
  .full-width {
    align-self: stretch;
    width: 100%;
  }

  .loading {
    color: var(--text-secondary, #999999);
    font-size: var(--t-body-sm-size, 0.8125rem);
    padding: var(--sp-xl, 32px);
  }

  .qr-warning {
    margin: 0;
    font-size: var(--t-body-sm-size, 0.8125rem);
    color: var(--accent-warm-text, #F0C04A);
    background: var(--accent-warm-muted, #3D2E10);
    border: 1px solid var(--accent-warm, #E0A320);
    border-radius: var(--r-input, 12px);
    padding: var(--sp-sm, 8px) var(--sp-md, 16px);
    text-align: left;
    line-height: 1.5;
  }

  .wide-btn {
    width: 100%;
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
