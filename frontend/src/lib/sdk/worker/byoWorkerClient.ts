/**
 * BYO Crypto Worker Client
 *
 * Main-thread RPC client for the BYO Web Worker. All cryptographic operations
 * and key material live inside the worker — this module only sends messages
 * and receives results.
 *
 * Follows the same pattern as the frontend's cryptoWorkerClient.ts but is
 * completely independent. Both packages depend on sdk-wasm directly.
 *
 * SECURITY: Keys never leave the worker. All functions return opaque base64
 * strings or serialized data — never raw key bytes.
 */

// ── Worker lifecycle ───────────────────────────────────────────────────────

let worker: Worker | null = null;
let workerReady = false;
let initPromise: Promise<void> | null = null;

// ── Request tracking ───────────────────────────────────────────────────────

let requestId = 0;
const pendingRequests = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void }>();

// ── Session timeout ────────────────────────────────────────────────────────

let sessionTimeoutId: ReturnType<typeof setTimeout> | null = null;
const SESSION_TIMEOUT_MS = 25 * 60 * 1000; // 25 min (5 min buffer from 30 min)

// ── Timeout durations by operation type ────────────────────────────────────

const ENCRYPT_DECRYPT_TIMEOUT_MS = 30_000;
const KEY_OP_TIMEOUT_MS = 10_000;
// C5: Phase 3d provider-integrated streaming pushes / pulls wrap real network
// I/O (upload chunk, Range download). A 10s ceiling spuriously evicted live
// sessions on slow providers — 120s keeps the guard-rail while accommodating
// multi-MB chunks over residential uplinks.
const STREAMING_TIMEOUT_MS = 120_000;

const ENCRYPT_DECRYPT_OPS = new Set([
  'v7EncryptInit', 'v7EncryptTakeHeader', 'v7EncryptPush', 'v7EncryptFinalize',
  'v7DecryptInit', 'v7DecryptPush', 'v7DecryptFinalize',
  'encryptFilenameAtomic',
  'byoDeriveVaultKeys', 'byoUnwrapVaultKey', 'byoDeriveKek',
  'byoEncryptVaultBody', 'byoDecryptVaultBody', 'byoWrapVaultKey',
  'byoComputeHeaderHmac', 'byoVerifyHeaderHmac',
  'byoRefreshToken',
  'byoRequestDestructiveToken',
  'byoVaultCreate', 'byoVaultRewrapWithPassphrase',
  'byoGenerateDeviceSigningKey', 'byoSealDeviceSigningKey', 'byoUnsealDeviceSigningKey',
  'byoEd25519Sign', 'byoEd25519Verify', 'byoMigrateVaultV1ToV2',
  // Vault session API
  'byoVaultOpen', 'byoVaultClose', 'byoVaultVerifyHeaderHmac', 'byoVaultDecryptBody',
  'byoVaultEncryptBody', 'byoVaultComputeHeaderHmac', 'byoVaultDeriveKek',
  'byoVaultLoadKeys', 'byoVaultDeriveSubkey', 'byoVaultGenerateKeypairWrapped',
  'webauthnDeriveWrappingKey', 'webauthnWrapDeviceKey',
  'webauthnUnwrapDeviceKey', 'webauthnGenerateDeviceKey',
  'webauthnDeriveVaultKeyWrappingKey', 'webauthnWrapVaultKey',
  'webauthnUnwrapVaultKey',
  'byoVaultWrapSessionVaultKeyWithPrf',
  'byoVaultLoadSessionFromWrappedVaultKey',
  'byoVaultSealDeviceSigningKey',
  'byoVaultUnsealDeviceSigningKey', 'byoVaultMigrateV1ToV2', 'byoVaultRewrap',
  // R6 multi-vault
  'byoManifestEncrypt', 'byoManifestDecrypt', 'byoManifestMerge', 'byoManifestValidate',
  'byoVaultBodyEncrypt', 'byoVaultBodyDecrypt',
  'byoDerivePerVaultWalKey', 'byoDerivePerVaultJournalKeys',
  'byoJournalAppend', 'byoJournalParse',
  'byoShareAuditPayload',
  'byoMergeRows',
  'byoManifestAddProvider', 'byoManifestRenameProvider', 'byoManifestSetPrimary', 'byoManifestTombstone', 'byoManifestUpdateProviderConfig',
  'byoPlanUnlock', 'byoPlanSave', 'byoPlanCrossProviderMove', 'byoDeriveManifestAeadKey',
  'byoCrossProviderMoveDecideReplay', 'byoCrossProviderMovePlanReconcile',
  // Generic dispatcher (P8)
  'byoProviderCall',
  // Config registry (R1.4)
  'byoInitConfig', 'byoReleaseConfig', 'byoRefreshConfigByHandle',
  // BYO streaming flows (Phase 2)
  'byoDownloadFlowInit', 'byoDownloadFlowPush', 'byoDownloadFlowFinalize', 'byoDownloadFlowAbort',
  'byoUploadFlowInit', 'byoUploadFlowPush', 'byoUploadFlowFinalize', 'byoUploadFlowAbort',
]);

// C5: provider-integrated streaming ops (Phase 3d) need a longer ceiling than
// the crypto-only ops above because they own a real HTTP request per call.
const STREAMING_OPS = new Set([
  'byoStreamUploadInit', 'byoStreamUploadPush', 'byoStreamUploadFinalize', 'byoStreamUploadAbort',
  'byoStreamDownloadInit', 'byoStreamDownloadPull', 'byoStreamDownloadClose',
  'byoCrossProviderStreamCopy',
]);

// ── Initialization ─────────────────────────────────────────────────────────

/**
 * Initialize the BYO crypto worker.
 * Must be called before any crypto operations.
 * @param timeoutMs - Maximum time to wait for worker initialization (default 10000ms)
 */
export async function initByoWorker(timeoutMs: number = 10000): Promise<void> {
  if (worker && workerReady) return;
  if (initPromise) return initPromise;

  initPromise = new Promise<void>((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new Error(`BYO worker initialization timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    try {
      worker = new Worker(new URL('./byo.worker.ts', import.meta.url), { type: 'module' });

      worker.onerror = (event) => {
        clearTimeout(timeoutId);
        console.error('[byoWorkerClient] Worker error:', event);
        if (!workerReady) {
          reject(new Error('Failed to initialize BYO worker'));
        }
      };

      worker.onmessage = (event) => {
        const { id, success, result, error } = event.data;

        const pending = pendingRequests.get(id);
        if (!pending) {
          console.error('[byoWorkerClient] No pending request for id:', id);
          return;
        }

        pendingRequests.delete(id);

        if (success) {
          pending.resolve(result);
        } else {
          pending.reject(new Error(error || 'Unknown worker error'));
        }
      };

      workerReady = true;
      clearTimeout(timeoutId);
      startHealthCheck();
      resolve();
    } catch (err) {
      clearTimeout(timeoutId);
      reject(err);
    }
  });

  return initPromise;
}

// ── Health check / session timeout ─────────────────────────────────────────

function startHealthCheck(): void {
  resetSessionTimeout();
}

function resetSessionTimeout(): void {
  if (sessionTimeoutId) clearTimeout(sessionTimeoutId);
  sessionTimeoutId = setTimeout(() => {
    onSessionTimeout().catch((e) => console.warn('[byoWorkerClient] session timeout cleanup:', e));
  }, SESSION_TIMEOUT_MS);
}

/**
 * Complete teardown on idle timeout: wipe every worker-held registry, clear
 * the WASM-side SFTP credential store, then terminate the worker so the next
 * operation re-inits with a fresh heap. A compromised main thread that
 * outlives the timeout therefore cannot reuse any cached handle to exfiltrate
 * data.
 */
async function onSessionTimeout(): Promise<void> {
  if (worker && workerReady) {
    await sendRequest({ type: 'clearAll' }).catch(() => {});
  }
  // WASM-held SFTP credentials (separate heap from the worker).
  try {
    await sftpClearAllCredentials();
  } catch {
    /* best effort */
  }
  // Terminate and reset — next initByoWorker() call boots a clean worker.
  if (worker) {
    worker.terminate();
  }
  worker = null;
  workerReady = false;
  initPromise = null;
  pendingRequests.clear();
  if (sessionTimeoutId) {
    clearTimeout(sessionTimeoutId);
    sessionTimeoutId = null;
  }
}

// ── Request dispatch ───────────────────────────────────────────────────────

function sendRequest<T>(request: Record<string, unknown>, transfer?: Transferable[]): Promise<T> {
  if (!worker) {
    return Promise.reject(new Error('BYO worker not initialized. Call initByoWorker() first.'));
  }

  const id = requestId++;
  const opType = request.type as string;
  const timeoutMs = STREAMING_OPS.has(opType)
    ? STREAMING_TIMEOUT_MS
    : ENCRYPT_DECRYPT_OPS.has(opType)
      ? ENCRYPT_DECRYPT_TIMEOUT_MS
      : KEY_OP_TIMEOUT_MS;

  const workerPromise = new Promise<T>((resolve, reject) => {
    pendingRequests.set(id, { resolve, reject } as any);

    const message: any = { id, request };
    if (transfer && transfer.length > 0) {
      worker!.postMessage(message, transfer);
    } else {
      worker!.postMessage(message);
    }
  });

  // Apply timeout
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => {
      pendingRequests.delete(id);
      reject(new Error(`Worker request timed out after ${timeoutMs}ms: ${request.type}`));
    }, timeoutMs);
  });

  // Reset session timeout on activity
  resetSessionTimeout();

  return Promise.race([workerPromise, timeoutPromise]);
}

// ── Key management ─────────────────────────────────────────────────────────

// W2: a previous `storeKeys` export transmitted raw ML-KEM + X25519 private
// key bytes as a JSON number array over postMessage. BYO never called it —
// private keys are loaded through the vault-session path where they stay
// inside WASM — and exporting it left a path for third-party consumers of
// `@wattcloud/sdk` to send raw key material through the main thread.
// The function has been removed; the worker op `storeKeys` is still handled
// (managed-mode CryptoBridge uses it), but BYO clients must go through the
// byoLoadKeys path.

/**
 * Check whether keys have been loaded for a session.
 */
export async function hasKeys(sessionId: string): Promise<boolean> {
  return sendRequest({ type: 'hasKeys', sessionId });
}

/**
 * Clear keys for a specific session, or all sessions if no sessionId provided.
 */
export async function clearKeys(sessionId?: string): Promise<void> {
  await sendRequest({ type: 'clearKeys', sessionId });
}

// ── V7 streaming encrypt ──────────────────────────────────────────────────

/**
 * Create a new V7 streaming encrypt session.
 * Returns a session ID for subsequent operations.
 */
export function newV7EncryptSession(): string {
  return crypto.randomUUID();
}

/**
 * Open a V7 encrypt session with the given public keys.
 * KEM encapsulation runs in the worker — content_key never leaves WASM.
 */
export async function openV7EncryptStream(sessionId: string, publicKeysJson: string): Promise<void> {
  await sendRequest({ type: 'v7EncryptInit', sessionId, publicKeysJson });
}

/**
 * Take the 1709-byte V7 header. Must be called exactly once per session,
 * before the first push (or at any point before finalize).
 */
export async function takeV7EncryptHeader(sessionId: string): Promise<Uint8Array> {
  const result = await sendRequest<ArrayBuffer>({ type: 'v7EncryptTakeHeader', sessionId });
  return new Uint8Array(result);
}

/**
 * Push plaintext through the encryptor. Returns a ciphertext frame.
 * The frame is [chunk_len_le32(4) || nonce(12) || ciphertext+gcm_tag].
 */
export async function pushV7EncryptStream(sessionId: string, plaintext: Uint8Array): Promise<Uint8Array> {
  const result = await sendRequest<ArrayBuffer>(
    { type: 'v7EncryptPush', sessionId, plaintext },
    [plaintext.buffer],
  );
  return new Uint8Array(result);
}

/**
 * Finalize the encryptor. Returns the 32-byte HMAC footer.
 * The session is destroyed after this call — content_key is zeroized.
 */
export async function closeV7EncryptStream(sessionId: string): Promise<Uint8Array> {
  const result = await sendRequest<ArrayBuffer>({ type: 'v7EncryptFinalize', sessionId });
  return new Uint8Array(result);
}

/**
 * Abort the encryptor and zeroize all key material.
 * Call this on error paths before finalize.
 */
export async function abortV7EncryptStream(sessionId: string): Promise<void> {
  await sendRequest({ type: 'v7EncryptAbort', sessionId });
}

// ── V7 streaming decrypt ───────────────────────────────────────────────────

/**
 * Create a new V7 streaming decrypt session.
 * Returns a session ID for subsequent operations.
 */
export function newV7StreamSession(): string {
  return crypto.randomUUID();
}

/**
 * Open a V7 decrypt session. Parses the 1709-byte header and decapsulates
 * the KEM ciphertext to derive the content_key. The header_end offset
 * indicates where body data begins (always 1709 for current format).
 */
export async function openV7Stream(
  sessionId: string,
  headerBytes: Uint8Array,
  secKeysJson: string,
  keySessionId?: string,
): Promise<{ headerEnd: number }> {
  return sendRequest(
    { type: 'v7DecryptInit', sessionId, headerBytes: headerBytes.buffer, secKeysJson, keySessionId },
    [headerBytes.buffer],
  );
}

/**
 * Push ciphertext through the decryptor. Returns plaintext bytes.
 * May return empty Uint8Array if the input doesn't complete a chunk.
 */
export async function pushV7Stream(sessionId: string, data: Uint8Array): Promise<Uint8Array> {
  const result = await sendRequest<ArrayBuffer>(
    { type: 'v7DecryptPush', sessionId, data: data.buffer },
    [data.buffer],
  );
  return new Uint8Array(result);
}

/**
 * Finalize the decryptor. Verifies the HMAC footer.
 * Throws on HMAC mismatch — the entire download is considered invalid.
 */
export async function closeV7Stream(sessionId: string, storedHmac: Uint8Array): Promise<void> {
  await sendRequest(
    { type: 'v7DecryptFinalize', sessionId, storedHmac: storedHmac.buffer },
    [storedHmac.buffer],
  );
}

/**
 * Abort the decryptor and zeroize all key material.
 */
export async function abortV7Stream(sessionId: string): Promise<void> {
  await sendRequest({ type: 'v7DecryptAbort', sessionId });
}

// ── Atomic filename encryption ──────────────────────────────────────────────

/**
 * Encrypt a filename (and optionally metadata) atomically.
 * Generates a fresh 32-byte filename key inside WASM, encrypts the filename
 * and metadata, and wraps the key as a V7 blob — all in one call.
 * The filename key is zeroized before this call returns.
 */
export async function encryptFilenameAtomic(
  filename: string,
  publicKeysJson: string,
  metadata?: string | null,
): Promise<{ encrypted_filename: string; encrypted_metadata: string | null; encrypted_filename_key: string }> {
  return sendRequest({
    type: 'encryptFilenameAtomic',
    filename,
    metadata: metadata ?? null,
    publicKeysJson,
  });
}

/**
 * Decrypt a single filename stored in the BYO vault.
 * Uses the private keys stored in the worker under sessionId.
 * @param encryptedFilenameB64 - Base64 AES-GCM-SIV ciphertext
 * @param encryptedFilenameKeyB64 - Base64 V7-format KEM-wrapped symmetric key
 * @param sessionId - Worker session that holds the private keys
 */
export async function byoDecryptFilename(
  encryptedFilenameB64: string,
  encryptedFilenameKeyB64: string,
  sessionId: string,
): Promise<{ filename: string }> {
  return sendRequest({
    type: 'byoDecryptFilename',
    encryptedFilenameB64,
    encryptedFilenameKeyB64,
    sessionId,
  });
}

// ── BYO vault operations ───────────────────────────────────────────────────

/** Parse a BYO vault header from raw bytes. */
export async function byoParseVaultHeader(vaultBytes: Uint8Array): Promise<any> {
  return sendRequest({ type: 'byoParseVaultHeader', vaultBytes: vaultBytes.buffer });
}

/** Derive BYO vault keys (vault_kek, client_kek_half) from passphrase. */
export async function byoDeriveVaultKeys(
  password: string,
  saltB64: string,
  memoryKb: number,
  iterations: number,
  parallelism: number,
): Promise<{ vault_kek: string; client_kek_half: string; argon_output: string }> {
  return sendRequest({
    type: 'byoDeriveVaultKeys',
    password,
    saltB64,
    memoryKb,
    iterations,
    parallelism,
  });
}

/** Unwrap vault_key from passphrase or recovery slot. */
export async function byoUnwrapVaultKey(
  wrapIvB64: string,
  wrappedKeyB64: string,
  unwrappingKeyB64: string,
): Promise<{ vault_key: string }> {
  return sendRequest({ type: 'byoUnwrapVaultKey', wrapIvB64, wrappedKeyB64, unwrappingKeyB64 });
}

/** Derive KEK from client_kek_half and shard. */
export async function byoDeriveKek(
  clientKekHalfB64: string,
  shardB64: string,
): Promise<{ kek: string }> {
  return sendRequest({ type: 'byoDeriveKek', clientKekHalfB64, shardB64 });
}

/** Derive recovery_vault_kek from recovery key. */
export async function byoDeriveRecoveryVaultKek(
  recoveryKeyB64: string,
): Promise<{ recovery_vault_kek: string }> {
  return sendRequest({ type: 'byoDeriveRecoveryVaultKek', recoveryKeyB64 });
}

/** Compute header HMAC for integrity verification. */
export async function byoComputeHeaderHmac(
  vaultKeyB64: string,
  headerPrefixB64: string,
): Promise<{ hmac: string }> {
  return sendRequest({ type: 'byoComputeHeaderHmac', vaultKeyB64, headerPrefixB64 });
}

/** Verify header HMAC using constant-time comparison. */
export async function byoVerifyHeaderHmac(
  vaultKeyB64: string,
  headerPrefixB64: string,
  expectedHmacB64: string,
): Promise<{ valid: boolean }> {
  return sendRequest({ type: 'byoVerifyHeaderHmac', vaultKeyB64, headerPrefixB64, expectedHmacB64 });
}

/** Wrap vault_key with a wrapping key (passphrase slot or recovery slot). */
export async function byoWrapVaultKey(
  vaultKeyB64: string,
  wrappingKeyB64: string,
): Promise<{ wrap_iv: string; wrapped_key: string }> {
  return sendRequest({ type: 'byoWrapVaultKey', vaultKeyB64, wrappingKeyB64 });
}

/**
 * Request a one-time token required for vault write (byoEncryptVaultBody).
 * Call this immediately before byoEncryptVaultBody; tokens expire after 30 s.
 * In UI code this call should be gated behind a user-initiated action so that
 * XSS alone cannot silently overwrite vault content.
 */
export async function byoRequestDestructiveToken(): Promise<string> {
  const res = await sendRequest({ type: 'byoRequestDestructiveToken' }) as { token: string };
  return res.token;
}

/** Encrypt vault body (SQLite bytes) with vault_key. Requires a valid opToken. */
export async function byoEncryptVaultBody(
  sqliteBytes: Uint8Array,
  vaultKeyB64: string,
  opToken: string,
): Promise<{ body_iv: string; body_ciphertext: string }> {
  return sendRequest({ type: 'byoEncryptVaultBody', sqliteBytes: sqliteBytes.buffer, vaultKeyB64, opToken });
}

/** Decrypt vault body with vault_key. */
export async function byoDecryptVaultBody(
  bodyIv: Uint8Array,
  bodyCiphertext: Uint8Array,
  vaultKeyB64: string,
): Promise<{ sqlite_bytes: string }> {
  // Combine nonce(12) || ciphertext into a single buffer for the worker
  const nonceAndCt = new Uint8Array(bodyIv.length + bodyCiphertext.length);
  nonceAndCt.set(bodyIv, 0);
  nonceAndCt.set(bodyCiphertext, bodyIv.length);
  return sendRequest({ type: 'byoDecryptVaultBody', nonceAndCt: nonceAndCt.buffer, vaultKeyB64 });
}

/** Generate random vault keys for new vault creation. */
export async function byoGenerateVaultKeys(): Promise<{
  vault_key: string;
  shard: string;
  vault_id: string;
  master_salt: string;
}> {
  return sendRequest({ type: 'byoGenerateVaultKeys' });
}

// ── BYO enrollment operations ──────────────────────────────────────────────

/** Initiate a new enrollment: generate ephemeral X25519 keypair + channel ID. */
export async function byoEnrollmentInitiate(): Promise<any> {
  return sendRequest({ type: 'byoEnrollmentInitiate' });
}

/** Derive session keys from ephemeral secret key, peer public key, and channel ID. */
export async function byoEnrollmentDeriveSession(
  ephSkB64: string,
  peerPkB64: string,
  channelIdB64: string,
): Promise<any> {
  return sendRequest({ type: 'byoEnrollmentDeriveSession', ephSkB64, peerPkB64, channelIdB64 });
}

/** Encrypt shard for transfer to new device. */
export async function byoEnrollmentEncryptShard(
  shardB64: string,
  encKeyB64: string,
  macKeyB64: string,
): Promise<any> {
  return sendRequest({ type: 'byoEnrollmentEncryptShard', shardB64, encKeyB64, macKeyB64 });
}

/** Decrypt shard received from existing device. */
export async function byoEnrollmentDecryptShard(
  envelopeB64: string,
  encKeyB64: string,
  macKeyB64: string,
): Promise<any> {
  return sendRequest({ type: 'byoEnrollmentDecryptShard', envelopeB64, encKeyB64, macKeyB64 });
}

// ── Enrollment session API (ZK-safe) ──────────────────────────────────────
// eph_sk, enc_key, mac_key, and received_shard are stored in WASM heap.
// JS only sees an opaque sessionId plus the shard at the WebCrypto step.

/** Open an enrollment channel. Returns { ephPkB64, channelIdB64, sessionId }. */
export async function byoEnrollmentOpen(): Promise<{ ephPkB64: string; channelIdB64: string; sessionId: number }> {
  return sendRequest({ type: 'byoEnrollmentOpen' });
}

/** Open an enrollment session for the JOINING device, reusing the
 *  initiator's channel ID from the QR. The two sides MUST agree on
 *  channel_id — it's mixed into the SAS HKDF info, so a freshly-minted
 *  channel_id on the joiner produces a different SAS code than the
 *  initiator's. Returns { ephPkB64, sessionId }. */
export async function byoEnrollmentJoin(channelIdB64: string): Promise<{ ephPkB64: string; sessionId: number }> {
  return sendRequest({ type: 'byoEnrollmentJoin', channelIdB64 });
}

/** Derive session keys from peer public key. Returns { sasCode }. */
export async function byoEnrollmentDeriveKeys(
  sessionId: number,
  peerPkB64: string,
): Promise<{ sasCode: number }> {
  return sendRequest({ type: 'byoEnrollmentDeriveKeys', sessionId, peerPkB64 });
}

/** Encrypt a shard for transfer using session keys. Returns { envelopeB64 }. */
export async function byoEnrollmentSessionEncryptShard(
  sessionId: number,
  shardB64: string,
): Promise<{ envelopeB64: string }> {
  return sendRequest({ type: 'byoEnrollmentSessionEncryptShard', sessionId, shardB64 });
}

/** Decrypt a shard from an envelope and store it in the session. */
export async function byoEnrollmentSessionDecryptShard(
  sessionId: number,
  envelopeB64: string,
): Promise<void> {
  await sendRequest({ type: 'byoEnrollmentSessionDecryptShard', sessionId, envelopeB64 });
}

/**
 * Consume and return the shard stored in the session.
 * The shard briefly appears in JS only for the WebCrypto device-slot encryption
 * step (accepted exception: non-extractable CryptoKey cannot be used from WASM).
 */
export async function byoEnrollmentSessionGetShard(
  sessionId: number,
): Promise<{ shardB64: string }> {
  return sendRequest({ type: 'byoEnrollmentSessionGetShard', sessionId });
}

/**
 * Encrypt a variable-length payload (e.g. a ProviderConfig JSON) using the
 * session keys. Payload must be ≤ 64 KiB. Returns `{ envelopeB64 }`.
 *
 * Used by the source device of an enrollment to ship the primary provider
 * config to the receiver alongside the shard, so the receiver does not have
 * to re-type provider credentials from scratch on first link.
 */
export async function byoEnrollmentSessionEncryptPayload(
  sessionId: number,
  payloadB64: string,
): Promise<{ envelopeB64: string }> {
  return sendRequest({ type: 'byoEnrollmentSessionEncryptPayload', sessionId, payloadB64 });
}

/** Decrypt a payload envelope using the session keys. Returns `{ payloadB64 }`. */
export async function byoEnrollmentSessionDecryptPayload(
  sessionId: number,
  envelopeB64: string,
): Promise<{ payloadB64: string }> {
  return sendRequest({ type: 'byoEnrollmentSessionDecryptPayload', sessionId, envelopeB64 });
}

/** Close and zeroize an enrollment session. */
export async function byoEnrollmentClose(sessionId: number): Promise<void> {
  await sendRequest({ type: 'byoEnrollmentClose', sessionId });
}

// ── SFTP credential registry ───────────────────────────────────────────────
// Credentials are stored inside the main-thread WASM heap (not in this
// worker, and not as JS strings). The functions below delegate to the
// sdk-wasm exports `sftp_store_credential_password`,
// `sftp_store_credential_publickey`, `sftp_clear_credential`, and
// `sftp_clear_all_credentials`. SftpSessionWasm reads the credential by
// handle via `auth_with_handle` — the plaintext never crosses the postMessage
// boundary back to the main thread, and it is never written to the worker's
// heap in the first place.

type WasmSftpModule = {
  sftp_store_credential_password: (password: string) => number;
  sftp_store_credential_publickey: (privateKey: string, passphrase?: string) => number;
  sftp_clear_credential: (handle: number) => void;
  sftp_clear_all_credentials: () => void;
};

async function wasm(): Promise<WasmSftpModule> {
  // Main-thread WASM needs its own init — the worker's initWasm() doesn't
  // propagate here. See mainWasm.ts for the full explanation.
  const { ensureMainThreadWasm } = await import('../mainWasm');
  return (await ensureMainThreadWasm()) as unknown as WasmSftpModule;
}

/** Store an SFTP password in the main-thread WASM heap. Returns an opaque handle. */
export async function sftpStoreCredential(
  password?: string,
  privateKey?: string,
  passphrase?: string,
): Promise<number> {
  const m = await wasm();
  if (password !== undefined) return m.sftp_store_credential_password(password);
  if (privateKey !== undefined) return m.sftp_store_credential_publickey(privateKey, passphrase);
  throw new Error('sftpStoreCredential: must provide password or privateKey');
}

/** Remove a single SFTP credential from the WASM registry. */
export async function sftpClearCredential(credHandle: number): Promise<void> {
  const m = await wasm();
  m.sftp_clear_credential(credHandle);
}

/** Remove ALL SFTP credentials from the WASM registry (call on vault lock). */
export async function sftpClearAllCredentials(): Promise<void> {
  const m = await wasm();
  m.sftp_clear_all_credentials();
}

/**
 * Wipe every worker-held secret registry on vault lock (F1).
 *
 * Clears the key bundle map, the provider `configRegistry` (HTTP-provider
 * credentials — OAuth tokens, WebDAV/SFTP passwords, S3 secrets held inside
 * encrypted manifest `config_json` strings), and pending OAuth PKCE
 * verifiers. Unlike `onSessionTimeout` this does NOT terminate the worker,
 * so the vault can be re-unlocked without reinitialising WASM. Complements
 * `sftpClearAllCredentials` which clears the separate WASM-side SFTP store.
 */
export async function byoClearAllWorkerState(): Promise<void> {
  await sendRequest({ type: 'clearAll' });
}

// ── OAuth PKCE verifier registry ───────────────────────────────────────────
// Verifiers are stored in the worker (isolated from main-thread XSS).

/** Begin an OAuth PKCE flow. Generates verifier+state in the worker. Returns {state, authUrl}. */
export async function oauthBeginFlow(
  providerType: string,
  clientId: string,
  redirectUri: string,
): Promise<{ state: string; authUrl: string }> {
  return sendRequest({ type: 'oauthBeginFlow', providerType, clientId, redirectUri });
}

/** Build the token exchange form body. Worker looks up the verifier by state and drops it. */
export async function oauthBuildExchangeForm(
  state: string,
  code: string,
): Promise<{ formBody: string }> {
  return sendRequest({ type: 'oauthBuildExchangeForm', state, code });
}

/** Discard a pending OAuth flow (popup cancelled, timeout, or error). */
export async function oauthAbortFlow(state: string): Promise<void> {
  await sendRequest({ type: 'oauthAbortFlow', state });
}

// ── Per-device signing keys (v2 vault) ────────────────────────────────────

/** Generate a fresh Ed25519 key pair for a device slot. */
export async function byoGenerateDeviceSigningKey(): Promise<{ publicKey: string; seed: string }> {
  return sendRequest({ type: 'byoGenerateDeviceSigningKey' }) as Promise<{ publicKey: string; seed: string }>;
}

/** Seal an Ed25519 seed into a device slot. Returns base64 wrapped (48 bytes). */
export async function byoSealDeviceSigningKey(
  vaultKeyB64: string,
  deviceIdB64: string,
  seedB64: string,
): Promise<string> {
  const res = await sendRequest({ type: 'byoSealDeviceSigningKey', vaultKeyB64, deviceIdB64, seedB64 }) as { wrapped: string };
  return res.wrapped;
}

/** Unseal an Ed25519 seed from a device slot. Returns base64 seed (32 bytes). */
export async function byoUnsealDeviceSigningKey(
  vaultKeyB64: string,
  deviceIdB64: string,
  wrappedB64: string,
): Promise<string> {
  const res = await sendRequest({ type: 'byoUnsealDeviceSigningKey', vaultKeyB64, deviceIdB64, wrappedB64 }) as { seed: string };
  return res.seed;
}

/** Sign a message (base64) with an Ed25519 seed (base64). Returns base64 signature (64 bytes). */
export async function byoEd25519Sign(seedB64: string, messageB64: string): Promise<string> {
  const res = await sendRequest({ type: 'byoEd25519Sign', seedB64, messageB64 }) as { signature: string };
  return res.signature;
}

/** Verify an Ed25519 signature. Returns true if valid. */
export async function byoEd25519Verify(
  publicKeyB64: string,
  messageB64: string,
  signatureB64: string,
): Promise<boolean> {
  const res = await sendRequest({ type: 'byoEd25519Verify', publicKeyB64, messageB64, signatureB64 }) as { valid: boolean };
  return res.valid;
}

/** Migrate a v1 vault file to v2. Returns migrated bytes (unchanged if already v2). */
export async function byoMigrateVaultV1ToV2(vaultBytes: Uint8Array, vaultKeyB64: string): Promise<Uint8Array> {
  return sendRequest({ type: 'byoMigrateVaultV1ToV2', vaultBytes, vaultKeyB64 }) as Promise<Uint8Array>;
}

// ── OAuth / PKCE ───────────────────────────────────────────────────────────

/** Generate a PKCE code_verifier + code_challenge pair (RFC 7636). */
export async function generatePkce(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  return sendRequest({ type: 'generatePkce' });
}
/**
 * Compute the V7 ciphertext size for a plaintext of `plaintextLen` bytes
 * using `chunkSize`-byte chunks. Delegates to sdk-core's `v7_cipher_size`.
 */
export async function v7CipherSize(plaintextLen: number, chunkSize: number): Promise<number> {
  const result = await sendRequest({ type: 'v7CipherSize', plaintextLen, chunkSize });
  return (result as { size: number }).size;
}

/** Get the static OAuth config for a provider type (null for non-OAuth providers). */
export async function providerOAuthConfig(
  providerType: string,
): Promise<{ authUrl: string; tokenUrl: string; scope: string; extraAuthParams: Array<{ key: string; value: string }> } | null> {
  return sendRequest({ type: 'providerOAuthConfig', providerType });
}

/** Build the OAuth2 authorization URL (includes PKCE challenge and state). */
export async function buildAuthUrl(
  providerType: string,
  clientId: string,
  redirectUri: string,
  state: string,
  codeChallenge: string,
): Promise<string> {
  return sendRequest({ type: 'buildAuthUrl', providerType, clientId, redirectUri, state, codeChallenge });
}

/** Build the application/x-www-form-urlencoded body for the authorization_code grant. */
export async function buildTokenExchangeForm(
  code: string,
  codeVerifier: string,
  redirectUri: string,
  clientId: string,
): Promise<string> {
  return sendRequest({ type: 'buildTokenExchangeForm', code, codeVerifier, redirectUri, clientId });
}

/** Build the application/x-www-form-urlencoded body for the refresh_token grant. */
export async function buildRefreshForm(refreshToken: string, clientId: string): Promise<string> {
  return sendRequest({ type: 'buildRefreshForm', refreshToken, clientId });
}

/** Parse a JSON OAuth token response body. */
export async function parseTokenResponse(
  body: Uint8Array,
): Promise<{ accessToken: string; refreshToken?: string; expiresIn?: number }> {
  return sendRequest({ type: 'parseTokenResponse', body });
}

/** Create a new FooterTrimmer session in the worker. */
export async function footerTrimmerNew(trimId: string, keep: number): Promise<void> {
  return sendRequest({ type: 'footerTrimmerNew', trimId, keep });
}

/** Push ciphertext bytes; returns bytes safe to pass to the V7 decryptor. */
export async function footerTrimmerPush(trimId: string, bytes: Uint8Array): Promise<Uint8Array> {
  return sendRequest({ type: 'footerTrimmerPush', trimId, bytes });
}

/** Finalize the trimmer. Returns { body: Uint8Array, footer: Uint8Array }. */
export async function footerTrimmerFinalize(
  trimId: string,
): Promise<{ body: Uint8Array; footer: Uint8Array }> {
  return sendRequest({ type: 'footerTrimmerFinalize', trimId });
}

/** Abort/discard a FooterTrimmer session without finalizing. */
export async function footerTrimmerAbort(trimId: string): Promise<void> {
  return sendRequest({ type: 'footerTrimmerAbort', trimId });
}

// ── BYO download flow (Phase 2) ────────────────────────────────────────────
//
// Single-session replacement for openV7Stream + footerTrimmerNew + footerTrimmerPush
// + footerTrimmerFinalize + closeV7Stream. The caller feeds raw provider bytes;
// header buffering, footer trimming, and HMAC verification are all internal.

/**
 * Open a new BYO download flow session.
 *
 * Keys are resolved from `keySessionId` (defaults to `sessionId`).
 * The flow handles V7 header buffering, HMAC footer separation, and AES-GCM decryption.
 */
export async function byoDownloadFlowInit(
  sessionId: string,
  keySessionId?: string,
): Promise<void> {
  return sendRequest({ type: 'byoDownloadFlowInit', sessionId, keySessionId });
}

/**
 * Feed raw ciphertext bytes to a download flow session.
 *
 * Returns a Uint8Array of any plaintext now available (may be empty if still
 * buffering the header or if no complete AES-GCM frames are ready yet).
 */
export async function byoDownloadFlowPush(
  sessionId: string,
  data: ArrayBuffer,
): Promise<ArrayBuffer> {
  const res = await sendRequest<{ plaintext: ArrayBuffer }>({ type: 'byoDownloadFlowPush', sessionId, data }, [data]);
  return res.plaintext;
}

/**
 * Finalize a download flow session and verify the HMAC footer.
 *
 * Throws if the HMAC does not match. Any plaintext already emitted by
 * `byoDownloadFlowPush` must be discarded if this throws.
 */
export async function byoDownloadFlowFinalize(sessionId: string): Promise<void> {
  return sendRequest({ type: 'byoDownloadFlowFinalize', sessionId });
}

/** Abort a download flow session without verifying the HMAC. */
export async function byoDownloadFlowAbort(sessionId: string): Promise<void> {
  return sendRequest({ type: 'byoDownloadFlowAbort', sessionId });
}

// ── BYO upload flow (Phase 2) ──────────────────────────────────────────────
//
// Single-session replacement for openV7EncryptStream + takeV7EncryptHeader
// + pushV7EncryptStream + closeV7EncryptStream. Init returns the V7 header bytes
// and the total ciphertext size; push returns the encrypted wire frame.

/**
 * Open a new BYO upload flow session.
 *
 * Returns the 1709-byte V7 header to upload as the first bytes, and
 * `totalSize` (the exact full ciphertext length) for the provider's
 * `Content-Length` header.
 *
 * `plaintextLen` must be the exact number of plaintext bytes that will be
 * pushed. Passing a wrong value does not cause a security failure but will
 * make `totalSize` wrong, causing provider upload errors.
 *
 * `chunkSize` is the exact non-final chunk size enforced by the WASM flow
 * (currently 524288 bytes / 512 KiB). Always slice plaintext at this boundary
 * rather than using a local constant to avoid drift.
 */
export async function byoUploadFlowInit(
  sessionId: string,
  publicKeysJson: string,
  plaintextLen: number,
): Promise<{ header: ArrayBuffer; totalSize: number; chunkSize: number }> {
  return sendRequest({ type: 'byoUploadFlowInit', sessionId, publicKeysJson, plaintextLen });
}

/**
 * Encrypt one plaintext chunk and return the V7 wire frame.
 *
 * Non-final chunks must be exactly `V7_ENCRYPT_CHUNK_SIZE` (512 KiB).
 * The final chunk (`isLast = true`) may be any length including zero.
 *
 * The returned `ArrayBuffer` is a Transferable — it is transferred from
 * the worker heap to the caller without copying.
 */
export async function byoUploadFlowPush(
  sessionId: string,
  plaintext: ArrayBuffer,
  isLast: boolean,
): Promise<ArrayBuffer> {
  const res = await sendRequest<{ frame: ArrayBuffer }>({ type: 'byoUploadFlowPush', sessionId, plaintext, isLast }, [plaintext]);
  return res.frame;
}

/**
 * Finalise a BYO upload flow session.
 *
 * Returns the 32-byte HMAC footer to upload as the very last bytes,
 * then close the provider stream.
 */
export async function byoUploadFlowFinalize(sessionId: string): Promise<ArrayBuffer> {
  const res = await sendRequest<{ footer: ArrayBuffer }>({ type: 'byoUploadFlowFinalize', sessionId });
  return res.footer;
}

/** Abort an upload flow session without finalizing. */
export async function byoUploadFlowAbort(sessionId: string): Promise<void> {
  return sendRequest({ type: 'byoUploadFlowAbort', sessionId });
}

// ── Relay auth / PoW ───────────────────────────────────────────────────────

/**
 * Derive the SFTP relay cookie purpose for a given host and port.
 * Returns "sftp:<32 lowercase hex chars>".
 */
export async function byoDeriveSftpPurpose(host: string, port: number): Promise<string> {
  return sendRequest({ type: 'byoDeriveSftpPurpose', host, port });
}

/**
 * Derive the enrollment relay cookie purpose for a given channel ID.
 * Returns "enroll:<channelId>".
 */
export async function byoDeriveEnrollmentPurpose(channelId: string): Promise<string> {
  return sendRequest({ type: 'byoDeriveEnrollmentPurpose', channelId });
}

/**
 * Solve the PoW challenge in the Web Worker.
 * Returns { answer: number } — the answer that satisfies the difficulty target.
 * Runs synchronously in WASM; runs in the Worker so the main thread stays responsive.
 */
export async function byoSolveRelayPow(
  nonceHex: string,
  purpose: string,
  difficulty: number,
): Promise<{ answer: number }> {
  return sendRequest({ type: 'byoSolveRelayPow', nonceHex, purpose, difficulty });
}

/**
 * Refresh an OAuth token via the Rust implementation.
 * Returns updated configJson with new access_token and optional refresh_token.
 * Only supported for gdrive, dropbox, onedrive. WebDAV uses static credentials.
 */
export async function byoRefreshToken(
  providerType: string,
  configJson: string,
): Promise<string> {
  return sendRequest({ type: 'byoRefreshToken', providerType, configJson });
}

// ── Config registry (R1.4) ────────────────────────────────────────────────

/**
 * Register a provider config in the worker's config registry.
 * Returns an opaque handle. The configJson (including credentials) never
 * returns to the main thread after this call.
 */
export async function byoInitConfig(configJson: string): Promise<string> {
  return sendRequest({ type: 'byoInitConfig', configJson });
}

/**
 * Remove a provider config from the worker registry, zeroising the entry.
 * Call on disconnect / provider removal.
 */
export async function byoReleaseConfig(configHandle: string): Promise<void> {
  await sendRequest({ type: 'byoReleaseConfig', configHandle });
}

/**
 * Refresh the OAuth token for a registered provider config.
 * The worker resolves the handle, calls the provider-specific refresh function,
 * and updates the registry entry. The refreshed credentials never leave the worker.
 */
export async function byoRefreshConfigByHandle(
  providerType: string,
  configHandle: string,
): Promise<void> {
  await sendRequest({ type: 'byoRefreshConfigByHandle', providerType, configHandle });
}

// ── Generic provider dispatcher (P8) ───────────────────────────────────────

/**
 * Generic StorageProvider operation dispatcher backed by the Rust WASM provider.
 *
 * - providerType: 'gdrive' | 'dropbox' | 'onedrive' | 'webdav' | 'box' | 'pcloud' | 's3'
 * - op: 'upload' | 'download' | 'list' | 'delete' | 'getVersion' |
 *       'createFolder' | 'deleteFolder' | 'createPublicLink' |
 *       'revokePublicLink' | 'createPresignedUrl'
 * - configHandle: opaque handle returned by byoInitConfig (credentials stay in worker)
 * - argsJson: JSON object with op-specific fields (NO config — worker injects from registry).
 *   For "upload": datab64 (base64 of bytes), name, ref? (null=new), expectedVersion?
 *   For "download": ref → result contains {datab64}
 *   For all others: see byo_providers.rs dispatch_op
 *
 * Returns a parsed JSON value (object, array, string, or null).
 */
export async function byoProviderCall(
  providerType: string,
  op: string,
  configHandle: string,
  argsJson: string,
): Promise<unknown> {
  return sendRequest({ type: 'byoProviderCall', providerType, op, configHandle, argsJson });
}

/**
 * Pipe a V7 ciphertext blob from one provider to another entirely inside WASM.
 * No ciphertext bytes cross the JS boundary.
 *
 * ZK-6: dstName MUST be an opaque blob path (data/{uuid}), never a plaintext filename.
 * Returns { ref, version } on success.
 */
/** Returns the number of chunks pushed in this upload session.
 *  Exposes no key material; use for "chunk N of M" progress instead of approximating bytes. */
export async function byoUploadFlowPosition(sessionId: string): Promise<number> {
  return sendRequest({ type: 'byoUploadFlowPosition', sessionId });
}

// ── Phase 3d: provider-integrated streaming sessions ──────────────────────────

/** Open a V7 upload stream session backed by a concrete Rust provider.
 *  Returns { sessionId, chunkSize } where chunkSize is V7_ENCRYPT_CHUNK_SIZE (512 KiB). */
export async function byoStreamUploadInit(
  pubKeysJson: string,
  providerType: string,
  configHandle: string,
  name: string,
  parentRef: string | null,
  plaintextLen: number,
): Promise<{ sessionId: string; chunkSize: number }> {
  return sendRequest({ type: 'byoStreamUploadInit', pubKeysJson, providerType, configHandle, name, parentRef, plaintextLen });
}

/** Encrypt one plaintext chunk and write the cipher frame to the provider.
 *  Nothing is returned — ciphertext stays inside WASM (ZK-5). */
export async function byoStreamUploadPush(
  sessionId: string,
  data: ArrayBuffer,
  isLast: boolean,
): Promise<void> {
  return sendRequest({ type: 'byoStreamUploadPush', sessionId, data, isLast }, [data]);
}

/** Write the HMAC footer, close the provider stream. Returns { ref, version }. */
export async function byoStreamUploadFinalize(
  sessionId: string,
): Promise<{ ref: string; version: string }> {
  return sendRequest({ type: 'byoStreamUploadFinalize', sessionId });
}

/** Abort an upload session. Drops the encryptor (zeroizes content_key). */
export async function byoStreamUploadAbort(sessionId: string): Promise<void> {
  return sendRequest({ type: 'byoStreamUploadAbort', sessionId });
}

/** Open a V7 download session backed by a concrete Rust provider. */
export async function byoStreamDownloadInit(
  secKeysJson: string,
  providerType: string,
  configHandle: string,
  ref_: string,
): Promise<string> {
  return sendRequest({ type: 'byoStreamDownloadInit', secKeysJson, providerType, configHandle, ref: ref_ });
}

/** Pull the next plaintext chunk. Returns null at EOF. */
export async function byoStreamDownloadPull(
  sessionId: string,
): Promise<Uint8Array | null> {
  return sendRequest({ type: 'byoStreamDownloadPull', sessionId });
}

/** Verify HMAC footer and close the download session.
 *  MUST return Ok before trusting any previously yielded plaintext. */
export async function byoStreamDownloadClose(sessionId: string): Promise<void> {
  return sendRequest({ type: 'byoStreamDownloadClose', sessionId });
}

export async function byoCrossProviderStreamCopy(
  srcType: string,
  srcConfigHandle: string,
  dstType: string,
  dstConfigHandle: string,
  srcRef: string,
  dstName: string,
  totalSize: number,
): Promise<{ ref: string; version: string }> {
  return sendRequest({
    type: 'byoCrossProviderStreamCopy',
    srcType, srcConfigHandle,
    dstType, dstConfigHandle,
    srcRef, dstName, totalSize,
  });
}

// ── Vault session API (ZK-safe) ────────────────────────────────────────────
//
// vault_key, client_kek_half, and kek are stored inside WASM heap and never
// returned to JS. Callers receive an opaque numeric session ID.

/**
 * Open a vault session: run Argon2id, derive vault_kek + client_kek_half,
 * unwrap vault_key, and store all key material in the WASM session registry.
 *
 * Returns an opaque session ID (number). Call `byoVaultClose(id)` when done.
 */
export async function byoVaultOpen(
  password: string,
  saltB64: string,
  memoryKb: number,
  iterations: number,
  parallelism: number,
  wrapIvB64: string,
  wrappedVaultKeyB64: string,
): Promise<number> {
  const res = await sendRequest<{ sessionId: number }>({
    type: 'byoVaultOpen',
    password,
    saltB64,
    memoryKb,
    iterations,
    parallelism,
    wrapIvB64,
    wrappedVaultKeyB64,
  });
  return res.sessionId;
}

/** Close a vault session and zeroize all key material. */
export async function byoVaultClose(sessionId: number): Promise<void> {
  await sendRequest({ type: 'byoVaultClose', sessionId });
}

/** Verify the vault header HMAC using the session vault_key. */
export async function byoVaultVerifyHeaderHmac(
  sessionId: number,
  headerPrefixB64: string,
  expectedHmacB64: string,
): Promise<{ valid: boolean }> {
  return sendRequest({ type: 'byoVaultVerifyHeaderHmac', sessionId, headerPrefixB64, expectedHmacB64 });
}

/**
 * Decrypt the vault body using the session vault_key.
 * `nonceAndCt` — `nonce(12) || ciphertext`.
 * Returns plaintext SQLite bytes.
 */
export async function byoVaultDecryptBody(
  sessionId: number,
  nonceAndCt: Uint8Array,
): Promise<Uint8Array> {
  const result = await sendRequest<ArrayBuffer>(
    { type: 'byoVaultDecryptBody', sessionId, nonceAndCt: nonceAndCt.buffer },
    [nonceAndCt.buffer],
  );
  return new Uint8Array(result);
}

/**
 * Encrypt the vault body using the session vault_key. Requires a valid opToken.
 * Returns `{ body_iv, body_ciphertext }` as base64.
 */
export async function byoVaultEncryptBody(
  sessionId: number,
  sqliteBytes: Uint8Array,
  opToken: string,
): Promise<{ body_iv: string; body_ciphertext: string }> {
  return sendRequest(
    { type: 'byoVaultEncryptBody', sessionId, sqliteBytes: sqliteBytes.buffer, opToken },
    [sqliteBytes.buffer],
  );
}

/** Compute the vault header HMAC using the session vault_key. Returns base64 HMAC. */
export async function byoVaultComputeHeaderHmac(
  sessionId: number,
  headerPrefixB64: string,
): Promise<{ hmac: string }> {
  return sendRequest({ type: 'byoVaultComputeHeaderHmac', sessionId, headerPrefixB64 });
}

/**
 * Derive the BYO KEK from client_kek_half + shard and store it in the session.
 * Must be called before `byoVaultLoadKeys`.
 */
export async function byoVaultDeriveKek(sessionId: number, shardB64: string): Promise<void> {
  await sendRequest({ type: 'byoVaultDeriveKek', sessionId, shardB64 });
}

/**
 * Decrypt ML-KEM and X25519 private keys using the session KEK, then store them
 * in the worker's key registry under `keySessionId`.
 * Private key bytes never reach the main thread — they transit within the worker only.
 */
export async function byoVaultLoadKeys(
  sessionId: number,
  mlkemSkEncrypted: Uint8Array,
  x25519SkEncrypted: Uint8Array,
  keySessionId: string,
): Promise<void> {
  await sendRequest(
    {
      type: 'byoVaultLoadKeys',
      sessionId,
      mlkemSkEncrypted: mlkemSkEncrypted.buffer,
      x25519SkEncrypted: x25519SkEncrypted.buffer,
      keySessionId,
    },
    [mlkemSkEncrypted.buffer, x25519SkEncrypted.buffer],
  );
}

/**
 * Derive a 32-byte subkey from the session vault_key using HKDF-SHA256.
 * `purpose` is the HKDF info string (e.g. "SecureCloud BYO WAL v1").
 * Callers use the returned bytes as raw key material for a non-extractable CryptoKey.
 * vault_key itself never leaves WASM.
 */
export async function byoVaultDeriveSubkey(sessionId: number, purpose: string): Promise<Uint8Array> {
  const result = await sendRequest<ArrayBuffer>({ type: 'byoVaultDeriveSubkey', sessionId, purpose });
  return new Uint8Array(result);
}

/**
 * Generate a fresh hybrid keypair inside the worker and return the public
 * halves as base64 alongside the private halves AES-GCM-wrapped under
 * `HKDF(vault_key, "SecureCloud BYO key_versions wrap v1")`. Raw private key
 * bytes never cross the worker→main boundary.
 */
export async function byoVaultGenerateKeypairWrapped(sessionId: number): Promise<{
  mlkemPublicKeyB64: string;
  mlkemPrivateKeyEncrypted: Uint8Array;
  x25519PublicKeyB64: string;
  x25519PrivateKeyEncrypted: Uint8Array;
}> {
  const res = await sendRequest<{
    mlkemPublicKeyB64: string;
    mlkemPrivateKeyEncrypted: ArrayBuffer;
    x25519PublicKeyB64: string;
    x25519PrivateKeyEncrypted: ArrayBuffer;
  }>({ type: 'byoVaultGenerateKeypairWrapped', sessionId });
  return {
    mlkemPublicKeyB64: res.mlkemPublicKeyB64,
    mlkemPrivateKeyEncrypted: new Uint8Array(res.mlkemPrivateKeyEncrypted),
    x25519PublicKeyB64: res.x25519PublicKeyB64,
    x25519PrivateKeyEncrypted: new Uint8Array(res.x25519PrivateKeyEncrypted),
  };
}

// ── WebAuthn PRF-gated device-key protection (SECURITY.md §12) ─────────────

/**
 * Derive the AES-GCM wrapping key from a WebAuthn PRF output.
 * `prfOutput` is the raw bytes from `extensions.prf.results.first` on the
 * `navigator.credentials.get()` result.
 *
 * Implementation note: we copy the caller's bytes into a fresh buffer and
 * transfer that copy. Transferring the caller's own `.buffer` would
 * detach it on return, breaking any downstream `fill(0)` zeroization or
 * re-use by the caller — and WebAuthnGate relies on being able to zeroize
 * its local copies immediately after the wrap/unwrap round-trip.
 */
export async function webauthnDeriveWrappingKey(prfOutput: Uint8Array): Promise<Uint8Array> {
  const payload = prfOutput.slice();
  const buf = await sendRequest<ArrayBuffer>(
    { type: 'webauthnDeriveWrappingKey', prfOutput: payload.buffer },
    [payload.buffer],
  );
  return new Uint8Array(buf);
}

/**
 * AES-256-GCM-wrap a 32-byte device key under a PRF-derived wrapping key.
 * Output format is `nonce(12) || ct||tag`.
 */
export async function webauthnWrapDeviceKey(
  deviceKey: Uint8Array,
  wrappingKey: Uint8Array,
): Promise<Uint8Array> {
  const deviceCopy = deviceKey.slice();
  const wrappingCopy = wrappingKey.slice();
  const buf = await sendRequest<ArrayBuffer>(
    {
      type: 'webauthnWrapDeviceKey',
      deviceKey: deviceCopy.buffer,
      wrappingKey: wrappingCopy.buffer,
    },
    [deviceCopy.buffer, wrappingCopy.buffer],
  );
  return new Uint8Array(buf);
}

/** Inverse of `webauthnWrapDeviceKey`. Returns the 32-byte device key. */
export async function webauthnUnwrapDeviceKey(
  wrapped: Uint8Array,
  wrappingKey: Uint8Array,
): Promise<Uint8Array> {
  const wrappedCopy = wrapped.slice();
  const wrappingCopy = wrappingKey.slice();
  const buf = await sendRequest<ArrayBuffer>(
    {
      type: 'webauthnUnwrapDeviceKey',
      wrapped: wrappedCopy.buffer,
      wrappingKey: wrappingCopy.buffer,
    },
    [wrappedCopy.buffer, wrappingCopy.buffer],
  );
  return new Uint8Array(buf);
}

/**
 * Generate a fresh random 32-byte device key inside WASM. Callers use this
 * when enrolling the first passkey so the raw key never exists in JS before
 * being wrapped for every credential.
 */
export async function webauthnGenerateDeviceKey(): Promise<Uint8Array> {
  const buf = await sendRequest<ArrayBuffer>({ type: 'webauthnGenerateDeviceKey' });
  return new Uint8Array(buf);
}

// ── Opt-in passkey-unlock helpers (SECURITY.md §12) ────────────────────────

/**
 * Derive the AES-GCM wrapping key used for the opt-in passkey-unlock mode.
 * Distinct from `webauthnDeriveWrappingKey` by HKDF info; the two derived
 * keys are guaranteed independent even when the same PRF output is reused.
 */
export async function webauthnDeriveVaultKeyWrappingKey(
  prfOutput: Uint8Array,
): Promise<Uint8Array> {
  const payload = prfOutput.slice();
  const buf = await sendRequest<ArrayBuffer>(
    { type: 'webauthnDeriveVaultKeyWrappingKey', prfOutput: payload.buffer },
    [payload.buffer],
  );
  return new Uint8Array(buf);
}

/** Byte-level vault_key wrap; `wrapping_key` comes from the derive helper above. */
export async function webauthnWrapVaultKey(
  vaultKey: Uint8Array,
  wrappingKey: Uint8Array,
): Promise<Uint8Array> {
  const vkCopy = vaultKey.slice();
  const wkCopy = wrappingKey.slice();
  const buf = await sendRequest<ArrayBuffer>(
    {
      type: 'webauthnWrapVaultKey',
      vaultKey: vkCopy.buffer,
      wrappingKey: wkCopy.buffer,
    },
    [vkCopy.buffer, wkCopy.buffer],
  );
  return new Uint8Array(buf);
}

/** Inverse of `webauthnWrapVaultKey`. Returns 32-byte `vault_key`. */
export async function webauthnUnwrapVaultKey(
  wrapped: Uint8Array,
  wrappingKey: Uint8Array,
): Promise<Uint8Array> {
  const wrappedCopy = wrapped.slice();
  const wkCopy = wrappingKey.slice();
  const buf = await sendRequest<ArrayBuffer>(
    {
      type: 'webauthnUnwrapVaultKey',
      wrapped: wrappedCopy.buffer,
      wrappingKey: wkCopy.buffer,
    },
    [wrappedCopy.buffer, wkCopy.buffer],
  );
  return new Uint8Array(buf);
}

/**
 * High-level helper: wraps the WASM-held `vault_key` of the given session
 * under a PRF-derived wrapping key and returns the wrapped bytes as base64.
 * The raw `vault_key` never leaves WASM. Used by `enablePasskeyUnlock` to
 * emit one wrapped copy per enrolled credential.
 */
export async function byoVaultWrapSessionVaultKeyWithPrf(
  sessionId: number,
  prfOutputB64: string,
): Promise<string> {
  const res = await sendRequest<{ wrappedB64: string }>({
    type: 'byoVaultWrapSessionVaultKeyWithPrf',
    sessionId,
    prfOutputB64,
  });
  return res.wrappedB64;
}

/**
 * High-level helper: unwrap a PRF-wrapped `vault_key` directly into a fresh
 * vault session, returning only the opaque `sessionId`. The raw `vault_key`
 * never crosses the WASM→JS boundary. Used by the unlock path when the
 * user chose "Unlock with passkey".
 */
export async function byoVaultLoadSessionFromWrappedVaultKey(
  wrappedB64: string,
  prfOutputB64: string,
): Promise<number> {
  const res = await sendRequest<{ sessionId: number }>({
    type: 'byoVaultLoadSessionFromWrappedVaultKey',
    wrappedB64,
    prfOutputB64,
  });
  return res.sessionId;
}

/** Session-based seal of an Ed25519 seed. Returns base64 wrapped (48 bytes). */
export async function byoVaultSealDeviceSigningKey(
  sessionId: number,
  deviceIdB64: string,
  seedB64: string,
): Promise<string> {
  const res = await sendRequest<{ wrapped: string }>({
    type: 'byoVaultSealDeviceSigningKey',
    sessionId,
    deviceIdB64,
    seedB64,
  });
  return res.wrapped;
}

/** Session-based unseal of an Ed25519 seed. Returns base64 seed (32 bytes). */
export async function byoVaultUnsealDeviceSigningKey(
  sessionId: number,
  deviceIdB64: string,
  wrappedB64: string,
): Promise<string> {
  const res = await sendRequest<{ seed: string }>({
    type: 'byoVaultUnsealDeviceSigningKey',
    sessionId,
    deviceIdB64,
    wrappedB64,
  });
  return res.seed;
}

/** Session-based v1→v2 vault migration. Returns migrated bytes. */
export async function byoVaultMigrateV1ToV2(
  sessionId: number,
  vaultBytes: Uint8Array,
): Promise<Uint8Array> {
  const result = await sendRequest<ArrayBuffer>(
    { type: 'byoVaultMigrateV1ToV2', sessionId, vaultBytes: vaultBytes.buffer },
    [vaultBytes.buffer],
  );
  return new Uint8Array(result);
}

/**
 * Re-wrap the vault_key with a new wrapping key (for passphrase change).
 * vault_key never leaves WASM — only the new wrapped form is returned.
 * `newWrappingKeyB64` is the new vault_kek (base64) derived from the new passphrase.
 */
export async function byoVaultRewrap(
  sessionId: number,
  newWrappingKeyB64: string,
): Promise<{ wrapIvB64: string; wrappedKeyB64: string }> {
  return sendRequest({ type: 'byoVaultRewrap', sessionId, newWrappingKeyB64 });
}

/**
 * Create a new vault: generate vault_key, shard, vault_id, master_salt; run
 * Argon2id on `password`; wrap vault_key with vault_kek — all inside WASM.
 *
 * Returns an opaque session ID plus the metadata needed to build the vault
 * header.  `shardB64` must be encrypted with the device CryptoKey before
 * storage (this step unavoidably happens in JS due to the non-extractable
 * WebCrypto key constraint).
 */
export async function byoVaultCreate(
  password: string,
  memoryKb: number,
  iterations: number,
  parallelism: number,
): Promise<{
  sessionId: number;
  shardB64: string;
  vaultIdB64: string;
  masterSaltB64: string;
  passWrapIvB64: string;
  passWrappedKeyB64: string;
}> {
  return sendRequest({ type: 'byoVaultCreate', password, memoryKb, iterations, parallelism });
}

/**
 * Open a vault session from the recovery slot.
 * Derives recovery_vault_kek from `recoveryKeyB64` inside WASM and unwraps vault_key.
 * Returns an opaque session ID.
 */
export async function byoVaultOpenRecovery(
  recoveryKeyB64: string,
  wrapIvB64: string,
  wrappedKeyB64: string,
): Promise<number> {
  const result = await sendRequest<{ sessionId: number }>({ type: 'byoVaultOpenRecovery', recoveryKeyB64, wrapIvB64, wrappedKeyB64 });
  return result.sessionId;
}

/**
 * Wrap the session vault_key with a recovery key (derives recovery_vault_kek inside WASM).
 * Returns the encrypted recovery slot bytes without exposing vault_key.
 */
export async function byoVaultWrapRecovery(
  sessionId: number,
  recoveryKeyB64: string,
): Promise<{ recWrapIvB64: string; recWrappedKeyB64: string }> {
  return sendRequest({ type: 'byoVaultWrapRecovery', sessionId, recoveryKeyB64 });
}

/**
 * Re-wrap the vault_key with a new passphrase: generates a fresh salt, runs
 * Argon2id, derives new vault_kek, and wraps — all inside WASM.
 * Returns the new passphrase slot plus the new master_salt (no KEK in JS).
 */
export async function byoVaultRewrapWithPassphrase(
  sessionId: number,
  newPassword: string,
  memoryKb: number,
  iterations: number,
  parallelism: number,
): Promise<{ wrapIvB64: string; wrappedKeyB64: string; masterSaltB64: string }> {
  return sendRequest({
    type: 'byoVaultRewrapWithPassphrase',
    sessionId,
    newPassword,
    memoryKb,
    iterations,
    parallelism,
  });
}

// ── Share link crypto (P10) ────────────────────────────────────────────────

/**
 * Extract the content_key from a V7 file header and encode as share fragment.
 * ZK-safe: content_key stays inside WASM, only the fragment is returned.
 *
 * sessionId: active vault session ID (holds private keys in worker registry)
 * headerB64: base64-encoded V7 file header (≥ 1709 bytes)
 * variant: "A" or "A+"
 * password: required for "A+"
 */
export async function byoCreateShareFragment(
  sessionId: string,
  headerB64: string,
  variant: 'A' | 'A+',
  password?: string,
): Promise<string> {
  return sendRequest({ type: 'byoCreateShareFragment', sessionId, headerB64, variant, password });
}

/**
 * Bundle-share creator: extract the per-file content_key from a V7 header.
 * Unlike `byoCreateShareFragment`, this returns the raw base64 content_key
 * because the caller needs to embed it inside the bundle manifest (which is
 * itself V7-encrypted under the bundle_key before upload).
 */
export async function byoBundleExtractFileKey(
  sessionId: string,
  headerB64: string,
): Promise<string> {
  return sendRequest({ type: 'byoBundleExtractFileKey', sessionId, headerB64 });
}

/**
 * Encrypt a bundle manifest under a known bundle_key and return the V7
 * ciphertext as base64. Used on the creator side to produce the `_manifest`
 * blob for folder / collection shares.
 */
export async function byoEncryptManifestV7(
  manifestBytesB64: string,
  contentKeyB64: string,
): Promise<string> {
  return sendRequest({ type: 'byoEncryptManifestV7', manifestBytesB64, contentKeyB64 });
}

/** Encode a 32-byte content_key as a Variant A fragment "k=<base64url>". */
export async function byoShareEncodeVariantA(contentKeyB64: string): Promise<string> {
  return sendRequest({ type: 'byoShareEncodeVariantA', contentKeyB64 });
}

/** Decode a Variant A fragment "k=<base64url>" → base64-encoded content_key. */
export async function byoShareDecodeVariantA(fragment: string): Promise<string> {
  return sendRequest({ type: 'byoShareDecodeVariantA', fragment });
}

/**
 * Wrap a content_key with Argon2id + AES-GCM (Variant A+).
 * Returns { saltB64url, encryptedCkB64url }.
 */
export async function byoShareWrapKey(
  contentKeyB64: string,
  password: string,
): Promise<{ saltB64url: string; encryptedCkB64url: string }> {
  return sendRequest({ type: 'byoShareWrapKey', contentKeyB64, password });
}

/**
 * Unwrap a password-protected content_key (Variant A+).
 * Returns base64-encoded content_key on success.
 * Throws on wrong password or corrupted data.
 */
export async function byoShareUnwrapKey(
  saltB64url: string,
  encryptedCkB64url: string,
  password: string,
): Promise<string> {
  return sendRequest({ type: 'byoShareUnwrapKey', saltB64url, encryptedCkB64url, password });
}

// ── R6 multi-vault ─────────────────────────────────────────────────────────

/** Encrypt manifest JSON into the vault_manifest.sc body blob. Returns `{ data: base64 }`. */
export async function byoManifestEncrypt(
  sessionId: number,
  manifestJson: string,
): Promise<{ data: string }> {
  return sendRequest({ type: 'byoManifestEncrypt', sessionId, manifestJson });
}

/** Decrypt the vault_manifest.sc body blob → `{ manifestJson }`. */
export async function byoManifestDecrypt(
  sessionId: number,
  bodyBlobB64: string,
): Promise<{ manifestJson: string }> {
  return sendRequest({ type: 'byoManifestDecrypt', sessionId, bodyBlobB64 });
}

/**
 * Merge multiple manifest JSON strings (one per provider) into one.
 * Input: JSON-array of manifest JSON strings, e.g. `'["<json1>","<json2>"]'`.
 * Returns `{ manifestJson }`.
 */
export async function byoManifestMerge(
  manifestJsonsJson: string,
  nowUnixSecs: number,
  minAcceptableVersion: number,
): Promise<{ manifestJson: string }> {
  return sendRequest({ type: 'byoManifestMerge', manifestJsonsJson, nowUnixSecs, minAcceptableVersion });
}

/** Validate a manifest JSON string. Throws on invariant violation. Returns `{ ok: true }`. */
export async function byoManifestValidate(
  manifestJson: string,
  nowUnixSecs: number,
): Promise<{ ok: boolean }> {
  return sendRequest({ type: 'byoManifestValidate', manifestJson, nowUnixSecs });
}

/** Encrypt per-vault SQLite bytes using the per-provider AEAD subkey. Returns `{ data: base64 }`. */
export async function byoVaultBodyEncrypt(
  sessionId: number,
  providerId: string,
  sqliteB64: string,
): Promise<{ data: string }> {
  return sendRequest({ type: 'byoVaultBodyEncrypt', sessionId, providerId, sqliteB64 });
}

/** Decrypt a per-vault body blob using the per-provider AEAD subkey. Returns `{ data: base64 }`. */
export async function byoVaultBodyDecrypt(
  sessionId: number,
  providerId: string,
  bodyBlobB64: string,
): Promise<{ data: string }> {
  return sendRequest({ type: 'byoVaultBodyDecrypt', sessionId, providerId, bodyBlobB64 });
}

/**
 * Derive the per-vault WAL encryption key for `providerId` and return it as a
 * non-extractable WebCrypto key. The raw bytes never leave the worker, so a
 * compromised main thread cannot exfiltrate them — only encrypt/decrypt
 * operations are possible through the returned handle.
 */
export async function byoDerivePerVaultWalKey(
  sessionId: number,
  providerId: string,
): Promise<{ key: CryptoKey }> {
  return sendRequest({ type: 'byoDerivePerVaultWalKey', sessionId, providerId });
}

/**
 * Derive per-vault journal AEAD + HMAC keys for `providerId` as
 * non-extractable WebCrypto handles. Same isolation as
 * [`byoDerivePerVaultWalKey`].
 */
export async function byoDerivePerVaultJournalKeys(
  sessionId: number,
  providerId: string,
): Promise<{ aeadKey: CryptoKey; hmacKey: CryptoKey }> {
  return sendRequest({ type: 'byoDerivePerVaultJournalKeys', sessionId, providerId });
}

/**
 * Build an unlock plan from manifest + provider availability.
 *
 * All IDs are JSON arrays of strings, e.g. `'["gdrive-uuid","dropbox-uuid"]'`.
 * Returns `{ planJson }` — deserialize as `UnlockPlan` from sdk-core.
 */
export async function byoPlanUnlock(
  manifestJson: string,
  onlineIdsJson: string,
  cachedIdsJson: string,
): Promise<{ planJson: string }> {
  return sendRequest({ type: 'byoPlanUnlock', manifestJson, onlineIdsJson, cachedIdsJson });
}

/**
 * Build a save plan from dirty + online provider IDs.
 * Returns `{ planJson }` — deserialize as `SavePlan` from sdk-core.
 */
export async function byoPlanSave(
  dirtyIdsJson: string,
  onlineIdsJson: string,
): Promise<{ planJson: string }> {
  return sendRequest({ type: 'byoPlanSave', dirtyIdsJson, onlineIdsJson });
}

/**
 * Build a cross-provider file move plan.
 * `destFolderId`: use -1 for root (no parent folder).
 * Returns `{ planJson }` — deserialize as `CrossProviderMovePlan`.
 */
export async function byoPlanCrossProviderMove(
  fileId: number,
  sourceProviderRef: string,
  srcProviderId: string,
  dstProviderId: string,
  destFolderId: number,
  displayName: string,
): Promise<{ planJson: string }> {
  return sendRequest({
    type: 'byoPlanCrossProviderMove',
    fileId,
    sourceProviderRef,
    srcProviderId,
    dstProviderId,
    destFolderId,
    displayName,
  });
}

/** Derive the manifest AEAD key (testing / debugging only). Returns `{ keyB64 }`. */
export async function byoDeriveManifestAeadKey(sessionId: number): Promise<{ keyB64: string }> {
  return sendRequest({ type: 'byoDeriveManifestAeadKey', sessionId });
}

/** Evaluate a pending WAL MoveStep for crash-recovery replay. Returns `{ decision, providerId?, providerRef? }`. */
export async function byoCrossProviderMoveDecideReplay(
  stepBytesB64: string,
  dstFileExists: boolean,
  srcBlobExistsStr: 'true' | 'false' | 'unknown',
): Promise<{ decision: string; providerId?: string; providerRef?: string }> {
  return sendRequest({ type: 'byoCrossProviderMoveDecideReplay', stepBytesB64, dstFileExists, srcBlobExistsStr });
}

/** Reconcile pending WAL blob-delete steps after crash recovery. Returns `{ actions }`. */
export async function byoCrossProviderMovePlanReconcile(
  stepsJson: string,
  dstFileExists: boolean,
  srcBlobExistsStr: 'true' | 'false' | 'unknown',
): Promise<{ actions: Array<{ type: string; provider_id: string; provider_ref: string }> }> {
  return sendRequest({ type: 'byoCrossProviderMovePlanReconcile', stepsJson, dstFileExists, srcBlobExistsStr });
}

// ── Row-merge (P3.2) ──────────────────────────────────────────────────────────

/**
 * Compute merge operations for one database table using the Rust merge algorithm.
 *
 * - `localRowsJson`: JSON array of row objects from the local DB
 * - `remoteRowsJson`: JSON array of row objects from the remote DB
 * - `isKeyVersions`: true for key_versions semantics (union, local wins on conflict)
 *
 * Returns `{ ops_json }` — a JSON array of `{ op: "insert"|"update"|"skip", row? }` objects,
 * one per remote row in the same order as `remoteRowsJson`.
 */
export async function byoMergeRows(
  localRowsJson: string,
  remoteRowsJson: string,
  isKeyVersions: boolean,
): Promise<{ ops_json: string }> {
  return sendRequest({ type: 'byoMergeRows', localRowsJson, remoteRowsJson, isKeyVersions });
}

// ── Journal codec (P3.1) ──────────────────────────────────────────────────────

/**
 * Serialize, encrypt, and HMAC one journal entry inside WASM.
 * Keys are derived from the open vault session — they never leave WASM.
 * Returns `{ entry_b64 }` — base64-encoded entry bytes ready to buffer.
 */
export async function byoJournalAppend(
  sessionId: number,
  providerId: string,
  entryType: string,
  table: string,
  rowId: number,
  dataJson: string,
): Promise<{ entry_b64: string }> {
  return sendRequest({ type: 'byoJournalAppend', sessionId, providerId, entryType, table, rowId, dataJson });
}

/**
 * Parse and verify a vault journal file inside WASM.
 * Returns `{ entries }` on success or throws on HMAC failure / corruption.
 */
export async function byoJournalParse(
  sessionId: number,
  providerId: string,
  journalB64: string,
): Promise<{ entries: Array<{ entry_type: string; table: string; row_id: number; data: string }> }> {
  return sendRequest({ type: 'byoJournalParse', sessionId, providerId, journalB64 });
}

/**
 * Build the JSON payload for a share-audit journal entry. The result is the
 * `dataJson` argument for a follow-up `byoJournalAppend` call against table
 * `share_audit`. Pure data construction — no vault session needed.
 *
 * @param direction "outbound" (user invoked OS share) or "inbound" (PWA
 *   received a Web Share Target POST)
 * @param fileRef opaque vault row id (string form)
 * @param counterpartyHint optional hint (e.g. inbound `url` form field).
 *   Pass `''` for none.
 * @param tsMs unix milliseconds of the event
 */
export async function byoShareAuditPayload(
  direction: 'outbound' | 'inbound',
  fileRef: string,
  counterpartyHint: string,
  tsMs: number,
): Promise<{ data_json: string }> {
  return sendRequest({ type: 'byoShareAuditPayload', direction, fileRef, counterpartyHint, tsMs });
}

// ── Manifest mutation helpers (P3.3) ──────────────────────────────────────────

/** Add a new provider entry to the manifest. Returns updated `manifestJson`. */
export async function byoManifestAddProvider(
  manifestJson: string,
  entryJson: string,
): Promise<{ manifestJson: string }> {
  return sendRequest({ type: 'byoManifestAddProvider', manifestJson, entryJson });
}

/** Rename a provider's display name. Returns updated `manifestJson`. */
export async function byoManifestRenameProvider(
  manifestJson: string,
  providerId: string,
  newName: string,
  nowUnixSecs: number,
): Promise<{ manifestJson: string }> {
  return sendRequest({ type: 'byoManifestRenameProvider', manifestJson, providerId, newName, nowUnixSecs });
}

/** Set a provider as the primary. Returns updated `manifestJson`. */
export async function byoManifestSetPrimary(
  manifestJson: string,
  providerId: string,
  nowUnixSecs: number,
): Promise<{ manifestJson: string }> {
  return sendRequest({ type: 'byoManifestSetPrimary', manifestJson, providerId, nowUnixSecs });
}

/** Tombstone (remove) a provider. Returns updated `manifestJson`. */
export async function byoManifestTombstone(
  manifestJson: string,
  providerId: string,
  nowUnixSecs: number,
): Promise<{ manifestJson: string }> {
  return sendRequest({ type: 'byoManifestTombstone', manifestJson, providerId, nowUnixSecs });
}

/** Replace a provider entry's config_json. Returns updated `manifestJson`.
 *  Caller is expected to have already validated the new config (e.g. by
 *  attempting init() against it) — the manifest layer treats config_json as opaque. */
export async function byoManifestUpdateProviderConfig(
  manifestJson: string,
  providerId: string,
  newConfigJson: string,
  nowUnixSecs: number,
): Promise<{ manifestJson: string }> {
  return sendRequest({
    type: 'byoManifestUpdateProviderConfig',
    manifestJson,
    providerId,
    newConfigJson,
    nowUnixSecs,
  });
}

// ── Stats (Phase 5) ──────────────────────────────────────────────────────────

/** Initialise the in-WASM stats sink and uploader. Call once on worker boot. */
export async function statsInit(baseUrl: string, deviceId: string): Promise<void> {
  await sendRequest({ type: 'statsInit', baseUrl, deviceId });
}

/** Push one event JSON into the in-WASM ring buffer. Fire-and-forget. */
export async function statsRecord(eventJson: string): Promise<void> {
  await sendRequest({ type: 'statsRecord', eventJson });
}

/** Return the current queue depth. */
export async function statsDrain(): Promise<number> {
  const { depth } = await sendRequest<{ depth: number }>({ type: 'statsDrain' });
  return depth;
}

/** Drain up to 200 events and POST them to /relay/stats. */
export async function statsFlush(): Promise<void> {
  await sendRequest({ type: 'statsFlush' });
}
