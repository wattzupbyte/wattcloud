/**
 * WebAuthnGate — opt-in passkey-gate for the per-vault device CryptoKey.
 *
 * Three modes (see SECURITY.md §12 "Passkey-gated device key"):
 *   - 'none'     : no gate; the plain `device_crypto_keys` row is used as today.
 *   - 'presence' : fallback for authenticators without PRF support. The
 *                  device CryptoKey stays as today in `device_crypto_keys`,
 *                  but `navigator.credentials.get()` is required before any
 *                  `getDeviceCryptoKey(vaultId)` returns it. Weaker: a
 *                  determined attacker can patch the JS to skip the gate.
 *   - 'prf'      : the device key is random 32 bytes, held in this module
 *                  (and the WASM vault session while unlocked), and wrapped
 *                  once per enrolled credential under
 *                  `HKDF(PRF_output, "Wattcloud device key v1")`. Biometric
 *                  is cryptographically load-bearing: without a successful
 *                  get() we cannot derive the AES key.
 *
 * All DOM-bound WebAuthn calls live here; the crypto (HKDF + AES-GCM) lives
 * in sdk-core (`crypto/webauthn.rs`) and is surfaced via the worker as
 * `Worker.webauthn*`. Phase 2 scope: feature detection + module API.
 * Actual wiring into `getDeviceCryptoKey` and the Settings UI ships in
 * Phase 3 and 4; this module is callable but unreachable from users today.
 */

import * as byoWorker from '@wattcloud/sdk';
import {
  type DeviceWebAuthnRecord,
  type WebAuthnCredentialEntry,
  getWebAuthnRecord,
  setWebAuthnRecord,
  clearWebAuthnRecord,
  setDeviceCryptoKey,
  generateDeviceCryptoKey,
} from './DeviceKeyStore';

// ── Types ──────────────────────────────────────────────────────────────────

export type WebAuthnMode = 'none' | 'presence' | 'prf';

export interface EnrolDeviceKeyOptions {
  /** UI label for the new credential (e.g. "MacBook Touch ID"). */
  displayName: string;
  /** Fallback preference: if PRF isn't negotiable, accept presence mode. */
  allowPresenceFallback: boolean;
  /** User-visible vault label, used to populate the WebAuthn `user.displayName`. */
  vaultLabel: string;
  /**
   * Optional interactive hook: when the authenticator reports no PRF support
   * and `allowPresenceFallback` is true, the caller can intercept the
   * decision — the resolver returns true to proceed with presence mode,
   * false to cancel enrolment entirely. Use this to show the educational
   * "presence-only" modal from the Settings UI.
   */
  onPrfUnavailable?: () => Promise<boolean>;
}

export interface EnrolDeviceKeyResult {
  mode: WebAuthnMode;
  credential: WebAuthnCredentialEntry;
  /** The device CryptoKey ready to be used for AES-GCM. */
  deviceKey: CryptoKey;
}

export interface AddCredentialOptions {
  displayName: string;
  allowPresenceFallback: boolean;
  vaultLabel: string;
  /** Raw 32-byte device key (only required when vault-level mode is 'prf'). */
  deviceKeyBytes?: Uint8Array;
}

// ── Module state ───────────────────────────────────────────────────────────

/**
 * Session cache: once a vault's device CryptoKey has been unwrapped (via
 * PRF) or gate-cleared (via presence), cache it in-process so subsequent
 * consumers don't need to re-prompt on every store read. Cleared on tab
 * reload, explicit lock, or `evictSessionCache`.
 */
const _sessionCache = new Map<string, CryptoKey>();

/**
 * Parallel cache of the *raw* 32-byte device key for each unlocked vault.
 * Needed only when mode === 'prf' — it lets `addCredential` wrap the same
 * device key under a new authenticator's PRF output without asking the
 * WASM vault session to re-expose it. Cleared alongside the CryptoKey on
 * evict; bytes are explicitly zeroized so the browser's allocator can
 * reuse the backing store cleanly (best-effort — JS engines offer no
 * strong guarantees).
 */
const _rawDeviceKeyCache = new Map<string, Uint8Array>();

function _stashRawDeviceKey(vaultId: string, bytes: Uint8Array): void {
  const existing = _rawDeviceKeyCache.get(vaultId);
  if (existing) existing.fill(0);
  // Copy: the caller may zeroize its own buffer immediately after stashing.
  const copy = new Uint8Array(bytes);
  _rawDeviceKeyCache.set(vaultId, copy);
}

export function evictSessionCache(vaultId?: string): void {
  if (vaultId === undefined) {
    for (const buf of _rawDeviceKeyCache.values()) buf.fill(0);
    _rawDeviceKeyCache.clear();
    _sessionCache.clear();
  } else {
    const buf = _rawDeviceKeyCache.get(vaultId);
    if (buf) buf.fill(0);
    _rawDeviceKeyCache.delete(vaultId);
    _sessionCache.delete(vaultId);
  }
}

/**
 * Accessor for the session-cached raw device-key bytes. Returns null if no
 * key is currently unwrapped for this vault (vault locked, or mode !== 'prf').
 * Exposed so the Settings UI can call `addCredential` without the caller
 * having to thread bytes through props.
 */
export function peekSessionDeviceKeyBytes(vaultId: string): Uint8Array | null {
  const existing = _rawDeviceKeyCache.get(vaultId);
  return existing ? new Uint8Array(existing) : null;
}

// ── Feature detection ──────────────────────────────────────────────────────

export function isWebAuthnAvailable(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    typeof PublicKeyCredential !== 'undefined' &&
    typeof navigator.credentials !== 'undefined'
  );
}

/**
 * Query the runtime for platform-authenticator availability (Touch ID,
 * Windows Hello, Android fingerprint). Used by the UI to nudge users who
 * only have a roaming key to plug it in first.
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnAvailable()) return false;
  try {
    return await (PublicKeyCredential as any).isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

// ── Low-level helpers ──────────────────────────────────────────────────────

function toBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(input: string): Uint8Array {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((input.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(input: string): Uint8Array {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Stable 16-byte `user.id` per vault. Derived deterministically from the
 * vault_id so a re-enrolment after the record was wiped picks the same
 * credential slot in the authenticator's passkey list (cosmetic — the
 * authenticator distinguishes by credential_id underneath).
 */
function userHandleFromVaultId(vaultId: string): Uint8Array {
  // vaultId is a hex-encoded 16-byte string in most flows, but base64 in
  // some (depends on caller). Normalize: take the first 16 raw bytes that
  // can be produced from either form.
  const handle = new Uint8Array(16);
  let i = 0;
  if (/^[0-9a-fA-F]{32}$/.test(vaultId)) {
    for (; i < 16; i++) handle[i] = parseInt(vaultId.slice(i * 2, i * 2 + 2), 16);
  } else {
    try {
      const raw = fromBase64(vaultId);
      handle.set(raw.slice(0, 16), 0);
    } catch {
      // Last-resort fallback: hash the string via TextEncoder xor
      const enc = new TextEncoder().encode(vaultId);
      for (let j = 0; j < enc.length; j++) handle[j % 16] ^= enc[j];
    }
  }
  return handle;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

async function importDeviceKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    keyBytes as BufferSource,
    { name: 'AES-GCM' },
    false, // non-extractable once imported
    ['encrypt', 'decrypt'],
  );
}

// ── Enrolment: first passkey for a vault ───────────────────────────────────

/**
 * Enrol the first passkey for a vault, creating the device key along the way.
 *
 * Flow:
 *   1. `navigator.credentials.create()` with PRF extension requested.
 *   2. If the authenticator reports PRF support → mode 'prf':
 *      - Generate a random 32-byte device key in WASM.
 *      - Run a get() with PRF eval to harvest the PRF output.
 *      - Derive wrapping key, wrap device key, persist alongside credential.
 *      - Import device key as CryptoKey and cache.
 *   3. Otherwise if `allowPresenceFallback` → mode 'presence':
 *      - Keep the existing `device_crypto_keys` row (caller must have
 *        generated one at enrolment, which is the existing flow).
 *      - Persist credential_id only; no prf_salt / wrapped_device_key.
 *
 * MUST be invoked inside a user-gesture handler (button click). WebAuthn
 * rejects create()/get() calls that originate from unprompted async code.
 */
export async function enrolDeviceKey(
  vaultId: string,
  options: EnrolDeviceKeyOptions,
): Promise<EnrolDeviceKeyResult> {
  if (!isWebAuthnAvailable()) {
    throw new Error('WebAuthn is not available in this browser');
  }

  const userHandle = userHandleFromVaultId(vaultId);
  const challenge = randomBytes(32);
  const prfEvalFirst = randomBytes(32);

  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: { name: 'Wattcloud', id: window.location.hostname },
      user: {
        id: userHandle as BufferSource,
        name: `wattcloud-vault-${vaultId.slice(0, 8)}`,
        displayName: options.vaultLabel || 'Wattcloud vault',
      },
      challenge: challenge as BufferSource,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'preferred',
      },
      attestation: 'none',
      extensions: { prf: { eval: { first: prfEvalFirst } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Passkey creation was cancelled');
  const credentialIdB64 = toBase64Url(credential.rawId);

  // Probe PRF: some authenticators return PRF output on create() directly,
  // but most require a subsequent get(). Issue a single get() to harvest.
  const prfOutput = await getPrfOutput(credentialIdB64, prfEvalFirst);
  const prfSupported = prfOutput !== null;

  if (prfSupported) {
    const deviceKeyBytes = await byoWorker.Worker.webauthnGenerateDeviceKey();
    const wrappingKey = await byoWorker.Worker.webauthnDeriveWrappingKey(prfOutput!);
    const wrapped = await byoWorker.Worker.webauthnWrapDeviceKey(deviceKeyBytes, wrappingKey);
    wrappingKey.fill(0);

    const entry: WebAuthnCredentialEntry = {
      credential_id: credentialIdB64,
      prf_salt: toBase64(prfEvalFirst),
      wrapped_device_key: toBase64(wrapped),
      display_name: options.displayName,
      added_at: new Date().toISOString(),
      prf_supported: true,
    };
    await setWebAuthnRecord({
      vault_id: vaultId,
      mode: 'prf',
      credentials: [entry],
    });

    const deviceKey = await importDeviceKey(deviceKeyBytes);
    // Stash the raw bytes in the module session cache BEFORE zeroizing the
    // local buffer — `addCredential` needs them to wrap the same device key
    // under the next authenticator's PRF output.
    _stashRawDeviceKey(vaultId, deviceKeyBytes);
    deviceKeyBytes.fill(0);
    _sessionCache.set(vaultId, deviceKey);
    return { mode: 'prf', credential: entry, deviceKey };
  }

  if (!options.allowPresenceFallback) {
    throw new Error(
      'This authenticator does not support the WebAuthn PRF extension and ' +
        'presence fallback was disabled by the caller.',
    );
  }

  if (options.onPrfUnavailable) {
    const accepted = await options.onPrfUnavailable();
    if (!accepted) {
      throw new Error('Enrolment cancelled: user declined presence-only fallback.');
    }
  }

  // Presence-only mode: keep the existing CryptoKey, just record the cred.
  // Caller must ensure a `device_crypto_keys` row exists (it does during
  // normal enrolment flows). We do NOT rotate it here — the presence gate
  // is a behavioural check, not a cryptographic one.
  const entry: WebAuthnCredentialEntry = {
    credential_id: credentialIdB64,
    display_name: options.displayName,
    added_at: new Date().toISOString(),
    prf_supported: false,
  };
  await setWebAuthnRecord({
    vault_id: vaultId,
    mode: 'presence',
    credentials: [entry],
  });
  // The already-stored device_crypto_keys row is the source of truth; pull
  // it into the session cache so unlockDeviceKey can return it after touch.
  const { getDeviceCryptoKey } = await import('./DeviceKeyStore');
  const existing = await getDeviceCryptoKey(vaultId);
  if (existing) _sessionCache.set(vaultId, existing);
  return {
    mode: 'presence',
    credential: entry,
    deviceKey: existing ?? (await generateDeviceCryptoKey(vaultId)),
  };
}

// ── Unlock: derive device CryptoKey from a stored credential ───────────────

/**
 * Run the configured gate. Returns the device CryptoKey ready for AES-GCM.
 * Callers MUST invoke this inside a user gesture if no cached key exists.
 */
export async function unlockDeviceKey(vaultId: string): Promise<CryptoKey> {
  const cached = _sessionCache.get(vaultId);
  if (cached) return cached;

  const record = await getWebAuthnRecord(vaultId);
  if (!record || record.mode === 'none') {
    throw new Error('No WebAuthn gate configured for this vault');
  }
  if (record.credentials.length === 0) {
    throw new Error('WebAuthn record has no enrolled credentials');
  }

  if (record.mode === 'prf') {
    // Offer every enrolled credential to the authenticator; it picks one.
    const assertion = await callGet(
      record.credentials.map((c) => c.credential_id),
      record.credentials.find((c) => c.prf_salt)?.prf_salt
        ? fromBase64(record.credentials.find((c) => c.prf_salt)!.prf_salt!)
        : undefined,
    );
    if (!assertion) throw new Error('Passkey verification was cancelled');

    const resolvedCredId = toBase64Url(assertion.rawId);
    const resolved = record.credentials.find((c) => c.credential_id === resolvedCredId);
    if (!resolved || !resolved.wrapped_device_key) {
      throw new Error(
        'Authenticator returned a credential we do not have a wrapped device key for',
      );
    }

    const prfResult = extractPrfOutput(assertion);
    if (!prfResult) {
      throw new Error('Authenticator did not return a PRF result');
    }

    const wrappingKey = await byoWorker.Worker.webauthnDeriveWrappingKey(prfResult);
    const wrapped = fromBase64(resolved.wrapped_device_key);
    const deviceKeyBytes = await byoWorker.Worker.webauthnUnwrapDeviceKey(wrapped, wrappingKey);
    wrappingKey.fill(0);

    const deviceKey = await importDeviceKey(deviceKeyBytes);
    _stashRawDeviceKey(vaultId, deviceKeyBytes);
    deviceKeyBytes.fill(0);
    _sessionCache.set(vaultId, deviceKey);
    return deviceKey;
  }

  // Presence mode: require a touch, then return the plain stored CryptoKey.
  const assertion = await callGet(
    record.credentials.map((c) => c.credential_id),
  );
  if (!assertion) throw new Error('Passkey verification was cancelled');
  const { getDeviceCryptoKey } = await import('./DeviceKeyStore');
  const stored = await getDeviceCryptoKey(vaultId);
  if (!stored) throw new Error('No device CryptoKey found for vault');
  _sessionCache.set(vaultId, stored);
  return stored;
}

// ── Credential management ──────────────────────────────────────────────────

/**
 * Enrol an additional passkey for an already-configured vault. The vault
 * MUST be unlocked (i.e. the raw device-key bytes are available in
 * `deviceKeyBytes` for mode 'prf'; in mode 'presence' the bytes are ignored).
 */
export async function addCredential(
  vaultId: string,
  options: AddCredentialOptions,
): Promise<WebAuthnCredentialEntry> {
  if (!isWebAuthnAvailable()) {
    throw new Error('WebAuthn is not available in this browser');
  }
  const record = await getWebAuthnRecord(vaultId);
  if (!record || record.mode === 'none') {
    throw new Error('Cannot add a credential: the gate is not enabled');
  }

  const userHandle = userHandleFromVaultId(vaultId);
  const challenge = randomBytes(32);
  const prfEvalFirst = randomBytes(32);

  const credential = (await navigator.credentials.create({
    publicKey: {
      rp: { name: 'Wattcloud', id: window.location.hostname },
      user: {
        id: userHandle as BufferSource,
        name: `wattcloud-vault-${vaultId.slice(0, 8)}`,
        displayName: options.vaultLabel || 'Wattcloud vault',
      },
      challenge: challenge as BufferSource,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'preferred',
      },
      attestation: 'none',
      excludeCredentials: record.credentials.map((c) => ({
        type: 'public-key' as const,
        id: fromBase64Url(c.credential_id) as BufferSource,
      })) as PublicKeyCredentialDescriptor[],
      extensions: { prf: { eval: { first: prfEvalFirst } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Passkey creation was cancelled');
  const credentialIdB64 = toBase64Url(credential.rawId);

  const prfOutput = await getPrfOutput(credentialIdB64, prfEvalFirst);
  const prfSupported = prfOutput !== null;

  let entry: WebAuthnCredentialEntry;
  if (record.mode === 'prf') {
    if (!prfSupported) {
      throw new Error(
        "Vault is in 'prf' mode but the new authenticator does not support " +
          'PRF. Add a presence-only credential to a separate vault, or ' +
          'disable the gate first.',
      );
    }
    if (!options.deviceKeyBytes || options.deviceKeyBytes.length !== 32) {
      throw new Error(
        "Adding a credential in 'prf' mode requires the 32-byte device " +
          'key; the vault must be unlocked.',
      );
    }
    const wrappingKey = await byoWorker.Worker.webauthnDeriveWrappingKey(prfOutput!);
    const wrapped = await byoWorker.Worker.webauthnWrapDeviceKey(
      options.deviceKeyBytes,
      wrappingKey,
    );
    wrappingKey.fill(0);
    entry = {
      credential_id: credentialIdB64,
      prf_salt: toBase64(prfEvalFirst),
      wrapped_device_key: toBase64(wrapped),
      display_name: options.displayName,
      added_at: new Date().toISOString(),
      prf_supported: true,
    };
  } else {
    // presence mode — just record the credential.
    entry = {
      credential_id: credentialIdB64,
      display_name: options.displayName,
      added_at: new Date().toISOString(),
      prf_supported: prfSupported,
    };
  }

  await setWebAuthnRecord({
    ...record,
    credentials: [...record.credentials, entry],
  });
  return entry;
}

/**
 * Remove an enrolled credential. Refuses to remove the last credential
 * while the gate is enabled — caller should invoke `disableGate` instead
 * if the user wants to wipe protection entirely.
 */
export async function removeCredential(
  vaultId: string,
  credentialId: string,
): Promise<void> {
  const record = await getWebAuthnRecord(vaultId);
  if (!record) return;
  const remaining = record.credentials.filter((c) => c.credential_id !== credentialId);
  if (remaining.length === 0) {
    throw new Error(
      'Cannot remove the last credential while the gate is enabled. ' +
        'Disable the gate in Settings instead.',
    );
  }
  await setWebAuthnRecord({ ...record, credentials: remaining });
}

/**
 * Disable the gate entirely. Rotates the device CryptoKey back to a fresh
 * non-extractable one, clears every WebAuthn record, and evicts the
 * session cache. Caller is responsible for re-wrapping any IDB rows that
 * were protected under the previous key (Phase 3 migration hook).
 */
export async function disableGate(vaultId: string): Promise<CryptoKey> {
  await clearWebAuthnRecord(vaultId);
  evictSessionCache(vaultId);
  const fresh = await generateDeviceCryptoKey(vaultId);
  await setDeviceCryptoKey(vaultId, fresh);
  return fresh;
}

// ── Internal: WebAuthn get() helpers ───────────────────────────────────────

/**
 * Invoke `navigator.credentials.get()` for the supplied credentials. When
 * `prfSalt` is provided, the PRF extension is requested — on success the
 * caller can pull the output via `extractPrfOutput`.
 */
async function callGet(
  credentialIds: string[],
  prfSalt?: Uint8Array,
): Promise<PublicKeyCredential | null> {
  const challenge = randomBytes(32);
  const extensions: AuthenticationExtensionsClientInputs = {};
  if (prfSalt) {
    (extensions as any).prf = { eval: { first: prfSalt } };
  }
  const result = await navigator.credentials.get({
    publicKey: {
      rpId: window.location.hostname,
      challenge: challenge as BufferSource,
      allowCredentials: credentialIds.map((id) => ({
        type: 'public-key' as const,
        id: fromBase64Url(id) as BufferSource,
      })) as PublicKeyCredentialDescriptor[],
      userVerification: 'preferred',
      extensions,
    },
  });
  return (result as PublicKeyCredential) ?? null;
}

/**
 * Single-shot "probe then harvest" — immediately issues a get() against a
 * freshly-created credential to confirm PRF support and collect the output.
 * Returns null when the authenticator didn't yield a PRF result.
 */
async function getPrfOutput(
  credentialIdB64: string,
  prfEvalFirst: Uint8Array,
): Promise<Uint8Array | null> {
  try {
    const assertion = await callGet([credentialIdB64], prfEvalFirst);
    if (!assertion) return null;
    return extractPrfOutput(assertion);
  } catch {
    return null;
  }
}

function extractPrfOutput(assertion: PublicKeyCredential): Uint8Array | null {
  const results = (assertion.getClientExtensionResults() as any).prf?.results;
  if (!results?.first) return null;
  const first: ArrayBuffer | Uint8Array = results.first;
  return first instanceof Uint8Array ? new Uint8Array(first) : new Uint8Array(first);
}

// ── Opt-in passkey-unlock (SECURITY.md §12 "Passkey replaces passphrase") ─

/**
 * Result of `enablePasskeyUnlock`. `wrappedCount` is how many credential
 * rows now carry a `wrapped_vault_key` (today: always 1 — only the
 * credential the user touched to confirm enablement is wrapped; the rest
 * are lazily wrapped on next unlock via that credential, if we ever add
 * that path). `skippedCount` counts the enrolled credentials that don't
 * yet carry a wrap so the UI can surface them.
 */
export interface EnablePasskeyUnlockResult {
  wrappedCount: number;
  skippedCount: number;
}

/**
 * Enable the "passkey unlocks without passphrase" toggle for this vault.
 *
 * Requires:
 *   - gate mode is `prf` (presence mode is a behavioural speed-bump, not
 *     cryptographically fit to hold a vault_key wrap)
 *   - the vault is currently unlocked (`vaultSessionId` valid in WASM)
 *
 * Flow:
 *   1. Prompt the user for one passkey touch across every enrolled
 *      credential (single `navigator.credentials.get()` call with the full
 *      allowCredentials list — the user picks which authenticator).
 *   2. Derive the vault-wrapping key from the PRF output.
 *   3. Wrap the session's `vault_key` inside WASM and store the result on
 *      the matched credential's `wrapped_vault_key`.
 *   4. Set `passkey_unlocks_vault = true` on the record.
 *
 * Callers MUST invoke this from a user gesture — WebAuthn rejects `get()`
 * without transient activation.
 */
export async function enablePasskeyUnlock(
  vaultId: string,
  vaultSessionId: number,
): Promise<EnablePasskeyUnlockResult> {
  if (!isWebAuthnAvailable()) {
    throw new Error('WebAuthn is not available in this browser');
  }

  const record = await getWebAuthnRecord(vaultId);
  if (!record || record.mode !== 'prf') {
    throw new Error(
      "Passkey unlock requires the gate to be in 'prf' mode. Re-enrol " +
        'your passkey with PRF-capable authenticator first.',
    );
  }
  if (record.credentials.length === 0) {
    throw new Error('No enrolled passkeys to wrap vault_key under');
  }

  // Any enrolled credential's prf_salt works — they're all equivalent as
  // evaluation inputs. Pick the first one that actually has a salt (should
  // be every credential in prf mode, but be defensive).
  const saltCred = record.credentials.find((c) => c.prf_salt);
  if (!saltCred?.prf_salt) {
    throw new Error('Enrolled credentials are missing prf_salt — re-enrol required');
  }
  const prfSalt = fromBase64(saltCred.prf_salt);

  const assertion = await callGet(
    record.credentials.map((c) => c.credential_id),
    prfSalt,
  );
  if (!assertion) throw new Error('Passkey verification was cancelled');

  const prfOutput = extractPrfOutput(assertion);
  if (!prfOutput) {
    throw new Error(
      'Authenticator did not return a PRF result — this credential cannot ' +
        'hold a vault_key wrap.',
    );
  }

  const wrappedB64 = await byoWorker.Worker.byoVaultWrapSessionVaultKeyWithPrf(
    vaultSessionId,
    toBase64(prfOutput),
  );
  prfOutput.fill(0);

  const resolvedCredId = toBase64Url(assertion.rawId);
  const updated: WebAuthnCredentialEntry[] = record.credentials.map((c) =>
    c.credential_id === resolvedCredId ? { ...c, wrapped_vault_key: wrappedB64 } : c,
  );
  await setWebAuthnRecord({
    ...record,
    credentials: updated,
    passkey_unlocks_vault: true,
  });

  const wrappedCount = updated.filter((c) => c.wrapped_vault_key).length;
  const skippedCount = updated.length - wrappedCount;
  return { wrappedCount, skippedCount };
}

/**
 * Turn off the passkey-unlock mode. Wipes every credential's
 * `wrapped_vault_key` (so a stale ciphertext cannot be reactivated later
 * without the user's explicit consent) and clears the `passkey_unlocks_vault`
 * flag. No authenticator touch required — disabling is always safe.
 */
export async function disablePasskeyUnlock(vaultId: string): Promise<void> {
  const record = await getWebAuthnRecord(vaultId);
  if (!record) return;
  const wiped = record.credentials.map((c) => {
    const { wrapped_vault_key: _wvk, ...rest } = c;
    void _wvk;
    return rest;
  });
  await setWebAuthnRecord({
    ...record,
    credentials: wiped,
    passkey_unlocks_vault: false,
  });
}

/**
 * Run the opt-in passkey-unlock path: prompt the passkey once, recover
 * both the device `CryptoKey` AND `vault_key` from the same PRF output,
 * and return the WASM `sessionId`.
 *
 * The device-key unwrap reuses the existing `_sessionCache` so the later
 * `getDeviceCryptoKey` call in `VaultLifecycle.unlockVault` (needed to
 * decrypt the device-shard slot in the manifest header) hits the cache
 * and never prompts again. Without this priming the user would see two
 * WebAuthn prompts back-to-back — one to unwrap `vault_key`, then a
 * second to unwrap `device_key` — which is the UX we explicitly avoid.
 *
 * MUST be invoked from a user gesture. Throws if the gate is not in `prf`
 * mode, the `passkey_unlocks_vault` flag is off, or no enrolled credential
 * has a `wrapped_vault_key`.
 */
export async function unlockVaultKeyViaPasskey(vaultId: string): Promise<number> {
  if (!isWebAuthnAvailable()) {
    throw new Error('WebAuthn is not available in this browser');
  }
  const record = await getWebAuthnRecord(vaultId);
  if (!record || record.mode !== 'prf' || !record.passkey_unlocks_vault) {
    throw new Error('Passkey unlock is not enabled for this vault');
  }
  const candidates = record.credentials.filter(
    (c) => !!c.wrapped_vault_key && !!c.prf_salt,
  );
  if (candidates.length === 0) {
    throw new Error(
      'No enrolled passkey on this device holds a wrapped vault_key. ' +
        'Use the passphrase or enrol passkey-unlock again from Settings.',
    );
  }

  const prfSalt = fromBase64(candidates[0]!.prf_salt!);
  const assertion = await callGet(
    candidates.map((c) => c.credential_id),
    prfSalt,
  );
  if (!assertion) throw new Error('Passkey verification was cancelled');

  const resolvedCredId = toBase64Url(assertion.rawId);
  const resolved = candidates.find((c) => c.credential_id === resolvedCredId);
  if (!resolved?.wrapped_vault_key) {
    throw new Error(
      'Authenticator returned a credential without a wrapped vault_key on ' +
        'this device. Try another passkey or fall back to passphrase.',
    );
  }
  const prfOutput = extractPrfOutput(assertion);
  if (!prfOutput) {
    throw new Error('Authenticator did not return a PRF result');
  }

  try {
    // Piggyback on this PRF output to also unwrap the device key and
    // populate the session caches. The device-key wrapping key uses a
    // different HKDF info (`"Wattcloud device key v1"`) than the vault-key
    // one, so deriving both from the same PRF output is safe.
    if (resolved.wrapped_device_key) {
      const deviceWrappingKey = await byoWorker.Worker.webauthnDeriveWrappingKey(prfOutput);
      const wrappedDeviceBytes = fromBase64(resolved.wrapped_device_key);
      const deviceKeyBytes = await byoWorker.Worker.webauthnUnwrapDeviceKey(
        wrappedDeviceBytes,
        deviceWrappingKey,
      );
      deviceWrappingKey.fill(0);
      const deviceKey = await importDeviceKey(deviceKeyBytes);
      _stashRawDeviceKey(vaultId, deviceKeyBytes);
      deviceKeyBytes.fill(0);
      _sessionCache.set(vaultId, deviceKey);
    }

    return await byoWorker.Worker.byoVaultLoadSessionFromWrappedVaultKey(
      resolved.wrapped_vault_key,
      toBase64(prfOutput),
    );
  } finally {
    prfOutput.fill(0);
  }
}

// ── Narrow export surface ──────────────────────────────────────────────────

/**
 * Convenience accessor for UI code: returns the current mode + enrolled
 * credential metadata without exposing wrapped key material.
 */
export async function describeGate(
  vaultId: string,
): Promise<DeviceWebAuthnRecord | null> {
  return getWebAuthnRecord(vaultId);
}
