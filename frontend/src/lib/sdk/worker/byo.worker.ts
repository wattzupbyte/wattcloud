/**
 * BYO Web Worker for cryptographic operations.
 *
 * SECURITY: Keys are stored in this worker's memory, isolated from the main
 * thread. XSS attacks on the main thread cannot access key material directly.
 * All cryptographic operations are performed in this worker context.
 *
 * This worker is independent from the frontend's crypto.worker.ts. It loads
 * sdk-wasm directly and only handles BYO-specific operations:
 *   - V7 streaming encrypt/decrypt (for file I/O through StorageProvider)
 *   - BYO vault operations (parse, derive, wrap/unwrap, encrypt/decrypt body)
 *   - BYO enrollment operations (initiate, derive session, encrypt/decrypt shard)
 *   - Atomic filename encryption (for vault metadata)
 *
 * Managed-mode operations (storeKeys, getKeys, etc.) are NOT included here —
 * they belong to the frontend worker. The getKeys handler is intentionally
 * omitted: raw secret keys must never leave the worker.
 */

// ── Worker initialization state ────────────────────────────────────────────

let wasmReady = false;
let initPromise: Promise<void> | null = null;

// ── WASM function references (loaded dynamically) ──────────────────────────

let init: (module_or_path?: string | URL | Request) => Promise<void>;
let V7StreamDecryptorWasm: any;
let V7StreamEncryptorWasm: any;
let encrypt_filename_with_fresh_key: any;
let decrypt_file_v7: any;
let decrypt_filename: any;

// BYO vault WASM functions
let byo_parse_vault_header: any;
let byo_derive_vault_keys: any;
// Exposed by the WASM module but not yet called from this worker. Kept
// bound (via the `wasmModule.byo_derive_vault_keys_default` assignment
// below) so adding a caller doesn't need to re-edit the wire-up block.
let _byo_derive_vault_keys_default: any;
let byo_unwrap_vault_key: any;
let byo_derive_kek: any;
let byo_derive_recovery_vault_kek: any;
let byo_compute_header_hmac: any;
let byo_verify_header_hmac: any;
let byo_wrap_vault_key: any;
let byo_encrypt_vault_body: any;
let byo_decrypt_vault_body: any;
let byo_generate_vault_keys: any;

// BYO enrollment WASM functions (legacy)
let byo_enrollment_initiate: any;
let byo_enrollment_derive_session: any;
let byo_enrollment_encrypt_shard: any;
let byo_enrollment_decrypt_shard: any;

// BYO enrollment session WASM functions (ZK-safe)
let byo_enrollment_open: any;
let byo_enrollment_join: any;
let byo_enrollment_derive_keys: any;
let byo_enrollment_session_encrypt_shard: any;
let byo_enrollment_session_decrypt_shard: any;
let byo_enrollment_session_get_shard: any;
let byo_enrollment_session_encrypt_payload: any;
let byo_enrollment_session_decrypt_payload: any;
let byo_enrollment_close: any;

// BYO device signing key WASM functions (v2 vault)
let byo_generate_device_signing_key: any;
let byo_seal_device_signing_key: any;
let byo_unseal_device_signing_key: any;
let byo_ed25519_sign: any;
let byo_ed25519_verify: any;
let byo_migrate_vault_v1_to_v2: any;

// BYO vault session API (ZK-safe: vault_key/kek never cross WASM boundary)
let byo_vault_create: any;
let byo_vault_open: any;
let byo_vault_open_recovery: any;
let byo_vault_wrap_recovery: any;
let byo_vault_rewrap_with_passphrase: any;
let byo_vault_close: any;
let byo_vault_verify_header_hmac: any;
let byo_vault_decrypt_body: any;
let byo_vault_encrypt_body: any;
let byo_vault_compute_header_hmac: any;
let byo_vault_derive_kek: any;
let byo_vault_load_keys: any;
let byo_vault_derive_subkey: any;
let byo_vault_generate_keypair_wrapped: any;
let byo_vault_seal_device_signing_key: any;
// WebAuthn PRF-gated device-key protection (SECURITY.md §12).
let webauthn_derive_wrapping_key: any;
let webauthn_wrap_device_key: any;
let webauthn_unwrap_device_key: any;
let webauthn_generate_device_key: any;
// Opt-in passkey-unlock (vault_key wrapped under PRF, SECURITY.md §12).
let webauthn_derive_vault_key_wrapping_key: any;
let webauthn_wrap_vault_key: any;
let webauthn_unwrap_vault_key: any;
let byo_vault_wrap_session_vault_key_with_prf: any;
let byo_vault_load_session_from_wrapped_vault_key: any;
let byo_vault_unseal_device_signing_key: any;
let byo_vault_migrate_v1_to_v2: any;
let byo_vault_rewrap: any;

// OAuth / PKCE
let generate_pkce: any;
let provider_oauth_config_wasm: any;
let build_auth_url_wasm: any;
let build_token_exchange_form_wasm: any;
let build_refresh_form_wasm: any;
let parse_token_response_wasm: any;

// V7 sizing helpers
let v7_cipher_size_wasm: any;
let v7_encrypt_chunk_size_wasm: any;

// FooterTrimmer
let FooterTrimmerWasm: any;

// BYO streaming flows (Phase 2)
let ByoDownloadFlowWasm: any;
let ByoUploadFlowWasm: any;

// BYO Rust provider OAuth token refresh (used by byoRefreshConfigByHandle)
let byo_gdrive_refresh_token: any;
let byo_dropbox_refresh_token: any;
let byo_onedrive_refresh_token: any;
let byo_box_refresh_token: any;
let byo_pcloud_refresh_token: any;

// Generic provider dispatcher (P8)
let byo_provider_call: any;

// Cross-provider streaming pipe (Phase 3c) — runs entirely in WASM, no bytes cross the JS boundary
let byo_cross_provider_stream_copy: any;

// Provider-integrated upload/download streaming sessions (Phase 3d)
let byo_stream_upload_init: any;
let byo_stream_upload_push: any;
let byo_stream_upload_finalize: any;
let byo_stream_upload_abort: any;
let byo_stream_download_init: any;
let byo_stream_download_pull: any;
let byo_stream_download_close: any;

// Stats (Phase 5)
let stats_init: any;
let stats_record: any;
let stats_drain: any;
let stats_flush: any;

// Share link crypto (P10)
let byo_create_share_fragment: any;
let byo_bundle_extract_file_key: any;
let byo_encrypt_manifest_v7: any;
let byo_share_encode_variant_a: any;
let byo_share_decode_variant_a: any;
let byo_share_wrap_key: any;
let byo_share_unwrap_key: any;

// Relay auth / PoW
let byo_derive_sftp_purpose_wasm: any;
let byo_derive_enrollment_purpose_wasm: any;
let byo_solve_relay_pow_wasm: any;

// Journal codec WASM functions (P3.1)
let byo_journal_append: any;
let byo_journal_parse: any;
let byo_share_audit_payload: any;

// Row-merge WASM function (P3.2)
let byo_merge_rows: any;

// Manifest mutation WASM functions (P3.3)
let byo_manifest_add_provider: any;
let byo_manifest_rename_provider: any;
let byo_manifest_set_primary_provider: any;
let byo_manifest_tombstone_provider: any;
let byo_manifest_update_provider_config: any;

// R6 multi-vault WASM functions
let byo_manifest_encrypt: any;
let byo_manifest_decrypt: any;
let byo_manifest_merge: any;
let byo_manifest_validate: any;
let byo_vault_body_encrypt: any;
let byo_vault_body_decrypt: any;
let byo_derive_per_vault_wal_key: any;
let byo_derive_per_vault_journal_keys: any;
let byo_plan_unlock: any;
let byo_plan_save: any;
let byo_plan_cross_provider_move: any;
let byo_cross_provider_move_decide_replay: any;
let byo_cross_provider_move_plan_reconcile: any;
let byo_derive_manifest_aead_key: any;

// ── Session maps ───────────────────────────────────────────────────────────

// Active streaming-decrypt sessions (sessionId → WASM decryptor)
const streamDecryptSessions = new Map<string, any>();

// Active streaming-encrypt sessions (sessionId → WASM encryptor)
const streamEncryptSessions = new Map<string, any>();

// Active FooterTrimmer sessions (trimId → WASM FooterTrimmer)
const footerTrimmerSessions = new Map<string, any>();

// Active ByoDownloadFlow sessions (sessionId → WASM ByoDownloadFlow)
const byoDownloadFlowSessions = new Map<string, any>();

// Active ByoUploadFlow sessions (sessionId → WASM ByoUploadFlow)
const byoUploadFlowSessions = new Map<string, any>();

// Provider config registry (R1.4) — keyed by opaque handle (UUID).
// configJson (containing credentials) is stored here and never returned to the main thread.
const configRegistry = new Map<string, string>();

// ── Key storage (BYO-mode: userId not used, stored by sessionId) ───────────

interface ByoKeyBundle {
  mlkem_secret_key: Uint8Array;
  x25519_secret_key: Uint8Array;
  timestamp: number;
}

const keyRegistry = new WeakMap<object, ByoKeyBundle>();
const activeKeys = new Map<string, { handle: object }>();

// ── KDF rate limiter ───────────────────────────────────────────────────────
// Prevents XSS from looping 128 MB Argon2id calls to hang or heat the device.
// Budget: 3 calls per 60 s rolling window; locked 10 min after 10 total calls.

const KDF_WINDOW_MS = 60_000;       // rolling window
const KDF_LIMIT = 3;                // calls allowed per window
const KDF_LOCK_THRESHOLD = 10;      // total calls before lock
const KDF_LOCK_DURATION_MS = 600_000; // 10-minute lock

const kdfState = {
  windowCalls: [] as number[],   // timestamps of calls in current window
  totalCalls: 0,                 // lifetime calls (reset on lock expiry)
  lockUntil: null as number | null,
};

function checkKdfRateLimit(): void {
  const now = Date.now();

  if (kdfState.lockUntil !== null) {
    if (now < kdfState.lockUntil) {
      const mins = Math.ceil((kdfState.lockUntil - now) / 60_000);
      throw new Error(`KDF locked due to excessive attempts. Try again in ${mins} minute(s).`);
    }
    // Lock expired — reset
    kdfState.lockUntil = null;
    kdfState.windowCalls = [];
    kdfState.totalCalls = 0;
  }

  // Evict calls outside the rolling window
  kdfState.windowCalls = kdfState.windowCalls.filter(t => now - t < KDF_WINDOW_MS);

  if (kdfState.windowCalls.length >= KDF_LIMIT) {
    kdfState.totalCalls++;
    if (kdfState.totalCalls >= KDF_LOCK_THRESHOLD) {
      kdfState.lockUntil = now + KDF_LOCK_DURATION_MS;
    }
    throw new Error('KDF rate limit exceeded. Please wait before retrying.');
  }

  kdfState.windowCalls.push(now);
  kdfState.totalCalls++;
}

// ── Destructive-operation token store ─────────────────────────────────────
// byoEncryptVaultBody (vault overwrite) requires a one-time token issued by
// byoRequestDestructiveToken. The main thread must call byoRequestDestructiveToken
// before each vault save, typically gated behind a user-initiated action, so that
// XSS alone cannot silently overwrite vault content without triggering the user-
// gesture path in the UI code.
//
// Security note: this is defense-in-depth. Sophisticated XSS that controls the
// main thread can request a token and immediately use it. The primary value is
// (a) slowing down naive XSS payloads and (b) making vault writes architecturally
// explicit at the protocol level.

const DESTRUCTIVE_TOKEN_TTL_MS = 30_000; // tokens expire after 30 seconds

// token → expiry timestamp
const destructiveTokens = new Map<string, number>();

function issueDestructiveToken(): string {
  // Prune expired tokens
  const now = Date.now();
  for (const [tok, exp] of destructiveTokens) {
    if (now > exp) destructiveTokens.delete(tok);
  }

  // Generate 16-byte random hex token
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const token = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  destructiveTokens.set(token, now + DESTRUCTIVE_TOKEN_TTL_MS);
  return token;
}

function consumeDestructiveToken(token: string | undefined): void {
  if (!token) {
    throw new Error('Vault write requires a destructive-operation token. Call byoRequestDestructiveToken first.');
  }
  const exp = destructiveTokens.get(token);
  if (exp === undefined || Date.now() > exp) {
    destructiveTokens.delete(token);
    throw new Error('Destructive-operation token is invalid or expired.');
  }
  destructiveTokens.delete(token);
}

// ── SFTP credentials ───────────────────────────────────────────────────────
// Credentials now live inside the main-thread WASM heap (sdk-wasm exports
// `sftp_store_credential_password` / `sftp_store_credential_publickey`) and
// are consumed by `SftpSessionWasm.auth_with_handle`. They are never stored
// as JS strings, so no worker-side registry is required.

// ── OAuth PKCE verifier registry ───────────────────────────────────────────
// Verifiers are stored here (worker memory, isolated from main-thread XSS).
// Keyed by random state string; dropped on successful exchange or on error.

interface OAuthPendingFlow {
  verifier: string;
  clientId: string;
  redirectUri: string;
  createdAt: number; // Date.now() — used for TTL eviction
}

const oauthPendingFlows = new Map<string, OAuthPendingFlow>();
const OAUTH_FLOW_TTL_MS = 5 * 60 * 1000; // 5 min

// Sweep stale pending flows every 5 minutes.
setInterval(() => {
  const now = Date.now();
  for (const [state, flow] of oauthPendingFlows) {
    if (now - flow.createdAt > OAUTH_FLOW_TTL_MS) oauthPendingFlows.delete(state);
  }
}, OAUTH_FLOW_TTL_MS);

// ── Helper functions ───────────────────────────────────────────────────────

function toBase64(arr: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    arr[i] = binary.charCodeAt(i);
  }
  return arr;
}

function zeroizeArray(arr: Uint8Array): void {
  crypto.getRandomValues(arr);
  arr.fill(0);
}

function storeKeys(
  sessionId: string,
  mlkemSecretKey: Uint8Array,
  x25519SecretKey: Uint8Array,
): void {
  const handle: object = {};
  const entry: ByoKeyBundle = {
    mlkem_secret_key: new Uint8Array(mlkemSecretKey),
    x25519_secret_key: new Uint8Array(x25519SecretKey),
    timestamp: Date.now(),
  };
  keyRegistry.set(handle, entry);
  activeKeys.set(sessionId, { handle });
}

function retrieveKeys(sessionId: string): ByoKeyBundle | null {
  const entry = activeKeys.get(sessionId);
  if (!entry) return null;
  // Return a direct reference — no copy. The worker is single-threaded so
  // this is safe. Avoiding copies prevents key material from lingering in
  // additional heap allocations that can't be zeroized.
  return keyRegistry.get(entry.handle) ?? null;
}

function clearSessionKeys(sessionId: string): void {
  const entry = activeKeys.get(sessionId);
  if (entry) {
    const keys = keyRegistry.get(entry.handle);
    if (keys) {
      zeroizeArray(keys.mlkem_secret_key);
      zeroizeArray(keys.x25519_secret_key);
    }
    activeKeys.delete(sessionId);
  }
}

function clearAllKeys(): void {
  for (const [, entry] of activeKeys) {
    const keys = keyRegistry.get(entry.handle);
    if (keys) {
      zeroizeArray(keys.mlkem_secret_key);
      zeroizeArray(keys.x25519_secret_key);
    }
  }
  activeKeys.clear();
}

// ── WASM initialization ────────────────────────────────────────────────────

async function initWasm(): Promise<void> {
  if (wasmReady) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    // Dynamic import — resolves to sdk-wasm pkg directory at build time
    const wasmModule = await import('@wattcloud/wasm') as any;

    init = wasmModule.default || wasmModule.init;
    V7StreamDecryptorWasm = wasmModule.V7StreamDecryptorWasm;
    V7StreamEncryptorWasm = wasmModule.V7StreamEncryptorWasm;
    encrypt_filename_with_fresh_key = wasmModule.encrypt_filename_with_fresh_key;
    decrypt_file_v7 = wasmModule.decrypt_file_v7;
    decrypt_filename = wasmModule.decrypt_filename;

    byo_parse_vault_header = wasmModule.byo_parse_vault_header;
    byo_derive_vault_keys = wasmModule.byo_derive_vault_keys;
    _byo_derive_vault_keys_default = wasmModule.byo_derive_vault_keys_default;
    byo_unwrap_vault_key = wasmModule.byo_unwrap_vault_key;
    byo_derive_kek = wasmModule.byo_derive_kek;
    byo_derive_recovery_vault_kek = wasmModule.byo_derive_recovery_vault_kek;
    byo_compute_header_hmac = wasmModule.byo_compute_header_hmac;
    byo_verify_header_hmac = wasmModule.byo_verify_header_hmac;
    byo_wrap_vault_key = wasmModule.byo_wrap_vault_key;
    byo_encrypt_vault_body = wasmModule.byo_encrypt_vault_body;
    byo_decrypt_vault_body = wasmModule.byo_decrypt_vault_body;
    byo_generate_vault_keys = wasmModule.byo_generate_vault_keys;

    byo_enrollment_initiate = wasmModule.byo_enrollment_initiate;
    byo_enrollment_derive_session = wasmModule.byo_enrollment_derive_session;
    byo_enrollment_encrypt_shard = wasmModule.byo_enrollment_encrypt_shard;
    byo_enrollment_decrypt_shard = wasmModule.byo_enrollment_decrypt_shard;

    byo_enrollment_open = wasmModule.byo_enrollment_open;
    byo_enrollment_join = wasmModule.byo_enrollment_join;
    byo_enrollment_derive_keys = wasmModule.byo_enrollment_derive_keys;
    byo_enrollment_session_encrypt_shard = wasmModule.byo_enrollment_session_encrypt_shard;
    byo_enrollment_session_decrypt_shard = wasmModule.byo_enrollment_session_decrypt_shard;
    byo_enrollment_session_get_shard = wasmModule.byo_enrollment_session_get_shard;
    byo_enrollment_session_encrypt_payload = wasmModule.byo_enrollment_session_encrypt_payload;
    byo_enrollment_session_decrypt_payload = wasmModule.byo_enrollment_session_decrypt_payload;
    byo_enrollment_close = wasmModule.byo_enrollment_close;

    byo_generate_device_signing_key = wasmModule.byo_generate_device_signing_key;
    byo_seal_device_signing_key = wasmModule.byo_seal_device_signing_key;
    byo_unseal_device_signing_key = wasmModule.byo_unseal_device_signing_key;
    byo_ed25519_sign = wasmModule.byo_ed25519_sign;
    byo_ed25519_verify = wasmModule.byo_ed25519_verify;
    byo_migrate_vault_v1_to_v2 = wasmModule.byo_migrate_vault_v1_to_v2;

    // Vault session API
    byo_vault_create = wasmModule.byo_vault_create;
    byo_vault_open = wasmModule.byo_vault_open;
    byo_vault_open_recovery = wasmModule.byo_vault_open_recovery;
    byo_vault_wrap_recovery = wasmModule.byo_vault_wrap_recovery;
    byo_vault_rewrap_with_passphrase = wasmModule.byo_vault_rewrap_with_passphrase;
    byo_vault_close = wasmModule.byo_vault_close;
    byo_vault_verify_header_hmac = wasmModule.byo_vault_verify_header_hmac;
    byo_vault_decrypt_body = wasmModule.byo_vault_decrypt_body;
    byo_vault_encrypt_body = wasmModule.byo_vault_encrypt_body;
    byo_vault_compute_header_hmac = wasmModule.byo_vault_compute_header_hmac;
    byo_vault_derive_kek = wasmModule.byo_vault_derive_kek;
    byo_vault_load_keys = wasmModule.byo_vault_load_keys;
    byo_vault_derive_subkey = wasmModule.byo_vault_derive_subkey;
    byo_vault_generate_keypair_wrapped = wasmModule.byo_vault_generate_keypair_wrapped;
    byo_vault_seal_device_signing_key = wasmModule.byo_vault_seal_device_signing_key;
    webauthn_derive_wrapping_key = wasmModule.webauthn_derive_wrapping_key;
    webauthn_wrap_device_key = wasmModule.webauthn_wrap_device_key;
    webauthn_unwrap_device_key = wasmModule.webauthn_unwrap_device_key;
    webauthn_generate_device_key = wasmModule.webauthn_generate_device_key;
    webauthn_derive_vault_key_wrapping_key = wasmModule.webauthn_derive_vault_key_wrapping_key;
    webauthn_wrap_vault_key = wasmModule.webauthn_wrap_vault_key;
    webauthn_unwrap_vault_key = wasmModule.webauthn_unwrap_vault_key;
    byo_vault_wrap_session_vault_key_with_prf =
      wasmModule.byo_vault_wrap_session_vault_key_with_prf;
    byo_vault_load_session_from_wrapped_vault_key =
      wasmModule.byo_vault_load_session_from_wrapped_vault_key;
    byo_vault_unseal_device_signing_key = wasmModule.byo_vault_unseal_device_signing_key;
    byo_vault_migrate_v1_to_v2 = wasmModule.byo_vault_migrate_v1_to_v2;
    byo_vault_rewrap = wasmModule.byo_vault_rewrap;

    generate_pkce = wasmModule.generatePkce;
    provider_oauth_config_wasm = wasmModule.providerOAuthConfig;
    build_auth_url_wasm = wasmModule.buildAuthUrl;
    build_token_exchange_form_wasm = wasmModule.buildTokenExchangeForm;
    build_refresh_form_wasm = wasmModule.buildRefreshForm;
    parse_token_response_wasm = wasmModule.parseTokenResponse;
    v7_cipher_size_wasm = wasmModule.v7CipherSize;
    v7_encrypt_chunk_size_wasm = wasmModule.v7EncryptChunkSize;
    FooterTrimmerWasm = wasmModule.FooterTrimmer;
    ByoDownloadFlowWasm = wasmModule.ByoDownloadFlow;
    ByoUploadFlowWasm = wasmModule.ByoUploadFlow;

    byo_gdrive_refresh_token = wasmModule.byoGdriveRefreshToken;
    byo_dropbox_refresh_token = wasmModule.byoDropboxRefreshToken;
    byo_onedrive_refresh_token = wasmModule.byoOnedriveRefreshToken;
    byo_box_refresh_token = wasmModule.byoBoxRefreshToken;
    byo_pcloud_refresh_token = wasmModule.byoPcloudRefreshToken;

    byo_provider_call = wasmModule.byoProviderCall;
    byo_cross_provider_stream_copy = wasmModule.byoCrossProviderStreamCopy;

    byo_stream_upload_init     = wasmModule.byoStreamUploadInit;
    byo_stream_upload_push     = wasmModule.byoStreamUploadPush;
    byo_stream_upload_finalize = wasmModule.byoStreamUploadFinalize;
    byo_stream_upload_abort    = wasmModule.byoStreamUploadAbort;
    byo_stream_download_init   = wasmModule.byoStreamDownloadInit;
    byo_stream_download_pull   = wasmModule.byoStreamDownloadPull;
    byo_stream_download_close  = wasmModule.byoStreamDownloadClose;

    byo_create_share_fragment = wasmModule.byo_create_share_fragment;
    byo_bundle_extract_file_key = wasmModule.byo_bundle_extract_file_key;
    byo_encrypt_manifest_v7 = wasmModule.byoEncryptManifestV7;
    byo_share_encode_variant_a = wasmModule.byo_share_encode_variant_a;
    byo_share_decode_variant_a = wasmModule.byo_share_decode_variant_a;
    byo_share_wrap_key = wasmModule.byo_share_wrap_key;
    byo_share_unwrap_key = wasmModule.byo_share_unwrap_key;

    byo_derive_sftp_purpose_wasm = wasmModule.byo_derive_sftp_purpose;
    byo_derive_enrollment_purpose_wasm = wasmModule.byo_derive_enrollment_purpose;
    byo_solve_relay_pow_wasm = wasmModule.byo_solve_relay_pow;

    // R6 multi-vault
    byo_manifest_encrypt = wasmModule.byo_manifest_encrypt;
    byo_manifest_decrypt = wasmModule.byo_manifest_decrypt;
    byo_manifest_merge = wasmModule.byo_manifest_merge;
    byo_manifest_validate = wasmModule.byo_manifest_validate;
    byo_vault_body_encrypt = wasmModule.byo_vault_body_encrypt;
    byo_vault_body_decrypt = wasmModule.byo_vault_body_decrypt;
    byo_derive_per_vault_wal_key = wasmModule.byo_derive_per_vault_wal_key;
    byo_derive_per_vault_journal_keys = wasmModule.byo_derive_per_vault_journal_keys;
    byo_plan_unlock = wasmModule.byo_plan_unlock;
    byo_plan_save = wasmModule.byo_plan_save;
    byo_plan_cross_provider_move = wasmModule.byo_plan_cross_provider_move;
    byo_cross_provider_move_decide_replay = wasmModule.byo_cross_provider_move_decide_replay;
    byo_cross_provider_move_plan_reconcile = wasmModule.byo_cross_provider_move_plan_reconcile;
    byo_derive_manifest_aead_key = wasmModule.byo_derive_manifest_aead_key;

    // Journal codec (P3.1)
    byo_journal_append = wasmModule.byo_journal_append;
    byo_journal_parse = wasmModule.byo_journal_parse;
    byo_share_audit_payload = wasmModule.byo_share_audit_payload;

    // Row-merge (P3.2)
    byo_merge_rows = wasmModule.byo_merge_rows;

    // Manifest mutations (P3.3)
    byo_manifest_add_provider = wasmModule.byo_manifest_add_provider;
    byo_manifest_rename_provider = wasmModule.byo_manifest_rename_provider;
    byo_manifest_set_primary_provider = wasmModule.byo_manifest_set_primary_provider;
    byo_manifest_tombstone_provider = wasmModule.byo_manifest_tombstone_provider;
    byo_manifest_update_provider_config = wasmModule.byo_manifest_update_provider_config;

    // Stats (Phase 5)
    stats_init = wasmModule.statsInit;
    stats_record = wasmModule.statsRecord;
    stats_drain = wasmModule.statsDrain;
    stats_flush = wasmModule.statsFlush;

    await init();
    wasmReady = true;
  })();

  return initPromise;
}

// ── Request types ──────────────────────────────────────────────────────────

interface StoreKeysRequest {
  type: 'storeKeys';
  sessionId: string;
  mlkemSecretKey: number[];
  x25519SecretKey: number[];
}


interface ClearKeysRequest {
  type: 'clearKeys';
  sessionId?: string;
}

interface ClearAllRequest {
  type: 'clearAll';
}

interface HasKeysRequest {
  type: 'hasKeys';
  sessionId: string;
}

// V7 streaming encrypt
interface V7EncryptInitRequest {
  type: 'v7EncryptInit';
  sessionId: string;
  publicKeysJson: string;
}

interface V7EncryptTakeHeaderRequest {
  type: 'v7EncryptTakeHeader';
  sessionId: string;
}

interface V7EncryptPushRequest {
  type: 'v7EncryptPush';
  sessionId: string;
  plaintext: ArrayBuffer;
}

interface V7EncryptFinalizeRequest {
  type: 'v7EncryptFinalize';
  sessionId: string;
}

interface V7EncryptAbortRequest {
  type: 'v7EncryptAbort';
  sessionId: string;
}

// V7 streaming decrypt
interface V7DecryptInitRequest {
  type: 'v7DecryptInit';
  sessionId: string;
  headerBytes: ArrayBuffer;
  secKeysJson: string;
  /** BYO mode: session ID that holds private keys (defaults to sessionId if omitted). */
  keySessionId?: string;
}

interface V7DecryptPushRequest {
  type: 'v7DecryptPush';
  sessionId: string;
  data: ArrayBuffer;
}

interface V7DecryptFinalizeRequest {
  type: 'v7DecryptFinalize';
  sessionId: string;
  storedHmac: ArrayBuffer;
}

interface V7DecryptAbortRequest {
  type: 'v7DecryptAbort';
  sessionId: string;
}

// Atomic filename encryption
interface EncryptFilenameAtomicRequest {
  type: 'encryptFilenameAtomic';
  filename: string;
  metadata?: string | null;
  publicKeysJson: string;
}

// BYO filename decryption
interface ByoDecryptFilenameRequest {
  type: 'byoDecryptFilename';
  encryptedFilenameB64: string;
  encryptedFilenameKeyB64: string;
  sessionId: string;
}

// BYO vault operations
interface ByoParseVaultHeaderRequest {
  type: 'byoParseVaultHeader';
  vaultBytes: ArrayBuffer;
}

interface ByoDeriveVaultKeysRequest {
  type: 'byoDeriveVaultKeys';
  password: string;
  saltB64: string;
  memoryKb: number;
  // C2: the WASM signature requires all three Argon2id params. Missing values
  // coerced to 0 via JS `undefined`, producing a silent derivation failure.
  iterations: number;
  parallelism: number;
}

interface ByoUnwrapVaultKeyRequest {
  type: 'byoUnwrapVaultKey';
  wrapIvB64: string;
  wrappedKeyB64: string;
  unwrappingKeyB64: string;
}

interface ByoDeriveKekRequest {
  type: 'byoDeriveKek';
  clientKekHalfB64: string;
  shardB64: string;
}

interface ByoDeriveRecoveryVaultKekRequest {
  type: 'byoDeriveRecoveryVaultKek';
  recoveryKeyB64: string;
}

interface ByoComputeHeaderHmacRequest {
  type: 'byoComputeHeaderHmac';
  vaultKeyB64: string;
  headerPrefixB64: string;
}

interface ByoVerifyHeaderHmacRequest {
  type: 'byoVerifyHeaderHmac';
  vaultKeyB64: string;
  headerPrefixB64: string;
  expectedHmacB64: string;
}

interface ByoWrapVaultKeyRequest {
  type: 'byoWrapVaultKey';
  vaultKeyB64: string;
  wrappingKeyB64: string;
}

interface ByoEncryptVaultBodyRequest {
  type: 'byoEncryptVaultBody';
  sqliteBytes: ArrayBuffer;
  vaultKeyB64: string;
  /** One-time token from byoRequestDestructiveToken — required for vault writes. */
  opToken: string;
}

interface ByoDecryptVaultBodyRequest {
  type: 'byoDecryptVaultBody';
  nonceAndCt: ArrayBuffer;
  vaultKeyB64: string;
}

interface ByoGenerateVaultKeysRequest {
  type: 'byoGenerateVaultKeys';
}

// Vault session API request types (ZK-safe: vault_key/kek stay in WASM)
interface ByoVaultOpenRequest {
  type: 'byoVaultOpen';
  password: string;
  saltB64: string;
  memoryKb: number;
  iterations: number;
  parallelism: number;
  wrapIvB64: string;
  wrappedVaultKeyB64: string;
}

interface ByoVaultCloseRequest {
  type: 'byoVaultClose';
  sessionId: number;
}

interface ByoVaultVerifyHeaderHmacRequest {
  type: 'byoVaultVerifyHeaderHmac';
  sessionId: number;
  headerPrefixB64: string;
  expectedHmacB64: string;
}

interface ByoVaultDecryptBodyRequest {
  type: 'byoVaultDecryptBody';
  sessionId: number;
  nonceAndCt: ArrayBuffer;
}

interface ByoVaultEncryptBodyRequest {
  type: 'byoVaultEncryptBody';
  sessionId: number;
  sqliteBytes: ArrayBuffer;
  opToken: string;
}

interface ByoVaultComputeHeaderHmacRequest {
  type: 'byoVaultComputeHeaderHmac';
  sessionId: number;
  headerPrefixB64: string;
}

interface ByoVaultDeriveKekRequest {
  type: 'byoVaultDeriveKek';
  sessionId: number;
  shardB64: string;
}

interface ByoVaultLoadKeysRequest {
  type: 'byoVaultLoadKeys';
  sessionId: number;
  mlkemSkEncrypted: ArrayBuffer;
  x25519SkEncrypted: ArrayBuffer;
  keySessionId: string;
}

interface ByoVaultDeriveSubkeyRequest {
  type: 'byoVaultDeriveSubkey';
  sessionId: number;
  purpose: string;
}

interface ByoVaultGenerateKeypairWrappedRequest {
  type: 'byoVaultGenerateKeypairWrapped';
  sessionId: number;
}

interface WebauthnDeriveWrappingKeyRequest {
  type: 'webauthnDeriveWrappingKey';
  prfOutput: ArrayBuffer;
}

interface WebauthnWrapDeviceKeyRequest {
  type: 'webauthnWrapDeviceKey';
  deviceKey: ArrayBuffer;
  wrappingKey: ArrayBuffer;
}

interface WebauthnUnwrapDeviceKeyRequest {
  type: 'webauthnUnwrapDeviceKey';
  wrapped: ArrayBuffer;
  wrappingKey: ArrayBuffer;
}

interface WebauthnGenerateDeviceKeyRequest {
  type: 'webauthnGenerateDeviceKey';
}

interface WebauthnDeriveVaultKeyWrappingKeyRequest {
  type: 'webauthnDeriveVaultKeyWrappingKey';
  prfOutput: ArrayBuffer;
}

interface WebauthnWrapVaultKeyRequest {
  type: 'webauthnWrapVaultKey';
  vaultKey: ArrayBuffer;
  wrappingKey: ArrayBuffer;
}

interface WebauthnUnwrapVaultKeyRequest {
  type: 'webauthnUnwrapVaultKey';
  wrapped: ArrayBuffer;
  wrappingKey: ArrayBuffer;
}

interface ByoVaultWrapSessionVaultKeyWithPrfRequest {
  type: 'byoVaultWrapSessionVaultKeyWithPrf';
  sessionId: number;
  prfOutputB64: string;
}

interface ByoVaultLoadSessionFromWrappedVaultKeyRequest {
  type: 'byoVaultLoadSessionFromWrappedVaultKey';
  wrappedB64: string;
  prfOutputB64: string;
}

interface ByoVaultSealDeviceSigningKeyRequest {
  type: 'byoVaultSealDeviceSigningKey';
  sessionId: number;
  deviceIdB64: string;
  seedB64: string;
}

interface ByoVaultUnsealDeviceSigningKeyRequest {
  type: 'byoVaultUnsealDeviceSigningKey';
  sessionId: number;
  deviceIdB64: string;
  wrappedB64: string;
}

interface ByoVaultMigrateV1ToV2Request {
  type: 'byoVaultMigrateV1ToV2';
  sessionId: number;
  vaultBytes: ArrayBuffer;
}

interface ByoVaultRewrapRequest {
  type: 'byoVaultRewrap';
  sessionId: number;
  newWrappingKeyB64: string;
}

interface ByoVaultCreateRequest {
  type: 'byoVaultCreate';
  password: string;
  memoryKb: number;
  iterations: number;
  parallelism: number;
}

interface ByoVaultOpenRecoveryRequest {
  type: 'byoVaultOpenRecovery';
  recoveryKeyB64: string;
  wrapIvB64: string;
  wrappedKeyB64: string;
}

interface ByoVaultWrapRecoveryRequest {
  type: 'byoVaultWrapRecovery';
  sessionId: number;
  recoveryKeyB64: string;
}

interface ByoVaultRewrapWithPassphraseRequest {
  type: 'byoVaultRewrapWithPassphrase';
  sessionId: number;
  newPassword: string;
  memoryKb: number;
  iterations: number;
  parallelism: number;
}

// BYO enrollment operations
interface ByoEnrollmentInitiateRequest {
  type: 'byoEnrollmentInitiate';
}

interface ByoEnrollmentDeriveSessionRequest {
  type: 'byoEnrollmentDeriveSession';
  ephSkB64: string;
  peerPkB64: string;
  channelIdB64: string;
}

interface ByoEnrollmentEncryptShardRequest {
  type: 'byoEnrollmentEncryptShard';
  shardB64: string;
  encKeyB64: string;
  macKeyB64: string;
}

interface ByoEnrollmentDecryptShardRequest {
  type: 'byoEnrollmentDecryptShard';
  envelopeB64: string;
  encKeyB64: string;
  macKeyB64: string;
}

// Enrollment session API (ZK-safe)
interface ByoEnrollmentOpenRequest {
  type: 'byoEnrollmentOpen';
}

interface ByoEnrollmentJoinRequest {
  type: 'byoEnrollmentJoin';
  channelIdB64: string;
}

interface ByoEnrollmentDeriveKeysRequest {
  type: 'byoEnrollmentDeriveKeys';
  sessionId: number;
  peerPkB64: string;
}

interface ByoEnrollmentSessionEncryptShardRequest {
  type: 'byoEnrollmentSessionEncryptShard';
  sessionId: number;
  shardB64: string;
}

interface ByoEnrollmentSessionDecryptShardRequest {
  type: 'byoEnrollmentSessionDecryptShard';
  sessionId: number;
  envelopeB64: string;
}

interface ByoEnrollmentSessionGetShardRequest {
  type: 'byoEnrollmentSessionGetShard';
  sessionId: number;
}

interface ByoEnrollmentSessionEncryptPayloadRequest {
  type: 'byoEnrollmentSessionEncryptPayload';
  sessionId: number;
  payloadB64: string;
}

interface ByoEnrollmentSessionDecryptPayloadRequest {
  type: 'byoEnrollmentSessionDecryptPayload';
  sessionId: number;
  envelopeB64: string;
}

interface ByoEnrollmentCloseRequest {
  type: 'byoEnrollmentClose';
  sessionId: number;
}

// SFTP credential registry (credentials stored in worker, not main-thread class fields)
interface SftpStoreCredentialRequest {
  type: 'sftpStoreCredential';
  password?: string;
  privateKey?: string;
  passphrase?: string;
}

interface SftpGetAuthCredsRequest {
  type: 'sftpGetAuthCreds';
  credHandle: number;
  username: string;
}

interface SftpClearCredentialRequest {
  type: 'sftpClearCredential';
  credHandle: number;
}

interface SftpClearAllCredentialsRequest {
  type: 'sftpClearAllCredentials';
}

interface OAuthBeginFlowRequest {
  type: 'oauthBeginFlow';
  providerType: string;
  clientId: string;
  redirectUri: string;
}

interface OAuthBuildExchangeFormRequest {
  type: 'oauthBuildExchangeForm';
  state: string;
  code: string;
}

interface OAuthAbortFlowRequest {
  type: 'oauthAbortFlow';
  state: string;
}

interface GeneratePkceRequest {
  type: 'generatePkce';
}

interface V7CipherSizeRequest {
  type: 'v7CipherSize';
  plaintextLen: number;
  chunkSize: number;
}

interface ProviderOAuthConfigRequest {
  type: 'providerOAuthConfig';
  providerType: string;
}

interface BuildAuthUrlRequest {
  type: 'buildAuthUrl';
  providerType: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
}

interface BuildTokenExchangeFormRequest {
  type: 'buildTokenExchangeForm';
  code: string;
  codeVerifier: string;
  redirectUri: string;
  clientId: string;
}

interface BuildRefreshFormRequest {
  type: 'buildRefreshForm';
  refreshToken: string;
  clientId: string;
}

interface ParseTokenResponseRequest {
  type: 'parseTokenResponse';
  body: Uint8Array;
}

interface FooterTrimmerNewRequest {
  type: 'footerTrimmerNew';
  trimId: string;
  keep: number;
}

interface FooterTrimmerPushRequest {
  type: 'footerTrimmerPush';
  trimId: string;
  bytes: Uint8Array;
}

interface FooterTrimmerFinalizeRequest {
  type: 'footerTrimmerFinalize';
  trimId: string;
}

interface FooterTrimmerAbortRequest {
  type: 'footerTrimmerAbort';
  trimId: string;
}

// ── BYO download flow (Phase 2) ─────────────────────────────────────────────

interface ByoDownloadFlowInitRequest {
  type: 'byoDownloadFlowInit';
  sessionId: string;
  keySessionId?: string;
}

interface ByoDownloadFlowPushRequest {
  type: 'byoDownloadFlowPush';
  sessionId: string;
  data: ArrayBuffer;
}

interface ByoDownloadFlowFinalizeRequest {
  type: 'byoDownloadFlowFinalize';
  sessionId: string;
}

interface ByoDownloadFlowAbortRequest {
  type: 'byoDownloadFlowAbort';
  sessionId: string;
}

// ── BYO upload flow (Phase 2) ───────────────────────────────────────────────

interface ByoUploadFlowInitRequest {
  type: 'byoUploadFlowInit';
  sessionId: string;
  publicKeysJson: string;
  plaintextLen: number;
}

interface ByoUploadFlowPushRequest {
  type: 'byoUploadFlowPush';
  sessionId: string;
  plaintext: ArrayBuffer;
  isLast: boolean;
}

interface ByoUploadFlowFinalizeRequest {
  type: 'byoUploadFlowFinalize';
  sessionId: string;
}

interface ByoUploadFlowAbortRequest {
  type: 'byoUploadFlowAbort';
  sessionId: string;
}

interface ByoUploadFlowPositionRequest {
  type: 'byoUploadFlowPosition';
  sessionId: string;
}

// Aggregate request unions — kept as named types so the master Request
// union that dispatches `case 'byo…':` branches can reference one symbol
// per flow instead of re-listing every step. These names are load-
// bearing: the big Request union a few hundred lines down cites them.
type ByoDownloadAndDecryptRequest =
  | ByoDownloadFlowInitRequest
  | ByoDownloadFlowPushRequest
  | ByoDownloadFlowFinalizeRequest
  | ByoDownloadFlowAbortRequest;

type ByoEncryptAndUploadRequest =
  | ByoUploadFlowInitRequest
  | ByoUploadFlowPushRequest
  | ByoUploadFlowFinalizeRequest
  | ByoUploadFlowAbortRequest
  | ByoUploadFlowPositionRequest;

interface ByoRefreshTokenRequest {
  type: 'byoRefreshToken';
  /** 'gdrive' | 'dropbox' | 'onedrive' (WebDAV uses static credentials) */
  providerType: string;
  configJson: string;
}

// ── Config registry (R1.4) + provider dispatch (P8) ─────────────────────────
// These request types were missing from the master Request union after an
// older refactor. Case handlers below destructure them directly, so any
// drift here surfaces as svelte-check errors on each `case 'byo…':` branch.

interface ByoInitConfigRequest {
  type: 'byoInitConfig';
  configJson: string;
}

interface ByoReleaseConfigRequest {
  type: 'byoReleaseConfig';
  configHandle: string;
}

interface ByoRefreshConfigByHandleRequest {
  type: 'byoRefreshConfigByHandle';
  providerType: string;
  configHandle: string;
}

interface ByoProviderCallRequest {
  type: 'byoProviderCall';
  providerType: string;
  op: string;
  configHandle: string;
  argsJson: string;
}

interface ByoCrossProviderStreamCopyRequest {
  type: 'byoCrossProviderStreamCopy';
  srcType: string;
  srcConfigHandle: string;
  dstType: string;
  dstConfigHandle: string;
  srcRef: string;
  dstName: string;
  totalSize: number;
}

interface ByoStreamUploadInitRequest {
  type: 'byoStreamUploadInit';
  pubKeysJson: string;
  providerType: string;
  configHandle: string;
  name: string;
  parentRef: string | null;
  plaintextLen: number;
}

interface ByoStreamUploadPushRequest {
  type: 'byoStreamUploadPush';
  sessionId: string;
  data: ArrayBuffer;
  isLast: boolean;
}

interface ByoStreamUploadFinalizeRequest {
  type: 'byoStreamUploadFinalize';
  sessionId: string;
}

interface ByoStreamUploadAbortRequest {
  type: 'byoStreamUploadAbort';
  sessionId: string;
}

interface ByoStreamDownloadInitRequest {
  type: 'byoStreamDownloadInit';
  secKeysJson: string;
  providerType: string;
  configHandle: string;
  ref: string;
}

interface ByoStreamDownloadPullRequest {
  type: 'byoStreamDownloadPull';
  sessionId: string;
}

interface ByoStreamDownloadCloseRequest {
  type: 'byoStreamDownloadClose';
  sessionId: string;
}

type ByoConfigRegistryRequest =
  | ByoInitConfigRequest
  | ByoReleaseConfigRequest
  | ByoRefreshConfigByHandleRequest;

type ByoProviderDispatchRequest =
  | ByoProviderCallRequest
  | ByoCrossProviderStreamCopyRequest
  | ByoStreamUploadInitRequest
  | ByoStreamUploadPushRequest
  | ByoStreamUploadFinalizeRequest
  | ByoStreamUploadAbortRequest
  | ByoStreamDownloadInitRequest
  | ByoStreamDownloadPullRequest
  | ByoStreamDownloadCloseRequest;

// R6 multi-vault request types
interface ByoManifestEncryptRequest {
  type: 'byoManifestEncrypt';
  sessionId: number;
  manifestJson: string;
}

interface ByoManifestDecryptRequest {
  type: 'byoManifestDecrypt';
  sessionId: number;
  bodyBlobB64: string;
}

interface ByoManifestMergeRequest {
  type: 'byoManifestMerge';
  /** JSON array of manifest JSON strings */
  manifestJsonsJson: string;
  /** Current Unix time in seconds; pass 0 to skip clock-skew check */
  nowUnixSecs: number;
  /** Minimum acceptable merged manifest_version; pass 0 to skip rollback check */
  minAcceptableVersion: number;
}

interface ByoManifestValidateRequest {
  type: 'byoManifestValidate';
  manifestJson: string;
  /** Unix timestamp in seconds; 0 skips clock-skew check */
  nowUnixSecs: number;
}

interface ByoVaultBodyEncryptRequest {
  type: 'byoVaultBodyEncrypt';
  sessionId: number;
  providerId: string;
  sqliteB64: string;
}

interface ByoVaultBodyDecryptRequest {
  type: 'byoVaultBodyDecrypt';
  sessionId: number;
  providerId: string;
  bodyBlobB64: string;
}

interface ByoDerivePerVaultWalKeyRequest {
  type: 'byoDerivePerVaultWalKey';
  sessionId: number;
  providerId: string;
}

interface ByoDerivePerVaultJournalKeysRequest {
  type: 'byoDerivePerVaultJournalKeys';
  sessionId: number;
  providerId: string;
}

interface ByoPlanUnlockRequest {
  type: 'byoPlanUnlock';
  manifestJson: string;
  onlineIdsJson: string;
  cachedIdsJson: string;
}

interface ByoPlanSaveRequest {
  type: 'byoPlanSave';
  dirtyIdsJson: string;
  onlineIdsJson: string;
}

interface ByoPlanCrossProviderMoveRequest {
  type: 'byoPlanCrossProviderMove';
  fileId: number;
  sourceProviderRef: string;
  srcProviderId: string;
  dstProviderId: string;
  /** Negative means root (no parent folder) */
  destFolderId: number;
  displayName: string;
}

interface ByoDeriveManifestAeadKeyRequest {
  type: 'byoDeriveManifestAeadKey';
  sessionId: number;
}

interface ByoCrossProviderMoveDecideReplayRequest {
  type: 'byoCrossProviderMoveDecideReplay';
  stepBytesB64: string;
  dstFileExists: boolean;
  srcBlobExistsStr: 'true' | 'false' | 'unknown';
}

interface ByoCrossProviderMovePlanReconcileRequest {
  type: 'byoCrossProviderMovePlanReconcile';
  stepsJson: string;
  dstFileExists: boolean;
  srcBlobExistsStr: 'true' | 'false' | 'unknown';
}

// Row-merge (P3.2)
interface ByoMergeRowsRequest {
  type: 'byoMergeRows';
  localRowsJson: string;
  remoteRowsJson: string;
  isKeyVersions: boolean;
}

// Manifest mutation helpers (P3.3)
interface ByoManifestAddProviderRequest {
  type: 'byoManifestAddProvider';
  manifestJson: string;
  entryJson: string;
}
interface ByoManifestRenameProviderRequest {
  type: 'byoManifestRenameProvider';
  manifestJson: string;
  providerId: string;
  newName: string;
  nowUnixSecs: number;
}
interface ByoManifestSetPrimaryRequest {
  type: 'byoManifestSetPrimary';
  manifestJson: string;
  providerId: string;
  nowUnixSecs: number;
}
interface ByoManifestTombstoneRequest {
  type: 'byoManifestTombstone';
  manifestJson: string;
  providerId: string;
  nowUnixSecs: number;
}
interface ByoManifestUpdateProviderConfigRequest {
  type: 'byoManifestUpdateProviderConfig';
  manifestJson: string;
  providerId: string;
  newConfigJson: string;
  nowUnixSecs: number;
}

// Journal codec (P3.1)
interface ByoJournalAppendRequest {
  type: 'byoJournalAppend';
  sessionId: number;
  providerId: string;
  entryType: string;
  table: string;
  rowId: number;
  dataJson: string;
}
interface ByoJournalParseRequest {
  type: 'byoJournalParse';
  sessionId: number;
  providerId: string;
  journalB64: string;
}

interface ByoShareAuditPayloadRequest {
  type: 'byoShareAuditPayload';
  direction: 'outbound' | 'inbound';
  fileRef: string;
  counterpartyHint: string;
  tsMs: number;
}

// Relay auth / PoW
interface ByoDeriveSftpPurposeRequest {
  type: 'byoDeriveSftpPurpose';
  host: string;
  port: number;
}

interface ByoDeriveEnrollmentPurposeRequest {
  type: 'byoDeriveEnrollmentPurpose';
  channelId: string;
}

interface ByoSolveRelayPowRequest {
  type: 'byoSolveRelayPow';
  nonceHex: string;
  purpose: string;
  difficulty: number;
}

type WorkerRequest =
  | ByoDeriveSftpPurposeRequest
  | ByoDeriveEnrollmentPurposeRequest
  | ByoSolveRelayPowRequest
  | StoreKeysRequest
  | ClearKeysRequest
  | ClearAllRequest
  | HasKeysRequest
  | V7EncryptInitRequest
  | V7EncryptTakeHeaderRequest
  | V7EncryptPushRequest
  | V7EncryptFinalizeRequest
  | V7EncryptAbortRequest
  | V7DecryptInitRequest
  | V7DecryptPushRequest
  | V7DecryptFinalizeRequest
  | V7DecryptAbortRequest
  | EncryptFilenameAtomicRequest
  | ByoDecryptFilenameRequest
  | ByoParseVaultHeaderRequest
  | ByoDeriveVaultKeysRequest
  | ByoUnwrapVaultKeyRequest
  | ByoDeriveKekRequest
  | ByoDeriveRecoveryVaultKekRequest
  | ByoComputeHeaderHmacRequest
  | ByoVerifyHeaderHmacRequest
  | ByoWrapVaultKeyRequest
  | ByoEncryptVaultBodyRequest
  | ByoDecryptVaultBodyRequest
  | ByoGenerateVaultKeysRequest
  | ByoEnrollmentInitiateRequest
  | ByoEnrollmentDeriveSessionRequest
  | ByoEnrollmentEncryptShardRequest
  | ByoEnrollmentDecryptShardRequest
  // Enrollment session API (ZK-safe)
  | ByoEnrollmentOpenRequest
  | ByoEnrollmentJoinRequest
  | ByoEnrollmentDeriveKeysRequest
  | ByoEnrollmentSessionEncryptShardRequest
  | ByoEnrollmentSessionDecryptShardRequest
  | ByoEnrollmentSessionGetShardRequest
  | ByoEnrollmentSessionEncryptPayloadRequest
  | ByoEnrollmentSessionDecryptPayloadRequest
  | ByoEnrollmentCloseRequest
  // SFTP credential registry
  | SftpStoreCredentialRequest
  | SftpGetAuthCredsRequest
  | SftpClearCredentialRequest
  | SftpClearAllCredentialsRequest
  // OAuth PKCE verifier registry
  | OAuthBeginFlowRequest
  | OAuthBuildExchangeFormRequest
  | OAuthAbortFlowRequest
  | GeneratePkceRequest
  | V7CipherSizeRequest
  | ProviderOAuthConfigRequest
  | BuildAuthUrlRequest
  | BuildTokenExchangeFormRequest
  | BuildRefreshFormRequest
  | ParseTokenResponseRequest
  | FooterTrimmerNewRequest
  | FooterTrimmerPushRequest
  | FooterTrimmerFinalizeRequest
  | FooterTrimmerAbortRequest
  | ByoEncryptAndUploadRequest
  | ByoDownloadAndDecryptRequest
  | ByoRefreshTokenRequest
  | ByoConfigRegistryRequest
  | ByoProviderDispatchRequest
  | { type: 'byoRequestDestructiveToken' }
  | { type: 'byoGenerateDeviceSigningKey' }
  | { type: 'byoSealDeviceSigningKey'; vaultKeyB64: string; deviceIdB64: string; seedB64: string }
  | { type: 'byoUnsealDeviceSigningKey'; vaultKeyB64: string; deviceIdB64: string; wrappedB64: string }
  | { type: 'byoEd25519Sign'; seedB64: string; messageB64: string }
  | { type: 'byoEd25519Verify'; publicKeyB64: string; messageB64: string; signatureB64: string }
  | { type: 'byoMigrateVaultV1ToV2'; vaultBytes: ArrayBuffer; vaultKeyB64: string }
  // Vault session API (ZK-safe)
  | ByoVaultCreateRequest
  | ByoVaultOpenRequest
  | ByoVaultOpenRecoveryRequest
  | ByoVaultWrapRecoveryRequest
  | ByoVaultRewrapWithPassphraseRequest
  | ByoVaultCloseRequest
  | ByoVaultVerifyHeaderHmacRequest
  | ByoVaultDecryptBodyRequest
  | ByoVaultEncryptBodyRequest
  | ByoVaultComputeHeaderHmacRequest
  | ByoVaultDeriveKekRequest
  | ByoVaultLoadKeysRequest
  | ByoVaultDeriveSubkeyRequest
  | ByoVaultGenerateKeypairWrappedRequest
  | WebauthnDeriveWrappingKeyRequest
  | WebauthnWrapDeviceKeyRequest
  | WebauthnDeriveVaultKeyWrappingKeyRequest
  | WebauthnWrapVaultKeyRequest
  | WebauthnUnwrapVaultKeyRequest
  | ByoVaultWrapSessionVaultKeyWithPrfRequest
  | ByoVaultLoadSessionFromWrappedVaultKeyRequest
  | WebauthnUnwrapDeviceKeyRequest
  | WebauthnGenerateDeviceKeyRequest
  | ByoVaultSealDeviceSigningKeyRequest
  | ByoVaultUnsealDeviceSigningKeyRequest
  | ByoVaultMigrateV1ToV2Request
  | ByoVaultRewrapRequest
  // Share link crypto (P10)
  | { type: 'byoCreateShareFragment'; sessionId: string; headerB64: string; variant: string; password?: string }
  | { type: 'byoBundleExtractFileKey'; sessionId: string; headerB64: string }
  | { type: 'byoEncryptManifestV7'; manifestBytesB64: string; contentKeyB64: string }
  | { type: 'byoShareEncodeVariantA'; contentKeyB64: string }
  | { type: 'byoShareDecodeVariantA'; fragment: string }
  | { type: 'byoShareWrapKey'; contentKeyB64: string; password: string }
  | { type: 'byoShareUnwrapKey'; saltB64url: string; encryptedCkB64url: string; password: string }
  // R6 multi-vault
  | ByoManifestEncryptRequest
  | ByoManifestDecryptRequest
  | ByoManifestMergeRequest
  | ByoManifestValidateRequest
  | ByoVaultBodyEncryptRequest
  | ByoVaultBodyDecryptRequest
  | ByoDerivePerVaultWalKeyRequest
  | ByoDerivePerVaultJournalKeysRequest
  | ByoPlanUnlockRequest
  | ByoPlanSaveRequest
  | ByoPlanCrossProviderMoveRequest
  | ByoDeriveManifestAeadKeyRequest
  | ByoCrossProviderMoveDecideReplayRequest
  | ByoCrossProviderMovePlanReconcileRequest
  | ByoJournalAppendRequest
  | ByoJournalParseRequest
  | ByoShareAuditPayloadRequest
  | ByoMergeRowsRequest
  | ByoManifestAddProviderRequest
  | ByoManifestRenameProviderRequest
  | ByoManifestSetPrimaryRequest
  | ByoManifestTombstoneRequest
  | ByoManifestUpdateProviderConfigRequest
  // Stats (Phase 5)
  | { type: 'statsInit'; baseUrl: string; deviceId: string }
  | { type: 'statsRecord'; eventJson: string }
  | { type: 'statsDrain' }
  | { type: 'statsFlush' }
  | { type: 'ping' };

// ── Message handler ────────────────────────────────────────────────────────

const CRYPTO_OPS = new Set([
  'v7EncryptInit', 'v7EncryptTakeHeader', 'v7EncryptPush', 'v7EncryptFinalize', 'v7EncryptAbort',
  'v7DecryptInit', 'v7DecryptPush', 'v7DecryptFinalize', 'v7DecryptAbort',
  'encryptFilenameAtomic', 'byoDecryptFilename',
  'byoParseVaultHeader', 'byoDeriveVaultKeys', 'byoUnwrapVaultKey', 'byoDeriveKek',
  'byoDeriveRecoveryVaultKek', 'byoComputeHeaderHmac', 'byoVerifyHeaderHmac',
  'byoWrapVaultKey', 'byoEncryptVaultBody', 'byoDecryptVaultBody', 'byoGenerateVaultKeys',
  'byoEnrollmentInitiate', 'byoEnrollmentDeriveSession',
  'byoEnrollmentEncryptShard', 'byoEnrollmentDecryptShard',
  'byoEnrollmentOpen', 'byoEnrollmentJoin', 'byoEnrollmentDeriveKeys',
  'byoEnrollmentSessionEncryptShard', 'byoEnrollmentSessionDecryptShard',
  'byoEnrollmentSessionGetShard',
  'byoEnrollmentSessionEncryptPayload', 'byoEnrollmentSessionDecryptPayload',
  'byoEnrollmentClose',
  'oauthBeginFlow',
  'oauthBuildExchangeForm',
  'oauthAbortFlow',
  'generatePkce',
  'v7CipherSize',
  'providerOAuthConfig',
  'buildAuthUrl',
  'buildTokenExchangeForm',
  'buildRefreshForm',
  'parseTokenResponse',
  'footerTrimmerNew',
  'footerTrimmerPush',
  'footerTrimmerFinalize',
  'footerTrimmerAbort',
  'byoDownloadFlowInit', 'byoDownloadFlowPush', 'byoDownloadFlowFinalize', 'byoDownloadFlowAbort',
  'byoUploadFlowInit', 'byoUploadFlowPush', 'byoUploadFlowFinalize', 'byoUploadFlowAbort', 'byoUploadFlowPosition',
  'byoRefreshToken',
  'byoRequestDestructiveToken',
  'byoGenerateDeviceSigningKey',
  'byoSealDeviceSigningKey',
  'byoUnsealDeviceSigningKey',
  'byoEd25519Sign',
  'byoEd25519Verify',
  'byoMigrateVaultV1ToV2',
  'byoDeriveSftpPurpose',
  'byoDeriveEnrollmentPurpose',
  'byoSolveRelayPow',
  'byoCreateShareFragment',
  'byoBundleExtractFileKey',
  'byoEncryptManifestV7',
  'byoShareEncodeVariantA',
  'byoShareDecodeVariantA',
  'byoShareWrapKey',
  'byoShareUnwrapKey',
  // Vault session API
  'byoVaultOpen',
  'byoVaultClose',
  'byoVaultVerifyHeaderHmac',
  'byoVaultDecryptBody',
  'byoVaultEncryptBody',
  'byoVaultComputeHeaderHmac',
  'byoVaultDeriveKek',
  'byoVaultLoadKeys',
  'byoVaultDeriveSubkey',
  'byoVaultGenerateKeypairWrapped',
  'webauthnDeriveWrappingKey',
  'webauthnWrapDeviceKey',
  'webauthnUnwrapDeviceKey',
  'webauthnGenerateDeviceKey',
  'webauthnDeriveVaultKeyWrappingKey',
  'webauthnWrapVaultKey',
  'webauthnUnwrapVaultKey',
  'byoVaultWrapSessionVaultKeyWithPrf',
  'byoVaultLoadSessionFromWrappedVaultKey',
  'byoVaultSealDeviceSigningKey',
  'byoVaultUnsealDeviceSigningKey',
  'byoVaultMigrateV1ToV2',
  'byoVaultRewrap',
  'byoVaultCreate',
  'byoVaultOpenRecovery',
  'byoVaultWrapRecovery',
  'byoVaultRewrapWithPassphrase',
  // R6 multi-vault
  'byoManifestEncrypt',
  'byoManifestDecrypt',
  'byoManifestMerge',
  'byoManifestValidate',
  'byoVaultBodyEncrypt',
  'byoVaultBodyDecrypt',
  'byoDerivePerVaultWalKey',
  'byoDerivePerVaultJournalKeys',
  'byoJournalAppend',
  'byoJournalParse',
  'byoShareAuditPayload',
  'byoMergeRows',
  'byoManifestAddProvider',
  'byoManifestRenameProvider',
  'byoManifestSetPrimary',
  'byoManifestTombstone',
  'byoManifestUpdateProviderConfig',
  'byoPlanUnlock',
  'byoPlanSave',
  'byoPlanCrossProviderMove',
  'byoCrossProviderMoveDecideReplay',
  'byoCrossProviderMovePlanReconcile',
  'byoCrossProviderStreamCopy',
  'byoStreamUploadInit', 'byoStreamUploadPush', 'byoStreamUploadFinalize', 'byoStreamUploadAbort',
  'byoStreamDownloadInit', 'byoStreamDownloadPull', 'byoStreamDownloadClose',
  'byoDeriveManifestAeadKey',
  // Stats (Phase 5)
  'statsInit',
  'statsRecord',
  'statsDrain',
  'statsFlush',
]);

async function handleMessage(request: WorkerRequest): Promise<any> {
  // Ensure WASM is initialized for crypto operations
  if (CRYPTO_OPS.has(request.type)) {
    await initWasm();
  }

  switch (request.type) {
    // ── Key management ──────────────────────────────────────────────────
    case 'storeKeys': {
      storeKeys(
        request.sessionId,
        new Uint8Array(request.mlkemSecretKey),
        new Uint8Array(request.x25519SecretKey),
      );
      return { stored: true };
    }

    case 'clearKeys': {
      if (request.sessionId) {
        clearSessionKeys(request.sessionId);
      } else {
        clearAllKeys();
      }
      return { cleared: true };
    }

    case 'clearAll': {
      // Complete teardown — used on session timeout or vault lock.
      // Wipes every worker-held registry before the main thread terminates
      // the worker; nothing that survives this point can leak to a
      // compromised/reloaded page.
      clearAllKeys();
      configRegistry.clear();
      oauthPendingFlows.clear();
      return { cleared: true };
    }

    case 'hasKeys': {
      return activeKeys.has(request.sessionId);
    }

    // ── V7 streaming encrypt ────────────────────────────────────────────
    case 'v7EncryptInit': {
      if (streamEncryptSessions.has(request.sessionId)) {
        throw new Error(`v7 encrypt session ${request.sessionId} already exists`);
      }
      try {
        const enc = V7StreamEncryptorWasm.create(request.publicKeysJson);
        streamEncryptSessions.set(request.sessionId, enc);
        return { ok: true };
      } catch (e: any) {
        throw new Error(`v7 encrypt init failed: ${e?.message ?? e}`);
      }
    }

    case 'v7EncryptTakeHeader': {
      const enc = streamEncryptSessions.get(request.sessionId);
      if (!enc) throw new Error(`v7 encrypt session ${request.sessionId} not found`);
      try {
        const header: Uint8Array = enc.takeHeader();
        return { header: header.buffer };
      } catch (e: any) {
        try { enc.free?.(); } catch { /* ignore */ }
        streamEncryptSessions.delete(request.sessionId);
        throw new Error(`v7 encrypt takeHeader failed: ${e?.message ?? e}`);
      }
    }

    case 'v7EncryptPush': {
      const enc = streamEncryptSessions.get(request.sessionId);
      if (!enc) throw new Error(`v7 encrypt session ${request.sessionId} not found`);
      try {
        const plaintext = new Uint8Array(request.plaintext);
        const frame: Uint8Array = enc.push(plaintext);
        plaintext.fill(0); // zeroize plaintext copy
        return { frame: frame.buffer };
      } catch (e: any) {
        try { enc.free?.(); } catch { /* ignore */ }
        streamEncryptSessions.delete(request.sessionId);
        throw new Error(`v7 encrypt push failed: ${e?.message ?? e}`);
      }
    }

    case 'v7EncryptFinalize': {
      const enc = streamEncryptSessions.get(request.sessionId);
      if (!enc) throw new Error(`v7 encrypt session ${request.sessionId} not found`);
      try {
        const hmac: Uint8Array = enc.finalize();
        try { enc.free?.(); } catch { /* ignore */ }
        streamEncryptSessions.delete(request.sessionId);
        return { hmac: hmac.buffer };
      } catch (e: any) {
        try { enc.free?.(); } catch { /* ignore */ }
        streamEncryptSessions.delete(request.sessionId);
        throw new Error(`v7 encrypt finalize failed: ${e?.message ?? e}`);
      }
    }

    case 'v7EncryptAbort': {
      const enc = streamEncryptSessions.get(request.sessionId);
      if (enc) {
        try { enc.free?.(); } catch { /* ignore */ }
        streamEncryptSessions.delete(request.sessionId);
      }
      return { ok: true };
    }

    // ── V7 streaming decrypt ──────────────────────────────────────────
    case 'v7DecryptInit': {
      if (streamDecryptSessions.has(request.sessionId)) {
        throw new Error(`v7 decrypt session ${request.sessionId} already exists`);
      }
      const keys = retrieveKeys(request.keySessionId ?? request.sessionId);
      if (!keys) throw new Error('Keys not loaded for session');
      const headerBytes = new Uint8Array(request.headerBytes);
      try {
        // SECURITY: JSON.stringify is called inline so the string containing
        // base64-encoded key material is passed directly to the WASM create()
        // call and never stored in a named variable. This minimises the window
        // in which it is reachable on the JS heap. JS strings are immutable and
        // cannot be zeroized, but short-lived unreferenced strings are eligible
        // for garbage collection sooner.
        const dec = V7StreamDecryptorWasm.create(
          headerBytes,
          JSON.stringify({
            mlkem_secret_key: toBase64(keys.mlkem_secret_key),
            x25519_secret_key: toBase64(keys.x25519_secret_key),
          }),
        );
        streamDecryptSessions.set(request.sessionId, dec);
        return { headerEnd: dec.headerEnd };
      } catch (e: any) {
        throw new Error(`v7 decrypt init failed: ${e?.message ?? e}`);
      }
    }

    case 'v7DecryptPush': {
      const dec = streamDecryptSessions.get(request.sessionId);
      if (!dec) throw new Error(`v7 decrypt session ${request.sessionId} not found`);
      try {
        const plaintext: Uint8Array = dec.push(new Uint8Array(request.data));
        return { plaintext: plaintext.buffer };
      } catch (e: any) {
        try { dec.free?.(); } catch { /* ignore */ }
        streamDecryptSessions.delete(request.sessionId);
        throw new Error(`v7 decrypt push failed: ${e?.message ?? e}`);
      }
    }

    case 'v7DecryptFinalize': {
      const dec = streamDecryptSessions.get(request.sessionId);
      if (!dec) throw new Error(`v7 decrypt session ${request.sessionId} not found`);
      try {
        dec.finalize(new Uint8Array(request.storedHmac));
      } catch (e: any) {
        try { dec.free?.(); } catch { /* ignore */ }
        streamDecryptSessions.delete(request.sessionId);
        throw new Error(`v7 decrypt finalize failed: ${e?.message ?? e}`);
      }
      try { dec.free?.(); } catch { /* ignore */ }
      streamDecryptSessions.delete(request.sessionId);
      return { ok: true };
    }

    case 'v7DecryptAbort': {
      const dec = streamDecryptSessions.get(request.sessionId);
      if (dec) {
        try { dec.free?.(); } catch { /* ignore */ }
        streamDecryptSessions.delete(request.sessionId);
      }
      return { ok: true };
    }

    // ── Atomic filename encryption ─────────────────────────────────────
    case 'encryptFilenameAtomic': {
      const result = encrypt_filename_with_fresh_key(
        request.filename,
        request.metadata ?? null,
        request.publicKeysJson,
      );
      if (!result || result.encrypted_filename === undefined
          || result.encrypted_filename_key === undefined) {
        throw new Error('Atomic filename encryption failed');
      }
      return {
        encrypted_filename: result.encrypted_filename,
        encrypted_metadata: result.encrypted_metadata ?? null,
        encrypted_filename_key: result.encrypted_filename_key,
      };
    }

    // ── BYO filename decryption ────────────────────────────────────────
    case 'byoDecryptFilename': {
      const keys = retrieveKeys(request.sessionId);
      if (!keys) throw new Error(`No keys for session ${request.sessionId}`);

      const secKeysJson = JSON.stringify({
        mlkem_secret_key: toBase64(keys.mlkem_secret_key),
        x25519_secret_key: toBase64(keys.x25519_secret_key),
      });

      // Step 1: unwrap the KEM-wrapped filename key (V7 format).
      // decrypt_file_v7 takes raw bytes and returns the unwrapped key bytes
      // (or undefined on error) — not an {error, data} object.
      const encryptedKeyBytes = fromBase64(request.encryptedFilenameKeyB64);
      const keyBytes: Uint8Array | undefined = decrypt_file_v7(encryptedKeyBytes, secKeysJson);
      if (!keyBytes) {
        throw new Error('Filename key unwrap failed');
      }

      // Step 2: decrypt the filename using the unwrapped symmetric key.
      // decrypt_filename takes both ciphertext and key as base64 strings.
      const keyB64 = toBase64(keyBytes);
      const nameResult = decrypt_filename(request.encryptedFilenameB64, keyB64);
      if (!nameResult || nameResult.name === undefined) {
        throw new Error('Filename decryption failed');
      }

      return { filename: nameResult.name };
    }

    // ── BYO vault operations ───────────────────────────────────────────
    case 'byoParseVaultHeader': {
      const result = byo_parse_vault_header(new Uint8Array(request.vaultBytes));
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoDeriveVaultKeys': {
      checkKdfRateLimit();
      const result = byo_derive_vault_keys(
        request.password,
        request.saltB64,
        request.memoryKb,
        request.iterations,
        request.parallelism,
      );
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoUnwrapVaultKey': {
      const result = byo_unwrap_vault_key(request.wrapIvB64, request.wrappedKeyB64, request.unwrappingKeyB64);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoDeriveKek': {
      const result = byo_derive_kek(request.clientKekHalfB64, request.shardB64);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoDeriveRecoveryVaultKek': {
      const result = byo_derive_recovery_vault_kek(request.recoveryKeyB64);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoComputeHeaderHmac': {
      const result = byo_compute_header_hmac(request.vaultKeyB64, request.headerPrefixB64);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoVerifyHeaderHmac': {
      const result = byo_verify_header_hmac(request.vaultKeyB64, request.headerPrefixB64, request.expectedHmacB64);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoWrapVaultKey': {
      const result = byo_wrap_vault_key(request.vaultKeyB64, request.wrappingKeyB64);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoRequestDestructiveToken': {
      return { token: issueDestructiveToken() };
    }

    case 'byoEncryptVaultBody': {
      consumeDestructiveToken(request.opToken);
      const nonceAndCt: Uint8Array | null = byo_encrypt_vault_body(
        new Uint8Array(request.sqliteBytes),
        request.vaultKeyB64
      );
      if (!nonceAndCt) throw new Error('byo_encrypt_vault_body failed');
      // Split nonce(12) || ciphertext — callers expect { body_iv: string, body_ciphertext: string }
      return {
        body_iv: toBase64(nonceAndCt.slice(0, 12)),
        body_ciphertext: toBase64(nonceAndCt.slice(12)),
      };
    }

    case 'byoDecryptVaultBody': {
      const sqlite: Uint8Array | null = byo_decrypt_vault_body(
        new Uint8Array(request.nonceAndCt),
        request.vaultKeyB64
      );
      if (!sqlite) throw new Error('byo_decrypt_vault_body failed');
      return { sqlite_bytes: toBase64(sqlite) };
    }

    case 'byoGenerateVaultKeys': {
      const result = byo_generate_vault_keys();
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    // ── BYO enrollment operations ──────────────────────────────────────
    case 'byoEnrollmentInitiate': {
      const result = byo_enrollment_initiate();
      if (!result) throw new Error('Enrollment initiation failed');
      return result;
    }

    case 'byoEnrollmentDeriveSession': {
      const result = byo_enrollment_derive_session(request.ephSkB64, request.peerPkB64, request.channelIdB64);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoEnrollmentEncryptShard': {
      const result = byo_enrollment_encrypt_shard(request.shardB64, request.encKeyB64, request.macKeyB64);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'byoEnrollmentDecryptShard': {
      const result = byo_enrollment_decrypt_shard(request.envelopeB64, request.encKeyB64, request.macKeyB64);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    // ── Enrollment session API (ZK-safe) ───────────────────────────────────
    case 'byoEnrollmentOpen': {
      const result = byo_enrollment_open();
      if (result && result.error) throw new Error(result.error);
      return { ephPkB64: result.eph_pk, channelIdB64: result.channel_id, sessionId: result.session_id };
    }

    case 'byoEnrollmentJoin': {
      const result = byo_enrollment_join(request.channelIdB64);
      if (result && result.error) throw new Error(result.error);
      return { ephPkB64: result.eph_pk, sessionId: result.session_id };
    }

    case 'byoEnrollmentDeriveKeys': {
      const result = byo_enrollment_derive_keys(request.sessionId, request.peerPkB64);
      if (result && result.error) throw new Error(result.error);
      return { sasCode: result.sas_code };
    }

    case 'byoEnrollmentSessionEncryptShard': {
      const result = byo_enrollment_session_encrypt_shard(request.sessionId, request.shardB64);
      if (result && result.error) throw new Error(result.error);
      return { envelopeB64: result.envelope_b64 };
    }

    case 'byoEnrollmentSessionDecryptShard': {
      const result = byo_enrollment_session_decrypt_shard(request.sessionId, request.envelopeB64);
      if (result && result.error) throw new Error(result.error);
      return {};
    }

    case 'byoEnrollmentSessionGetShard': {
      const result = byo_enrollment_session_get_shard(request.sessionId);
      if (result && result.error) throw new Error(result.error);
      return { shardB64: result.shard_b64 };
    }

    case 'byoEnrollmentSessionEncryptPayload': {
      const result = byo_enrollment_session_encrypt_payload(request.sessionId, request.payloadB64);
      if (result && result.error) throw new Error(result.error);
      return { envelopeB64: result.envelope_b64 };
    }

    case 'byoEnrollmentSessionDecryptPayload': {
      const result = byo_enrollment_session_decrypt_payload(request.sessionId, request.envelopeB64);
      if (result && result.error) throw new Error(result.error);
      return { payloadB64: result.payload_b64 };
    }

    case 'byoEnrollmentClose': {
      byo_enrollment_close(request.sessionId);
      return {};
    }

    // ── SFTP credential registry ───────────────────────────────────────────
    // The worker no longer owns SFTP credentials — they live inside
    // the main-thread WASM heap via `sftp_store_credential_*`. The message
    // handlers below remain as no-op compatibility stubs so older main-thread
    // code paths surface a loud error rather than a silent half-migration.
    case 'sftpStoreCredential':
    case 'sftpGetAuthCreds':
    case 'sftpClearCredential':
    case 'sftpClearAllCredentials': {
      throw new Error(
        'SFTP credentials now live in main-thread WASM; call sdk-wasm ' +
          'sftp_store_credential_* / sftp_clear_credential directly instead of the worker.',
      );
    }

    // ── OAuth PKCE verifier registry ───────────────────────────────────────
    case 'oauthBeginFlow': {
      const pkce = generate_pkce();
      if (pkce && pkce.error) throw new Error(pkce.error);
      // Generate random state
      const stateBytes = new Uint8Array(16);
      crypto.getRandomValues(stateBytes);
      const state = Array.from(stateBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      oauthPendingFlows.set(state, {
        verifier: pkce.codeVerifier,
        clientId: request.clientId,
        redirectUri: request.redirectUri,
        createdAt: Date.now(),
      });
      // Build auth URL via WASM so main thread only gets the URL, not the verifier.
      const authUrl = build_auth_url_wasm(
        request.providerType, request.clientId, request.redirectUri, state, pkce.codeChallenge,
      );
      return { state, authUrl };
    }

    case 'oauthBuildExchangeForm': {
      const flow = oauthPendingFlows.get(request.state);
      if (!flow) throw new Error('Unknown OAuth state — flow not found or already completed');
      // Drop immediately regardless of outcome.
      oauthPendingFlows.delete(request.state);
      const formBody = build_token_exchange_form_wasm(
        request.code, flow.verifier, flow.redirectUri, flow.clientId,
      );
      return { formBody };
    }

    case 'oauthAbortFlow': {
      oauthPendingFlows.delete(request.state);
      return {};
    }

    case 'generatePkce': {
      const result = generate_pkce();
      if (result && result.error) throw new Error(result.error);
      return { codeVerifier: result.codeVerifier, codeChallenge: result.codeChallenge };
    }

    case 'v7CipherSize': {
      const size = v7_cipher_size_wasm(request.plaintextLen, request.chunkSize);
      return { size };
    }

    case 'providerOAuthConfig': {
      const cfg = provider_oauth_config_wasm(request.providerType);
      return cfg ?? null;
    }

    case 'buildAuthUrl': {
      return build_auth_url_wasm(
        request.providerType,
        request.clientId,
        request.redirectUri,
        request.state,
        request.codeChallenge,
      );
    }

    case 'buildTokenExchangeForm': {
      return build_token_exchange_form_wasm(
        request.code,
        request.codeVerifier,
        request.redirectUri,
        request.clientId,
      );
    }

    case 'buildRefreshForm': {
      return build_refresh_form_wasm(request.refreshToken, request.clientId);
    }

    case 'parseTokenResponse': {
      const result = parse_token_response_wasm(request.body);
      if (result && result.error) throw new Error(result.error);
      return result;
    }

    case 'footerTrimmerNew': {
      const ft = new FooterTrimmerWasm(request.keep);
      footerTrimmerSessions.set(request.trimId, ft);
      return null;
    }

    case 'footerTrimmerPush': {
      const ft = footerTrimmerSessions.get(request.trimId);
      if (!ft) throw new Error(`footerTrimmerPush: unknown trimId ${request.trimId}`);
      const released = ft.push(request.bytes);
      return released;
    }

    case 'footerTrimmerFinalize': {
      const ft = footerTrimmerSessions.get(request.trimId);
      if (!ft) throw new Error(`footerTrimmerFinalize: unknown trimId ${request.trimId}`);
      footerTrimmerSessions.delete(request.trimId);
      const result = ft.finalize();
      return { body: result.body, footer: result.footer };
    }

    case 'footerTrimmerAbort': {
      footerTrimmerSessions.delete(request.trimId);
      return null;
    }

    // ── BYO download flow (Phase 2) ───────────────────────────────────────
    case 'byoDownloadFlowInit': {
      if (byoDownloadFlowSessions.has(request.sessionId)) {
        throw new Error(`byoDownloadFlow session ${request.sessionId} already exists`);
      }
      const keys = retrieveKeys(request.keySessionId ?? request.sessionId);
      if (!keys) throw new Error('Keys not loaded for session');
      try {
        // SECURITY: JSON.stringify inline — key material never stored in named var.
        const flow = ByoDownloadFlowWasm.create(
          JSON.stringify({
            mlkem_secret_key: toBase64(keys.mlkem_secret_key),
            x25519_secret_key: toBase64(keys.x25519_secret_key),
          }),
        );
        byoDownloadFlowSessions.set(request.sessionId, flow);
        return { ok: true };
      } catch (e: any) {
        throw new Error(`byoDownloadFlow init failed: ${e?.message ?? e}`);
      }
    }

    case 'byoDownloadFlowPush': {
      const flow = byoDownloadFlowSessions.get(request.sessionId);
      if (!flow) throw new Error(`byoDownloadFlow session ${request.sessionId} not found`);
      try {
        const plaintext: Uint8Array = flow.push(new Uint8Array(request.data));
        return { plaintext: plaintext.buffer };
      } catch (e: any) {
        try { flow.free?.(); } catch { /* ignore */ }
        byoDownloadFlowSessions.delete(request.sessionId);
        throw new Error(`byoDownloadFlow push failed: ${e?.message ?? e}`);
      }
    }

    case 'byoDownloadFlowFinalize': {
      const flow = byoDownloadFlowSessions.get(request.sessionId);
      if (!flow) throw new Error(`byoDownloadFlow session ${request.sessionId} not found`);
      try {
        flow.finalize();
        return { ok: true };
      } catch (e: any) {
        throw new Error(`byoDownloadFlow finalize failed: ${e?.message ?? e}`);
      } finally {
        try { flow.free?.(); } catch { /* ignore */ }
        byoDownloadFlowSessions.delete(request.sessionId);
      }
    }

    case 'byoDownloadFlowAbort': {
      const flow = byoDownloadFlowSessions.get(request.sessionId);
      if (flow) {
        try { flow.free?.(); } catch { /* ignore */ }
        byoDownloadFlowSessions.delete(request.sessionId);
      }
      return { ok: true };
    }

    // ── BYO upload flow (Phase 2) ─────────────────────────────────────────
    case 'byoUploadFlowInit': {
      if (byoUploadFlowSessions.has(request.sessionId)) {
        throw new Error(`byoUploadFlow session ${request.sessionId} already exists`);
      }
      try {
        const flow = ByoUploadFlowWasm.create(request.publicKeysJson, request.plaintextLen);
        byoUploadFlowSessions.set(request.sessionId, flow);
        const header: Uint8Array = flow.takeHeader();
        const chunkSize: number = v7_encrypt_chunk_size_wasm();
        return { header: header.buffer, totalSize: flow.totalSize, chunkSize };
      } catch (e: any) {
        // Clean up if flow was created before the error
        const existingFlow = byoUploadFlowSessions.get(request.sessionId);
        if (existingFlow) {
          try { existingFlow.free?.(); } catch { /* ignore */ }
          byoUploadFlowSessions.delete(request.sessionId);
        }
        throw new Error(`byoUploadFlow init failed: ${e?.message ?? e}`);
      }
    }

    case 'byoUploadFlowPush': {
      const flow = byoUploadFlowSessions.get(request.sessionId);
      if (!flow) throw new Error(`byoUploadFlow session ${request.sessionId} not found`);
      try {
        const plaintext = new Uint8Array(request.plaintext);
        const frame: Uint8Array = flow.pushChunk(plaintext, request.isLast);
        plaintext.fill(0); // zeroize plaintext copy
        return { frame: frame.buffer };
      } catch (e: any) {
        try { flow.free?.(); } catch { /* ignore */ }
        byoUploadFlowSessions.delete(request.sessionId);
        throw new Error(`byoUploadFlow push failed: ${e?.message ?? e}`);
      }
    }

    case 'byoUploadFlowFinalize': {
      const flow = byoUploadFlowSessions.get(request.sessionId);
      if (!flow) throw new Error(`byoUploadFlow session ${request.sessionId} not found`);
      try {
        const footer: Uint8Array = flow.finalize();
        return { footer: footer.buffer };
      } catch (e: any) {
        throw new Error(`byoUploadFlow finalize failed: ${e?.message ?? e}`);
      } finally {
        try { flow.free?.(); } catch { /* ignore */ }
        byoUploadFlowSessions.delete(request.sessionId);
      }
    }

    case 'byoUploadFlowAbort': {
      const flow = byoUploadFlowSessions.get(request.sessionId);
      if (flow) {
        try { flow.free?.(); } catch { /* ignore */ }
        byoUploadFlowSessions.delete(request.sessionId);
      }
      return { ok: true };
    }

    case 'byoUploadFlowPosition': {
      const flow = byoUploadFlowSessions.get(request.sessionId);
      if (!flow) return 0;
      return flow.position() as number;
    }

    case 'byoRefreshToken': {
      const { providerType, configJson } = request;
      let fn: (configJson: string) => Promise<string>;
      switch (providerType) {
        case 'gdrive': fn = byo_gdrive_refresh_token; break;
        case 'dropbox': fn = byo_dropbox_refresh_token; break;
        case 'onedrive': fn = byo_onedrive_refresh_token; break;
        case 'box': fn = byo_box_refresh_token; break;
        case 'pcloud': fn = byo_pcloud_refresh_token; break;
        default: throw new Error(`byoRefreshToken: ${providerType} does not support OAuth refresh`);
      }
      return await fn(configJson);
    }

    // ── Config registry (R1.4) ────────────────────────────────────────
    case 'byoInitConfig': {
      const { configJson } = request;
      const handle: string = crypto.randomUUID();
      configRegistry.set(handle, configJson as string);
      return handle;
    }

    case 'byoReleaseConfig': {
      const { configHandle } = request;
      configRegistry.delete(configHandle as string);
      return null;
    }

    case 'byoRefreshConfigByHandle': {
      const { providerType, configHandle } = request;
      const cfg = configRegistry.get(configHandle as string);
      if (!cfg) throw new Error(`byoRefreshConfigByHandle: unknown handle`);
      let fn: (configJson: string) => Promise<string>;
      switch (providerType) {
        case 'gdrive':   fn = byo_gdrive_refresh_token;   break;
        case 'dropbox':  fn = byo_dropbox_refresh_token;  break;
        case 'onedrive': fn = byo_onedrive_refresh_token; break;
        case 'box':      fn = byo_box_refresh_token;      break;
        case 'pcloud':   fn = byo_pcloud_refresh_token;   break;
        default: throw new Error(`byoRefreshConfigByHandle: ${providerType as string} does not support OAuth refresh`);
      }
      const updated: string = await fn(cfg);
      configRegistry.set(configHandle as string, updated);
      return null;
    }

    // ── Generic provider dispatcher (P8) ──────────────────────────────
    case 'byoProviderCall': {
      const { providerType, op, configHandle, argsJson } = request;
      const cfg = configRegistry.get(configHandle as string);
      if (!cfg) throw new Error(`byoProviderCall: unknown config handle`);
      const args = { ...(JSON.parse(argsJson as string) as Record<string, unknown>), config: JSON.parse(cfg) };
      const result: string = await byo_provider_call(providerType, op, JSON.stringify(args));
      return JSON.parse(result);
    }

    case 'byoCrossProviderStreamCopy': {
      const { srcType, srcConfigHandle, dstType, dstConfigHandle, srcRef, dstName, totalSize } = request;
      const srcCfg = configRegistry.get(srcConfigHandle as string);
      if (!srcCfg) throw new Error(`byoCrossProviderStreamCopy: unknown src config handle`);
      const dstCfg = configRegistry.get(dstConfigHandle as string);
      if (!dstCfg) throw new Error(`byoCrossProviderStreamCopy: unknown dst config handle`);
      const result = await byo_cross_provider_stream_copy(
        srcType, srcCfg,
        dstType, dstCfg,
        srcRef, dstName, totalSize,
      );
      return JSON.parse(result);
    }

    // ── Phase 3d: provider-integrated streaming sessions ──────────────────
    case 'byoStreamUploadInit': {
      const { pubKeysJson, providerType, configHandle, name, parentRef, plaintextLen } = request;
      const cfg = configRegistry.get(configHandle as string);
      if (!cfg) throw new Error(`byoStreamUploadInit: unknown config handle`);
      return byo_stream_upload_init(pubKeysJson, providerType, cfg, name, parentRef ?? undefined, plaintextLen);
    }

    case 'byoStreamUploadPush': {
      const { sessionId, data, isLast } = request;
      // S9: the plaintext chunk arrives via structured clone / transfer and
      // lives in the worker JS heap for the duration of the WASM call. After
      // the WASM has consumed and encrypted it, zero the JS-visible buffer so
      // plaintext doesn't linger for the GC cycle. (The buffer is the caller's
      // copy — neutering it here is safe because WASM has already read from it.)
      const buf = new Uint8Array(data as ArrayBuffer);
      try {
        return await byo_stream_upload_push(sessionId, data as ArrayBuffer, isLast);
      } finally {
        buf.fill(0);
      }
    }

    case 'byoStreamUploadFinalize': {
      const { sessionId } = request;
      const resultStr: string = await byo_stream_upload_finalize(sessionId);
      return JSON.parse(resultStr);
    }

    case 'byoStreamUploadAbort': {
      const { sessionId } = request;
      return byo_stream_upload_abort(sessionId);
    }

    case 'byoStreamDownloadInit': {
      const { secKeysJson, providerType, configHandle, ref: ref_ } = request;
      const cfg = configRegistry.get(configHandle as string);
      if (!cfg) throw new Error(`byoStreamDownloadInit: unknown config handle`);
      return byo_stream_download_init(secKeysJson, providerType, cfg, ref_);
    }

    case 'byoStreamDownloadPull': {
      const { sessionId } = request;
      const result = await byo_stream_download_pull(sessionId);
      // result is null (EOF) or Uint8Array (plaintext chunk, may be empty during header phase)
      return result;
    }

    case 'byoStreamDownloadClose': {
      const { sessionId } = request;
      return byo_stream_download_close(sessionId);
    }

    // ── Per-device signing keys (v2 vault) ─────────────────────────────
    case 'byoGenerateDeviceSigningKey': {
      const result = byo_generate_device_signing_key();
      if (result && result.error) throw new Error(result.error);
      return { publicKey: result.public_key, seed: result.seed };
    }

    case 'byoSealDeviceSigningKey': {
      const result = byo_seal_device_signing_key(request.vaultKeyB64, request.deviceIdB64, request.seedB64);
      if (result && result.error) throw new Error(result.error);
      return { wrapped: result.wrapped };
    }

    case 'byoUnsealDeviceSigningKey': {
      const result = byo_unseal_device_signing_key(request.vaultKeyB64, request.deviceIdB64, request.wrappedB64);
      if (result && result.error) throw new Error(result.error);
      return { seed: result.seed };
    }

    case 'byoEd25519Sign': {
      const result = byo_ed25519_sign(request.seedB64, request.messageB64);
      if (result && result.error) throw new Error(result.error);
      return { signature: result.signature };
    }

    case 'byoEd25519Verify': {
      const result = byo_ed25519_verify(request.publicKeyB64, request.messageB64, request.signatureB64);
      if (result && result.error) throw new Error(result.error);
      return { valid: result.valid };
    }

    case 'byoMigrateVaultV1ToV2': {
      const bytes = new Uint8Array(request.vaultBytes);
      const migrated = byo_migrate_vault_v1_to_v2(bytes, request.vaultKeyB64);
      if (!migrated) throw new Error('byoMigrateVaultV1ToV2: migration failed');
      return migrated;
    }

    case 'ping':
      return { pong: true };

    // ── Vault session API (ZK-safe) ─────────────────────────────────────
    case 'byoVaultCreate': {
      checkKdfRateLimit();
      const result = byo_vault_create(
        request.password,
        request.memoryKb,
        request.iterations,
        request.parallelism,
      );
      if (result && result.error) throw new Error(result.error);
      return {
        sessionId: result.session_id as number,
        shardB64: result.shard_b64 as string,
        vaultIdB64: result.vault_id_b64 as string,
        masterSaltB64: result.master_salt_b64 as string,
        passWrapIvB64: result.pass_wrap_iv_b64 as string,
        passWrappedKeyB64: result.pass_wrapped_key_b64 as string,
      };
    }

    case 'byoVaultOpenRecovery': {
      const result = byo_vault_open_recovery(
        request.recoveryKeyB64,
        request.wrapIvB64,
        request.wrappedKeyB64,
      );
      if (result && result.error) throw new Error(result.error);
      return { sessionId: result.session_id as number };
    }

    case 'byoVaultWrapRecovery': {
      const result = byo_vault_wrap_recovery(request.sessionId, request.recoveryKeyB64);
      if (result && result.error) throw new Error(result.error);
      return {
        recWrapIvB64: result.rec_wrap_iv_b64 as string,
        recWrappedKeyB64: result.rec_wrapped_key_b64 as string,
      };
    }

    case 'byoVaultRewrapWithPassphrase': {
      checkKdfRateLimit();
      const result = byo_vault_rewrap_with_passphrase(
        request.sessionId,
        request.newPassword,
        request.memoryKb,
        request.iterations,
        request.parallelism,
      );
      if (result && result.error) throw new Error(result.error);
      return {
        wrapIvB64: result.wrap_iv_b64 as string,
        wrappedKeyB64: result.wrapped_key_b64 as string,
        masterSaltB64: result.master_salt_b64 as string,
      };
    }

    case 'byoVaultOpen': {
      checkKdfRateLimit();
      const result = byo_vault_open(
        request.password,
        request.saltB64,
        request.memoryKb,
        request.iterations,
        request.parallelism,
        request.wrapIvB64,
        request.wrappedVaultKeyB64,
      );
      if (result && result.error) throw new Error(result.error);
      return { sessionId: result.session_id as number };
    }

    case 'byoVaultClose': {
      byo_vault_close(request.sessionId);
      return { ok: true };
    }

    case 'byoVaultVerifyHeaderHmac': {
      const result = byo_vault_verify_header_hmac(
        request.sessionId,
        request.headerPrefixB64,
        request.expectedHmacB64,
      );
      if (result && result.error) throw new Error(result.error);
      return { valid: result.valid as boolean };
    }

    case 'byoVaultDecryptBody': {
      const sqlite: Uint8Array | null = byo_vault_decrypt_body(
        request.sessionId,
        new Uint8Array(request.nonceAndCt),
      );
      if (!sqlite) throw new Error('byo_vault_decrypt_body failed');
      return sqlite.buffer;
    }

    case 'byoVaultEncryptBody': {
      consumeDestructiveToken(request.opToken);
      const nonceAndCt: Uint8Array | null = byo_vault_encrypt_body(
        request.sessionId,
        new Uint8Array(request.sqliteBytes),
      );
      if (!nonceAndCt) throw new Error('byo_vault_encrypt_body failed');
      // Callers expect { body_iv, body_ciphertext } as base64 strings
      return {
        body_iv: toBase64(nonceAndCt.slice(0, 12)),
        body_ciphertext: toBase64(nonceAndCt.slice(12)),
      };
    }

    case 'byoVaultComputeHeaderHmac': {
      const result = byo_vault_compute_header_hmac(request.sessionId, request.headerPrefixB64);
      if (result && result.error) throw new Error(result.error);
      return { hmac: result.hmac_b64 as string };
    }

    case 'byoVaultDeriveKek': {
      const result = byo_vault_derive_kek(request.sessionId, request.shardB64);
      if (result && result.error) throw new Error(result.error);
      return { ok: true };
    }

    case 'byoVaultLoadKeys': {
      const result = byo_vault_load_keys(
        request.sessionId,
        new Uint8Array(request.mlkemSkEncrypted),
        new Uint8Array(request.x25519SkEncrypted),
      );
      if (result && result.error) throw new Error(result.error);
      // Store decrypted keys in the worker's key registry under keySessionId
      const mlkemSk = fromBase64(result.mlkem_sk_b64 as string);
      const x25519Sk = fromBase64(result.x25519_sk_b64 as string);
      storeKeys(request.keySessionId, mlkemSk, x25519Sk);
      // Zeroize the intermediate copies
      zeroizeArray(mlkemSk);
      zeroizeArray(x25519Sk);
      return { ok: true };
    }

    case 'byoVaultDeriveSubkey': {
      const bytes: Uint8Array | null = byo_vault_derive_subkey(request.sessionId, request.purpose);
      if (!bytes) throw new Error('byo_vault_derive_subkey failed — session not found');
      return bytes.buffer;
    }

    case 'byoVaultGenerateKeypairWrapped': {
      const result = byo_vault_generate_keypair_wrapped(request.sessionId);
      if (result && result.error) throw new Error(result.error);
      return {
        mlkemPublicKeyB64: result.mlkem_public_key_b64 as string,
        mlkemPrivateKeyEncrypted: (result.mlkem_private_key_encrypted as Uint8Array).buffer,
        x25519PublicKeyB64: result.x25519_public_key_b64 as string,
        x25519PrivateKeyEncrypted: (result.x25519_private_key_encrypted as Uint8Array).buffer,
      };
    }

    case 'webauthnDeriveWrappingKey': {
      const bytes: Uint8Array = webauthn_derive_wrapping_key(new Uint8Array(request.prfOutput));
      return bytes.buffer;
    }

    case 'webauthnWrapDeviceKey': {
      const bytes: Uint8Array = webauthn_wrap_device_key(
        new Uint8Array(request.deviceKey),
        new Uint8Array(request.wrappingKey),
      );
      return bytes.buffer;
    }

    case 'webauthnUnwrapDeviceKey': {
      const bytes: Uint8Array = webauthn_unwrap_device_key(
        new Uint8Array(request.wrapped),
        new Uint8Array(request.wrappingKey),
      );
      return bytes.buffer;
    }

    case 'webauthnGenerateDeviceKey': {
      const bytes: Uint8Array = webauthn_generate_device_key();
      return bytes.buffer;
    }

    case 'webauthnDeriveVaultKeyWrappingKey': {
      const bytes: Uint8Array = webauthn_derive_vault_key_wrapping_key(
        new Uint8Array(request.prfOutput),
      );
      return bytes.buffer;
    }

    case 'webauthnWrapVaultKey': {
      const bytes: Uint8Array = webauthn_wrap_vault_key(
        new Uint8Array(request.vaultKey),
        new Uint8Array(request.wrappingKey),
      );
      return bytes.buffer;
    }

    case 'webauthnUnwrapVaultKey': {
      const bytes: Uint8Array = webauthn_unwrap_vault_key(
        new Uint8Array(request.wrapped),
        new Uint8Array(request.wrappingKey),
      );
      return bytes.buffer;
    }

    case 'byoVaultWrapSessionVaultKeyWithPrf': {
      const result = byo_vault_wrap_session_vault_key_with_prf(
        request.sessionId,
        request.prfOutputB64,
      );
      if (result && result.error) throw new Error(result.error);
      return { wrappedB64: result.wrapped_b64 as string };
    }

    case 'byoVaultLoadSessionFromWrappedVaultKey': {
      const result = byo_vault_load_session_from_wrapped_vault_key(
        request.wrappedB64,
        request.prfOutputB64,
      );
      if (result && result.error) throw new Error(result.error);
      return { sessionId: result.session_id as number };
    }

    case 'byoVaultSealDeviceSigningKey': {
      const result = byo_vault_seal_device_signing_key(
        request.sessionId,
        request.deviceIdB64,
        request.seedB64,
      );
      if (result && result.error) throw new Error(result.error);
      return { wrapped: result.wrapped as string };
    }

    case 'byoVaultUnsealDeviceSigningKey': {
      const result = byo_vault_unseal_device_signing_key(
        request.sessionId,
        request.deviceIdB64,
        request.wrappedB64,
      );
      if (result && result.error) throw new Error(result.error);
      return { seed: result.seed as string };
    }

    case 'byoVaultMigrateV1ToV2': {
      const bytes = new Uint8Array(request.vaultBytes);
      const migrated: Uint8Array | null = byo_vault_migrate_v1_to_v2(request.sessionId, bytes);
      if (!migrated) throw new Error('byo_vault_migrate_v1_to_v2 failed');
      return migrated.buffer;
    }

    case 'byoVaultRewrap': {
      const result = byo_vault_rewrap(request.sessionId, request.newWrappingKeyB64);
      if (result && result.error) throw new Error(result.error);
      return { wrapIvB64: result.wrap_iv_b64 as string, wrappedKeyB64: result.wrapped_key_b64 as string };
    }

    // ── Relay auth / PoW ────────────────────────────────────────────────
    case 'byoDeriveSftpPurpose': {
      const purpose: string = byo_derive_sftp_purpose_wasm(request.host, request.port);
      return purpose;
    }

    case 'byoDeriveEnrollmentPurpose': {
      const purpose: string = byo_derive_enrollment_purpose_wasm(request.channelId);
      return purpose;
    }

    case 'byoSolveRelayPow': {
      const result = byo_solve_relay_pow_wasm(request.nonceHex, request.purpose, request.difficulty);
      if (result && typeof result === 'object' && 'error' in result) {
        throw new Error(result.error as string);
      }
      return result; // { answer: number }
    }

    // ── Share link crypto (P10) ────────────────────────────────────────────

    case 'byoCreateShareFragment': {
      // Variant A or A+: decapsulate V7 header inside WASM, return fragment only.
      // The content_key never leaves WASM memory.
      const keys = retrieveKeys(request.sessionId);
      if (!keys) throw new Error('no keys for session ' + request.sessionId);
      const mlkemB64 = btoa(String.fromCharCode(...keys.mlkem_secret_key));
      const x25519B64 = btoa(String.fromCharCode(...keys.x25519_secret_key));
      if (request.variant === 'A+' && !request.password) {
        throw new Error('password required for variant A+');
      }
      const fragment = byo_create_share_fragment(
        mlkemB64,
        x25519B64,
        request.headerB64,
        request.variant,
        request.password ?? null,
      );
      if (fragment && typeof fragment === 'object' && 'error' in fragment) {
        throw new Error(fragment.error as string);
      }
      return fragment as string;
    }

    case 'byoBundleExtractFileKey': {
      // Bundle-share creator: decapsulate the V7 KEM in WASM and hand the
      // per-file content_key back as base64. The caller re-encrypts it into
      // the bundle manifest under the bundle_key, so the relay never sees
      // any per-file key in plaintext.
      const keys = retrieveKeys(request.sessionId);
      if (!keys) throw new Error('no keys for session ' + request.sessionId);
      const mlkemB64 = btoa(String.fromCharCode(...keys.mlkem_secret_key));
      const x25519B64 = btoa(String.fromCharCode(...keys.x25519_secret_key));
      const result = byo_bundle_extract_file_key(mlkemB64, x25519B64, request.headerB64);
      if (result && typeof result === 'object' && 'error' in result) {
        throw new Error(result.error as string);
      }
      return result as string;
    }

    case 'byoEncryptManifestV7': {
      // V7-encrypt a bundle manifest under the bundle_key. Used by the
      // creator to produce the `_manifest` blob for folder / collection
      // shares. The bundle_key itself lives in the URL fragment; the relay
      // never sees it.
      const manifestBytes = Uint8Array.from(atob(request.manifestBytesB64), (c) => c.charCodeAt(0));
      const ciphertext = byo_encrypt_manifest_v7(manifestBytes, request.contentKeyB64);
      if (ciphertext && typeof ciphertext === 'object' && 'error' in (ciphertext as any)) {
        throw new Error((ciphertext as any).error as string);
      }
      // Return the ciphertext as base64 so the postMessage payload stays
      // simple; the client re-decodes before POST.
      const bytes = ciphertext as Uint8Array;
      let bin = '';
      const CHUNK = 0x8000;
      for (let i = 0; i < bytes.byteLength; i += CHUNK) {
        bin += String.fromCharCode(...bytes.subarray(i, Math.min(i + CHUNK, bytes.byteLength)));
      }
      return btoa(bin);
    }

    case 'byoShareEncodeVariantA': {
      const fragment = byo_share_encode_variant_a(request.contentKeyB64);
      if (fragment && typeof fragment === 'object' && 'error' in fragment) {
        throw new Error(fragment.error as string);
      }
      return fragment as string;
    }

    case 'byoShareDecodeVariantA': {
      const ck = byo_share_decode_variant_a(request.fragment);
      if (ck && typeof ck === 'object' && 'error' in ck) {
        throw new Error(ck.error as string);
      }
      return ck as string; // base64-encoded content_key
    }

    case 'byoShareWrapKey': {
      checkKdfRateLimit(); // Argon2id call — rate-limited
      const result = byo_share_wrap_key(request.contentKeyB64, request.password);
      if (result && typeof result === 'object' && 'error' in result) {
        throw new Error(result.error as string);
      }
      return result as { saltB64url: string; encryptedCkB64url: string };
    }

    case 'byoShareUnwrapKey': {
      checkKdfRateLimit(); // Argon2id call — rate-limited
      const ck = byo_share_unwrap_key(request.saltB64url, request.encryptedCkB64url, request.password);
      if (ck && typeof ck === 'object' && 'error' in ck) {
        throw new Error(ck.error as string);
      }
      return ck as string; // base64-encoded content_key
    }

    // ── R6 multi-vault ──────────────────────────────────────────────────

    case 'byoManifestEncrypt': {
      const result = byo_manifest_encrypt(request.sessionId, request.manifestJson);
      if (result && result.error) throw new Error(result.error);
      return { data: result.data as string };
    }

    case 'byoManifestDecrypt': {
      const result = byo_manifest_decrypt(request.sessionId, request.bodyBlobB64);
      if (result && result.error) throw new Error(result.error);
      return { manifestJson: result.manifest_json as string };
    }

    case 'byoManifestMerge': {
      const result = byo_manifest_merge(
        request.manifestJsonsJson,
        request.nowUnixSecs,
        request.minAcceptableVersion,
      );
      if (result && result.error) throw new Error(result.error);
      return { manifestJson: result.manifest_json as string };
    }

    case 'byoManifestValidate': {
      const result = byo_manifest_validate(request.manifestJson, request.nowUnixSecs);
      if (result && result.error) throw new Error(result.error);
      return { ok: true };
    }

    case 'byoVaultBodyEncrypt': {
      const result = byo_vault_body_encrypt(request.sessionId, request.providerId, request.sqliteB64);
      if (result && result.error) throw new Error(result.error);
      return { data: result.data as string };
    }

    case 'byoVaultBodyDecrypt': {
      const result = byo_vault_body_decrypt(request.sessionId, request.providerId, request.bodyBlobB64);
      if (result && result.error) throw new Error(result.error);
      return { data: result.data as string };
    }

    case 'byoDerivePerVaultWalKey': {
      // Derive the raw key inside the worker, import it as a non-extractable
      // WebCrypto key, and hand the CryptoKey across to the main thread via
      // structured clone. A non-extractable CryptoKey cannot be read back to
      // raw bytes, so the vault subkey never crosses the postMessage boundary
      // in plaintext — even a compromised main thread cannot exfiltrate it.
      const result = byo_derive_per_vault_wal_key(request.sessionId, request.providerId);
      if (result && result.error) throw new Error(result.error);
      const bytes = fromBase64(result.key_b64 as string);
      try {
        const key = await crypto.subtle.importKey(
          'raw',
          bytes as unknown as ArrayBuffer,
          { name: 'AES-GCM' },
          false,
          ['encrypt', 'decrypt'],
        );
        return { key };
      } finally {
        bytes.fill(0);
      }
    }

    case 'byoDerivePerVaultJournalKeys': {
      const result = byo_derive_per_vault_journal_keys(request.sessionId, request.providerId);
      if (result && result.error) throw new Error(result.error);
      const aeadBytes = fromBase64(result.aead_key_b64 as string);
      const hmacBytes = fromBase64(result.hmac_key_b64 as string);
      try {
        const [aeadKey, hmacKey] = await Promise.all([
          crypto.subtle.importKey(
            'raw',
            aeadBytes as unknown as ArrayBuffer,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt'],
          ),
          crypto.subtle.importKey(
            'raw',
            hmacBytes as unknown as ArrayBuffer,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign', 'verify'],
          ),
        ]);
        return { aeadKey, hmacKey };
      } finally {
        aeadBytes.fill(0);
        hmacBytes.fill(0);
      }
    }

    case 'byoPlanUnlock': {
      const result = byo_plan_unlock(request.manifestJson, request.onlineIdsJson, request.cachedIdsJson);
      if (result && result.error) throw new Error(result.error);
      return { planJson: result.plan_json as string };
    }

    case 'byoPlanSave': {
      const result = byo_plan_save(request.dirtyIdsJson, request.onlineIdsJson);
      if (result && result.error) throw new Error(result.error);
      return { planJson: result.plan_json as string };
    }

    case 'byoPlanCrossProviderMove': {
      const result = byo_plan_cross_provider_move(
        request.fileId,
        request.sourceProviderRef,
        request.srcProviderId,
        request.dstProviderId,
        request.destFolderId,
        request.displayName,
      );
      if (result && result.error) throw new Error(result.error);
      return { planJson: result.plan_json as string };
    }

    case 'byoDeriveManifestAeadKey': {
      const result = byo_derive_manifest_aead_key(request.sessionId);
      if (result && result.error) throw new Error(result.error);
      return { keyB64: result.key_b64 as string };
    }

    // ── Cross-provider move reconciler (S4) ────────────────────────────
    case 'byoCrossProviderMoveDecideReplay': {
      const req = request as ByoCrossProviderMoveDecideReplayRequest;
      const result = byo_cross_provider_move_decide_replay(
        req.stepBytesB64,
        req.dstFileExists,
        req.srcBlobExistsStr,
      );
      if (result && result.error) throw new Error(result.error);
      return {
        decision: result.decision as string,
        providerId: result.provider_id as string | undefined,
        providerRef: result.provider_ref as string | undefined,
      };
    }

    case 'byoCrossProviderMovePlanReconcile': {
      const req = request as ByoCrossProviderMovePlanReconcileRequest;
      const result = byo_cross_provider_move_plan_reconcile(
        req.stepsJson,
        req.dstFileExists,
        req.srcBlobExistsStr,
      );
      if (result && result.error) throw new Error(result.error);
      return { actions: result.actions as Array<{ type: string; provider_id: string; provider_ref: string }> };
    }

    // ── Journal codec (P3.1) ────────────────────────────────────────────
    case 'byoJournalAppend': {
      const req = request as ByoJournalAppendRequest;
      const result = byo_journal_append(req.sessionId, req.providerId, req.entryType, req.table, req.rowId, req.dataJson);
      if (result && result.error) throw new Error(result.error);
      return { entry_b64: result.entry_b64 as string };
    }

    case 'byoJournalParse': {
      const req = request as ByoJournalParseRequest;
      const result = byo_journal_parse(req.sessionId, req.providerId, req.journalB64);
      if (result && result.error) throw new Error(result.error);
      return { entries: result.entries };
    }

    case 'byoShareAuditPayload': {
      const req = request as ByoShareAuditPayloadRequest;
      const result = byo_share_audit_payload(req.direction, req.fileRef, req.counterpartyHint, req.tsMs);
      if (result && result.error) throw new Error(result.error);
      return { data_json: result.data_json as string };
    }

    // ── Row-merge (P3.2) ────────────────────────────────────────────────
    case 'byoMergeRows': {
      const result = byo_merge_rows(request.localRowsJson, request.remoteRowsJson, request.isKeyVersions);
      if (result && result.error) throw new Error(result.error);
      return { ops_json: result.ops_json as string };
    }

    // ── Manifest mutation helpers (P3.3) ────────────────────────────────
    case 'byoManifestAddProvider': {
      const result = byo_manifest_add_provider(request.manifestJson, request.entryJson);
      if (result && result.error) throw new Error(result.error);
      return { manifestJson: result.manifest_json as string };
    }

    case 'byoManifestRenameProvider': {
      const result = byo_manifest_rename_provider(request.manifestJson, request.providerId, request.newName, request.nowUnixSecs);
      if (result && result.error) throw new Error(result.error);
      return { manifestJson: result.manifest_json as string };
    }

    case 'byoManifestSetPrimary': {
      const result = byo_manifest_set_primary_provider(request.manifestJson, request.providerId, request.nowUnixSecs);
      if (result && result.error) throw new Error(result.error);
      return { manifestJson: result.manifest_json as string };
    }

    case 'byoManifestTombstone': {
      const result = byo_manifest_tombstone_provider(request.manifestJson, request.providerId, request.nowUnixSecs);
      if (result && result.error) throw new Error(result.error);
      return { manifestJson: result.manifest_json as string };
    }

    case 'byoManifestUpdateProviderConfig': {
      const result = byo_manifest_update_provider_config(
        request.manifestJson,
        request.providerId,
        request.newConfigJson,
        request.nowUnixSecs,
      );
      if (result && result.error) throw new Error(result.error);
      return { manifestJson: result.manifest_json as string };
    }

    // ── Stats (Phase 5) ─────────────────────────────────────────────────
    case 'statsInit': {
      stats_init(request.baseUrl, request.deviceId);
      return null;
    }

    case 'statsRecord': {
      stats_record(request.eventJson);
      return null;
    }

    case 'statsDrain': {
      return { depth: stats_drain() as number };
    }

    case 'statsFlush': {
      await stats_flush();
      return null;
    }

    default:
      throw new Error(`Unknown request type: ${(request as any).type}`);
  }
}

// ── Worker message handling ─────────────────────────────────────────────────

self.onmessage = async (event: MessageEvent) => {
  const { id, request }: { id: number; request: WorkerRequest } = event.data;

  try {
    const result = await handleMessage(request);
    self.postMessage({ id, success: true, result });
  } catch (error: any) {
    self.postMessage({ id, success: false, error: error.message || 'Unknown error' });
  }
};

// Initialize WASM on worker start
initWasm().catch((err) => {
  console.error('[byo.worker] Failed to initialize WASM:', err);
});