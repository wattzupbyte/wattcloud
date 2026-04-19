/**
 * Type declarations for the @wattcloud/wasm module.
 *
 * This module is built by wasm-pack from sdk-wasm and loaded at runtime.
 * The actual types are defined in the pkg directory after building.
 */
declare module '@wattcloud/wasm' {
  export function init(module_or_path?: string | URL | Request): Promise<void>;

  // BYO streaming flows (replaces V7StreamDecryptorWasm+FooterTrimmer and V7StreamEncryptorWasm)
  export class ByoDownloadFlow {
    /**
     * Initialise with JSON `{mlkem_secret_key, x25519_secret_key}` (base64 values).
     * @throws if the JSON is malformed or keys are invalid.
     */
    static create(secKeysJson: string): ByoDownloadFlow;
    /**
     * Feed raw ciphertext bytes; returns any plaintext now available (may be empty).
     * Buffers the first V7_HEADER_MIN bytes before decrypting; trims the HMAC footer.
     * @throws on AES-GCM decryption failure.
     */
    push(data: Uint8Array): Uint8Array;
    /**
     * Verify the HMAC footer. Throws on mismatch — callers MUST discard all
     * plaintext previously yielded by push() if this throws.
     * @throws {Error} on HMAC mismatch or truncated stream.
     */
    finalize(): void;
    free(): void;
  }

  export class ByoUploadFlow {
    /**
     * Initialise with JSON `{mlkem_public_key, x25519_public_key}` (base64) + exact plaintext length.
     * `plaintextLen` must not exceed Number.MAX_SAFE_INTEGER (internally treated as f64).
     * @throws if the JSON is malformed, keys are invalid, or plaintextLen is negative.
     */
    static create(pubKeysJson: string, plaintextLen: number): ByoUploadFlow;
    /** Total ciphertext bytes (header + frames + footer). Use for Content-Length. */
    readonly totalSize: number;
    /**
     * Consume and return the 1709-byte V7 header. Call exactly once, before any pushChunk.
     * This method is single-shot: calling it a second time throws.
     * @throws if called more than once.
     */
    takeHeader(): Uint8Array;
    /**
     * Encrypt one chunk and return the V7 wire frame.
     * Non-final chunks (isLast=false) must be exactly V7_ENCRYPT_CHUNK_SIZE (512 KiB).
     * The final chunk (isLast=true) may be any length including zero.
     * @throws on size contract violation or AES-GCM failure.
     */
    pushChunk(plaintext: Uint8Array, isLast: boolean): Uint8Array;
    /**
     * Return the 32-byte HMAC footer. Upload as the last bytes, then close stream.
     * @throws if finalize is called before pushChunk(_, isLast=true) for non-empty files.
     */
    finalize(): Uint8Array;
    free(): void;
  }

  // V7 streaming (legacy — kept for any callers not yet migrated to ByoDownloadFlow/ByoUploadFlow)
  export class V7StreamDecryptorWasm {
    static create(headerBytes: Uint8Array, secKeysJson: string): V7StreamDecryptorWasm;
    readonly headerEnd: number;
    push(data: Uint8Array): Uint8Array;
    finalize(storedHmac: Uint8Array): void;
    free(): void;
  }

  export class V7StreamEncryptorWasm {
    static create(publicKeysJson: string): V7StreamEncryptorWasm;
    takeHeader(): Uint8Array;
    push(plaintext: Uint8Array): Uint8Array;
    finalize(): Uint8Array;
    free(): void;
  }

  // Filename crypto
  export function decrypt_file_v7(encryptedData: Uint8Array, secKeysJson: string): Uint8Array | null;
  export function decrypt_filename(encryptedNameB64: string, keyB64: string): { name: string } | null;

  // Atomic filename encryption
  export function encrypt_filename_with_fresh_key(
    filename: string,
    metadata: string | null,
    publicKeysJson: string,
  ): { encrypted_filename: string; encrypted_metadata: string | null; encrypted_filename_key: string };

  // BYO vault operations
  export function byo_parse_vault_header(vaultBytes: Uint8Array): any;
  export function byo_derive_vault_keys(
    password: string,
    saltB64: string,
    memoryKb: number,
    iterations: number,
    parallelism: number,
  ): any;
  export function byo_derive_vault_keys_default(password: string, saltB64: string): any;
  export function byo_unwrap_vault_key(wrapIvB64: string, wrappedKeyB64: string, unwrappingKeyB64: string): any;
  export function byo_derive_kek(clientKekHalfB64: string, shardB64: string): any;
  export function byo_derive_recovery_vault_kek(recoveryKeyB64: string): any;
  export function byo_compute_header_hmac(vaultKeyB64: string, headerPrefixB64: string): any;
  export function byo_verify_header_hmac(vaultKeyB64: string, headerPrefixB64: string, expectedHmacB64: string): any;
  export function byo_wrap_vault_key(vaultKeyB64: string, wrappingKeyB64: string): any;
  export function byo_encrypt_vault_body(sqliteBytes: Uint8Array, vaultKeyB64: string): Uint8Array | null;
  export function byo_decrypt_vault_body(nonceAndCt: Uint8Array, vaultKeyB64: string): Uint8Array | null;
  export function byo_generate_vault_keys(): any;

  // BYO enrollment operations (legacy — eph_sk / enc_key cross boundary)
  export function byo_enrollment_initiate(): any;
  export function byo_enrollment_derive_session(ephSkB64: string, peerPkB64: string, channelIdB64: string): any;
  export function byo_enrollment_encrypt_shard(shardB64: string, encKeyB64: string, macKeyB64: string): any;
  export function byo_enrollment_decrypt_shard(envelopeB64: string, encKeyB64: string, macKeyB64: string): any;

  // Enrollment session API (ZK-safe: eph_sk / enc_key / mac_key never cross WASM boundary)
  export function byo_enrollment_open(): any;
  export function byo_enrollment_derive_keys(sessionId: number, peerPkB64: string): any;
  export function byo_enrollment_session_encrypt_shard(sessionId: number, shardB64: string): any;
  export function byo_enrollment_session_decrypt_shard(sessionId: number, envelopeB64: string): any;
  export function byo_enrollment_session_get_shard(sessionId: number): any;
  export function byo_enrollment_close(sessionId: number): void;

  // Vault session API (ZK-safe: vault_key/kek never cross WASM boundary)

  // Creation / recovery session entry points
  export function byo_vault_create(password: string, memoryKb: number, iterations: number, parallelism: number): any;
  export function byo_vault_open_recovery(recoveryKeyB64: string, wrapIvB64: string, wrappedKeyB64: string): any;
  export function byo_vault_wrap_recovery(sessionId: number, recoveryKeyB64: string): any;
  export function byo_vault_rewrap_with_passphrase(sessionId: number, newPassword: string, memoryKb: number, iterations: number, parallelism: number): any;

  // Unlock session entry point
  export function byo_vault_open(password: string, saltB64: string, memoryKb: number, iterations: number, parallelism: number, wrapIvB64: string, wrappedVaultKeyB64: string): any;
  export function byo_vault_close(sessionId: number): void;
  export function byo_vault_verify_header_hmac(sessionId: number, headerPrefixB64: string, expectedHmacB64: string): any;
  export function byo_vault_decrypt_body(sessionId: number, nonceAndCt: Uint8Array): Uint8Array | null;
  export function byo_vault_encrypt_body(sessionId: number, sqliteBytes: Uint8Array): Uint8Array | null;
  export function byo_vault_compute_header_hmac(sessionId: number, headerPrefixB64: string): any;
  export function byo_vault_derive_kek(sessionId: number, shardB64: string): any;
  export function byo_vault_load_keys(sessionId: number, mlkemSkEncrypted: Uint8Array, x25519SkEncrypted: Uint8Array): any;
  export function byo_vault_derive_subkey(sessionId: number, purpose: string): Uint8Array | null;
  export function byo_vault_seal_device_signing_key(sessionId: number, deviceIdB64: string, seedB64: string): any;
  export function byo_vault_unseal_device_signing_key(sessionId: number, deviceIdB64: string, wrappedB64: string): any;
  export function byo_vault_migrate_v1_to_v2(sessionId: number, vaultBytes: Uint8Array): Uint8Array | null;
  export function byo_vault_rewrap(sessionId: number, newWrappingKeyB64: string): any;

  // BYO SFTP relay session
  export class SftpSessionWasm {
    constructor(
      sendText: (msg: string) => void,
      sendTextAndBinary: (text: string, bin: Uint8Array) => void,
      close: () => void,
    );
    on_recv_text(msg: string): void;
    on_recv_binary(data: Uint8Array): void;
    on_close(): void;
    /** Read-and-reset SFTP relay bandwidth counters. Returns bytes sent and received since last call. */
    relayBandwidthAndReset(): { sent: number; recv: number };
    free(): void;
  }

  // BYO usage statistics
  /** Initialise the stats subsystem. Call once on worker boot after device UUID is confirmed. */
  export function statsInit(base_url: string, device_id: string): void;
  /** Queue a single event (JSON object with a "kind" field). Sync and fire-and-forget. */
  export function statsRecord(event_json: string): void;
  /** Return current queue depth (number of pending events). */
  export function statsDrain(): number;
  /** Drain up to 200 events and POST to /relay/stats. Browser attaches relay_auth cookie automatically. */
  export function statsFlush(): Promise<void>;

  // Health check
  export function health_check(): string;
}