# Wattcloud — Technical Specification

BYO (Bring Your Own) storage mode lets users encrypt and store their files on a provider they own and control (Google Drive, Dropbox, Microsoft OneDrive, WebDAV, SFTP, Box, pCloud, or S3-compatible object storage). The Wattcloud server acts only as a stateless relay for enrollment; it never holds, processes, or has access to any key material or plaintext data.

This document is the authoritative technical reference for the BYO implementation. For SDK security invariants see `SECURITY.md`.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Vault File Format](#vault-file-format)
3. [Cryptographic Key Hierarchy](#cryptographic-key-hierarchy)
4. [Multi-Provider](#multi-provider)
5. [Device Enrollment Protocol](#device-enrollment-protocol)
6. [OAuth 2.0 / PKCE Flow](#oauth-20--pkce-flow)
7. [Storage Providers](#storage-providers)
8. [V7 Streaming Encrypt / Decrypt Pipeline](#v7-streaming-encrypt--decrypt-pipeline)
9. [BYO Web Worker](#byo-web-worker)
10. [BYO Relay Server](#byo-relay-server)
11. [Vault Lifecycle & Offline Recovery](#vault-lifecycle--offline-recovery)
12. [Zero-Knowledge Security Properties](#zero-knowledge-security-properties)
13. [Error Model](#error-model)
14. [Build & Test](#build--test)
15. [Dependencies](#dependencies)

---

## Architecture

```
+--------------------------------------------------------------------+
|  Browser                                                           |
|                                                                    |
|  +---------------+  postMessage  +---------------------------+    |
|  |  Svelte BYO   |<------------>|  BYO Web Worker           |    |
|  |  Frontend     |              |  sdk-wasm (WASM module)   |    |
|  |  (thin UI)    |              |  - All crypto ops         |    |
|  +---------------+              |  - V7 encrypt/decrypt     |    |
|                                 |  - Vault parse/seal       |    |
|                                 |  - Key registry           |    |
|                                 +-----------+---------------+    |
|                                             | fetch/WebSocket     |
|                                             v                     |
|                                 +---------------------------+     |
|                                 |  StorageProvider (TS)    |     |
|                                 |  GDrive / Dropbox /      |     |
|                                 |  OneDrive / WebDAV /     |     |
|                                 |  SFTP / Box / pCloud     |     |
|                                 +---------------------------+     |
+--------------------------------------------------------------------+
        | HTTPS (enrollment relay only)         | HTTPS / WebSocket
        v                                       v
+-------------------+               +--------------------------+
|  BYO Relay Server |               |  User-owned Storage      |
|  (stateless)      |               |  (Google Drive, Dropbox, |
|  /relay/ws?mode=  |               |  OneDrive, WebDAV, SFTP, |
|  enrollment|sftp  |               |  Box, pCloud)            |
|  enrollment|sftp  |               +--------------------------+
+-------------------+
```

**Key principle:** The relay server is transit-only. It never stores, decrypts, or inspects vault data. All cryptographic operations run inside the BYO Web Worker in the browser.

### Component Overview

| Component | Path | Role |
|-----------|------|------|
| BYO frontend | `frontend/src/` | Svelte UI + vault lifecycle orchestration |
| `@wattcloud/sdk` | `frontend/src/lib/sdk/` | StorageProvider dispatcher, OAuth popup, Web Worker client |
| BYO Web Worker | `frontend/src/lib/sdk/worker/byo.worker.ts` | All crypto; key isolation from main thread |
| sdk-wasm BYO bindings | `sdk/sdk-wasm/src/byo.rs`, `sdk-wasm/src/oauth.rs` | WASM exports used by the worker |
| sdk-core BYO logic | `sdk/sdk-core/src/byo/` | Vault crypto, PKCE, OAuth builders, enrollment, providers |
| sdk-core crypto | `sdk/sdk-core/src/crypto/` | V7 wire format, FooterTrimmer, constants |
| BYO relay | `byo-relay/` (Rust) | WebSocket relay for enrollment, SFTP, share pointers |

---

## Vault File Format

The vault is split into two files per provider plus a shared manifest replicated to every provider:

```
SecureCloud/
  vault_manifest.sc            ← header + encrypted manifest blob; replicated to every provider
  vault_<provider_id>.sc       ← per-provider body only; unique to this provider
  vault_journal_<provider_id>.j  ← cloud-side mutation journal (flushed on save, deleted after)
```

### vault_manifest.sc

Contains the Argon2id-gated bootstrap header and an AES-GCM-encrypted manifest blob listing all providers.

```
[header (1227 bytes)] [body_iv (12)] [body_ciphertext + GCM tag]
```

### vault_<provider_id>.sc

Body-only format — no header. Encrypted with a per-provider subkey derived from `vault_key`. Contains only the rows belonging to this provider.

```
[body_iv (12)] [body_ciphertext + GCM tag]
```

### vault_journal_<provider_id>.j — VaultJournal Wire Format

Canonical codec lives in `sdk-core/src/byo/vault_journal.rs`. The TS `VaultJournal` class delegates all encoding/decoding to this Rust module via WASM.

**Journal file:**
```
[magic (8)] [entry*]
```
Magic = `0x53 0x43 0x4a 0x4e 0x52 0x4c 0x00 0x01` (`"SCJNRL\x00\x01"`)

**Entry (variable length):**
```
Offset  Length  Field
------  ------  -----------------------------------------------
0       1       entry_type: 0x01=INSERT, 0x02=UPDATE, 0x03=DELETE
1       1       table_len  (≤ 255)
2       N       table name (UTF-8, no NUL)
2+N     4       row_id (u32 LE)
6+N     1       iv_len = 12 (constant; reject other values)
7+N     12      AES-GCM nonce (random per entry)
19+N    4       enc_data_len (u32 LE)
23+N    M       AES-GCM ciphertext + 16-byte tag (plaintext = JSON row)
23+N+M  32      HMAC-SHA256(journal_hmac_key, entry bytes [0 .. 23+N+M])
```

**Security properties:**
- Encrypt-then-MAC: HMAC covers all bytes before the trailing 32-byte tag.
- `parse_journal` fails closed on any entry HMAC mismatch — the entire journal is discarded (H5 fix).
- Keys are derived per-provider: `HKDF(vault_key, "per-vault-journal-v1" || provider_id)` → `(aead_key, hmac_key)`.

### vault_manifest.sc Header Layout (1227 bytes, fixed)

```
Offset  Length  Field
------  ------  -------------------------------------------------
0       8       Magic: "SCVAULT\x00"
8       2       Format version (u16 LE) -- currently 0x0001
10      4       Argon2id memory_kib (u32 LE) -- 131072 (128 MB)
14      4       Argon2id iterations (u32 LE) -- 3
18      4       Argon2id parallelism (u32 LE) -- 4
```

**Bounded Parameters (DoS resistance — C4):**
`byo_vault_open` in sdk-wasm enforces hard ceilings on Argon2id parameters *before* running
derivation, so a hostile provider cannot inflate params to lock the browser:

| Parameter  | Ceiling |
|------------|---------|
| memory_kb  | 256 MiB (262 144 KiB) |
| iterations | 10 |
| parallelism| 8 |

Headers outside these bounds are rejected with `Argon2ParamsOutOfBounds` before any CPU or
memory is spent.  The nominal vault parameters (128 MB / 3 / 4) are well within all ceilings.
The header HMAC is still verified after a successful open — a tampered but in-bounds header is
caught by the HMAC check, preserving the HMAC-after-unwrap integrity guarantee.

```
22      32      master_salt -- random per vault, used as Argon2id salt
54      16      vault_id -- random per vault, stable across all devices
70      12      pass_wrap_iv -- AES-GCM nonce for passphrase-wrapped vault_key
82      48      pass_wrapped_vault_key -- AES-GCM(vault_kek, vault_key) + 16-byte tag
130     12      recovery_wrap_iv -- AES-GCM nonce for recovery-wrapped vault_key
142     48      recovery_wrapped_vault_key -- AES-GCM(recovery_vault_kek, vault_key) + tag
190     1       active_device_count (u8) -- number of filled device slots (0-8)
191     1000    device_slots[8] -- 8 x 125 bytes (see below)
1191    4       revocation_epoch (u32 LE) -- bumped on recovery / device clear
1195    32      header_hmac -- HMAC-SHA256(vault_key, bytes[0..1195])
```

Total header: **1227 bytes**.

### Device Slot Layout (125 bytes each)

```
Offset  Length  Field
------  ------  -------------------------------------------------
0       1       status: 0x00 = empty, 0x01 = active
1       16      device_id -- random per device
17      12      wrap_iv -- AES-GCM nonce
29      48      encrypted_shard -- AES-GCM(device_crypto_key, shard_32B) + 16-byte tag
77      48      signing_key_wrapped -- AES-GCM(HKDF(vault_key,"BYO device signing v2"), ed25519_seed_32B) + 16-byte tag
                (v2 only; zeros on a v1-migrated slot until re-enrolled)
```

### Manifest JSON (encrypted in vault_manifest.sc body)

```json
{
  "manifest_version": 7,
  "providers": [
    {
      "provider_id": "01J…",
      "type": "gdrive",
      "display_name": "Google Drive (work)",
      "config_json": "…encrypted credentials blob…",
      "is_primary": true,
      "sftp_host_key_fingerprint": null,
      "vault_version_hint": 42,
      "created_at": 1713254400,
      "updated_at": 1713254400,
      "tombstone": false
    }
  ]
}
```

- `manifest_version`: monotonic u64; `max(all fetched) + 1` on save.
- `tombstone`: true when a provider is removed; row kept so removes are not resurrected.
- `vault_version_hint`: last-known vault ETag for this provider (advisory).
- `is_primary`: at most one true; the primary provider is the canonical location for the manifest.

Provider credentials (`config_json`) are encrypted with a manifest-scoped subkey (see §Key Hierarchy). They are never transmitted to the relay server.

### Per-provider SQLite Schema

Each `vault_<provider_id>.sc` contains only the rows belonging to that provider. Cross-provider relationships (e.g., a folder's parent) are rejected by database triggers.

| Table | Purpose |
|-------|---------|
| `key_versions` | Vault key version history — shared across providers; never deleted |
| `files` | Encrypted file metadata: name, size, storage_ref, mime_type, timestamps, `provider_id` |
| `folders` | Encrypted folder metadata: name, parent_id, `provider_id` |
| `favorites` | User-marked favorites, `provider_id` |
| `trash` | Soft-deleted items, `provider_id` |
| `share_tokens` | Share link records, `provider_id` |
| `vault_meta` | Per-vault metadata: `vault_version`, `enrolled_devices` |

All name/metadata columns containing user data are encrypted before being written to SQLite. The `provider_id` column on data tables is `NOT NULL` and enforced by `BEFORE INSERT/UPDATE` triggers that abort cross-provider parent references.

---

## Cryptographic Key Hierarchy

### Vault Key Generation (once per vault creation)

```
vault_key     = 32 random bytes  -- root key; encrypts manifest + all per-provider bodies
shard         = 32 random bytes  -- stored in device slots, combined with password half
vault_id      = 16 random bytes  -- stable across all devices
master_salt   = 32 random bytes  -- per-vault Argon2id salt
```

### Passphrase Path (online or offline, password required)

```
password (never stored)
    |
    v  Argon2id(password, master_salt, m=131072 KiB, t=3, p=4) -> 64 bytes
argon_output
    |
    v  HKDF-SHA256(argon_output[0..32], info="SecureCloud BYO VaultKEK v1", L=32)
vault_kek
    |
    v  AES-256-GCM-Decrypt(vault_kek, pass_wrap_iv, pass_wrapped_vault_key)
vault_key  (stays in WASM; never crosses the postMessage boundary)
```

### Device Path (device enrolled, password required once for enrollment)

```
password + master_salt
    |
    v  Argon2id(128 MB, t=3, p=4) -> 64 bytes
argon_output
    |
    v  HKDF-SHA256(argon_output[32..64], info="SecureCloud KEKHalf v2", L=32)
client_kek_half

device_crypto_key (device-local, see enrollment)
    |
    v  AES-256-GCM-Decrypt(device_crypto_key, slot.wrap_iv, slot.encrypted_shard)
shard

HKDF-SHA256(client_kek_half || shard, info="SecureCloud KEKv2", L=32)
    |
    v
content_kek  -- used to wrap per-file content_key in V7 header
```

### Recovery Key Path

```
recovery_key_bytes[1..33]  (bytes 1-32 of the 37-byte recovery blob;
                            byte 0 = version, bytes 33-36 = checksum)
    |
    v  HKDF-SHA256(recovery_key_bytes[1..33],
                   info="SecureCloud BYO RecoveryVaultKEK v1", L=32)
recovery_vault_kek
    |
    v  AES-256-GCM-Decrypt(recovery_vault_kek, recovery_wrap_iv,
                           recovery_wrapped_vault_key)
vault_key
```

### Per-Vault and Manifest Subkey Derivation

All subkeys are derived inside WASM from `vault_key` via HKDF-SHA256. `provider_id` is concatenated into the `info` string for domain separation — it never enters the key material directly.

```
vault_key
│
├── HKDF(info="SecureCloud BYO manifest v1")
│       → manifest_aead_key (32 B)   — encrypts vault_manifest.sc body
│
├── HKDF(info="per-vault-aead-v1" || provider_id)
│       → vault_aead_key[provider_id]  — encrypts vault_<provider_id>.sc body
│
├── HKDF(info="per-vault-hmac-v1" || provider_id)
│       → vault_hmac_key[provider_id]  — HMAC for vault body integrity
│
├── HKDF(info="per-vault-wal-v1" || provider_id)
│       → wal_key[provider_id]         — WAL encryption (IndexedDB)
│
└── HKDF(info="per-vault-journal-v1" || provider_id)
        → journal_aead_key + journal_hmac_key[provider_id]
```

Key security properties:
- Different `provider_id` values → cryptographically distinct subkeys (domain separation).
- Manifest key uses a distinct `info` string with no `provider_id` suffix → independent domain.
- Subkeys are non-extractable; they never leave WASM memory.
- `vault_key` does **not** change during passphrase change or recovery re-key. Only the wrapping (Argon2id params + AES-GCM wrap) changes, so manifest and per-vault body blobs remain valid after re-keying without re-encryption.

### Key Lifetime Policy

| Key | Zeroized when |
|-----|---------------|
| `argon_output` | Immediately after deriving `vault_kek` + `client_kek_half` |
| `vault_kek` / `recovery_vault_kek` | Immediately after unwrapping `vault_key` |
| `vault_key` | Worker memory; zeroized on vault lock / tab close |
| `shard` | Immediately after deriving `content_kek` |
| `client_kek_half` | Immediately after combining with shard |
| `content_key` (per-file) | After `closeV7EncryptStream` / `closeV7Stream` (ZeroizeOnDrop) |
| Provider tokens | Cleared from worker memory on vault lock |

### Header Integrity

```
HMAC-SHA256(vault_key, header_bytes[0..1195]) == header_hmac   (v2)
HMAC-SHA256(vault_key, header_bytes[0..807])  == header_hmac   (v1 — legacy, migration only)
```

Verified after unwrapping `vault_key` from any path. A mismatch means wrong passphrase, wrong recovery key, or header corruption. The `sdk-core` API exposes strict variants (`compute_header_hmac` for v2, `compute_header_hmac_v1` for migration) so a v2 vault cannot be verified via the v1 offset — the HMAC there would cover only bytes `[0..807]`, leaving `device_slots` (191..1191) and `revocation_epoch` (1191..1195) outside the MAC domain.

---

## Multi-Provider

### No Cross-Provider Folders

Folders and files are scoped to a single provider by `provider_id NOT NULL`. A folder's parent must belong to the same provider; a file's folder must belong to the same provider. These constraints are enforced by `BEFORE INSERT/UPDATE` triggers that `RAISE(ABORT, 'cross-provider …')`. There are no cross-provider folder trees.

### Offline Provider UI

When a provider's health-ping fails (`OfflineDetector`, 30 s base, 5 min max, backoff 1.5×), its `ProviderMeta.status` transitions to `'offline'`:

- **Provider chip** (tab bar): offline dot + "· Offline" label appended.
- **Active tab banner** (`OfflineBanner.svelte`): "⚠ <Provider> is offline. Showing cached files. Read-only until reconnected." + Retry button.
- **Write controls**: Upload / New folder / Move-into / Delete disabled with tooltip in offline tab.
- **Global pill**: "N providers offline" appears in the header; click opens provider-status panel.
- **Save indicator**: Shows "Synced to N/M providers — queued for <Provider> when online."

The offline UI is informational only — cached data is read-only and clearly marked. Write operations are queued and deferred to next reconnect.

### Cross-Provider Move

Transfers V7 ciphertext blobs verbatim between providers. No re-encryption is needed because V7 content keys are per-file (wrapped with the user's ML-KEM/X25519 public key in the V7 header) and are independent of `vault_key` or `provider_id`.

**Steps:**
1. `src_provider.download(src_storage_ref)` → raw V7 ciphertext bytes
2. `dst_provider.upload(null, fileName, ciphertextBytes)` → new `dst_storage_ref`
3. `UPDATE files SET provider_id=dst, storage_ref=dst_ref, folder_id=NULL WHERE id=?` in unified SQLite
4. `src_provider.delete(src_storage_ref)` (best-effort; orphan blob cleaned on next reconcile)
5. `markDirty(srcProviderId)` + `markDirty(dstProviderId)` → both vaults are saved on next flush

**Atomicity**: steps are journaled. A crash between steps 2 and 3 leaves an orphan blob on `dst` (detected and cleaned by the blob reconciler on next open). A crash between steps 3 and 4 leaves an orphan blob on `src` (also cleaned). The user sees the file in the dst tab only after step 3 commits.

**Folder moves**: each file inside is moved recursively; a mirror folder structure is created on `dst` first; `src` folder tree is deleted last.

---

## Device Enrollment Protocol

Enrollment links a new device to an existing vault so it can access vault data without re-entering the vault passphrase on every use. A one-time shard transfer is performed over a relay WebSocket channel protected by ephemeral ECDH and confirmed by a Short Authentication String (SAS).

### Protocol Sequence

```
Existing Device (A)           Relay Server          New Device (B)
        |                          |                       |
        | gen eph_skA, eph_pkA     |                       |
        | gen channel_id (16 B)    |                       |
        | display QR:              |                       |
        |   { v:1,                 |                       |
        |     ch:b64url(ch_id),    |                       |
        |     pk:b64url(eph_pkA) } |                       |
        |                          |                       |
        | WS /relay/ws?mode=       |                       |
        |   enrollment&ch=<id>     |                       |
        |------------------------->|                       |
        |                          |  scan QR              |
        |                          |<----------------------|
        |                          | WS (same ch_id)       |
        |                          |<----------------------|
        |<------ relay: peer joined|---------------------->|
        |                          |                       |
        | send { pkA: b64url(...) }|                       |
        |------------------------->|---------------------->|
        |         { pkB: b64url(...) }                     |
        |<-------------------------|<----------------------|
        |                          |                       |
        | X25519(eph_skA, eph_pkB) |  X25519(eph_skB,eph_pkA)
        |   -> shared_secret       |    -> shared_secret   |
        |                          |   (same value)        |
        |                          |                       |
        | HKDF(shared, "SCEnroll Enc v1") -> enc_key (32B) |
        | HKDF(shared, "SCEnroll MAC v1") -> mac_key (32B) |
        | HKDF(shared, "SCEnroll SAS v1") -> sas_bytes (6B)|
        |   sas_code = LE32(sas_bytes[0..4]) % 1_000_000  |
        |                          |                       |
        | display sas_code         |    display sas_code   |
        | user confirms match on both screens              |
        |                          |                       |
        | encrypt_shard(shard, enc_key, mac_key):          |
        |   nonce(12) + AES-GCM(enc_key,shard) + HMAC(mac_key,ct)
        |------------------------->|---------------------->|
        |                          |   verify HMAC         |
        |                          |   decrypt shard       |
        |                          |   store in slot       |
        |                          |   send ACK            |
        |<-------------------------|<----------------------|
```

### Shard Envelope Wire Format (92 bytes)

```
[nonce (12)] [AES-256-GCM(enc_key, shard) + 16-byte tag (48)] [HMAC-SHA256(mac_key, nonce||ct) (32)]
```

Encrypt-then-MAC. HMAC is verified before decryption (MAC failure = reject immediately).

### SAS Security

The 6-digit SAS code is a visual binding of the ECDH handshake. If an active MITM substituted either public key, the shard would be encrypted to the attacker's key, but both devices would compute a different SAS code. The user visually confirming the match prevents this substitution.

### QR Code Format

```json
{ "v": 1, "ch": "<base64url(channel_id_16_bytes)>", "pk": "<base64url(eph_pk_32_bytes)>" }
```

---

## OAuth 2.0 / PKCE Flow

### Supported Providers

| Provider | Token URL | Scopes | Refresh Token |
|----------|-----------|--------|---------------|
| Google Drive | `https://oauth2.googleapis.com/token` | `drive.file offline_access` | Yes (forced via `prompt=consent`) |
| Dropbox | `https://api.dropboxapi.com/oauth2/token` | `files.content.write files.content.read` | Yes (via `token_access_type=offline` in auth URL) |
| Microsoft OneDrive | `https://login.microsoftonline.com/common/oauth2/v2.0/token` | `files.readwrite offline_access` | Yes |
| Box | `https://api.box.com/oauth2/token` | `root_readwrite` | Yes |
| pCloud (US) | `https://api.pcloud.com/oauth2_token` | (implicit) | Yes |
| pCloud (EU) | `https://eapi.pcloud.com/oauth2_token` | (implicit) | Yes |

WebDAV and SFTP use static credentials (no OAuth).

### PKCE Generation (sdk-core)

```
code_verifier  = base64url_nopad(32 random bytes)   -- 43 characters
code_challenge = base64url_nopad(SHA-256(code_verifier))
state          = hex(16 random bytes)               -- 32 characters (CSRF protection)
```

All implemented in `sdk-core/src/byo/pkce.rs`. PKCE generation runs in the BYO worker via the `generatePkce()` wasm export.

### Flow Sequence (browser)

```
1. Worker: generate PKCE pair + state
2. Worker: build_auth_url(provider, client_id, redirect_uri, state, code_challenge)
3. Main thread: window.open(auth_url, popup)
4. User authenticates with provider
5. Provider redirects to /oauth/callback?code=...&state=...
6. Callback page: window.opener.postMessage({ code, state }, origin)
7. Main thread: verify state matches; pass code to worker
8. Worker: build_token_exchange_form(code, code_verifier, redirect_uri, client_id)
9. Main thread: fetch(token_url, { method: 'POST', body: form }) -> token JSON
10. Worker: parse_token_response(response_bytes) -> { access_token, refresh_token, expires_in }
11. Encrypt token in vault manifest `config_json` (written on next save)
```

Steps 2, 8, and 10 execute Rust code in the worker via wasm-bindgen. Steps 3-7 and the `fetch()` in step 9 remain in TS (browser-specific I/O).

### Token Refresh

```
Worker: build_refresh_form(refresh_token, client_id) -> form body
Main thread: fetch(token_url, { method: 'POST', body: form }) -> token JSON
Worker: parse_token_response(response_bytes) -> new { access_token, expires_in }
```

On `invalid_grant` (refresh token revoked), the full OAuth flow is re-triggered.

---

## Storage Providers

### StorageProvider Interface

All providers implement `StorageProvider` (defined in `frontend/src/lib/sdk/types.ts`; authoritative Rust trait in `sdk-core/src/byo/provider.rs`).

**Lifecycle:**
```typescript
init(savedConfig?: ProviderConfig): Promise<void>
isReady(): boolean
disconnect(): Promise<void>
getConfig(): ProviderConfig
refreshAuth(): Promise<void>
```

**Blob I/O** (complete files; vault metadata blob, small files):
```typescript
upload(ref: string | null, name: string, data: Uint8Array, options?: UploadOptions): Promise<UploadResult>
download(ref: string): Promise<{ data: Uint8Array; version: string }>
delete(ref: string): Promise<void>
getVersion(ref: string): Promise<string>
```

**Streaming I/O** (large files; V7 ciphertext frames):
```typescript
uploadStream(ref, name, totalSize, options?): Promise<{ stream: WritableStream<Uint8Array>; result: Promise<UploadResult> }>
downloadStream(ref: string): Promise<ReadableStream<Uint8Array>>
```

**Directory operations:**
```typescript
list(parentRef?: string): Promise<StorageEntry[]>
createFolder(name: string, parentRef?: string): Promise<{ ref: string }>
deleteFolder(ref: string): Promise<void>
```

### ProviderConfig Schema

```typescript
interface ProviderConfig {
  type: 'gdrive' | 'dropbox' | 'onedrive' | 'webdav' | 'sftp' | 'box' | 'pcloud' | 's3';
  // OAuth providers
  accessToken?: string;
  refreshToken?: string;
  tokenExpiry?: number;     // Unix ms
  clientId?: string;        // App client_id (Vite env var; Android BuildConfig)
  // WebDAV
  serverUrl?: string;
  username?: string;
  password?: string;
  // SFTP
  sftpHost?: string;
  sftpPort?: number;
  sftpUsername?: string;
  sftpPassword?: string;
  sftpPrivateKey?: string;  // PEM-encoded
  sftpPassphrase?: string;
  // pCloud
  pcloudRegion?: 'us' | 'eu'; // selects api.pcloud.com vs eapi.pcloud.com
  // S3-compatible (S3, R2, Wasabi, MinIO)
  s3Endpoint?: string;         // override for R2/B2/Wasabi/MinIO; omit for AWS
  s3Region?: string;
  s3Bucket?: string;
  s3AccessKeyId?: string;
  s3SecretAccessKey?: string;
  s3PathStyle?: boolean;       // true for MinIO and some B2 deployments
}
```

Stored encrypted in the manifest body (`config_json` field of the provider's `ManifestEntry`). Never transmitted to the relay server. The manifest body is AES-GCM encrypted before upload; see §Manifest JSON.

### Provider Implementations

#### Google Drive

| Property | Value |
|----------|-------|
| API | Google Drive v3 REST |
| Root folder | `SecureCloud/` (auto-created on first init) |
| File ref | Drive file ID |
| Version | Drive `etag` |
| Conflict detection | `If-Match` header -> HTTP 412 |
| New file upload | Multipart POST to `upload/drive/v3/files?uploadType=multipart` |
| Resumable upload | POST `upload/drive/v3/files?uploadType=resumable` -> `Location` header (session URI) |
| Token refresh | `byo_gdrive_refresh_token()` Rust orchestrator |

#### Dropbox

| Property | Value |
|----------|-------|
| API | Dropbox v2 REST |
| Root folder | `/SecureCloud/` |
| File ref | Dropbox path string |
| Version | `rev` tag |
| Conflict detection | rev mismatch -> HTTP 409 |
| Upload (small) | POST `content.dropboxapi.com/2/files/upload` with `Dropbox-API-Arg` header |
| Streaming upload | `upload_session/start` → `upload_session/append_v2` (128 MiB chunks) → `upload_session/finish` |
| Token refresh | `byo_dropbox_refresh_token()` Rust orchestrator |

#### Microsoft OneDrive

| Property | Value |
|----------|-------|
| API | Microsoft Graph v1.0 |
| Root folder | `/drive/root:/SecureCloud/` |
| File ref | Graph item ID |
| Version | Graph `eTag` |
| Conflict detection | `If-Match` header -> HTTP 412 |
| Resumable upload | POST `/me/drive/root:/{path}:/createUploadSession` -> `uploadUrl` |
| Token refresh | `byo_onedrive_refresh_token()` Rust orchestrator |

#### WebDAV

| Property | Value |
|----------|-------|
| Protocol | HTTP (RFC 4918) |
| Auth | `Authorization: Basic base64(user:password)` on every request |
| Root folder | `{serverUrl}/SecureCloud/` |
| File ref | URL path |
| Version | ETag (from `PROPFIND` or `HEAD`) |
| Conflict detection | `If-Match` header -> HTTP 412 |
| Directory listing | `PROPFIND` with `Depth: 1`; XML response parsed with `quick-xml` |
| Folder create | `MKCOL` (HTTP 405 = already exists -> treat as success) |
| Streaming upload | Nextcloud chunking v2 (`MKCOL` + ranged `PUT` + `MOVE`) for files ≥ 5 MiB; tus.io when `Tus-Resumable` header advertised; single `PUT` (BufferThenPut) for < 5 MiB or non-NC servers |

#### Box

| Property | Value |
|----------|-------|
| API | Box Content API v2 |
| Root folder | `SecureCloud/` folder (auto-created; folder ID stored in config) |
| File ref | Box file ID |
| Version | Box `etag` |
| Conflict detection | `If-Match` header → HTTP 412 |
| Upload (≤ 20 MiB) | `POST /2.0/files/content` multipart |
| Streaming upload | `POST /2.0/files/upload_session` → ranged `PUT` parts → commit |
| Token refresh | `byo_box_refresh_token()` Rust orchestrator |

#### pCloud

| Property | Value |
|----------|-------|
| API | pCloud REST (US: `api.pcloud.com`; EU: `eapi.pcloud.com`) |
| Root folder | `SecureCloud/` (auto-created; folder ID stored in config) |
| File ref | pCloud `fileid` (numeric) |
| Version | `hash` field from `stat` |
| Conflict detection | hash mismatch check before overwrite |
| Upload | `POST /uploadfile` |
| Token refresh | `byo_pcloud_refresh_token()` Rust orchestrator |

#### S3-Compatible (S3, R2, Wasabi, MinIO, Backblaze B2)

| Property | Value |
|----------|-------|
| API | AWS S3 REST (SigV4-signed) |
| Root prefix | `SecureCloud/` |
| File ref | S3 object key |
| Version | ETag (MD5 or server-computed) |
| Conflict detection | `If-Match` header → HTTP 412 |
| Signing | SigV4 with `UNSIGNED-PAYLOAD` (all content is V7 ciphertext; integrity guaranteed by AES-GCM + HMAC) |
| Upload (small) | Single `PUT` object |
| Streaming upload | `CreateMultipartUpload` → `UploadPart` × N → `CompleteMultipartUpload` |
| Presigned URL | `GetObject` SigV4 presign (capped at 24 h; used for B1 share links) |
| Endpoint override | `s3Endpoint` in config; enables R2, Wasabi, MinIO, Backblaze B2 |
| Path-style | `s3PathStyle: true` for MinIO and some B2 deployments |

#### SFTP

| Property | Value |
|----------|-------|
| Protocol | SSH File Transfer Protocol (RFC 4254) via WebSocket relay |
| Auth | Password or PEM private key (with optional passphrase) |
| Root folder | `/SecureCloud/` (on remote server) |
| File ref | Remote file path |
| Version | `mtime:size` (no ETag) |
| Relay | `wss://<relay>/relay/ws?mode=sftp` |
| Wire format | Two-frame: JSON header + binary body (see Relay Protocol v2 section) |

#### Relay Protocol v2

The `host_key` handshake frame includes a `relay_version` field. When `relay_version >= 2`, the client uses the v2 streaming verbs:

| Verb | Direction | Purpose |
|------|-----------|---------|
| `write_open` | client→relay | Open a new upload session; returns `session_id` |
| `write_chunk` | client→relay | Send next binary frame (8 MiB max); relay buffers ciphertext only |
| `write_close` | client→relay | Finalize upload; relay writes to SFTP server |
| `write_abort` | client→relay | Cancel upload; relay discards buffer |
| `rename` | client→relay | Atomic rename (temp path → final path) |

V1 single-shot `write` verb remains supported for relay deployments that have not upgraded. Relay-side buffer holds at most 200 MiB of V7 ciphertext per session; exceeding this limit returns an error and the upload must be aborted and restarted.

TOFU host-key fingerprint is stored per `provider_id` in the encrypted vault SQLite. Never transmitted to the relay.

### Rust Orchestrators and WASM Dispatcher (P8)

All HTTP-based providers (GDrive, Dropbox, OneDrive, WebDAV, Box, pCloud, S3) are implemented as `impl StorageProvider` in sdk-core. Browser access goes through a single generic WASM dispatcher:

```
byo_provider_call(provider_type, op, config_json, args_json) -> JSON
```

Supported ops: `upload`, `download`, `delete`, `getVersion`, `list`, `createFolder`, `deleteFolder`, `createPublicLink`, `revokePublicLink`, `createPresignedUrl`. The per-provider TS HTTP classes (GDriveProvider, DropboxProvider, etc.) are retired (P8). The `WasmStorageProviderShim` TS class routes all calls through the generic dispatcher.

SFTP uses a `RelayTransport` WebSocket shim (TS, ~100 LoC) wrapping the `SftpRelayClient<T>` Rust state machine (sdk-core, P7). The main-thread holds no credentials; all state lives in the BYO worker.

```
ByoUploadStream.upload():
    Worker.byoEncryptAndUpload(providerType, configJson, name, plaintext, pubKeysJson, parentRef?)
        -> ref string

ByoDownloadStream.decrypt():
    Worker.byoDownloadAndDecrypt(providerType, configJson, ref, byoKeySessionId)
        -> plaintext Uint8Array
```

---

## V7 Streaming Encrypt / Decrypt Pipeline

BYO uses the same V7 wire format as managed mode. The streaming pipeline operates at constant memory regardless of file size.

### Wire Format Constants

| Constant | Value | Source |
|----------|-------|--------|
| `V7_HEADER_MIN` | 1709 bytes | `sdk-core/src/crypto/constants.rs` |
| `V7_FRAME_OVERHEAD` | 32 bytes | 4 (len LE u32) + 12 (nonce) + 16 (GCM tag) |
| `V7_FOOTER_LEN` | 32 bytes | HMAC-SHA256 |
| `V7_ENCRYPT_CHUNK_SIZE` | 524288 bytes (512 KiB) | Plaintext chunk size |

### Ciphertext Size Formula

```
cipher_size(plaintext_len, chunk_size):
  if plaintext_len == 0: return V7_HEADER_MIN + V7_FOOTER_LEN  (= 1741)
  n = ceil(plaintext_len / chunk_size)
  return V7_HEADER_MIN + n * V7_FRAME_OVERHEAD + plaintext_len + V7_FOOTER_LEN
```

### Upload Encryption

```
Worker.newV7EncryptSession()           -> session_id
Worker.openV7EncryptStream(session_id, publicKeysJson)
    -> hybrid KEM encapsulation (X25519 + ML-KEM-1024) in WASM
    -> stores content_key, file_iv, HMAC state in worker
Worker.takeV7EncryptHeader(session_id) -> 1709-byte V7 header (write to provider)

for each 512 KiB chunk:
    plaintext = file.slice(i*512KiB, (i+1)*512KiB)
    frame = Worker.pushV7EncryptStream(session_id, plaintext)
    plaintext.fill(0)                  <- zeroize immediately
    writer.write(frame)
    frame.fill(0)                      <- zeroize after queuing

footer = Worker.closeV7EncryptStream(session_id)  -> 32-byte HMAC footer
writer.write(footer)
footer.fill(0)
writer.close()                         <- provider finalizes upload
```

Key material (`content_key`, `file_iv`, HMAC state) stays in worker WASM memory throughout. `closeV7EncryptStream` triggers `ZeroizeOnDrop` on the encryptor session.

### Download Decryption

```
readable = provider.downloadStream(ref)
reader = readable.getReader()

// 1. Read exactly V7_HEADER_MIN bytes
{ data: headerBuf, remainder: afterHeader } = readExact(reader, 1709)

// 2. Open decrypt session and FooterTrimmer
sessionId = Worker.newV7StreamSession()
Worker.openV7Stream(sessionId, headerBuf, secKeysJson, byoKeySessionId)
    -> decapsulates ML-KEM + X25519 to recover content_key
trimId = "ft-<timestamp>-<random>"
Worker.footerTrimmerNew(trimId, V7_FOOTER_LEN)  <- retains last 32 bytes

// 3. Feed remainder + stream through FooterTrimmer
for each chunk from reader:
    safe = Worker.footerTrimmerPush(trimId, chunk)  <- bytes NOT in footer
    plaintext = Worker.pushV7Stream(sessionId, safe)
    yield plaintext

// 4. Finalize
{ body, footer } = Worker.footerTrimmerFinalize(trimId)
plaintext = Worker.pushV7Stream(sessionId, body)
yield plaintext

// 5. HMAC verification (throws on failure -- caller must discard all prior plaintext)
Worker.closeV7Stream(sessionId, footer)
```

The `FooterTrimmer` state machine (`sdk-core/src/crypto/wire_format.rs`) buffers exactly `V7_FOOTER_LEN` bytes, releasing only bytes that are definitively not the footer. This mirrors the Android implementation -- the same Rust code is used on both platforms.

#### Phase 3d: Provider-Integrated Streaming Sessions

When the provider is WASM-backed (`WasmStorageProviderShim`, i.e. all HTTP providers), upload and download sessions own the provider stream directly inside WASM rather than returning cipher frames to JS.

**Upload (`ByoUploadStream.uploadWasm`):**
```
byoStreamUploadInit(pubKeysJson, providerType, configJson, blobName, parentRef?, plaintextLen)
  → { sessionId, chunkSize }
  // Opens provider upload_stream_open, writes V7 header; session lives in WASM thread_local map.

for each plaintext chunk:
  byoStreamUploadPush(sessionId, plaintextChunk: ArrayBuffer, isLast)
  // encrypt → upload_stream_write; cipher frame never returned to JS (ZK-5).

byoStreamUploadFinalize(sessionId) → { ref, version }
  // Writes HMAC footer, closes provider stream, drops V7StreamEncryptor (ZeroizeOnDrop).
```

**Download (`ByoDownloadStream.decryptWasm`):**
```
byoStreamDownloadInit(secKeysJson, providerType, configJson, ref) → sessionId
  // Opens provider download_stream_open; session lives in WASM thread_local map.

while (chunk = byoStreamDownloadPull(sessionId)) !== null:
  // download_stream_read → ByoDownloadFlow.push → yield plaintext to JS.

byoStreamDownloadClose(sessionId)
  // Verifies HMAC footer (throws on mismatch); drops V7StreamDecryptor (ZeroizeOnDrop).
```

Memory profile: peak JS heap is one V7_ENCRYPT_CHUNK_SIZE (512 KiB) plaintext chunk in transit. Ciphertext bytes never cross the WASM/JS boundary. Falls back to the JS-orchestrated `ByoUploadFlow`/`ByoDownloadFlow` path for SFTP (which uses a TypeScript WebSocket relay, not a WASM-backed HTTP provider).

#### Range-Based Download Streaming (HTTP Providers)

The Rust-side `download_stream_*` methods for every HTTP provider use `RangedDownloadBuffer` (`sdk-core/src/byo/providers/mod.rs`) to issue one 8 MiB `Range: bytes=N-M` request per chunk. Peak WASM heap per download is bounded by the chunk size plus the V7StreamDecryptor plaintext frame — independent of file size.

| Provider | Range mechanism |
|----------|-----------------|
| GDrive | `GET {DRIVE_API}/{ref}?alt=media` with Bearer + Range; CDN preserves Range through 302. |
| OneDrive | `GET /items/{id}/content` with Bearer + Range; CDN preserves Range through 302. |
| Box | `GET /files/{id}/content` with Bearer + Range; CDN preserves Range through 302. |
| WebDAV | `GET {href}` with stored Basic/Bearer auth header + Range. |
| Dropbox | `POST content.dropboxapi.com/2/files/download` with Dropbox-API-Arg + Range header. |
| pCloud | `getfilelink` resolves a short-lived CDN URL at open time; Range requests go directly to the CDN (no Bearer header). CDN URL expiry mid-download is a known limitation. |
| S3/R2/Wasabi/MinIO | SigV4 re-signs on every chunk with Range in the additional_headers canonical set. |

`download_stream_open` does **not** issue an initial HEAD — total size is discovered lazily from the `Content-Range` response header on the first 206. Lock discipline: the provider's state `Mutex` is never held across the HTTP `.await` — `download_stream_read` extracts `(request, http_call)` under a brief lock, releases it, makes the call, then re-locks to `apply_response`.

**ZK-6 note:** The `blobName` passed to `byoStreamUploadInit` (and to `provider.uploadStream` on the legacy path) MUST be an opaque UUID — never the user's plaintext filename. The encrypted filename is stored separately in the vault SQLite `files.encrypted_filename` column.

---

## BYO Web Worker

The BYO Web Worker (`frontend/src/lib/sdk/worker/byo.worker.ts`) runs all cryptographic operations in an isolated context. Key material never crosses the `postMessage` boundary to the main thread.

### Message Interface

Messages use a discriminated union over `op` (operation name). All `CRYPTO_OPS` run sequentially in a single-threaded worker; no concurrent crypto state.

#### Vault Operations

| Op | Input | Output |
|----|-------|--------|
| `parseVaultHeader` | `{ vaultBytes: ArrayBuffer }` | `VaultHeader` JSON |
| `deriveVaultKeys` | `{ password, masterSalt, argonParams }` | opaque key handles |
| `unwrapVaultKey` | `{ wrapIv, wrapped, unwrappingKeyHandle }` | vault_key handle |
| `wrapVaultKey` | `{ vaultKeyHandle, wrappingKeyHandle }` | `{ iv, wrapped }` |
| `encryptVaultBody` | `{ sqliteBytes, vaultKeyHandle }` | `{ iv, ciphertext }` |
| `decryptVaultBody` | `{ bodyIv, ciphertext, vaultKeyHandle }` | sqlite bytes |
| `generateVaultKeys` | -- | `{ vaultKey, shard, vaultId, masterSalt }` (opaque handles) |

#### Enrollment Operations

| Op | Input | Output |
|----|-------|--------|
| `enrollmentInitiate` | -- | `{ ephSk, ephPk, channelId }` |
| `enrollmentDeriveSession` | `{ ephSk, peerPk }` | `{ encKey, macKey, sasCode }` |
| `enrollmentEncryptShard` | `{ shard, encKey, macKey }` | 92-byte envelope |
| `enrollmentDecryptShard` | `{ envelope, encKey, macKey }` | shard bytes |

#### V7 Streaming Operations

| Op | Input | Output |
|----|-------|--------|
| `newV7EncryptSession` | -- | session_id |
| `openV7EncryptStream` | `{ sessionId, publicKeysJson }` | -- |
| `takeV7EncryptHeader` | `{ sessionId }` | `ArrayBuffer` (1709 bytes) |
| `pushV7EncryptStream` | `{ sessionId, plaintext: ArrayBuffer }` | `ArrayBuffer` (frame) |
| `closeV7EncryptStream` | `{ sessionId }` | `ArrayBuffer` (32-byte footer) |
| `abortV7EncryptStream` | `{ sessionId }` | -- |
| `newV7StreamSession` | -- | session_id |
| `openV7Stream` | `{ sessionId, headerBuf, secKeysJson, byoKeySessionId? }` | -- |
| `pushV7Stream` | `{ sessionId, ciphertext: ArrayBuffer }` | `ArrayBuffer` (plaintext) |
| `closeV7Stream` | `{ sessionId, footer: ArrayBuffer }` | -- (throws on HMAC failure) |
| `abortV7Stream` | `{ sessionId }` | -- |
| `footerTrimmerNew` | `{ trimId, keep }` | -- |
| `footerTrimmerPush` | `{ trimId, bytes: ArrayBuffer }` | `ArrayBuffer` (safe bytes) |
| `footerTrimmerFinalize` | `{ trimId }` | `{ body: ArrayBuffer, footer: ArrayBuffer }` |
| `footerTrimmerAbort` | `{ trimId }` | -- |

#### OAuth / PKCE Operations

| Op | Input | Output |
|----|-------|--------|
| `generatePkce` | -- | `{ codeVerifier, codeChallenge }` |
| `buildAuthUrl` | `{ provider, clientId, redirectUri, state, codeChallenge }` | URL string |
| `buildTokenExchangeForm` | `{ code, codeVerifier, redirectUri, clientId }` | form body string |
| `buildRefreshForm` | `{ refreshToken, clientId }` | form body string |
| `parseTokenResponse` | `{ responseBytes: ArrayBuffer }` | `{ accessToken, refreshToken?, expiresIn? }` |

#### Rust Provider Orchestrators

| Op | Input | Output |
|----|-------|--------|
| `byoEncryptAndUpload` | `{ providerType, configJson, name, plaintext: ArrayBuffer, pubKeysJson, parentRef? }` | ref string |
| `byoDownloadAndDecrypt` | `{ providerType, configJson, ref, byoKeySessionId }` | `ArrayBuffer` (plaintext) |
| `byoRefreshToken` | `{ providerType, configJson }` | updated configJson string |
| `byoProviderCall` | `{ providerType, op, configHandle, argsJson }` | JSON result string (op-dependent) |
| `byoCrossProviderStreamCopy` | `{ srcType, srcConfigHandle, dstType, dstConfigHandle, srcRef, dstName, totalSize }` | `{ ref, version }` |

**Phase 3d provider-integrated session ops** (all use `configHandle` keyed into the worker's config registry):

| Op | Input | Output |
|----|-------|--------|
| `byoStreamUploadInit` | `{ pubKeysJson, providerType, configHandle, name, parentRef?, plaintextLen }` | `{ sessionId, chunkSize }` |
| `byoStreamUploadPush` | `{ sessionId, data: ArrayBuffer, isLast }` | -- (cipher stays in WASM) |
| `byoStreamUploadFinalize` | `{ sessionId }` | `{ ref, version }` |
| `byoStreamUploadAbort` | `{ sessionId }` | -- |
| `byoStreamDownloadInit` | `{ secKeysJson, providerType, configHandle, ref }` | `sessionId` |
| `byoStreamDownloadPull` | `{ sessionId }` | `Uint8Array` or `null` (EOF) |
| `byoStreamDownloadClose` | `{ sessionId }` | -- (throws on HMAC failure) |

### Key Registry

Secret keys (ML-KEM + X25519 private keys) are stored in a `WeakMap<handle, KeyPair>` keyed by opaque object handles. The registry is separate from V7 session maps. `byoDownloadAndDecrypt` retrieves stored keys internally -- the main thread only passes an opaque `byoKeySessionId` string.

---

## BYO Relay Server

The relay server (`byo/server/`) is a minimal Rust/Axum service. It is stateless regarding cryptographic material.

### Endpoints

#### `GET /relay/auth`

Issues a `relay_auth` HttpOnly cookie signed with `RELAY_SIGNING_KEY` (HMAC-SHA256 over timestamp). Required before connecting to the WebSocket relay. Prevents the relay from being used by external services.

#### `WebSocket /relay/ws`

Dispatch via `mode` query parameter.

**`?mode=enrollment&channel=<base64url_channel_id>`**

- Ephemeral channel keyed by `channel_id` (16 bytes, base64url)
- Maximum 2 clients per channel
- Forwards messages between peers without inspection
- Channel TTL: 3 minutes idle (checked every 30 seconds) — the relay is a
  short-lived enrollment rendezvous, not a persistent tunnel; the window
  was tightened from 10 min (the original SPEC value) to limit unrelated
  tunnel abuse, and every legitimate enrollment completes in well under
  that budget (typically <30 s)
- Maximum message size: 1 KB — a shard envelope is 92 bytes and public
  keys are 32 bytes, so 1 KB is strict-enough to block generic-tunnel
  abuse while leaving headroom for any real enrollment message.
  Lifetime cap per channel: 8 KB
- Rate limit: 10 channel joins per minute per IP
- After shard transfer completes, both sides close the WebSocket

**`?mode=sftp&host=...&port=...`**

Translates JSON-RPC over WebSocket to SSH/SFTP.

Validation:
1. Resolve `host` to IP address
2. Reject private/loopback/link-local addresses (SSRF protection)
3. Port must be in range 1-65535

JSON-RPC methods:

| Method | Params | Result |
|--------|--------|--------|
| `auth` | `{ username, password?, privateKey?, passphrase? }` | `{}` |
| `stat` | `{ path }` | `{ size, mtime, isDir }` |
| `list` | `{ path }` | `StorageEntry[]` |
| `read` | `{ path }` | JSON header + binary frame |
| `write` | `{ path, size }` + binary frame | `{}` |
| `mkdir` | `{ path }` | `{}` |
| `delete` | `{ path }` | `{}` |
| `rename` | `{ from, to }` | `{}` |

**Binary frame protocol:**

- Read: server sends `{ id, result: { size } }` JSON then binary frame (file bytes)
- Write: client sends `{ id, method: "write", params: { path, size } }` JSON then binary frame

Maximum binary frame: 16 MB. Idle timeout: 30 minutes.

#### `POST /relay/share/b1` (authenticated)

Creates a B1 share record: a presigned provider URL pointer with expiry. Requires a purpose-scoped, single-use relay auth cookie (`purpose = "share:b1"`).

Request body: `{ share_id, provider_url, expires_in_secs }`
Response: `{ share_id, expires_at, owner_token }` — `owner_token` is `hex(HMAC-SHA256(share_signing_key, share_id || token_nonce || ":owner"))`. The `token_nonce` is a fresh 16-byte random value the server stores in the share record; a sweeper purge + re-registration therefore invalidates every previously-issued token. `share_signing_key` is loaded from the `RELAY_SHARE_SIGNING_KEY` env var and is distinct from the JWT cookie key (`RELAY_SIGNING_KEY`) — different primitives must not share key material (SC1). The client stores the `owner_token` in vault SQLite; it is the bearer credential for revocation.

B1 design note: the relay stores the provider presigned URL and returns it to recipients, who then fetch ciphertext directly from the provider. The relay does not proxy the ciphertext. Range behaviour is determined by the provider; the relay does not restrict it.

#### `GET /relay/share/b1/:share_id` (unauthenticated)

Returns `{ provider_url, expires_at }` for an active, non-expired, non-revoked share. Returns 404 for expired, missing, or revoked — opaque with no distinction so a recipient cannot infer whether a share was explicitly revoked vs naturally expired. Rate-limited: 10 req/min per share_id, 60 req/min per source IP.

#### `DELETE /relay/share/b1/:share_id` (unauthenticated, token-gated)

Revokes a B1 record. Requires `X-Owner-Token: <token>` header containing the HMAC token returned at creation. No relay cookie needed — the token is the bearer credential. Returns 403 on token mismatch.

#### `POST /relay/share/b2` (authenticated)

Uploads a V7 ciphertext blob (max 200 MiB). Requires a purpose-scoped, single-use relay auth cookie (`purpose = "share:b2"`). First byte must be `0x07` (V7 marker) and body must be at least 1741 bytes (V7 header + footer); smaller payloads are rejected. Hard expiry cap: 30 days.

Headers: `X-Share-Id`, `X-Expires-In`
Response: `{ share_id, expires_at, owner_token }` — same HMAC ownership token scheme as B1.

#### `GET /relay/share/b2/:share_id` (unauthenticated)

Streams ciphertext to recipient. Same opaque-404 and rate-limit rules as B1.

#### `DELETE /relay/share/b2/:share_id` (unauthenticated, token-gated)

Revokes a B2 record. Requires `X-Owner-Token: <token>` header. Same scheme as B1 DELETE.

**Share relay security invariants:**
- Server stores no content keys, no vault keys, no credentials.
- B1 row: opaque provider URL (capability to ciphertext) + expiry + revoked flag only.
- B2 row: V7 ciphertext only; relay never sees plaintext.
- Create endpoints (`POST /relay/share/b1`, `POST /relay/share/b2`) require PoW + purpose-scoped single-use relay auth cookie (signed with `RELAY_SIGNING_KEY`).
- Revoke endpoints (`DELETE`) use HMAC ownership tokens (no relay cookie). Tokens are keyed on a separate `RELAY_SHARE_SIGNING_KEY` and bind a server-stored per-record `token_nonce`, so they cannot be forged from a JWT-key compromise and cannot be replayed across record lifecycles.
- Expiry and revocation are independently enforced server-side and client-side.

### Security Headers

```
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Limitations

- SFTP host key fingerprint is stored per `provider_id` in the encrypted vault SQLite after the first connection (TOFU). On subsequent connections, a mismatch is rejected before authentication.
- Relay server holds no state between connections; enrollment channels expire after 10 minutes.

---

## Vault Lifecycle & Offline Recovery

### First Vault Creation (first provider only)

```
1. Worker: generateVaultKeys() -> vault_key, shard, vault_id, master_salt
2. Worker: Argon2id(password, master_salt) -> vault_kek
3. Worker: wrapVaultKey(vault_key, vault_kek) -> pass_wrap_iv, pass_wrapped_vault_key
4. Worker: generate recovery key (37 bytes: version + 32 random + 4-byte checksum)
5. Worker: derive recovery_vault_kek from recovery key -> wrapVaultKey -> recovery slot
6. Worker: derive manifest_aead_key from vault_key (HKDF "SecureCloud BYO manifest v1")
7. Worker: create empty per-provider SQLite schema; export sqlite_bytes
8. Worker: byoVaultBodyEncrypt(session_id, provider_id, sqlite_bytes) -> vault_<pid>.sc bytes
9. Worker: build manifest JSON { manifest_version:1, providers:[{provider_id, …}] }
10. Worker: byoManifestEncrypt(session_id, manifest_json) -> manifest blob
11. Worker: build header (magic + params + salts + wrapped keys + HMAC)
12. Primary provider: upload vault_manifest.sc = [header + manifest blob]
13. Primary provider: upload vault_<provider_id>.sc = [body_iv + body_ciphertext]
14. UI: display recovery key once; user must copy before proceeding
```

### Vault Unlock

```
1. Fetch vault_manifest.sc from every known provider in parallel
   (known providers come from IndexedDB; seeded with primary provider on first attach)
2. Worker: byoManifestDecrypt(session_id, manifestBytes) on each fetched manifest
3. Worker: byoManifestMerge([manifest_json, …]) -> merged_manifest_json
4. If any provider's manifest_version < merged.manifest_version:
     re-upload merged manifest to that provider (background; non-blocking)
5. Compare merged.manifest_version with IndexedDB last_seen_manifest_version:
     if fetched < stored -> raise rollbackWarning
6. For each provider in merged.providers (parallel):
   a. Download vault_<provider_id>.sc  (or load from IndexedDB encrypted-body cache on failure)
   b. Worker: byoVaultBodyDecrypt(session_id, provider_id, bodyBytes) -> sqlite_bytes
   c. INSERT rows into unified in-memory SQLite (stamping provider_id if absent)
7. For each provider: replay vault_journal_<provider_id>.j if it exists
8. Vault is open; unified SQLite held in Worker memory
```

**Fail-closed**: if zero manifests are fetchable and no IDB cache exists, unlock is aborted. Partial index (manifest decoded, some provider bodies missing) is allowed only when the missing providers have a valid IDB-cached body; otherwise unlock blocks.

### Offline Provider Handling

- After a successful vault body download, the encrypted bytes are stored in IndexedDB keyed by `provider_id` + version.
- IDB bytes are always encrypted (per-vault subkey); plaintext SQLite bytes never persist to browser storage.
- On unlock, if a provider's fetch fails or times out (5 s default), the IDB-cached bytes are used instead.
- Offline providers load read-only into the unified DB. The UI marks them with an offline chip and banner; write actions are disabled for their tab.

### Offline Conflict Resolution (ConflictResolver)

On `ConflictError` during vault upload (`If-Match` / ETag mismatch):

1. Download remote `vault_<provider_id>.sc`
2. Worker: `byoVaultBodyDecrypt(session_id, provider_id, remoteBytes)` -> remote sqlite
3. Row-by-row merge into local DB (scoped to `provider_id`):
   - Remote-only rows: INSERT (OR IGNORE)
   - Both: keep the row with the later `updated_at` (or `created_at`)
   - `key_versions`: UNION — never delete
   - `vault_meta.vault_version`: take `max + 1`
   - `vault_meta.enrolled_devices`: union by `device_id`
4. Retry upload (up to 3 times)

### Vault Save (two-phase commit)

The save is structured as a 2-phase commit so that WAL and journal entries are only
cleared once both the vault body and the manifest that names it have been confirmed:

```
Phase 1 — Flush journals (fail hard; abort if any flush fails)
  For each dirty provider:
    Await journal.flush() -> upload vault_journal_<pid>.j to provider

Phase 2 — Upload vault bodies
  For each dirty provider_id:
    1. Extract rows WHERE provider_id = ? from unified SQLite -> per-provider sqlite_bytes
    2. Worker: byoVaultBodyEncrypt(session_id, provider_id, sqlite_bytes) -> vault body blob
    3. Provider: upload vault_<provider_id>.sc (overwrite semantics)
       -> On ConflictError: run ConflictResolver, then retry
    4. Track as successful body upload

Phase 3 — Upload manifest
    5. Worker: byoManifestEncrypt(session_id, manifest_json) -> manifest blob
    6. Upload vault_manifest.sc to ALL reachable providers (best-effort per-provider)
    7. If ZERO providers confirmed the manifest: abort save; dirty state preserved for retry

Phase 4 — Two-phase commit (only after manifest is confirmed)
    8. For each provider with confirmed body upload:
       a. Clear WAL (IndexedDB wal entries)
       b. Set dirty flag = false
       c. Await journal.commit() -> delete vault_journal_<pid>.j from provider
       d. Remove from dirty set
    9. If dirty set is now empty: set global dirty flag = false

Provider removal (removeProvider):
  - Best-effort delete vault_<pid>.sc and vault_journal_<pid>.j from the removed
    provider's storage BEFORE tombstoning the manifest entry, so a future manifest
    rollback cannot resurrect the provider's files.
```

**Retry semantics**: if the save fails partway (e.g. manifest upload fails), the dirty
flag and WAL entries remain intact.  On the next save cycle the full Phase 1-4 sequence
is retried, giving idempotent recovery.

### Manifest Mutation Helpers (pure functions, sdk-core)

Provider lifecycle mutations are implemented as pure Rust functions in
`sdk-core/src/byo/manifest.rs` and exposed through WASM (`byo_manifest_*`).
All mutations run `validate_manifest` on the result before returning, so
invariant violations (duplicate primary, tombstone+primary, etc.) are caught
immediately regardless of which platform calls them.

| WASM export | Effect |
|---|---|
| `byoManifestAddProvider` | Append a new `ManifestEntry`; rejects duplicate `provider_id` |
| `byoManifestRenameProvider` | Update `display_name`; rejects tombstoned targets |
| `byoManifestSetPrimary` | Set `is_primary = true` on target, clear all others |
| `byoManifestTombstone` | Set `tombstone = true`, clear `is_primary`; can't undo |

`VaultLifecycle.addProvider`, `renameProvider`, `setAsPrimaryProvider`, and
`removeProvider` (tombstone step) all delegate to these WASM exports.

### Manifest Merge Rules (pure function, sdk-core)

- **Union of `provider_id`s** across all fetched manifests.
- Per entry: take the record with the **highest `updated_at`**; tombstones win if `updated_at` is later.
- **Clock-skew rejection**: any entry with `updated_at > now + 3600 s` is rejected with an error before
  merge proceeds. A hostile provider cannot pin its entry forever by setting `updated_at = u64::MAX`.
  Pass `now_unix_secs` to `byoManifestMerge`; pass `0` only in tests.
- `is_primary`: exactly one active entry may be `true`; on conflict pick highest `updated_at`;
  tie-break by alphabetical `provider_id`. A tombstoned entry with `is_primary = true` is an invariant
  violation rejected by `validate_manifest`.
- `manifest_version = max(all fetched) + 1` on any save. Equal manifests → skip upload.
- **Rollback resistance**: `byoManifestMerge` accepts a `min_acceptable_version` parameter.  The
  caller passes `last_seen_manifest_version` from IndexedDB (`DeviceRecord.last_seen_manifest_version`).
  If the merged version would be less than that floor, the merge is rejected with an error and
  `vaultStore.setRollbackWarning(true)` is set.  The floor is updated to
  `max(stored, merged.manifest_version)` after each successful unlock.

### Session & Concurrency (Cross-Tab Safety)

Multiple browser tabs can open the same origin, and each would try to unlock the same vault.
Concurrent vault sessions produce duplicate `manifest_version` values and lost writes.

**Lock protocol (C6):**
- On `unlockVault`, after parsing the vault header (to learn `vault_id`), the tab calls:
  ```
  navigator.locks.request('byo-vault-<vault_id>', { mode: 'exclusive', ifAvailable: true }, ...)
  ```
- If the lock is **not available** (another tab holds it): unlock is aborted, `vaultStore.tabOwnership` is
  set to `'other'`, and a banner is shown: *"Another tab is managing this vault. Close that tab to take over."*
- If the lock **is granted**: `vaultStore.tabOwnership` is set to `'this'` and unlock proceeds normally.
- The lock is held as a long-lived Promise that resolves only when `lockVault()` is called, at which
  point other tabs can re-attempt unlock.

**Fallback**: if `navigator.locks` is unavailable (SSR, older browsers), the lock step is skipped and
both tabs proceed. This is a best-effort guarantee, not a hard invariant.

**Lock name**: `byo-vault-<hex vault_id>` (example: `byo-vault-deadbeef01234567deadbeef01234567`).
The name is scoped to the vault so vaults on different providers coexist without interfering.

### Deferred Manifest Sync

When a provider comes back online after being offline during a manifest update, `OfflineDetector` detects the `offline → online` transition and compares the provider's stored `manifest_version` with the current merged version. If behind, the current manifest is uploaded automatically.

### Device Revocation

```
1. Worker: open vault, find target device slot by device_id
2. Worker: zero out slot: status=0x00, all bytes set to 0
3. Worker: bump revocation_epoch (u32 LE at offset 1191)
4. Worker: recompute header HMAC
5. Primary provider: upload vault_manifest.sc with updated header + original manifest blob
   (manifest blob unchanged — vault_key unchanged)
6. Push updated manifest to all other reachable providers
```

### Passphrase Change / Recovery Re-key

`vault_key` does **not** change. Only its wrapping changes:

```
1. Worker: byoVaultRewrapWithPassphrase(session_id, new_passphrase) -> passSlot
   (generates new master_salt; Argon2id + AES-GCM wrap inside WASM)
2. Worker: byoVaultWrapRecovery(session_id, new_recovery_key_b64) -> recSlot
3. Patch header in-place: new master_salt, pass slot, rec slot, device slots, revocation_epoch
4. Worker: byoVaultComputeHeaderHmac(session_id, header_bytes[0..1195]) -> hmac
5. Assemble: [patched header (1227)] + [original manifest blob (unchanged)]
6. Primary provider: upload vault_manifest.sc
7. Push updated manifest to all other reachable providers
```

Per-provider vault bodies and manifest body are NOT re-encrypted (same `vault_key` → same subkeys → blobs remain valid).

### Vault Key Rotation (after vault_key compromise)

```
1. Worker: generate new vault_key
2. For each provider_id:
   a. Re-derive subkeys from new vault_key
   b. Re-encrypt vault_<provider_id>.sc body with new subkey
   c. Upload vault_<provider_id>.sc
3. Re-encrypt manifest body with new manifest_aead_key
4. Re-wrap pass / recovery / device slots under new vault_kek (from new master_salt + Argon2id)
5. Recompute header HMAC with new vault_key
6. Upload vault_manifest.sc = [new header + new manifest blob] to all providers
```

Old `vault_key` cannot decrypt any body after rotation. All subkeys change.

---

## Zero-Knowledge Security Properties

### What the relay server never receives

- Vault passphrase (Argon2id runs in-browser)
- `vault_key` (never transmitted)
- `shard` (transmitted only once during enrollment, encrypted with ephemeral ECDH key)
- Provider tokens (stored encrypted in vault SQLite)
- File content or filenames (encrypted before reaching provider)
- Private keys (X25519, ML-KEM)

### BYO-Specific Zero-Knowledge Table

| # | Invariant |
|---|-----------|
| BYO-ZK-1 | Provider stores only opaque ciphertext; cannot distinguish vault header from body |
| BYO-ZK-2 | Provider credentials stored encrypted in manifest body (`config_json`); token theft requires `vault_key` |
| BYO-ZK-3 | Relay server receives only ECDH public keys + encrypted shard envelope; cannot reconstruct shard |
| BYO-ZK-4 | Shard alone is insufficient to decrypt vault (requires password-derived `client_kek_half`) |
| BYO-ZK-5 | Per-file content keys derived via hybrid X25519+ML-KEM; same key hierarchy as managed mode |
| BYO-ZK-6 | SAS verification binds ECDH public keys to visual confirmation; prevents relay-side MITM |
| BYO-ZK-7 | SFTP relay receives only SSH protocol traffic over TLS; relay cannot decrypt SFTP payload |
| BYO-ZK-8 | Attacker controlling one provider can pin an old manifest on that provider only; merge takes highest version from other reachable providers |
| BYO-ZK-9 | Per-provider vault body subkeys are HKDF-distinct; compromising one provider's body does not weaken others |
| BYO-ZK-10 | Offline IDB cache stores only AES-GCM ciphertext (per-vault subkey); plaintext SQLite bytes never persist to browser storage |

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Provider compromise (vault body stolen) | `vault_key` required; derived from password + Argon2id (128 MB); offline brute-force impractical |
| Provider compromise (credentials stolen) | Credentials are inside encrypted manifest body; attacker needs `vault_key` first |
| Password brute-force | Argon2id m=128 MB, t=3, p=4 (~1-2 s per attempt on modern hardware; offline-only) |
| Device shard + no password | Shard alone insufficient; `client_kek_half` requires Argon2id(password) |
| MITM during enrollment | SAS (6-digit code) provides visual binding of ECDH keys; different keys -> different SAS |
| XSS on main thread | Keys isolated in dedicated Web Worker; JS on the main thread cannot reach worker memory |
| Relay server compromise | Relay sees encrypted shard envelope only; cannot reconstruct shard (no ECDH private key) |
| Attacker pins old manifest on one provider | Merge takes highest `manifest_version` from other reachable providers; single-provider rollback cannot hide new providers or forge entries without the HMAC key |
| Manifest version rollback | Device stores `last_seen_manifest_version` in IDB; regression → `rollbackWarning` modal; user must explicitly proceed |
| Cross-provider data leakage | Per-provider subkeys via HKDF(vault_key, provider_id); each body is independently keyed; cross-provider parent refs blocked by DB triggers |
| Provider token expiry / revocation | Triggers explicit re-auth flow; vault contents unaffected |

### Key Differences from Managed Mode

| Property | Value |
|----------|-------|
| Password hashing | Argon2id 128 MB, t=3, p=4 |
| Shard source | Device-local (vault header slot) |
| Server involvement | Stateless relay only; no key material touches the server |
| Vault location | User-owned storage provider (Drive, Dropbox, OneDrive, Box, pCloud, WebDAV, SFTP, S3) |
| Provider token storage | Encrypted in vault SQLite |
| Recovery code | Separate `recovery_vault_kek` path |
| File encryption | V7 (AES-256-GCM chunked + hybrid X25519 + ML-KEM-1024) |

---

## Error Model

### ProviderError Codes

| Code | Meaning | Typical cause |
|------|---------|---------------|
| `CONFLICT` | ETag/rev mismatch | Concurrent vault modification from another device |
| `NOT_FOUND` | File or folder absent | Deleted externally, wrong ref |
| `UNAUTHORIZED` | Token expired or revoked | Requires `refreshAuth()` or full OAuth re-flow |
| `FORBIDDEN` | Insufficient permissions | Provider quota exceeded or ACL issue |
| `RATE_LIMITED` | Provider API rate limit | Back off and retry with exponential jitter |
| `NETWORK_ERROR` | Connectivity failure | Offline, DNS failure, timeout |
| `PROVIDER_ERROR` | Generic provider error | See message for details |
| `INVALID_RESPONSE` | Malformed response | Provider API change or proxy corruption |
| `SFTP_RELAY_ERROR` | WebSocket relay failure | Relay unreachable, SSH auth failure |

### ConflictError

Thrown on HTTP 409/412 from the provider. Contains `currentVersion` (ETag/rev), which the caller uses for merge-based conflict resolution.

### Streaming Decrypt HMAC Failure

`closeV7Stream()` throws if the HMAC footer does not match. The caller **must discard all previously yielded plaintext**. The `ByoDownloadStream.decrypt()` generator propagates the throw; callers must not commit partial output.

---

## Build & Test

```bash
# Compile sdk-wasm with BYO exports
make build-sdk-wasm

# Build BYO TypeScript package
cd frontend && npm run build

# Build BYO frontend (Svelte + Vite)
cd frontend && npm run build:byo

# Rust unit tests (includes provider mock tests, requires 'providers' feature)
cd sdk && cargo test --features providers

# TypeScript unit tests
cd frontend && npm test  # includes frontend/tests/sdk/

# WASM in-browser tests
make test-sdk-wasm

# Full suite
make test-all
```

### Provider Unit Test Coverage

Each provider (GDrive, Dropbox, OneDrive, WebDAV, Box, pCloud, S3) has a `MockProviderHttpClient` (Rust) or `MockProvider` (TS E2E only) that plays back canned HTTP responses. Tests cover:
- `init()` creates / reuses root folder
- `upload()` sends correct auth headers
- Resumable upload open/write/close round-trip
- `download()` returns body
- HTTP 401 -> `ProviderError::Unauthorized`
- HTTP 412 -> `ProviderError::Conflict { current_version }`

### Streaming Test Coverage

Additional test coverage for the V7 + Range streaming path:

**sdk-core Rust tests:**
- `byo::providers::tests::apply_response_*` (10 tests): `RangedDownloadBuffer` status-code handling (206 with/without Content-Range, 200 fallback, 416 EOF, error propagation), offset advancement, total_size discovery, implicit EOF via short reads.
- `byo::providers::gdrive::tests::gdrive_download_stream_e2e_v7_roundtrip_via_range`: **full end-to-end test**. Generates a hybrid keypair, V7-encrypts a 3 MiB plaintext, uploads to a stateful Range-honoring `MockHttp`, streams back through `RangedDownloadBuffer` chunked reads, and V7-decrypts. Asserts byte-for-byte plaintext recovery.
- `byo::providers::gdrive::tests::download_stream_multi_chunk_via_range`: multi-chunk 206 + `Content-Range` integration.
- `byo::providers::dropbox::tests::dropbox_download_range_headers_correctly_formed`: verifies the exact wire-format headers on Dropbox's `POST /files/download` range request (method, URL, Bearer, Dropbox-API-Arg, Range).
- `byo::providers::pcloud::tests::download_stream_auto_refreshes_cdn_url_on_403`: CDN URL auto-refresh flow after mid-stream 403.
- `byo::providers::pcloud::tests::download_stream_surface_unauthorized_after_second_403`: no infinite retry loop on persistent 403.

**Frontend Vitest tests:**
- `frontend/tests/byo/ByoDataProvider.test.ts`: `crossProviderMove` Phase 3a pipeTo path — verifies chunks flow through `pipeTo` without accumulation, blob name is opaque UUID (ZK-6), DB row is updated, source-delete best-effort.

### Memory Verification (Manual QA)

The streaming work targets a specific memory ceiling: **one V7_ENCRYPT_CHUNK_SIZE (512 KiB) plaintext chunk + one 8 MiB provider chunk** in WASM heap per in-flight upload/download, regardless of file size. To empirically confirm in a live browser:

1. Start the dev stack (`make dev`) and complete BYO vault setup.
2. Open DevTools → Performance → record, or use `performance.memory.usedJSHeapSize`.
3. Baseline: record heap size before upload.
4. Upload a 1 GiB test file (`dd if=/dev/urandom of=/tmp/big.bin bs=1M count=1024`).
5. Sample JS heap during upload — should stay within ~50-100 MiB above baseline (browser + UI overhead; cipher frames are NOT in JS heap due to Phase 3d).
6. Download the same file; peak JS heap during download should stay similar (the plaintext-chunk window in `DownloadStream.decryptWasm` is bounded by V7_ENCRYPT_CHUNK_SIZE).
7. Cross-provider move (e.g. GDrive → Dropbox) of a 1 GiB file: JS heap should see near-zero ciphertext (Phase 3c pipe stays inside WASM).

If heap exceeds file-size-scaled bounds, investigate: likely the `WasmStorageProviderShim` upload path is in use (legacy, only for SFTP) or the test is pinning chunks via a pause signal that keeps them alive.

### Provider Range-Request Verification (Manual QA)

Unit tests use mock HTTP clients. The following should be verified against live providers before full production rollout:

1. **GDrive/OneDrive/Box 302→CDN Range preservation**: upload a large file, begin a download, inspect the Network tab and confirm the second request (to the CDN URL after redirect) includes the `Range` header.
2. **Dropbox POST + Range**: Dropbox's docs state `POST /2/files/download` supports `Range`. Verify actual `Content-Range` response header on an upload/download round-trip.
3. **S3 SigV4 + Range**: verify the `Authorization` header signs the `Range` additional header; any S3-compatible endpoint that rejects an unsigned `Range` header would surface an `Unauthorized` error.
4. **pCloud CDN URL expiry**: simulate a long idle by pausing a download for >15 min (or manually expire via pCloud API), confirm the download resumes cleanly via `fetch_pcloud_cdn_url` refresh.

---

## Dependencies

### Rust (sdk-core, sdk-wasm, sdk-ffi)

| Crate | Purpose |
|-------|---------|
| `ml-kem` | ML-KEM-1024 (NIST FIPS 203) |
| `x25519-dalek` | X25519 ECDH |
| `aes-gcm` | AES-256-GCM |
| `argon2` | Argon2id KDF (128 MB, t=3, p=4) |
| `hkdf` / `sha2` | HKDF-SHA256 |
| `hmac` | HMAC-SHA256 |
| `getrandom` | CSPRNG (maps to `crypto.getRandomValues` in WASM) |
| `base64` | Base64url (at WASM/FFI boundary only) |
| `serde_json` | Provider config + OAuth response parsing |
| `reqwest` (wasm feature) | HTTP for Rust provider orchestrators (uses `web-sys::fetch`) |
| `quick-xml` | WebDAV PROPFIND response parsing |
| `aws-sigv4` | SigV4 request signing for S3-compatible providers (pure-logic, wasm32-compatible) |
| `zeroize` | Key material zeroization |

### TypeScript (byo/)

| Package | Purpose |
|---------|---------|
| `@wattcloud/wasm` | WASM bindings (vault crypto, V7 streaming, OAuth) |
| `better-sqlite3` | SQLite in-process (vault DB) |
| `vitest` | Unit tests |

---

## Usage Statistics

BYO records lightweight, privacy-respecting usage metrics. Stats are aggregated
server-side in SQLite; the relay never sees plaintext, filenames, or IP addresses.

### Privacy Invariants

| Rule | Detail |
|------|--------|
| No IP logging | `/relay/stats` endpoint discards the source IP before any processing |
| Device UUID hashed | Raw UUID is hashed server-side with `HMAC-SHA256(STATS_HMAC_KEY, uuid)` before storage |
| Ciphertext bytes only | `bytes` values come exclusively from ciphertext contexts (V7 frames, relay blobs, SFTP frames) |
| No filenames or paths | Wire format accepts only: `kind`, `ts`, `provider_type`, `bytes`, `error_class`, `share_variant`, `*_bucket` |
| Aggregate only | No per-event rows persisted — only counter aggregates and daily dedup tables |

### Wire Format (`POST /relay/stats`)

Requires a `relay_auth` HttpOnly cookie with `purpose="stats"` (same PoW
handshake as share cookies — `acquireRelayCookie('stats')`).

```jsonc
{
  "device_id": "5f3b1234-...",   // lowercase UUIDv4; hashed before storage
  "events": [
    { "kind": "vault_unlock",  "ts": 1713283200 },
    { "kind": "vault_lock",    "ts": 1713283900 },
    { "kind": "vault_save",    "ts": 1713283230 },
    { "kind": "upload",        "ts": 1713283210, "provider_type": "gdrive",  "bytes": 12345678 },
    { "kind": "download",      "ts": 1713283220, "provider_type": "dropbox", "bytes": 98765 },
    { "kind": "error",         "ts": 1713283230, "provider_type": "s3",      "error_class": "RateLimited" },
    { "kind": "share_create",  "ts": 1713283240, "share_variant": "B2" },
    { "kind": "share_resolve", "ts": 1713283250, "share_variant": "A" },
    { "kind": "share_revoke",  "ts": 1713283260, "share_variant": "B1" },
    { "kind": "relay_bandwidth_sftp",  "ts": 1713283270, "bytes": 524288 },
    { "kind": "relay_bandwidth_share", "ts": 1713283280, "bytes": 131072 },
    { "kind": "device_size_snapshot",  "ts": 1713283290, "provider_type": "gdrive",
      "file_count_bucket": 12, "vault_size_bucket": 28 }
  ]
}
```

Server-enforced limits: body ≤ 64 KiB, ≤ 200 events per batch, `ts` clamped to
`[now-2d, now+5min]`. Unknown `kind` values are silently dropped (forward-compat).

### Flush Schedule

- 60-second `setInterval` in the BYO worker client.
- `visibilitychange → hidden` triggers an immediate flush.
- Early flush when queue depth ≥ 50 events.

### Configuration (`byo-relay`)

| Env var | Default | Notes |
|---------|---------|-------|
| `STATS_HMAC_KEY` | — | **Required** (hex or base64, ≥ 32 B). Server fails to start without it. |
| `STATS_DB_PATH` | `/var/lib/byo-relay/stats.sqlite3` | SQLite WAL file path |
| `STATS_INGEST_PER_MIN` | `10` | Per-device rate limit (batches/min) |
| `STATS_BATCH_MAX_EVENTS` | `200` | Max events per POST |
| `STATS_MAX_BODY_BYTES` | `65536` | Max POST body size |

### Admin CLI (`byo-admin`)

```bash
# View daily stats (runs inside the container)
make stats-log
make stats-log GRAN=weekly
make stats-log GRAN=monthly FROM=2026-01-01 TO=2026-04-01

# Destructively wipe all stats rows (leaves schema intact)
make stats-clear
```

Or directly: `docker compose exec byo-relay byo-admin log --granularity daily`

### SQLite Schema

Three tables in `/var/lib/byo-relay/stats.sqlite3`:

- **`counters`** — aggregate event counts + byte sums, keyed by `(bucket_date, event_kind, provider_type, error_class, share_variant)`.
- **`device_day_provider`** — one row per `(day, device_hash, provider_type)` for provider-mix distinct-device counts.
- **`device_day_size`** — one row per `(day, device_hash, provider_type)` storing `file_count_bucket` + `vault_size_bucket` histograms.

Aggregation to weekly/monthly/yearly is performed at query time via SQLite `strftime()`.
Schema version tracked in `schema_meta` for future migrations.

---

## Production Deployment

For first-time deploy, upgrade, rollback, and secrets bootstrap, see
[`docs/BYO-DEPLOYMENT.md`](docs/BYO-DEPLOYMENT.md).
