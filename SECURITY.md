# SDK Security Architecture

This document describes the security properties of the Rust SDK and how they are enforced. It is the authoritative reference for implementers.

- For the managed-backend mode, decisions must conform to `SPEC-MANAGED.md`.
- For the BYO storage mode, decisions must conform to `SPEC-BYO.md`.

---

## 1. Trust Boundaries

```
┌────────────────────────────────────────────────────────┐
│  Browser (Untrusted Execution Environment)              │
│                                                        │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Web Worker (XSS-isolated context)              │  │
│  │  sdk-wasm (WASM module)                         │  │
│  │  - Holds ALL key material in Worker memory      │  │
│  │  - Main thread never sees raw key bytes         │  │
│  │  - Runs Argon2id, KEM, AES-GCM, HMAC            │  │
│  └─────────────────────────────────────────────────┘  │
│                ↑ postMessage (opaque handles)           │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Main Thread                                    │  │
│  │  Svelte components (UI only)                    │  │
│  │  CryptoBridge (typed postMessage wrapper)       │  │
│  └─────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
                    ↕ HTTPS + CSRF token
┌────────────────────────────────────────────────────────┐
│  Backend (Trusted for Availability, NOT for Data)       │
│  - Never sees plaintext files, passwords, or keys      │
│  - Stores only encrypted key bundles + ciphertext      │
│  - Holds server_shard (useless without client_kek_half)│
└────────────────────────────────────────────────────────┘
```

**What the backend never receives:**
- Plaintext passwords
- Master secrets / recovery keys
- `client_kek_half` or full KEK
- Decrypted file content or filenames
- Plaintext private keys

---

## 2. Key Hierarchy

```
Password (user input, never stored)
    │
    ▼ Argon2id(m=65536, t=3, p=4, output=64 bytes, salt=auth_salt)
argon_output[0:64]
    │                               │
    │ argon_output[0:32]            │ argon_output[32:64]
    ▼                               ▼
HKDF-SHA256                    HKDF-SHA256
info="SecureCloud Auth v1"     info="SecureCloud KEKHalf v2"
    │                               │
    ▼                               ▼
auth_hash                      client_kek_half
(sent to server for auth)      (NEVER sent to server)
    │                               │
    │                               │ + server_shard (32 bytes, AES-GCM encrypted with MASTER_KEY)
    │                               ▼
    │                          HKDF-SHA256(client_kek_half || server_shard)
    │                          info="SecureCloud KEKv2"
    │                               │
    │                               ▼
    │                              KEK (Key Encryption Key, 32 bytes)
    │                               │
    │                               ├── AES-GCM(KEK, mlkem_private_key)
    │                               └── AES-GCM(KEK, x25519_private_key)
    │                                       │ stored in key_versions table
    │                                       │ decrypted into CryptoBridge Worker memory
    │
    │
Recovery Key (37 bytes, displayed once, never stored)
    │ recovery_key[1:33]
    ▼
HKDF-SHA256
info="SecureCloud RecoveryKEK v1"
    │
    ▼
recovery_kek
    ├── AES-GCM(recovery_kek, mlkem_private_key)   \_ recovery-encrypted
    └── AES-GCM(recovery_kek, x25519_private_key)  /  copies in key_versions

Per-File Encryption (v7):
ML-KEM-1024 + X25519 keypair → Hybrid Encapsulation → shared_secret
HKDF-SHA256(shared_secret, info="SecureCloud v6", L=64)   # label historical
    ├── wrapping_key[0:32]  (AES-GCM-wraps the per-file content_key)
    └── kem_hmac_key[32:64] (discarded in v7)

content_key          = random 256-bit per file
encrypted_file_key   = wrapping_iv(12) || AES-GCM(wrapping_key, content_key)
chunk_hmac_key       = HKDF-SHA256(content_key, info="chunk-hmac-v1", L=32)
chunk_nonce(i)       = file_iv XOR LE96(i)
key_commitment       = BLAKE2b-256(content_key || file_iv)
```

**Key lifetime policy:**
- `argon_output`: zeroized immediately after deriving `auth_hash` and `client_kek_half`
- `client_kek_half`: zeroized after combining with `server_shard` to derive `KEK`
- `server_shard`: zeroized after KEK derivation
- `KEK`: zeroized after decrypting all private keys into Worker memory
- `recovery_kek`: zeroized immediately after use
- Private keys in Worker memory: zeroized on logout, session expiry, or tab close

---

## 3. Zeroization Policy

**Rule:** Every type containing key material MUST:

1. Derive `Zeroize` and `ZeroizeOnDrop` from the `zeroize` crate
2. NOT implement `Clone` (prevents silent key material duplication)
3. Implement `Debug` printing `[REDACTED]` — never the actual value
4. NOT appear in log output, error messages, or serialized API payloads

**Enforcement:**
- `sdk-core` is compiled with `#![deny(clippy::unwrap_used, clippy::expect_used)]`
- Types: `PrivateKey`, `SymmetricKey`, `Argon2Output`, `ClientKekHalf`, `ServerShard`, `Kek`, `RecoveryKek`, `ContentKey`, `HmacKey`
- All `Vec<u8>` holding key material must be wrapped in a newtype that derives `ZeroizeOnDrop`

**Platform note:** In WASM linear memory, there is no guarantee that the OS will zero freed memory. `ZeroizeOnDrop` provides a best-effort guarantee by writing zero bytes before deallocation.

---

## 4. Nonce Management

| Context | Size | Generation | Uniqueness Guarantee |
|---------|------|-----------|---------------------|
| v7 chunked content nonces | 12 bytes | `file_iv XOR LE96(chunk_index)` | Deterministic per (file, chunk); `file_iv` is random per file |
| v7 key wrapping (efk) | 12 bytes | CSPRNG (`wrapping_iv`) | Random per wrap operation |
| Filename encryption (SIV) | 12 bytes | HMAC-SHA256(key, plaintext)[0:12] | Deterministic — same filename + key → same nonce (SIV property: safe for repeated encryption of same value) |
| KEK wrapping (trusted device) | 12 bytes | CSPRNG | Random per operation |

**Rules:**
- Never reuse a nonce with the same key
- `OsRng` is the only approved entropy source (maps to `crypto.getRandomValues()` in WASM via `getrandom`'s `js` feature)
- `thread_rng()` must never be used for cryptographic operations
- Nonces are prepended to ciphertext and included in HMAC/integrity inputs

---

## 5. Post-Quantum Strategy

The SDK uses a **hybrid classical + post-quantum** construction. There is no classical-only fallback — if the PQ component fails, the entire operation fails.

### Algorithm choices

| Algorithm | Type | Standard | Key sizes |
|-----------|------|----------|-----------|
| ML-KEM-1024 | KEM (PQ) | NIST FIPS 203 | pk: 1,568 B, sk: 3,168 B, ct: 1,568 B |
| X25519 | KEM (classical) | RFC 7748 | pk: 32 B, sk: 32 B |

### Hybrid KEM construction (v7)

```
encapsulate(recipient_mlkem_pk, recipient_x25519_pk):
    (x25519_ss, x25519_ct) = X25519-ECDH(ephemeral_sk, recipient_pk)
    (mlkem_ss, mlkem_ct)   = ML-KEM-1024.Encapsulate(recipient_mlkem_pk)
    combined_ikm = x25519_ss || mlkem_ss
    (wrapping_key || kem_hmac_key) = HKDF-SHA256(combined_ikm, info="SecureCloud v6", L=64)
    header = [0x07(1)] [file_iv(12)] [eph_x25519_pk(32)] [mlkem_ct(1568)] [efk_len(4)] [efk(60)] [key_commitment(32)]

decapsulate(mlkem_sk, x25519_sk, header):
    x25519_ss = X25519-ECDH(x25519_sk, eph_x25519_pk)
    mlkem_ss  = ML-KEM-1024.Decapsulate(mlkem_sk, mlkem_ct)
    combined_ikm = x25519_ss || mlkem_ss
    (wrapping_key || kem_hmac_key) = HKDF-SHA256(combined_ikm, info="SecureCloud v6", L=64)
```

The HKDF info string literal is `"SecureCloud v6"` for historical reasons: it names the *hybrid KEM construction*, not a file format. V7 is the only wire format the code implements or accepts. `wrapping_key` is used to AES-GCM-wrap the per-file random `content_key`; `kem_hmac_key` is discarded (v7's chunk HMAC key is separately derived via `HKDF-SHA256(content_key, info="chunk-hmac-v1")`).

**Security properties:**
- If X25519 is broken by a quantum computer → ML-KEM-1024 still protects
- If ML-KEM-1024 is broken by a new classical attack → X25519 still protects
- Both must be broken simultaneously to compromise a file key

---

## 6. Streaming Decrypt Invariant

The v7 download path (`V7StreamDecryptor` in `sdk-core`, `V7StreamDecryptorWasm`
in `sdk-wasm`, consumed by `frontend/src/lib/downloadService.ts`) releases
plaintext **incrementally**, before the trailing 32-byte HMAC footer has been
verified. This is a deliberate departure from the usual "verify MAC before
trusting any byte" rule, and the justification is worth stating explicitly
because it is the kind of thing a future reviewer will (rightly) flag.

### Why incremental release is safe

V7 encrypts each chunk independently with AES-256-GCM. Two properties of the
chunk framing prevent the attacks that an unauthenticated-prefix release
usually enables:

1. **Per-chunk authentication.** Each frame is
   `[len_le32(4) || nonce(12) || ciphertext || gcm_tag(16)]`. AES-GCM verifies
   the tag before producing any plaintext bytes for that chunk, so a corrupted
   chunk is rejected at the AEAD layer. Bit-flips, substitutions, and injected
   garbage in the body are caught immediately — not at EOF.
2. **Chunk-index-bound nonces.** The per-chunk nonce is
   `file_iv XOR LE96(chunk_index)`. The decryptor re-derives this nonce from
   its monotonically increasing internal counter, ignoring whatever the wire
   says. That means an attacker cannot reorder, duplicate, or omit frames
   without causing AES-GCM authentication to fail on the first out-of-place
   frame. Reordering is therefore detected at the AEAD layer as well, not
   only at the outer HMAC.

The only attack these properties do **not** catch is **truncation at a
chunk boundary**: a valid prefix of frames is, by definition, a valid
sequence of frames, and the AEAD layer has no way to know that more frames
were supposed to follow. The HMAC footer (`HMAC-SHA256(hmac_key,
chunk_index_le32 || ciphertext for every chunk)`) exists exclusively to
catch this case — it is the only guarantee the reader has that the stream
reached its intended end.

### Consequences for callers

- **Plaintext bytes emitted by `push()` before `finalize()` returns are
  cryptographically trustworthy at the per-chunk level, but not yet
  confirmed to be a complete file.** Callers must treat a failed
  `finalize()` as a download failure and discard any partially-written
  output. The frontend's `downloadService.ts` handles this by aborting the
  `FileSystemWritableFileStream` (single-file) or aborting the `downloadZip`
  iterator (bulk) in the error path, leaving no partial file on disk.
- **The HMAC key is derived separately** via
  `HKDF-SHA256(content_key, info=CHUNK_HMAC_V1, L=32)` so the footer MAC
  is domain-separated from the AEAD keys. A forged content-key would not
  be able to produce a valid footer without also forging the HMAC key.
- **The content key and HMAC state never leave the crypto worker.** The
  streaming decryptor lives inside the WASM context for the duration of
  the download; the main thread only holds an opaque session id. On
  finalize, `Zeroize` clears the content key before the struct drops.

### Upload-side streaming encryptor

`V7StreamEncryptor` (`sdk-core`, exposed to the browser as
`V7StreamEncryptorWasm`) is the upload-side symmetric of the streaming
decryptor. It owns a session that lives inside the crypto Web Worker for
the full duration of an upload:

```
newV7EncryptSession()         → session_id (opaque string, main thread)
openV7EncryptStream(session_id, public_keys_json)
    ↳ performs hybrid KEM encapsulation inside the worker
    ↳ stores content_key, file_iv, chunk_hmac_key, HMAC accumulator
takeV7EncryptHeader(session_id) → 1709-byte V7 header (wire bytes only)
pushV7EncryptStream(session_id, plaintext_chunk) → 512 KiB+ wire frame
closeV7EncryptStream(session_id) → 32-byte HMAC footer, zeroizes session
```

The main thread only ever sees opaque wire-format bytes (header, frames,
footer). `content_key`, `kem_hmac_key`, `chunk_hmac_key`, `file_iv`, and
the running HMAC state never cross the postMessage boundary. On
`closeV7EncryptStream` (or `abortV7EncryptStream` in the error path) the
session's `Zeroize` impl wipes all key material before the struct drops.

This closes the key-isolation gap that existed while the upload pipeline
still used the `encrypt_file_v7_init` → `encrypt_file_v7_chunk` →
`compute_v7_hmac` three-step dance, which returned `content_key` to the
main thread as a base64 string.

#### Non-exportability invariant

`V7StreamEncryptor` (in `sdk-core/src/crypto/wire_format.rs`) and its BYO
wrapper `ByoUploadFlow` carry a load-bearing invariant: **they MUST NOT
gain `Clone`, `Serialize`, or any `snapshot`/`restore` method**.
`content_key` and the running HMAC state must be `Zeroize` and
`ZeroizeOnDrop` and must never be persisted to host storage (IndexedDB,
Android Room, iOS CoreData, or disk).

Cross-process resume of an upload is therefore NOT supported by
replaying a snapshot. A restarted worker must either:

- **Re-upload from byte 0**: run `V7StreamEncryptor::new` again, produce
  a fresh `file_iv` and fresh header, and upload the whole V7 blob anew.
  The previous partial upload on the provider side is orphaned and
  collected by the reconciler (for providers that expose an in-progress
  upload ID) or overwritten (for providers that don't).

- **Read-only access to `position()` for progress UI**: `chunk_index`
  (a `u32` counter) is safe to expose via `position()` because it is a
  public identifier, not key material. This is the only accessor.

Phase 3d's `byoStreamUpload*` sessions in `sdk-wasm/src/byo_streaming.rs`
own the encryptor by value inside a `thread_local!` map; dropping the
session (finalize/abort/error/worker teardown) triggers `ZeroizeOnDrop`.
Sessions do not survive a page reload because the entire WASM instance
is fresh.

### Upload pipeline parallelism

The bulk upload path (`frontend/src/lib/uploadService.ts`) mirrors the
bulk download path's two-layer concurrency model:

1. **Across files:** up to `UPLOAD_CONCURRENCY = 3` files encrypt and
   upload in parallel. Each in-flight file gets its own
   `V7StreamEncryptor` session, so they do not share key state. The
   backend caps concurrent upload sessions per user at 5
   (`backend/src/uploads.rs` → `MAX_CONCURRENT_SESSIONS_PER_USER`), so
   N=3 leaves headroom for retries.
2. **Within a file:** the `UploadChunkWriter` keeps one `PUT
   /api/files/uploads/:id/chunks/:idx` in flight while the worker
   encrypts the next buffer's worth of chunks. PUTs are still strictly
   sequential on the wire — the backend rejects out-of-order `chunk_idx`
   values — so depth-1 back-pressure is sufficient. The win is
   overlapping worker CPU with network I/O, not HTTP multiplexing.

Parallelism is a performance property, not a security property: every
in-flight session is cryptographically independent, so concurrency
neither strengthens nor weakens the zero-knowledge model.

### Streaming plaintext sink

Once the decryptor emits plaintext, it has to reach disk without passing
through a `Blob` (which would buffer the whole file in main-thread
memory and defeat the entire rework). The frontend picks one of three
sinks at runtime, in priority order:

1. **File System Access API** (`showSaveFilePicker` →
   `FileSystemWritableFileStream`). Chrome/Edge desktop only. No
   intermediate process — the browser writes the stream directly to the
   user-selected file. Zero new trust surface.
2. **Stream-saver service worker** (`frontend/public/stream-saver-sw.js`).
   Safari, Firefox, Chrome-on-iOS, and mobile. The main thread posts a
   `{filename, mime, size}` handshake to the SW, hands over a
   `MessageChannel` port, and waits for a `registered` ack; the SW
   creates a one-shot `TransformStream` keyed by a random 128-bit
   session id. The main thread then navigates a hidden iframe to
   `/stream-saver/<session-id>`; the SW's `fetch` handler intercepts
   that URL and responds with
   `new Response(readable, {headers: Content-Disposition: attachment,
   Content-Security-Policy: "default-src 'none'",
   X-Content-Type-Options: nosniff})`. Plaintext chunks flow through
   the message channel with per-chunk acks (bounded backpressure) into
   the transform stream writer, and the browser's native download
   manager drains the response straight to disk. No key material ever
   traverses the SW, and the SW holds no state beyond the in-flight
   session's `TransformStream` handles.
3. **Guarded blob fallback.** If neither sink is available (insecure
   HTTP origin, SW registration failure), the pipeline refuses
   downloads larger than `BLOB_FALLBACK_MAX_BYTES = 500 MiB` by
   throwing `FsaFallbackTooLargeError` to the user instead of risking
   a tab OOM. Below the cap, plaintext is collected in memory via
   `new Response(source).blob()` and handed to an anchor click —
   identical to the legacy path.

**Why the SW does not weaken the zero-knowledge model:**

- **No key material.** The service worker is a pure byte pipe. It
  never sees `content_key`, `hmac_key`, `file_iv`, `mlkem_private_key`,
  `x25519_private_key`, `KEK`, or any derivation thereof. All
  decryption happens in the crypto Web Worker; only plaintext
  `Uint8Array` chunks cross the boundary into the SW.
- **Same origin.** SWs are scoped to the origin that registered them;
  no cross-origin JavaScript can open one of our `/stream-saver/<id>`
  URLs, and the registration itself requires a secure context
  (HTTPS or localhost). Cross-origin iframes and popups cannot
  invoke the pipe.
- **Short-lived, one-shot sessions.** Each session id is a random
  128-bit value minted with `crypto.getRandomValues()`. The `fetch`
  handler consumes and deletes the session on first match; any
  subsequent request for the same id returns 404. Session records
  also expire after 60 seconds of inactivity, whether or not they
  have been consumed. There is no persistent store.
- **Response headers are hard-coded.** `Content-Disposition:
  attachment` forces download instead of inline rendering;
  `Content-Security-Policy: default-src 'none'` blocks any script,
  style, or subresource execution from the response body if a bug
  somehow routed it into a browsing context; `X-Content-Type-Options:
  nosniff` disables MIME-sniffing escalation. The SW never echoes
  user-controlled bytes into response headers — only the session
  id appears in the intercepted URL, and it is matched against
  `^/stream-saver/([A-Za-z0-9_-]+)$` before any routing.
- **Caching disabled.** The stream-saver route is served with
  `Cache-Control: no-store`, and the service worker script itself
  must be served with a short or zero cache lifetime so updates
  propagate (see infra follow-up in `PLAN_STREAMING.md` for the
  nginx production configuration).
- **Does not share scope with the crypto worker.** The crypto Web
  Worker and the stream-saver Service Worker are distinct worker
  kinds with separate global contexts. The crypto worker is a
  dedicated `Worker` whose module is loaded via bundled JS; the
  SW is a top-level worker whose lifecycle is managed by the
  browser. They do not share memory or message channels.

**Residual risk:** a compromised SW (e.g. via a successful supply chain
attack on `stream-saver-sw.js`) would see plaintext bytes for downloads
that use the SW sink path. This is strictly no worse than a compromise
of `downloadService.ts` itself — both are main-thread-adjacent JS with
access to plaintext after decryption — and is the reason the SW file
is tiny (~100 lines), pinned to a static path, and distributed from
the same origin as the rest of the frontend bundle. It does **not**
expose key material, which stays behind the dedicated crypto worker
boundary regardless of sink choice.

---

## 7. Platform Abstraction Traits

The SDK defines traits in `sdk-core` for platform-specific capabilities. Implementations live in platform crates.

### `KeyStorage` (sdk-core::keys)

```rust
pub trait KeyStorage: Send + Sync {
    fn store(&self, version_id: &str, key_material: &[u8]) -> Result<(), SdkError>;
    fn retrieve(&self, version_id: &str) -> Result<Option<Vec<u8>>, SdkError>;
    fn delete(&self, version_id: &str) -> Result<(), SdkError>;
    fn exists(&self, version_id: &str) -> Result<bool, SdkError>;
}
```

| Platform | Implementation | Backing store |
|----------|----------------|---------------|
| Web (WASM) | `WebKeyStorage` in sdk-wasm | Web Worker memory (WeakMap, never crosses to main thread) |
| Android (future) | `AndroidKeyStorage` in sdk-ffi | Android Keystore |

### `TokenStorage` (sdk-core::session)

```rust
pub trait TokenStorage: Send + Sync {
    fn store_refresh_token(&self, token: &str) -> Result<(), SdkError>;
    fn retrieve_refresh_token(&self) -> Result<Option<String>, SdkError>;
    fn clear_refresh_token(&self) -> Result<(), SdkError>;
}
```

Web implementation: access tokens in memory only; refresh tokens are `HttpOnly; Secure; SameSite=Strict` cookies managed by the browser (not accessible to JavaScript).

---

## 8. Zero-Knowledge Invariants

The system is zero-knowledge with respect to the server. The following invariants must hold at all times:

| # | Invariant | Enforcement |
|---|-----------|-------------|
| ZK-1 | Server never receives plaintext passwords | Argon2id runs client-side; only `auth_hash` (HKDF-derived) is sent |
| ZK-2 | Server never receives `client_kek_half` | Derived client-side; never serialized or transmitted |
| ZK-3 | Server never receives the full KEK | Two-factor split: `HKDF(client_kek_half \|\| server_shard)`; server only has `server_shard` |
| ZK-4 | Server never receives plaintext private keys | Private keys encrypted with KEK before being sent to `register-finalize` |
| ZK-5 | Server never receives plaintext file content | AES-256-GCM encryption with per-file random keys before upload |
| ZK-6 | Server never receives plaintext filenames | AES-GCM-SIV encryption with filename key derived from master secret |
| ZK-7 | Server never receives plaintext recovery key | Recovery key displayed to user only; `recovery_kek_encrypted` stored server-side (encrypted with `MASTER_KEY`), not the recovery key itself |

**Verification checklist for new API calls:**
Before implementing any function that sends data to the backend:
1. Is the payload free of plaintext key material? If unsure — stop and flag.
2. Is the payload free of the master password or argon_output? It must be.
3. Does the payload contain only: encrypted blobs, HKDF-derived auth tokens, HMAC challenge responses, or public keys? If yes — proceed.

---

## 9. No-Panic Guarantee

`sdk-core` must never panic in any public function. Panics in WASM abort the entire web application.

**Enforcement:**
- `#![deny(clippy::unwrap_used, clippy::expect_used)]` at the crate level
- All public functions return `Result<T, SdkError>`
- Array/slice access uses `.get()` with explicit bounds checking, never direct indexing
- Parsing uses `TryFrom`/`TryInto`/`FromStr`, never assuming success
- All decrypt/parse functions are fuzz-tested to confirm they return `Err` on malformed input (Phase 7)

---

## 10. WASM Binary Size

**Target:** Under 2 MB gzipped.

**Current Phase 0 size:** 13 KB uncompressed (stubs only).

As crypto code is added in Phase 1+, monitor with:

```bash
wasm-pack build --target web --release --out-name secure_cloud_wasm
gzip -c sdk-wasm/pkg/secure_cloud_wasm_bg.wasm | wc -c
```

If > 2 MB gzipped after Phase 1 crypto:
1. Profile with `twiggy top sdk-wasm/pkg/secure_cloud_wasm_bg.wasm`
2. Disable unused `web-sys` features in sdk-wasm
3. Consider `wasm-opt -Oz` (already applied by wasm-pack with `wasm-opt` feature)
4. Feature-gate heavy crypto (e.g., argon2) behind a WASM-specific feature

---

## 11. Dependency Security

```bash
cd sdk && cargo audit
```

Pin exact versions for all crypto dependencies (matching `wasm/Cargo.toml`):
- `ml-kem = "0.2.3"` — FIPS 203 ML-KEM-1024
- `kem = "=0.3.0-pre.0"` — KEM traits
- `aes-gcm = "0.10"` — AES-256-GCM
- `argon2 = "0.5"` — Argon2id KDF

No `unsafe` blocks allowed in `sdk-core` unless:
1. Absolutely required (document with a `# Safety` comment)
2. Reviewed and approved
3. Covered by fuzz tests

---

## 12. BYO Mode Security Architecture

BYO (Bring Your Own storage) mode adds a second key hierarchy independent of the managed-backend flow. The trust boundary shifts: the Secure Cloud server is no longer trusted for availability — it is only a stateless relay.

### Trust Boundary (BYO)

```
+----------------------------------------------------------+
|  Browser                                                 |
|                                                          |
|  +----------------------------------------------+       |
|  |  BYO Web Worker (XSS-isolated)               |       |
|  |  sdk-wasm BYO module                         |       |
|  |  - Vault crypto (Argon2id, AES-GCM, HKDF)   |       |
|  |  - V7 streaming encrypt/decrypt              |       |
|  |  - Enrollment ECDH + SAS                     |       |
|  |  - Per-file X25519 + ML-KEM-1024 KEM         |       |
|  +----------------------------------------------+       |
|              ^ postMessage (opaque handles)              |
|  +----------------------------------------------+       |
|  |  Main Thread (BYO Svelte UI)                 |       |
|  |  - OAuth popup / fetch for token exchange    |       |
|  |  - Provider HTTP I/O (no key material)       |       |
|  +----------------------------------------------+       |
+----------------------------------------------------------+
        | TLS only
        v
+------------------+       +---------------------------+
|  BYO Relay       |       |  User-owned Storage       |
|  (stateless;     |       |  Provider (GDrive etc.)   |
|  no key material)|       |  (opaque ciphertext only) |
+------------------+       +---------------------------+
```

### BYO Key Hierarchy

See `SPEC-BYO.md § Cryptographic Key Hierarchy` for the complete derivation graph. Key differences from managed mode:

| Property | BYO | Managed |
|----------|-----|---------|
| Argon2id memory | 128 MB | 64 MB |
| Shard storage | Vault header device slot (device-local) | Server `user_key_shards` table |
| Server role | None (stateless relay only) | Holds server_shard; required for KEK derivation |
| Recovery path | `HKDF(recovery_key[1..33], "SecureCloud BYO RecoveryVaultKEK v1")` | `HKDF(recovery_key[1..33], "SecureCloud RecoveryKEK v1")` |

The two recovery HKDF info strings are intentionally distinct — a managed recovery key cannot be used to decrypt a BYO vault and vice versa.

**Per-vault and manifest subkey derivation:**

All subkeys are derived inside WASM; `vault_key` never leaves WASM memory.

```
vault_key
│
├── HKDF(info="SecureCloud BYO manifest v1")
│       → manifest_aead_key          encrypts vault_manifest.sc body
│
├── HKDF(info="per-vault-aead-v1" || provider_id)
│       → vault_aead_key[pid]        encrypts vault_<pid>.sc body
│
├── HKDF(info="per-vault-hmac-v1" || provider_id)
│       → vault_hmac_key[pid]        integrity MAC for vault body
│
├── HKDF(info="per-vault-wal-v1" || provider_id)
│       → wal_key[pid]               WAL encryption (IndexedDB)
│
└── HKDF(info="per-vault-journal-v1" || provider_id)
        → journal_aead_key + journal_hmac_key[pid]
```

Domain separation invariants:
- Different `provider_id` values → different subkeys (HKDF info collision impossible given distinct byte strings).
- Manifest info string has no `provider_id` suffix → independent from all per-vault subkeys.
- `vault_key` is stable across passphrase change and recovery re-key; only the wrapping (Argon2id params + AES-GCM slots) changes. Bodies do NOT need re-encryption after re-keying.

### Manifest Replication Threat Model

`vault_manifest.sc` is replicated identically to every attached provider. The manifest body is AES-GCM encrypted with `manifest_aead_key` (derived from `vault_key`); the header is HMAC-SHA256 authenticated with `vault_key`.

**Attacker controls one provider:**
- Can pin an old manifest (lower `manifest_version`) on that provider.
- Client's merge algorithm takes the **highest** `manifest_version` from all reachable providers → single-provider rollback cannot hide newly-added providers or forge manifest entries.
- Cannot forge a valid manifest body without `manifest_aead_key`, which requires `vault_key`.

**Clock-skew / `updated_at` pinning (C3):**
- A hostile provider could set `updated_at = u64::MAX` to permanently win last-writer-wins for its entries.
- `merge_manifests` rejects any entry with `updated_at > now + 3600 s` with a hard error before merge proceeds.
  The caller passes the current wall-clock time (`now_unix_secs`) to the WASM function.
- Entries outside the envelope are not silently accepted; merge fails, and the UI surfaces an error.

**Rollback resistance (C3 / C8):**
- Each device stores `last_seen_manifest_version` in `DeviceRecord` (IndexedDB).
- `byoManifestMerge` accepts `min_acceptable_version = last_seen_manifest_version`; if the merged
  result would be less than this floor, the merge is rejected with an error.
- Single-manifest unlock path also checks the floor and sets `rollbackWarning` on regression.
- `last_seen_manifest_version` is updated to `max(stored, merged)` after every successful unlock.

**Invariant: `tombstone && is_primary` contradiction (C7):**
- `validate_manifest` rejects any entry with both `tombstone = true` and `is_primary = true`.
  A hostile manifest with this combination is rejected before it can affect the primary selection.

**Consequence:** An attacker controlling N-1 of N providers but not the KEK cannot forge manifest
entries, cannot pin stale entries indefinitely via clock manipulation, and cannot roll the manifest
back to a version the client has already seen.

### Offline-Cache Encryption

After a successful vault body download, the encrypted bytes are stored in IndexedDB keyed by `(provider_id, version)`. The stored bytes are **always ciphertext** — the per-vault AES-GCM-encrypted body. Plaintext SQLite bytes never persist to browser storage.

Properties:
- An attacker who steals the browser profile gets only ciphertext bytes; decryption requires `vault_key`.
- Cache entries are keyed by version (ETag); stale entries do not silently serve outdated state.
- On unlock, if a provider fetch fails (timeout 5 s), the IDB-cached body is used as a read-only fallback. The UI marks the provider offline/read-only.

### Credential Handling (BYO)

Provider credentials (OAuth tokens, WebDAV passwords, SFTP keys) are stored in the `config_json` field of the encrypted manifest body. They are never:
- Transmitted to the relay server
- Stored in browser localStorage or sessionStorage
- Included in any log output or error messages

The manifest body is AES-GCM encrypted before upload to any provider; credentials are inside this ciphertext. The ZK property is identical to the former `provider_config` table that credentials previously occupied — only the storage location changed (manifest vs SQLite).

### BYO Zero-Knowledge Invariants

| # | Invariant |
|---|-----------|
| BYO-ZK-1 | Relay server receives only encrypted shard envelopes and ECDH public keys; cannot reconstruct shard |
| BYO-ZK-2 | Provider stores only opaque V7 ciphertext + vault header/body blobs; cannot derive `vault_key` |
| BYO-ZK-3 | Provider credentials stored encrypted in manifest body (`config_json`); theft requires `vault_key` |
| BYO-ZK-4 | Shard alone is insufficient; `client_kek_half` = Argon2id(password) is also required |
| BYO-ZK-5 | SAS verification prevents relay-side key substitution during enrollment |
| BYO-ZK-6 | Per-file content keys use the same X25519+ML-KEM hybrid KEM as managed mode |
| BYO-ZK-7 | SFTP relay receives only SSH protocol traffic over TLS; relay cannot decrypt SFTP payload |
| BYO-ZK-8 | Share content keys are fresh AES-256 random per file, never derived from KEK or `vault_key`; a leaked share URL compromises exactly one file |
| BYO-ZK-9 | B1/B2 share relay stores no content keys; B1 stores opaque provider URL; B2 stores V7 ciphertext only |
| BYO-ZK-10 | Per-provider vault body subkeys are HKDF-distinct; compromising one provider's body does not weaken others |
| BYO-ZK-11 | Offline IDB cache stores only AES-GCM ciphertext; plaintext SQLite bytes never persist to browser storage |

### ProviderHttpClient vs HttpClient

`sdk-core` now has two HTTP client traits:

- **`HttpClient`** (`api/mod.rs`): relative-path, managed-backend only. Used for auth, file upload/download, key exchange with the Secure Cloud server.
- **`ProviderHttpClient`** (`api/provider_http.rs`): absolute URL, arbitrary headers, arbitrary methods (including `PROPFIND`, `MKCOL`). Used by BYO provider Rust implementations in sdk-core (GDrive, Dropbox, OneDrive, WebDAV, Box, pCloud, S3). All HTTP provider logic lives in Rust (P8); the `WasmStorageProviderShim` TS class routes through the generic `byo_provider_call` WASM dispatcher. **Must never be used for managed-backend calls.**

These traits are intentionally separate to prevent confusion between the two network planes. `ProviderHttpClient` is only compiled when the `providers` Cargo feature is enabled.

### Enrollment Protocol Security

The enrollment shard envelope uses **Encrypt-then-MAC**:
```
envelope = nonce(12) || AES-256-GCM(enc_key, shard)(48) || HMAC-SHA256(mac_key, nonce||ct)(32)
```

The HMAC is verified before any decryption attempt. `enc_key` and `mac_key` are derived from an ephemeral X25519 ECDH shared secret via separate HKDF info strings (`"SCEnroll Enc v1"` and `"SCEnroll MAC v1"`), providing domain separation.

The 6-digit SAS code is derived via `HKDF(shared, "SCEnroll SAS v1")` and displayed on both devices. Visual confirmation by the user is the only MITM protection during enrollment; the protocol has no other channel binding mechanism.

### SFTP Protocol in sdk-core (P7)

The full SFTP relay client state machine (`SftpRelayClient<T: RelayTransport>`) lives in `sdk-core/src/byo/sftp/`. This covers: JSON+binary two-frame protocol, `host_key` TOFU handshake, v1/v2 capability negotiation, upload state machine (`write_open`/`write_chunk`/`write_close`/`write_abort`), and all SFTP verbs. Platform-specific WebSocket lifecycle is a thin `RelayTransport` shim (~100 LoC TS / future OkHttp Kotlin). TOFU fingerprint is stored encrypted in vault SQLite; never in plaintext, never on the server.

### Streaming Decrypt in BYO

The same `V7StreamDecryptor` / `V7StreamEncryptor` are used in both managed and BYO modes. The BYO-specific addition is `FooterTrimmer`:

- The provider stream does not frame the 32-byte HMAC footer separately.
- `FooterTrimmer` buffers exactly `V7_FOOTER_LEN` (32) bytes at the tail of the stream, releasing all earlier bytes as safe to push to the decryptor.
- Implemented once in Rust (`sdk-core/src/crypto/wire_format.rs`) and used on all platforms (WASM via `FooterTrimmerWasm`, Android via UniFFI, future pure-Rust orchestrators).
- The streaming decrypt HMAC invariant from §6 applies unchanged: callers must discard output if `closeV7Stream` fails.
- Resumable provider uploads (Dropbox upload sessions, WebDAV NC-chunking v2, SFTP relay v2 `write_chunk`) carry only V7 ciphertext across the wire. The V7 wire format and `FooterTrimmer` invariants are unaffected by the upload transport. The SFTP relay v2 server-side buffer (≤ 200 MiB) holds only ciphertext and is never persisted beyond the duration of a single upload session.
