# SDK Security Architecture

This document describes the security properties of the Rust SDK and how they
are enforced. It is the authoritative reference for implementers.

For the BYO protocol (vault format, enrollment, OAuth flow, provider APIs,
relay server) see `SPEC.md`.

Certain HKDF info strings and the vault root folder path contain the
literal bytes `"SecureCloud"` — these are frozen protocol identifiers from
earlier versions of the codebase. They are part of the V7 wire format and
the on-disk vault layout; renaming them would make every existing vault
undecryptable. Treat them as magic constants, not as product references.

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
                    ↕ HTTPS
┌────────────────────────────────────────────────────────┐
│  Wattcloud relay (byo-relay — stateless, no DB)        │
│  - Forwards enrollment frames between two devices      │
│  - Forwards SFTP / WebDAV relay traffic (ciphertext)   │
│  - Serves share pointer + optional ciphertext blob     │
│  - R5 logging: no client IPs persisted (§13.2)         │
│  - Keeps only: nonce state, rate-limit counters        │
└────────────────────────────────────────────────────────┘
                    ↕ HTTPS + OAuth access token
┌────────────────────────────────────────────────────────┐
│  User's own storage provider (GDrive/Dropbox/…)         │
│  - Stores opaque V7 ciphertext files                   │
│  - Sees only encrypted bytes + opaque filenames        │
│  - Owned by the user; relay never touches this         │
└────────────────────────────────────────────────────────┘
```

**What the relay never receives:**
- Plaintext passwords
- Master secrets / recovery keys
- `client_kek_half` or full KEK
- Decrypted file content or filenames
- Plaintext private keys
- OAuth tokens for the user's storage provider (those stay in the Worker)

---

## 2. Key Hierarchy

```
Password (user input, never stored)
    │
    ▼ Argon2id(m=131072, t=3, p=4, output=64 bytes, salt=auth_salt)  # BYO = 128 MB
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

The HKDF info string literal is `"SecureCloud v6"` — a frozen protocol
identifier from an earlier name of the codebase, retained verbatim so V7
ciphertext produced by older clients remains decryptable. It labels the
*hybrid KEM construction*, not a file format. V7 is the only wire format
the code implements or accepts. `wrapping_key` is used to AES-GCM-wrap the
per-file random `content_key`; `kem_hmac_key` is discarded (v7's chunk
HMAC key is separately derived via `HKDF-SHA256(content_key,
info="chunk-hmac-v1")`).

**Security properties:**
- If X25519 is broken by a quantum computer → ML-KEM-1024 still protects
- If ML-KEM-1024 is broken by a new classical attack → X25519 still protects
- Both must be broken simultaneously to compromise a file key

---

## 6. Streaming Decrypt Invariant

The v7 download path (`V7StreamDecryptor` in `sdk-core`, `V7StreamDecryptorWasm`
in `sdk-wasm`, wrapped by `frontend/src/lib/sdk/streaming/DownloadStream.ts`
and sunk to disk by `frontend/src/lib/byo/streamToDisk.ts`) releases
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
  output. The frontend's `streamToDisk.ts` handles this by aborting the
  `FileSystemWritableFileStream` (single-file) or the `downloadZip`
  iterator in `sdk/streaming/zip.ts` (bulk) in the error path, leaving
  no partial file on disk.
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
`ZeroizeOnDrop` and must never be persisted to host storage (IndexedDB
or any other disk-backed store).

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
2. **Hand-rolled download service worker**
   (`frontend/public/dl/sw-download.js`, scoped to `/dl/`). Covers
   Firefox, Safari (desktop + iOS 16.4+ via OPFS), and Chrome-on-iOS.
   The main thread posts a `{type: 'register', id, filename, mime}`
   handshake to the SW over a `MessageChannel`, receives a `ready` ack
   on the returned port, and then triggers the download by clicking a
   hidden `<a download href="/dl/<id>">`. (Anchor clicks are used
   rather than the StreamSaver-style hidden-iframe navigation because
   Firefox does not reliably route iframe-initiated navigation fetches
   through a same-origin SW's `fetch` handler.) The SW matches the
   incoming fetch against `^/dl/([a-f0-9]{16,64})$`, looks the entry up
   in an in-memory `Map`, and responds with
   `new Response(readable, {headers: Content-Disposition: attachment,
   Content-Security-Policy: "default-src 'none'",
   Cache-Control: no-store, X-Content-Type-Options: nosniff})`.
   Plaintext chunks flow from the main thread into the SW via
   `postMessage` with transferable `ArrayBuffer`s (zero-copy), the SW
   enqueues them onto the `ReadableStream`'s controller, and the
   browser's native download manager drains the `Response` straight to
   disk. No key material ever traverses the SW, and the SW holds no
   state beyond the in-flight session's `ReadableStream` controller.
3. **Guarded blob fallback.** If neither sink is available (insecure
   HTTP origin, SW registration failure on a browser without the File
   System Access API), the pipeline refuses downloads larger than
   `SMALL_BLOB_LIMIT = 1 GiB` by throwing a descriptive error to the
   user instead of risking a tab OOM. Below the cap, plaintext is
   collected in memory chunk-by-chunk, wrapped in a `Blob`, and handed
   to an anchor click — identical to the legacy path.

**Why the SW does not weaken the zero-knowledge model:**

- **No key material.** The service worker is a pure byte pipe. It
  never sees `content_key`, `hmac_key`, `file_iv`, `mlkem_private_key`,
  `x25519_private_key`, `KEK`, or any derivation thereof. All
  decryption happens in the crypto Web Worker; only plaintext
  `Uint8Array` chunks cross the boundary into the SW.
- **Same origin.** SWs are scoped to the origin that registered them;
  no cross-origin JavaScript can open one of our `/dl/<id>` URLs, and
  the registration itself requires a secure context (HTTPS or
  localhost). Cross-origin iframes and popups cannot invoke the pipe.
- **Short-lived, one-shot sessions.** Each session id is a random
  128-bit value minted with `crypto.getRandomValues()` and rendered as
  lowercase hex. A `ReadableStream` can be read by only one consumer,
  so even if a second fetch for the same id raced through before the
  SW's post-`done` grace-period cleanup fired, it would find an empty
  stream. The register step applies a 30-second orphan timeout (session
  is auto-errored and removed if no fetch ever arrives); the done/error
  paths release the entry after a 60-second grace window so the
  anchor-click's fetch can't race ahead of the map insert on slow
  hardware. There is no persistent store.
- **Response headers are hard-coded.** `Content-Disposition:
  attachment` forces download instead of inline rendering;
  `Content-Security-Policy: default-src 'none'` blocks any script,
  style, image, or subresource execution if `Content-Disposition`
  ever failed to force the download path and the body were rendered
  as a document (defense-in-depth; CSP has no effect on the native
  download manager draining the Response body to disk);
  `X-Content-Type-Options: nosniff` disables MIME-sniffing escalation;
  `Cache-Control: no-store` prevents the native download-manager
  response from being cached. The SW never echoes user-controlled
  bytes into response headers — only the session id appears in the
  intercepted URL, and it is matched against
  `^/dl/([a-f0-9]{16,64})$` (hex charset only) before any routing.
  The filename in `Content-Disposition` is RFC 5987 encoded with a
  stripped ASCII fallback (`\r\n\0/\\` removed).
- **Caching disabled.** The SW response sets `Cache-Control:
  no-store`, and the SW script itself is served with a short cache
  lifetime by `byo-relay`'s static-asset handler so updates to
  `sw-download.js` propagate on the next visit.
- **Does not share scope with the crypto worker.** The crypto Web
  Worker and the download Service Worker are distinct worker kinds
  with separate global contexts. The crypto worker is a dedicated
  `Worker` whose module is loaded via bundled JS; the SW is a
  top-level worker whose lifecycle is managed by the browser. They do
  not share memory or message channels.

**Residual risk:** a compromised SW (e.g. via a successful supply
chain attack on `sw-download.js`) would see plaintext bytes for
downloads that use the SW sink path. This is strictly no worse than a
compromise of `streamToDisk.ts` itself — both are main-thread-adjacent
JS with access to plaintext after decryption — and is the reason the
SW file is tiny (~200 lines), pinned to a static path, and distributed
from the same origin as the rest of the frontend bundle. It does
**not** expose key material, which stays behind the dedicated crypto
worker boundary regardless of sink choice.

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

### `TokenStorage`

The `TokenStorage` trait lived in `sdk-core::session` upstream. That module was
deleted in the Wattcloud carveout (BYO has no login session against a managed
backend — OAuth access/refresh tokens for each user's storage provider live in
the encrypted manifest body instead, see §12). No `TokenStorage` implementation
exists in this repo.

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
wasm-pack build --target web --release --out-name wattcloud_sdk_wasm
gzip -c sdk-wasm/pkg/wattcloud_sdk_wasm_bg.wasm | wc -c
```

If > 2 MB gzipped after Phase 1 crypto:
1. Profile with `twiggy top sdk-wasm/pkg/wattcloud_sdk_wasm_bg.wasm`
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

### Accepted advisories (deferred upgrades)

Dependabot tracks security alerts at <https://github.com/wattzupbyte/wattcloud/security/dependabot>.
Some of them are intentionally deferred because the vulnerability surface
does not apply to how Wattcloud uses the dependency. Each entry here
explains why, and is revisited at every release.

| Package | CVE / summary | Why deferred |
|---------|---------------|--------------|
| `rand` 0.8 (sdk-core, sdk-wasm) | unsound with custom logger using `rand::rng()` | Wattcloud does not set a custom rand logger. The unsound path is unreachable. Fix is in `rand` 0.9, a major bump that would cascade through `argon2` 0.5 and `ml-kem` 0.2.3, both of which still pin `rand_core` 0.6. Would need a coordinated major-version bump across the crypto stack. `byo-relay` is independent and already on `rand` 0.10. No outstanding Dependabot alert. |

Production-relevant advisories (e.g. `jsonwebtoken` 9.3 → 10.3 for
authorization-bypass type confusion) ARE applied immediately.

---

## 12. BYO Mode Security Architecture

BYO (Bring Your Own storage) is the *only* mode in this repo — the managed
flow was pruned in the Wattcloud carveout. The sentence below is kept because
its statement about the trust boundary is still correct on its own merits:
the Wattcloud relay is never trusted for availability or integrity; every
byte that crosses it is end-to-end encrypted or HMAC-authenticated.

BYO introduces a second key hierarchy distinct from the managed-mode one that
existed upstream. The trust boundary: the Wattcloud server is never trusted
for availability — it is only a stateless relay.

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

See `SPEC.md § Cryptographic Key Hierarchy` for the complete derivation graph. Key differences from managed mode:

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
├── HKDF(info="per-vault-journal-v1" || provider_id)
│       → journal_aead_key + journal_hmac_key[pid]
│
└── HKDF(info="SecureCloud BYO key_versions wrap v1")
        → K_wrap                      AES-GCM-wraps `key_versions` private keys
```

Domain separation invariants:
- Different `provider_id` values → different subkeys (HKDF info collision impossible given distinct byte strings).
- Manifest info string has no `provider_id` suffix → independent from all per-vault subkeys.
- `vault_key` is stable across passphrase change and recovery re-key; only the wrapping (Argon2id params + AES-GCM slots) changes. Bodies do NOT need re-encryption after re-keying.

### Key Versions (BYO)

`key_versions` is a per-vault SQLite table (replicated in every per-provider body) that stores the vault's active and archived **hybrid ML-KEM-1024 + X25519 keypairs**. These keypairs perform the recipient side of the hybrid KEM that wraps each file's per-file `content_key` (see §5 "Post-Quantum Strategy").

At-rest layout (one row per active or archived version):
- `mlkem_public_key`, `x25519_public_key` — cleartext. The enclosing vault body is already AEAD-authenticated by `manifest_aead_key`, so tampering requires `vault_key`.
- `mlkem_private_key_encrypted`, `x25519_private_key_encrypted` — `nonce(12) || AES-256-GCM(K_wrap, nonce, private_key_bytes)`.

The wrapping key is:

```
K_wrap = HKDF-SHA256(vault_key, info="SecureCloud BYO key_versions wrap v1", L=32)
```

`"SecureCloud BYO key_versions wrap v1"` is a **frozen protocol constant**. Renaming it invalidates every vault's `key_versions` rows; treat a change as a protocol version bump.

Why `vault_key` (not `KEK`):
- In managed mode the private keys were wrapped under `KEK = HKDF(client_kek_half || server_shard)`, which was effectively a per-user value because `server_shard` was shared across all of a user's devices.
- In BYO, `shard` is **per-device** (random 32 B in each device slot). Every device computes a different `KEK`, so a KEK-wrapped private key cannot be shared across devices. Wrapping under a `vault_key`-derived subkey is what makes the row portable: every enrolled device reaches `vault_key` via its own slot → shard → KEK → unwrap vault_key, and then re-derives the same `K_wrap`.

Key-version lifecycle:
- **Setup** (`ByoSetup.svelte`): a fresh hybrid keypair is generated inside WASM (`byo_vault_generate_keypair_wrapped`), wrapped with `K_wrap`, and inserted as `version = 1, status = 'active'` alongside the initial vault body.
- **Recovery**: `vault_key` is *stable* across recovery re-key, so `K_wrap` does not change and existing rows remain decryptable without any re-encryption. The current recovery path only patches the manifest **header**; it does not rotate the hybrid keypair. A compromise-containment rotation (archive the old version, insert a new version with fresh keys, re-encrypt every per-provider body) is a documented future enhancement — deferred because it must touch each provider's body file, not just the manifest, and multi-provider coordination during recovery is non-trivial.
- **Archival**: marking a row `status = 'archived'` keeps the private key available for decrypting old files. New uploads use the newest `active` row.

Zero-knowledge invariant: the WASM export `byo_vault_generate_keypair_wrapped` returns public halves in base64 and private halves as already-wrapped bytes. Raw private key bytes never cross the WASM→JS boundary during generation or load — they exist in plaintext only inside the worker's isolated key registry during `byo_vault_load_keys`, and are zeroized on session close (see §3).

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

Provider credentials (OAuth tokens, WebDAV passwords, SFTP passwords and private keys) are stored in the `config_json` field of the encrypted manifest body. Every provider type is treated uniformly — SFTP credentials persist alongside OAuth refresh tokens rather than being re-prompted on every session, and benefit from the same IDB encryption layer described below. They are never:
- Transmitted to the relay server
- Stored in browser localStorage or sessionStorage
- Included in any log output or error messages

The manifest body is AES-GCM encrypted before upload to any provider; credentials are inside this ciphertext. The ZK property is identical to the former `provider_config` table that credentials previously occupied — only the storage location changed (manifest vs SQLite).

**Per-device persistence (IDB `provider_configs` store).** To avoid re-typing credentials / re-running OAuth on every page reload, a second copy of each provider config is stored on-device in an IndexedDB object store (`sc-byo` DB, `provider_configs` store, keyed by `provider_id`). The `config` payload is wrapped with AES-256-GCM under the per-vault **non-extractable** device `CryptoKey` (`extractable: false`) that already protects the enrollment shard; non-secret meta (vault_label, provider type, display_name, is_primary, saved_at) is stored in clear so the "Your vaults" landing screen can render before the user has unlocked a vault. The store never leaves the device — the browser same-origin policy plus the non-extractable key together ensure that a filesystem-level theft of the browser profile cannot unwrap the configs offline.

**Threat model caveat.** Non-extractability defends against raw-key exfiltration; it does not defend against same-origin RCE. A successful DOM-XSS on the Wattcloud origin can invoke `crypto.subtle.decrypt` against the handle and read tokens back as plaintext in-memory. Defenses: a tight CSP (see below), SRI on assets, all crypto offloaded to a Web Worker, and Trusted Types enforcement (rolled out in Report-Only first). This is the same exposure that exists for any live passphrase entry or unlocked vault session — the IDB store does not introduce a new class.

**Forgetting a provider on one device.** `deleteProviderConfig(provider_id)` removes just the IDB row; the provider stays enrolled in the vault manifest and continues working on other devices. `deleteVaultProviderConfigs(vault_id)` removes every row for a vault (used by "Forget on this device" in the vault-list sheet) and additionally drops the `DeviceRecord`, device `CryptoKey`, encrypted WAL entries, and body-cache rows for that vault.

**Storage persistence.** On app startup, `navigator.storage.persist()` is called best-effort so the browser will not silently evict our IDB under storage pressure; eviction would lose the device CryptoKey and force the user to re-enroll the device via another device or recovery key.

### Passkey-gated device key (BYO)

**Opt-in.** Users can require a WebAuthn authenticator (Touch ID, Windows Hello, Android fingerprint, YubiKey, etc.) to materialize the per-vault device `CryptoKey`. Enabled per-vault from Settings → Security → Credential Protection. Default is off so first-run setup stays friction-free.

**Three modes.** Stored on a new per-vault `device_webauthn` IDB row (`sc-byo` DB v3); row absent = mode `none`.

| Mode | What's persisted | Biometric is… | Defends against |
|------|------------------|---------------|-----------------|
| `none` (default) | Plain `device_crypto_keys` row, `extractable:false` | n/a | Raw-key exfil (non-extractability defeats disk-only attackers with no OS-keychain access) |
| `presence` | Same plain CryptoKey + `credential_id` list | Behaviourally required (`navigator.credentials.get()` before any `crypto.subtle.decrypt`) | Someone with an unlocked browser on the origin, but not a determined attacker with same-origin code execution — the gate can be patched out of the JS at runtime |
| `prf` | `credential_id`, `prf_salt`, `wrapped_device_key` per credential; NO plain CryptoKey row for the vault | Cryptographically required — the device key literally cannot be derived without a successful `prf` extension output from the authenticator | Presence scenarios *plus* same-origin DOM XSS: without a fresh PRF output, the wrapped device key stays opaque ciphertext |

**PRF derivation.**

```
prf_output         (32 B from WebAuthn's extensions.prf.results.first)
    │
    ▼   HKDF-SHA256, info="Wattcloud device key v1", L=32
wrapping_key
    │
    └── AES-256-GCM(wrapping_key, device_key)
         = nonce(12) || ct||tag
         → stored as `wrapped_device_key` in the device_webauthn row
```

The device key itself is a fresh random 32 bytes minted inside WASM by `webauthn_generate_device_key` (Phase 1 WASM export); raw bytes never cross the WASM→JS boundary during enrolment beyond the short-lived wrap call, and are zeroized immediately after `crypto.subtle.importKey('raw', …, extractable:false, …)`. `"Wattcloud device key v1"` is a frozen protocol constant (CLAUDE.md HKDF-info list); a rename would invalidate every `wrapped_device_key` written before the change.

**Multi-credential.** Any number of enrolled credentials can unlock the same vault. Each credential produces its own PRF output → its own wrapping key → its own copy of the wrapped device key. "Add another passkey" in Settings wraps the same device-key bytes under the new credential's wrapping key (bytes parked in the WebAuthnGate session cache between unlock and lock). Removing credentials is per-row; the last one cannot be removed while the gate is enabled — the user must disable the gate first, which rotates everything back onto a fresh plain `extractable:false` CryptoKey.

**Migration on enable/disable.** Changing mode triggers `DeviceKeyMigration.migrateDeviceKey`: decrypt the device shard in the manifest header with the old key, re-encrypt with the new key, patch the device slot, recompute the HMAC via `byo_vault_compute_header_hmac`, upload the manifest. Then every `provider_configs` IDB row for this vault is re-wrapped under the new key, and stale WAL entries are cleared. The manifest upload runs first so a failed upload leaves IDB intact and the caller can roll back by not switching the `device_webauthn` record.

**Lockout recovery.** The gate guards only per-device at-rest wrappings — never vault data itself. If the user loses every enrolled passkey:
- Open the vault on another device that still has a passkey, and re-enrol this device through the QR / SAS link flow.
- Or use the recovery key (`ByoRecovery.svelte`): recovery re-derives the KEK via the recovery slot and issues a new device shard; the user then re-enables the gate on the recovered device if desired.

The vault passphrase, recovery key, `vault_key`, `KEK`, and all `key_versions` private keys are never gated by the passkey in the default configuration — they're either session-only (kept in the WASM vault session and zeroized on lock) or never persisted at all.

**Opt-in: "Passkey replaces passphrase".** A separate toggle in Settings → Security → Credential Protection (default **off**) relaxes this last rule for users who explicitly want one-tap unlock. When enabled:

- On enable, the currently-open session's `vault_key` is wrapped under `wrapping_key_vk = HKDF-SHA256(PRF_output, info="Wattcloud vault_key wrap v1", L=32)` inside WASM. Only the resulting ciphertext crosses the WASM→JS boundary.
- The wrap is stored per-credential as `wrapped_vault_key` on `WebAuthnCredentialEntry`, alongside the existing `wrapped_device_key`. A fresh `passkey_unlocks_vault = true` flag on the `DeviceWebAuthnRecord` gates the unlock path.
- On unlock, `WebAuthnGate.unlockVaultKeyViaPasskey` prompts for a passkey, harvests a PRF output, derives `wrapping_key_vk`, calls `byo_vault_load_session_from_wrapped_vault_key` (the unwrap + session-create happens inside WASM — raw `vault_key` bytes never land in JS), and returns the WASM session id. `VaultLifecycle.unlockVault` accepts that session id via `preopenedSessionId` and skips Argon2id and the passphrase-wrapped-vault_key unwrap entirely.
- The passphrase path still exists as a fallback — losing the passkey on this device, or opening the vault on a device where passkey-unlock is off, still works through the passphrase.
- **HKDF info is distinct** from the device-key wrap (`"Wattcloud device key v1"` vs `"Wattcloud vault_key wrap v1"`) so the two wrapping keys are guaranteed independent, even though both derive from the same PRF output. Tested in `sdk-core/src/crypto/webauthn.rs::vault_key_wrap_is_domain_separated_from_device_key_wrap`.
- **Threat model shift.** The default design requires *two* factors to open the vault: possession of the device (shard + device `CryptoKey`) and knowledge (passphrase → Argon2id → KEK). Enabling this toggle collapses the knowledge factor into possession: an attacker who owns the device and can trigger one biometric touch (malware that social-engineers a touch, attacker with the unlocked device in hand, or an authenticator that a user can be coerced into approving) unlocks the vault without needing the passphrase. For the full threat model, BYO-ZK-4 is relaxed for this specific vault — see BYO-ZK-15 below.
- **Disable.** Turning the toggle off (Settings → Security → Credential Protection) wipes `wrapped_vault_key` from every enrolled credential and clears the flag. No biometric touch is required to disable — disabling is always safe. The next unlock will prompt for the passphrase again.
- **Multi-credential.** Enable wraps `vault_key` only for the single credential the user touched during the confirm. Other enrolled credentials keep `wrapped_vault_key` undefined and still need the passphrase when used; the Settings UI surfaces a toast indicating how many credentials still need to be extended, and the user re-confirms once per authenticator to extend the wrap.
- **Lockout isolation unchanged.** Because the recovery key unlocks via the header's recovery slot (`rec_wrapped_vault_key`), and that path is independent of the passkey wrap, a lost / evicted passkey never locks the user out — the recovery key always works.

**Threat model caveat.** Presence mode is a behavioural speed-bump, not a cryptographic gate. A determined attacker with same-origin code execution (DOM XSS, malicious extension) can patch out the `navigator.credentials.get()` call and reach the plain stored CryptoKey directly. This mode exists because PRF support is still uneven across platform authenticators (notably Android Samsung) — it covers the "someone grabs my unlocked laptop" and "mistyped passphrase" cases without requiring hardware that not every supported device has. The Settings UI labels it plainly and the educational modal explains the distinction before the user opts in.

**Rate-limiting.** WebAuthn authenticators themselves rate-limit failed attempts; Wattcloud adds no extra counter on top. A locked-out authenticator returns `NotAllowedError`, which `WebAuthnGate.unlockDeviceKey` surfaces as a clean "Passkey verification was cancelled" message — the user can retry or switch to another enrolled credential.

**Cross-device behaviour.** The gate is strictly per-device-per-vault. Every device has its own `device_crypto_keys` row, its own shard in the manifest device slots, and its own `device_webauthn` row. Enabling the gate on a laptop has no effect on the user's phone and vice versa — the UI spells this out in both the auto-offer modal and the Settings sub-page. Consequences:

- **Passkey syncing (iCloud Keychain, Google Password Manager, Bitwarden, KeePassXC).** The WebAuthn PRF output for a synced passkey is consistent across the user's devices on Apple + Google + Bitwarden by design, but Wattcloud does *not* exploit this — each device enrols its own fresh credential so the per-device security boundary stays clean (and so a user who signs out of their password manager on one device doesn't accidentally break unlock there). A future optimisation could offer "Use a synced passkey across my devices" as an explicit button.
- **Device loss isolation.** Losing every passkey on device A does not affect device B. The user unlocks on B with B's own passkey (if enrolled) or passphrase and either re-enrols A via QR-link or uses the recovery key.
- **Link-another-device (QR/SAS pairing).** The new device starts at `mode: 'none'` — the gate state does *not* propagate across pairing. Users who want protection on the linked device must enable separately.
- **Cross-browser on the same OS.** Each browser has its own `sc-byo` IndexedDB and its own device enrolment. macOS Keychain passkeys are visible across Chrome and Safari, but Wattcloud creates a new credential per enrolment, so the two browsers won't share a `credential_id` either.
- **Private/incognito mode.** IndexedDB is ephemeral in private browsing. Enabling the gate in a private window persists only for the session; `navigator.storage.persist()` cannot save the enrolment, so it vanishes with the tab. The `ByoCredentialProtection` Enable flow calls `navigator.storage.persist()` and surfaces a warning toast if it returns false so the user knows the enrolment may be silently evicted.
- **Browser downgrade / PRF regression.** A browser that stops reporting PRF support (e.g. a downgrade to a pre-PRF release) cannot unwrap a `prf`-mode device key on that device. The vault is not lost — the user uses the recovery key or another device's enrolment to re-establish access.
- **Storage pressure eviction.** Browsers may evict IDB rows under disk pressure. The `navigator.storage.persist()` call at app startup is best-effort; eviction of `device_webauthn` or `device_crypto_keys` on a particular device requires the same re-enrolment path as device loss.

### Security Headers

The byo-relay attaches these headers to every HTML/JSON response (see `byo-relay/src/security_headers.rs`):

| Header | Value | Rationale |
|--------|-------|-----------|
| `Content-Security-Policy` | `default-src 'none'` baseline; `script-src 'self' 'wasm-unsafe-eval'`; `style-src-elem 'self'` + `style-src-attr 'unsafe-inline'`; explicit `connect-src` allowlist for OAuth providers + `wss://{domain}`; `object-src 'none'`; `frame-ancestors 'none'`; `base-uri 'none'`; `form-action 'none'` | Fail-closed defaults. The style-src split pins external stylesheets to 'self' while still allowing Svelte `style:` directive output (inline `style=""` attributes). `base-uri 'none'` defeats `<base>`-element injection; `form-action 'none'` blocks exfil via classic form submit. |
| `Content-Security-Policy-Report-Only` | `require-trusted-types-for 'script'` | Logs DOM-XSS sink violations without breaking production. Promoted to enforcing after audit. |
| `X-Content-Type-Options` | `nosniff` | Blocks MIME sniffing. |
| `X-Frame-Options` | `DENY` | Legacy clickjacking defense paired with `frame-ancestors`. |
| `Referrer-Policy` | `no-referrer` | Prevents URL leakage to third-party origins. |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Denies the three most sensitive device-access APIs (the QR scanner requests its own permission at use-time — the denial here only cuts implicit/ambient grants). |
| `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` | Keeps OAuth popup compatibility while isolating our browsing context from cross-origin attackers. |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | Two-year HSTS. |

The `/share/*` routes use a narrower CSP that drops the OAuth origins and the WSS entry; recipients only fetch ciphertext from the Wattcloud relay's own `/relay/share/*` endpoints, so `connect-src 'self'` is sufficient. The legacy "recipient hits provider presigned URL" path is gone.

### BYO Zero-Knowledge Invariants

| # | Invariant |
|---|-----------|
| BYO-ZK-1 | Relay server receives only encrypted shard envelopes and ECDH public keys; cannot reconstruct shard |
| BYO-ZK-2 | Provider stores only opaque V7 ciphertext + vault header/body blobs; cannot derive `vault_key` |
| BYO-ZK-3 | Provider credentials stored encrypted in manifest body (`config_json`); theft requires `vault_key` |
| BYO-ZK-4 | Shard alone is insufficient; `client_kek_half` = Argon2id(password) is also required. **Relaxed by BYO-ZK-15 when the opt-in "Passkey replaces passphrase" toggle is ON for a particular vault on a particular device.** |
| BYO-ZK-5 | SAS verification prevents relay-side key substitution during enrollment |
| BYO-ZK-6 | Per-file content keys use the same X25519+ML-KEM hybrid KEM as managed mode |
| BYO-ZK-7 | SFTP relay receives only SSH protocol traffic over TLS; relay cannot decrypt SFTP payload |
| BYO-ZK-8 | Share content keys are fresh AES-256 random per file, never derived from KEK or `vault_key`; a leaked share URL compromises exactly one file |
| BYO-ZK-9 | Share relay stores V7 ciphertext only — never content keys, never filenames, never manifest JSON outside its own V7 envelope. Bundle manifests carry the per-file `content_key`s but are themselves AES-256-GCM sealed under the URL-fragment `bundle_key`. |
| BYO-ZK-10 | Per-provider vault body subkeys are HKDF-distinct; compromising one provider's body does not weaken others |
| BYO-ZK-11 | Offline IDB cache stores only AES-GCM ciphertext; plaintext SQLite bytes never persist to browser storage |
| BYO-ZK-12 | Device-local provider configs (one IDB row per `provider_id`) persist the credential blob only as AES-GCM ciphertext wrapped by the non-extractable per-vault device `CryptoKey`; meta fields (vault_label, type, display_name, is_primary) are non-secret. Removing a row does not affect the provider's enrollment in the remote vault manifest. |
| BYO-ZK-13 | `key_versions` private keys are AES-GCM-wrapped under `K_wrap = HKDF(vault_key, "SecureCloud BYO key_versions wrap v1")`, not under any per-device KEK. Every enrolled device derives the same `K_wrap` via its own slot → shard → KEK → vault_key path, so the single wrapped row is portable across devices; the provider sees only ciphertext. |
| BYO-ZK-14 | When the WebAuthn gate is in `prf` mode, the per-vault device key is derivable only through `HKDF(PRF_output, "Wattcloud device key v1")`. The plain `device_crypto_keys` row for that vault is deleted; the only at-rest artifact is `wrapped_device_key = AES-GCM(wrapping_key, device_key)`. A disk-only attacker, even with the IDB + the non-extractable CryptoKey handles, cannot unwrap without a live PRF touch. |
| BYO-ZK-15 | The opt-in "Passkey replaces passphrase" mode (OFF by default) stores `wrapped_vault_key = AES-GCM(HKDF(PRF_output, "Wattcloud vault_key wrap v1"), vault_key)` on each enrolled credential. When ON, `vault_key` is recoverable on this device with a passkey touch alone — collapsing the knowledge factor into possession. The plaintext `vault_key` never crosses the WASM→JS boundary on either the wrap or unwrap path; only the wrapped ciphertext does. HKDF info is distinct from the device-key wrap, so a compromise of one ciphertext does not weaken the other. Disabling the toggle wipes every `wrapped_vault_key` copy atomically. |

### ProviderHttpClient vs HttpClient

`sdk-core` now has two HTTP client traits:

- **`ProviderHttpClient`** (`api/provider_http.rs`): absolute URL, arbitrary headers, arbitrary methods (including `PROPFIND`, `MKCOL`). Used by BYO provider Rust implementations in sdk-core (GDrive, Dropbox, OneDrive, WebDAV, Box, pCloud, S3). All HTTP provider logic lives in Rust (P8); the `WasmStorageProviderShim` TS class routes through the generic `byo_provider_call` WASM dispatcher.

`ProviderHttpClient` is only compiled when the `providers` Cargo feature is enabled. The historical `HttpClient` trait (managed-mode API plumbing) was removed with the managed carveout.

### Enrollment Protocol Security

The enrollment shard envelope uses **Encrypt-then-MAC**:
```
envelope = nonce(12) || AES-256-GCM(enc_key, shard)(48) || HMAC-SHA256(mac_key, nonce||ct)(32)
```

The HMAC is verified before any decryption attempt. `enc_key` and `mac_key` are derived from an ephemeral X25519 ECDH shared secret via separate HKDF info strings (`"SCEnroll Enc v1"` and `"SCEnroll MAC v1"`), providing domain separation.

The 6-digit SAS code is derived via `HKDF(shared, "SCEnroll SAS v1")` and displayed on both devices. Visual confirmation by the user is the only MITM protection during enrollment; the protocol has no other channel binding mechanism.

**Optional primary-provider config transfer.** To let a new device join a
vault from a cold start (no provider added locally yet), the receiver may
ask the source for its primary `ProviderConfig`. The source encrypts the
JSON under the same session keys as the shard and sends it in a
variable-length `PayloadEnvelope`:

```
payload_envelope = nonce(12) || ct_len_be(4) || AES-256-GCM(enc_key, plaintext) || HMAC-SHA256(mac_key, nonce||ct_len_be||ct)(32)
```

The length prefix is committed into the HMAC so a relay cannot truncate
the frame without detection. Plaintext is capped at 64 KiB
(`MAX_PAYLOAD_PLAINTEXT_LEN`) and the sender rejects anything larger;
receivers double-check post-decrypt as a belt-and-braces guard. Transfer
only happens **after SAS confirmation** — an attacker who fails the SAS
check never sees a config envelope.

Threat-model impact vs. pre-feature baseline:

- **SAS bypass now leaks the primary provider credentials** (OAuth tokens
  for GDrive/Dropbox/OneDrive/Box/pCloud, static creds for WebDAV/S3) in
  addition to the shard. Compensating controls: SAS is still the only gate
  (visually confirmed, short window, ephemeral channel), and for **SFTP
  the source never holds the password/private key** (they live in the
  WASM heap and are stripped by `SftpProvider.getConfig()`), so the
  envelope exposes only host/port/username/basePath/TOFU fingerprint —
  the receiver must still re-enter the SSH secret.
- **Receiver opt-in.** The transfer is sent only after the receiver
  explicitly messages `ready_for_config`; a receiver that already has a
  local provider (legacy flow from the unlock screen) never asks for it
  and the source does not send one.
- **No relay trust change.** The relay still sees only opaque encrypted
  frames; it cannot read or tamper with payload contents without the
  session's `enc_key` / `mac_key`, which never leave either device's WASM
  heap.

### SFTP Protocol in sdk-core (P7)

The full SFTP relay client state machine (`SftpRelayClient<T: RelayTransport>`) lives in `sdk-core/src/byo/sftp/`. This covers: JSON+binary two-frame protocol, `host_key` TOFU handshake, upload state machine (`write_open`/`write_chunk`/`write_close`/`write_abort`), streaming download verbs (`read_open`/`read_chunk`/`read_close`, relay protocol v3), and all SFTP verbs. Platform-specific WebSocket lifecycle is a thin `RelayTransport` shim (~100 LoC TS / future OkHttp Kotlin). TOFU fingerprint is stored encrypted in vault SQLite; never in plaintext, never on the server. The relay protocol v1 single-shot `write` fallback was retired at v3 — every production relay now speaks v2+ upload.

### Streaming Decrypt in BYO

The same `V7StreamDecryptor` / `V7StreamEncryptor` are used in both managed and BYO modes. The BYO-specific addition is `FooterTrimmer`:

- The provider stream does not frame the 32-byte HMAC footer separately.
- `FooterTrimmer` buffers exactly `V7_FOOTER_LEN` (32) bytes at the tail of the stream, releasing all earlier bytes as safe to push to the decryptor.
- Implemented once in Rust (`sdk-core/src/crypto/wire_format.rs`); the browser consumes it via `FooterTrimmerWasm`.
- The streaming decrypt HMAC invariant from §6 applies unchanged: callers must discard output if `closeV7Stream` fails.
- Resumable provider uploads (Dropbox upload sessions, WebDAV NC-chunking v2, SFTP relay v2 `write_chunk`) carry only V7 ciphertext across the wire. The V7 wire format and `FooterTrimmer` invariants are unaffected by the upload transport. The SFTP relay v2 server-side buffer (≤ 200 MiB) holds only ciphertext and is never persisted beyond the duration of a single upload session.
- SFTP relay v3 streaming download holds only a live `ssh2::File` handle per session (bounded at 8 concurrent open reads per WebSocket connection) and forwards 256 KiB chunks as they are read from the SSH server. Chunks are transient — relay-side RAM never accumulates more than a single in-flight chunk per session. The `russh_sftp::File::Drop` impl auto-closes the remote handle on tokio if the client disconnects without calling `read_close`.
- Client-side share uploads (`ByoDataProvider.createShareLink` and the bundle equivalent) stream ciphertext straight from `provider.downloadStream()` into the relay's `/relay/share/b2` or `/relay/share/bundle/…/blob/…` routes via `fetch(…, { body: stream, duplex: 'half' })`. No intermediate file-sized JS buffer on supported browsers (Chrome/Firefox 105+, Safari 17.4+); older browsers fall back to the previous buffered POST with a console warning. The relay still sees only V7 ciphertext — the streaming change is purely about JS heap residue, not about the trust boundary.

### Share relay storage surface

The share relay is the one place the Wattcloud server stores anything
durable for end users. The storage surface is bounded and audited:

- **On-disk content is V7 ciphertext only.** Single-file shares park one
  blob; bundle shares park one blob per source file plus an encrypted
  manifest (`_manifest`). The relay has no knowledge of filenames,
  directory layout, MIME types, or total plaintext size — all of that
  lives inside V7 bodies and encrypted manifest JSON.
- **SQLite index** (`share_store.db` on the relay) holds: `share_id`,
  `kind` (`file` | `folder` | `collection`), `blob_count`, cumulative
  ciphertext `total_bytes`, `expires_at`, `revoked`, `sealed`, and the
  server-side `token_nonce` + per-bundle `bundle_token_hash`. No source
  IPs, no device IDs, no share-body sampling.
- **Key material never reaches the relay.** Per-file `content_key`s are
  embedded in the AES-256-GCM-sealed manifest under a `bundle_key` that
  is emitted only in the URL fragment. The fragment never hits the
  server.
- **Bounded lifetime.** Create calls require a hard expiry ≤ 30 days.
  Unsealed bundles older than `UNSEALED_MAX_LIFETIME_SECS` (4 h) are
  swept. Owner-initiated `DELETE /relay/share/b2/:id` purges blobs and
  index rows atomically.
- **Per-IP byte budget.** The daily upload budget (`share_byte_budget`)
  prevents a single attacker from filling the share filesystem. The
  headroom endpoint exposes budget utilisation without revealing
  anyone else's share activity.
- **Revocation is authoritative server-side.** `revoked = 1` rejects
  every GET regardless of fragment — a leaked URL loses access the
  moment the owner revokes.

These properties are why CLAUDE.md describes the relay as
*near-stateless* rather than *stateless*. The share surface is the
intentional exception; any new feature that would widen it (arbitrary
server-side user state, plaintext metadata, unbounded retention) must
go through a threat-model update before landing.

---

## 13. Release Integrity and Host-side Isolation

Wattcloud ships as cosign-signed release tarballs, not Docker images. The
VPS-side trust chain is:

- **Signing happens inside Actions.** `release.yml` uses Sigstore keyless
  signing via the workflow's OIDC identity — no long-lived signing key
  exists, and every signature is logged to the Rekor transparency log.
  The signer identity pinned on the VPS is the full workflow path:
  `https://github.com/wattzupbyte/wattcloud/.github/workflows/release.yml@refs/tags/v*.*.*`
  with issuer `https://token.actions.githubusercontent.com`.
- **Verification happens before extraction.** `install.sh` (for first
  install) and `wattcloud-update` (for every roll) run
  `cosign verify-blob` against the tarball with the pinned identity regex
  before `tar -xzf`. A compromised GitHub release asset fails verification
  and the script aborts before touching `/opt/wattcloud/current`.
- **Forks override via env, not patching.** `TRUSTED_SIGNER_IDENTITY` in
  `/etc/wattcloud/wattcloud.env` replaces the default regex. No script
  modification is needed to run a fork's signed release.
- **Rollback is first-class.** Upgrades extract to
  `/opt/wattcloud/releases/vX.Y.Z/` and swap `/opt/wattcloud/current`
  atomically. `wattcloud-update --rollback` points the symlink back. The
  previous release stays on disk (retention: last 3).

### 13.1 Systemd Sandboxing

byo-relay runs directly as a systemd service (`packaging/wattcloud.service`)
— there is no Docker in the default deploy path. Isolation is provided by
systemd sandbox directives, configured to match the threat model of a
stateless relay with a narrow I/O surface:

| Directive | Effect | Why it matters |
|-----------|--------|----------------|
| `DynamicUser=yes` | allocates a per-service UID that doesn't exist before/after | a compromise cannot pivot to a persistent home directory or re-use the UID in another service |
| `StateDirectory=wattcloud` | creates `/var/lib/wattcloud` owned by the dynamic UID | stats DB is writable; nothing else on the filesystem is |
| `ProtectSystem=strict` | `/usr`, `/boot`, `/etc` read-only to the service | a code-exec compromise cannot modify binaries or write persistence |
| `ProtectHome=yes` | `/root` and `/home` invisible | no lateral movement to operator credentials |
| `NoNewPrivileges=yes` | setuid binaries can't escalate | defense against kernel LPE chains that require privileged child processes |
| `CapabilityBoundingSet=` | empty — no Linux capabilities | cannot open raw sockets, bind to privileged ports, or re-mount anything |
| `AmbientCapabilities=` | empty | never grants capabilities to child processes |
| `MemoryDenyWriteExecute=yes` | W+X pages disallowed | blocks most shellcode and JIT-spray techniques |
| `SystemCallFilter=@system-service ~@privileged @resources` | seccomp allowlist | blocks `mount`, `kexec`, `reboot`, `bpf`, `perf_event_open`, etc. |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | no raw sockets, no routing-table sockets | blocks network probing / ARP spoofing from a compromised relay |
| `RestrictNamespaces=yes` | service can't create namespaces | blocks container-escape-like pivots |
| `PrivateTmp=yes` | own `/tmp` | no cross-service leakage |
| `PrivateDevices=yes` | no access to `/dev/mem`, `/dev/kmem`, block devices | cannot read raw disk or memory |
| `LockPersonality=yes` | no setting exec personality | blocks a common exploit building block |

For a zero-state relay that holds no plaintext and no key material, this
sandboxing is roughly equivalent to a minimal container — without the
Docker runtime, the extra trust boundary, or the container daemon's
attack surface.

### 13.2 R5 Privacy-minimized Logging

`harden-vps.sh` enables the R5 posture by default when the operator
runs `sudo wattcloud harden` (opt out with `--no-r5-logging`); the base
app install (`deploy-vps.sh`) makes no system-wide logging changes.
Its purpose is **GDPR minimization** —
keep the relay out of "controller of personal data" scope by
avoiding persisted IP addresses wherever possible, while retaining
enough system visibility for operational debugging and brute-force
protection.

**Kept with bounded retention (30 days):**

- `journald` is persistent (`Storage=persistent`,
  `SystemMaxUse=500M`, `MaxRetentionSec=30day`). Kernel, OOM,
  service-failure, and unit logs are available for post-mortem.
- `sshd` auth events retain source IPs — the one IP-bearing log
  stream in the system. `fail2ban`'s sshd jail reads these via
  `backend=systemd` to ban brute-force attempts inside its
  `findtime` window. Exposure is bounded by `MaxRetentionSec`.

**Stripped at the source (never written to disk):**

- Caddy access logs are emitted in JSON with every IP- and
  credential-bearing field deleted via the filter encoder:
  `remote_ip`, `remote_port`, `client_ip`, `X-Forwarded-For`,
  `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`, `Forwarded`,
  `Cookie`, `Authorization`, `Set-Cookie`, `user_id`. What remains
  is method, URI, host, status, duration, bytes, UA, TLS details —
  useful for debugging without PII. Rotated at 50 MB × 5 files ×
  30 days.
- `byo-relay` installs no request-logging middleware (no
  `tower_http::trace::TraceLayer`); `tracing_subscriber` defaults
  to `warn`, so normal request paths emit nothing under default
  load.
- `rsyslog` is disabled — all structured logs flow through `journald`
  or Caddy's own rotating file logger.
- Kernel `log_martians` is suppressed via
  `net.ipv4.conf.*.log_martians=0` so stray-packet IPs don't hit
  the ring buffer.

**byo-relay invariant — who vs. where:** `client_ip` is extracted
for rate-limiting, auth-failure tracking, and PoW challenge
binding, but **never appears in any log line**. Destination
addresses (SFTP `remote_host`, share-fetch URLs) may appear in
logs. Without a co-located client identifier, destination addresses
are infrastructure metadata rather than personal data about an
identified natural person. The invariant to preserve in future
changes is **"never co-log `client_ip` + destination in the same
event."**

**Trade-offs and escape hatches:**

- 30 days is the GDPR exposure window for sshd source IPs. It can
  be shortened in `journald.conf.d/wattcloud-retention.conf`; the
  lower bound is whatever `fail2ban`'s widest `findtime` needs
  (default `recidive` is 86400 s = 1 day).
- `--no-r5-logging` disables the posture entirely: kernel martian
  suppression off, Caddy writes default IP-bearing access logs,
  `journald` uses Ubuntu defaults, `rsyslog` stays on. Use only if
  you have a non-Wattcloud compliance posture that supersedes this.

## 14. Abuse Protections (Relay)

The relay runs in front of user-supplied storage and accepts shared
ciphertext uploads from enrolled devices. Without bounds, a compromised
device or a runaway client can saturate disk, saturate bandwidth, or
use the relay as a free anonymous hosting surface. This section
documents the limits, the threat model behind each, and the env vars
operators tune to adapt them.

### Threat model (what we're actually defending against)

1. **Disk exhaustion** — a client (or a coordinated set) pushes shares
   until the relay's storage partition fills and the service stops
   accepting new uploads (including legitimate ones).
2. **Free hosting / asymmetric storage** — a client parks many shares
   at the TTL ceiling (30 days) to use the relay as a durable
   anonymous mirror instead of a short-lived handoff.
3. **Bandwidth amplification** — a leaked share URL becomes a mirror
   for a viral payload: a 900 MB file downloaded from the relay 10×/s
   by strangers costs the operator 9 GB/s of egress.
4. **Runaway upload** — a client omits or misreports Content-Length
   and keeps sending until disk fills mid-stream, bypassing any
   declared-length cap.
5. **SFTP relay abuse** — a compromised device uses the SFTP relay
   gateway to attack third-party SSH servers (credential spraying,
   host scanning).

### Per-IP identity model

The relay's auth cookies are intentionally device-agnostic (`jti`,
`iat`, `exp` — no stable identity). All abuse limits are keyed on
client IP, bucketed to IPv4 / IPv6 /64 so subnet rotation doesn't
bypass (see §12 §"IPv6 /64 bucketing" for the primitive). This is a
deliberate trade-off: per-device limits would require adding identity
to the cookie, which conflicts with the near-stateless posture in
CLAUDE.md. Per-IP is blunt but correct for the threat model above.

### Limits and env vars

| Env var | Default | What it caps | Status on breach |
|---------|---------|--------------|------------------|
| `SHARE_MAX_BLOB_BYTES` | 1 GB | Size of any single share blob (file share main blob, bundle content blob, bundle manifest). Enforced pre-stream via Content-Length and mid-stream via a byte counter. | 413 Payload Too Large |
| `SHARE_CREATE_PER_HOUR_PER_IP` | 10 | New share creations per IP per hour. Sliding window. | 429 Too Many Requests |
| `SHARE_CREATE_PER_DAY_PER_IP` | 50 | New share creations per IP per day. Sliding window. | 429 Too Many Requests |
| `SHARE_TOTAL_STORAGE_PER_IP_BYTES` | 5 GB | Aggregate *live* (non-revoked, non-expired) share bytes attributed to an IP. Released as the sweeper prunes expired/revoked shares and on explicit revoke. | 507 Insufficient Storage |
| `SHARE_DOWNLOAD_PER_HOUR_PER_SHARE` | 10 | GETs per share_id per hour (existing limit, now env-driven). | 429 |
| `SHARE_DOWNLOAD_BYTES_PER_HOUR_PER_SHARE` | 1 GB | Total bytes served per share_id per hour. Complements the fetch count so one large share can't amplify via repeated reads. | 429 |
| `SHARE_MAX_CONCURRENT_DOWNLOADS` | 1 | Concurrent GETs per share_id. RAII guard; released on body finish / connection drop. | 429 |
| `SHARE_SLOW_START_SECS` | 300 | Window after share creation during which the bandwidth cap below applies. | — (throttle only) |
| `SHARE_SLOW_START_MAX_BPS` | 10 MB/s | Bandwidth ceiling during slow-start. Token-bucket paced per-response. | — |
| `DISK_WATERMARK_PERCENT` | 80 | statvfs-derived usage on the storage filesystem. New shares refused at or above. | 507 |
| `SHARE_DAILY_BYTES_PER_IP` | 50 GB | Per-IP daily upload ingress (existing). | 507 |
| `SFTP_MAX_CONCURRENT_PER_IP` | 3 | Concurrent SFTP relay sessions per IP. | 429 at handshake |
| `SFTP_FAILED_AUTH_PER_5MIN` | 5 | Failed auth attempts per 5 minutes before a 1-hour block. | SSH auth failure |
| `AUTH_MAX_BODY_BYTES` | 16 KB | Body ceiling on `/relay/auth` (enrollment JWK + PoW solution). Tight cap replaces axum's 2 MB default so a misbehaving client can't tie up a parse task. | 413 |
| `BUNDLE_INIT_MAX_BODY_BYTES` | 4 KB | Body ceiling on `/relay/share/bundle/init` (JSON: kind + expires_in_secs). | 413 |

### Why these numbers

- **1 GB max blob** + **5 GB aggregate per IP** means a single IP
  can hold at most 5 shares at the max size at any one time. Tight
  enough to kill the "free hosting" mode, loose enough for a
  legitimate photo-zip or video share to land.
- **10 fetches + 1 GB per hour per share** means a worst-case leaked
  link serves ~24 GB/day as long as the content fits the byte
  budget. Enough for a handful of intended recipients; not enough
  for amplification.
- **1 concurrent download** means extra recipients retry with
  backoff rather than racing each other. Shifts amplification cost
  from the relay to the clients; nobody "loses" access, they just
  wait a few seconds.
- **5-minute slow-start at 10 MB/s** bounds the "I posted the link
  to a chat of 500 people" burst to ~3 GB during the window that
  an operator would actually notice the spike.
- **80% disk watermark** leaves headroom for in-flight uploads +
  the sweeper's catch-up after the alarm fires, without burning
  through the last 20% before an operator can react.
- **SFTP 3 concurrent / 5 failed in 5 min** tightens the pre-existing
  `(5 concurrent / 5 failed in 10 min)` by a factor of ~2× in both
  dimensions — the relay's SFTP gateway is a proxy to *someone's*
  SSH server, and brute force on the origin should be rate-limited
  well below the origin's own fail2ban threshold.

### What's not (yet) implemented

- **Per-stream bandwidth metering** outside slow-start. A share past
  slow-start serves at line speed; in practice limited by the
  per-share bytes-per-hour budget and per-IP daily budget. Fine-
  grained per-stream tokio throttling is future work if bandwidth
  ends up being the dominant cost.
- **fail2ban-style HTTP pattern detection** on the share endpoints.
  Caddy's `rate_limit` module (documented in `packaging/Caddyfile.tmpl`)
  is the coarser outer safety net; a pattern-aware detector would
  catch slow-but-persistent abusers better. Consider if the coarse
  limit starts dropping legitimate traffic.
- **Per-device limits**. Would require adding a stable device
  pseudonym to relay cookies. Conflicts with the near-stateless
  posture; revisit only if per-IP proves insufficient.
- **WebDAV / S3 provider protections** (analogous to SFTP's
  concurrent + auth-failure caps). Both providers are *client-side*
  integrations — the relay is out of the data path — so the abuse
  surface is different. The client runs inside the user's browser
  against the user's own credentials; a compromised browser already
  owns those credentials directly. The relay's role in these flows
  is zero. If provider-specific DoS protection matters, it happens
  at the provider side (Dropbox rate limits, etc.), not here.

### Operator playbook

- **Tune limits** by setting the env vars above in
  `/etc/wattcloud/wattcloud.env` and restarting `wattcloud.service`.
  Changes take effect on restart; no migration needed — state is
  in-memory and rebuilds.
- **Investigate abuse** by watching `journalctl -u wattcloud` for
  repeated 429 / 507 responses. The relay logs response codes but
  not IPs (§R5 privacy posture). Correlate with the sshd source-IP
  log if the same bucket is hitting the SFTP limits.
- **Emergency**: `DISK_WATERMARK_PERCENT=50` bumps the watermark
  down, turning creation off early. Sweeper keeps running; upload
  resumes when below the watermark.

## 15. Access Control (Restricted Enrollment)

The relay's abuse protections in §14 cap the resource cost of any
individual enrolled user. When the operator wants to go further and
prevent *strangers who discover the URL* from using the relay at all —
the self-hosted "my instance is for my household" case — the
`WATTCLOUD_ENROLLMENT_MODE=restricted` env flag gates every operational
relay path behind a device cookie issued via owner-minted invite codes.

### Threat model

Adversary: a random visitor who discovers the URL (search-engine
scraping, neighbour's network scan, URL shared accidentally).

In-scope goals (what we block):
- Random visitor uses relay as a free SFTP proxy.
- Random visitor parks share blobs on the operator's disk.
- Random visitor enrols a device at all.
- Motivated attacker brute-forces invite codes.

Out-of-scope (what cookie-only auth doesn't address):
- Stolen device cookie from a compromised owner browser (malicious
  extension, OS-level malware). The cookie is HttpOnly + SameSite=Strict
  so XSS / cross-site leaks are blocked, but in-session exfiltration by
  local malware isn't. Mitigated per-incident via the *Sign out on this
  device* button (§Recovery below) which revokes the cookie
  server-side.
- Shared-computer leftover sessions. Same mitigation: explicit sign-out
  revokes the cookie server-side so later discovery of the cookie
  bytes doesn't grant access.
- A compromised OS on the server. The bootstrap token lives on the
  server filesystem; anyone with shell access to it can claim. This is
  consistent with "OS compromise = game over" across the entire stack.

**Critical invariant: admin compromise ≠ vault compromise.** Even a
malicious owner cannot decrypt any member's files — the ZK invariants
(ZK-1…ZK-7) are enforced in the crypto layer, orthogonal to admin
auth. Worst case of a stolen admin cookie is operational mischief
(mint themselves an invite, revoke your device, fill your disk), never
plaintext leakage. This bounds the blast radius dramatically.

### Mode flag

```
WATTCLOUD_ENROLLMENT_MODE=restricted   # fresh-install default
WATTCLOUD_ENROLLMENT_MODE=open         # no gate (or unset → open)
```

Existing installs on upgrade: env-absent → Open, preserving backcompat.
Fresh installs: `deploy-vps.sh` writes `restricted`.

Unknown values fall back to `open` with a warning in the log so a
typo can't silently enable a mode that blocks the operator out.

### Data model (relay-side)

Three SQLite tables in `/var/lib/wattcloud/enrollment.sqlite3` (systemd
install path; bare-binary default is `/var/lib/byo-relay/enrollment.sqlite3`,
overridden in `packaging/wattcloud.service` via `Environment=ENROLLMENT_DB_PATH`):

- `authorized_devices(device_id, pubkey, label, is_owner, created_at,
  last_seen_hour, revoked_at)` — one row per enrolled device. `pubkey`
  is a 32-byte placeholder today, reserved for v1.1 server-verified
  passkey attestations. `last_seen_hour` is bucketed to UTC hour to
  match the R5 privacy posture (§13.2) — no fine-grained timing
  metadata.
- `invite_codes(id, code_hash, label, issued_by, created_at, expires_at,
  used_by, used_at)` — HMAC-hashed codes, single-use. `code_hash =
  HMAC-SHA256(RELAY_SIGNING_KEY, normalized_code)` where the normalized
  form strips non-alphanumerics and uppercases.
- `bootstrap_token(id=1, token_hash, created_at, expires_at)` — at most
  one row at a time. HMAC-hashed with the same key as invite codes.
  Plaintext lives in the relay's state dir (0700 owned by the
  `DynamicUser=yes` service user) for `sudo wattcloud claim-token` to
  consume. File mode 0644 inside; parent dir gates access to root.

### Device JWT cookie (`wattcloud_device`)

HS256-signed JWT in an HttpOnly / Secure / SameSite=Strict / Path=/ cookie.
Claims: `{sub: device_id, kind: "device", is_owner, iat, exp, jti}`.
90-day TTL with sliding refresh — see the session lifecycle table
below.

Middleware on operational routes (`/relay/auth/challenge`, `/relay/auth`,
`/relay/share/b2`, `/relay/share/bundle/*`, `/relay/stats`) looks up the
device row on every request and rejects on `revoked_at IS NOT NULL`, so
revocation is immediate — no JWT-deny-list necessary. Admin-only routes
(`/relay/admin/invite`, `/relay/admin/invites/:id`, `/relay/admin/devices`,
`/relay/admin/devices/:id`) additionally require `is_owner=1`.

### Session lifecycle

The goal: an active device never has to re-enrol, but a silent device
eventually ages out so a long-forgotten cookie can't be weaponised.

| Event | Server-side effect | User-visible effect |
|---|---|---|
| Claim / redeem succeeds | Cookie minted, `iat = now`, `exp = now + 90d` | Device is signed in; SPA remembers via the `wc_enrolled_once` localStorage hint |
| Any gated or `/me` request with a valid cookie | `last_seen_hour` bumped. If `exp - now < 7d`, a fresh cookie replaces the old one in the response | Session continuously prolonged on active use; no re-enrol prompts |
| 90d of total silence | No refresh fires; `exp` passes. Next request fails `verify_device_jwt` | SPA boot probe reports `device: null`; paired with the `wc_enrolled_once` hint, a "Session expired" screen explains the expiry and routes to invite entry |
| User clicks **Sign out on this device** | `revoked_at` set on the device row; cookie cleared via `Max-Age=0`. `wc_enrolled_once` cleared client-side | Next boot shows the plain "invite-only" screen, not the expired-variant |
| Owner revokes another device | `revoked_at` set; next request from the revoked device fails middleware lookup → 401 + cookie clear | That device sees the expired-variant on its next visit |

The `wc_enrolled_once` hint is a UX-only signal and carries no security
weight — the server decides cookie validity. Its sole role is to
distinguish a first-time invitee (plain entry) from a returning one
whose cookie aged out (explanatory "Session expired" framing).

### Brute-force ceilings

Two-tier sliding windows per IP (IPv6 bucketed to /64):

| Endpoint | Per-5-min | Per-hour | Cryptographic entropy |
|---|---|---|---|
| `/relay/admin/claim` | 5 | 10 | 32-byte hex token (≥256 bits) |
| `/relay/admin/redeem` | 5 | 10 | 31¹¹ ≈ 3×10¹⁶ |
| `/relay/admin/invite` (owner-only mint) | — | 10 | — |
| `/relay/info` | — | 60/min | public, no secret |

The entropy does the heavy lifting — the ceilings exist to bound the
limiter map memory and short-circuit patient botnet-style attacks.

On top of that, `/relay/admin/claim` and `/redeem` reuse the relay's
existing PoW handshake (see §SFTP relay / enrollment flow for the
original pattern). Each attempt must first fetch a challenge from
`GET /relay/admin/claim/challenge` or `/redeem/challenge`, solve
`sha256(nonce ‖ purpose ‖ answer_le64)` to ≥`POW_DIFFICULTY_BITS`
leading zeros, and submit the `(nonce_id, answer)` pair with the
request. Server state: single-use nonce, IP-bound (can't be farmed on
one machine and spent on another), purpose-bound. This doesn't close
any brute-force window that entropy + rate limits didn't already close,
but it shifts per-attempt cost to the bot's CPU so coordinated
guessing gets proportionally more expensive. Legit clients solve it in
milliseconds inside the Web Worker.

### Bootstrap path

At startup in restricted mode with zero non-revoked owners, the relay
mints a 32-byte bootstrap token, HMACs + stores its hash, and writes
the plaintext to `bootstrap.txt` inside the relay's state dir. The
parent dir is 0700 owned by the `DynamicUser=yes` service user
(systemd `StateDirectoryMode=0700`), so reading the token requires
root — `sudo wattcloud claim-token` `cat`s + unlinks the file. 24-h
TTL.

Claim is idempotent with respect to bootstrapped state: a valid token
produces an owner regardless of `owner_count`. This is deliberate —
`wattcloud regenerate-claim-token` (via `byo-admin
regenerate-bootstrap-token`) is the recovery path for a locked-out
owner, and it shouldn't require destroying existing members.

### Recovery

- **Lose sole-owner device**: `sudo wattcloud regenerate-claim-token`
  mints a fresh token (HMAC written to DB via `byo-admin`, plaintext
  written to `bootstrap.txt`), then `sudo wattcloud claim-token` reads
  it, then paste into the bootstrap screen. The new device joins as
  an additional owner; the stale device can be revoked afterwards.
- **Sign out on shared computer**: POST `/relay/admin/signout` revokes
  the current device server-side and clears the cookie. The cookie
  bytes are no longer honoured even if captured. To come back, a fresh
  invite is needed.
- **Emergency reset**: wipe `enrollment.sqlite3` + restart the relay.
  Fresh install behaviour: new bootstrap token auto-minted, all existing
  enrolments gone. Last-resort — operators should prefer the
  non-destructive regenerate path above.

### What's deferred to v1.1

Real server-verified WebAuthn/PRF 2FA on admin actions. The
`authorized_devices.pubkey` column is already populated at enrolment
(currently with random placeholder bytes) so the server-side
infrastructure is pre-wired; the SPA side grows:

1. Generate an ed25519 keypair at enrolment (wrapped under the
   WebAuthn/PRF output from §12 so it's non-extractable).
2. Sign admin requests with that key; relay verifies the signature
   header against the stored `pubkey`.

This is a design pass, not an overnight push, so it ships in v1.1
rather than getting grafted onto the v1 feature.
