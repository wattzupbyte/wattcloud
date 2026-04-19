# CLAUDE.md — Wattcloud

Zero-knowledge, Bring-Your-Own-storage cloud file manager. The relay server
never sees plaintext or key material; all crypto runs client-side inside a
WebAssembly module.

Wattcloud is the BYO-only carveout of SecureCloud. **Do not reintroduce managed
modules here** — the `managed` feature was removed from `sdk-core` deliberately.

## Project Layout

| Path | Stack | Purpose |
|------|-------|---------|
| `/sdk/sdk-core` | Rust | Pure crypto + business logic. No I/O, no `unwrap`, no panics. |
| `/sdk/sdk-wasm` | Rust → wasm-bindgen | Browser crypto kernel. Compiled with wasm-pack. |
| `/byo-server` | Rust, Axum | Stateless relay (enrollment, SFTP, share pointers, stats). |
| `/byo` | TypeScript | `@wattcloud/sdk` — StorageProvider dispatcher, Web Worker client, vault journal. |
| `/frontend` | Svelte + Vite | Browser SPA. Single entry point (`src/main.ts`, `index.html`). |
| `/scripts` | Bash | `deploy-vps.sh`, `ci.sh`, `release.sh`, `update.sh`, `harden-dev.sh`, `byo-smoke.sh`. |

## Authoritative References

| Document | Scope |
|----------|-------|
| `SPEC.md` | BYO protocol, vault format, enrollment, OAuth flow, provider APIs. |
| `SECURITY.md` | Threat model, key hierarchy, zeroization policy. |
| `README.md` | Architecture + operator quickstart + OAuth setup + deployment. |

## Zero-Knowledge Invariants (MUST NOT be violated)

| ID | Rule | Enforcement |
|----|------|-------------|
| ZK-1 | Server never receives plaintext passwords | Argon2id runs client-side; only `auth_hash` is sent |
| ZK-2 | Server never receives `client_kek_half` | Derived client-side; never serialized or transmitted |
| ZK-3 | Server never receives the full KEK | Two-factor split across `client_kek_half` + server shard |
| ZK-4 | Server never receives plaintext private keys | KEK-wrapped before transmission |
| ZK-5 | Server never receives plaintext file content | AES-256-GCM encrypted before upload |
| ZK-6 | Server never receives plaintext filenames | AES-GCM-SIV encrypted |
| ZK-7 | Server never receives plaintext recovery key | Displayed once; never stored or sent |

**Before adding any API call:** verify the payload contains ONLY encrypted
blobs, HKDF-derived auth tokens, HMAC challenge responses, or public keys.

## Crypto-interop Invariant

`sdk/sdk-core/src/crypto/` must remain byte-for-byte identical to the
corresponding files in the upstream SecureCloud repo so V7 ciphertext is
interoperable. If you change a crypto primitive here, propagate the same
change in the other repo and vice versa.

## Cryptographic Primitives

| Function | Algorithm | Notes |
|----------|-----------|-------|
| KDF | Argon2id (64 MB, 3 iter, 4 parallel) | Client-side only |
| Key agreement | Hybrid X25519 + ML-KEM-1024 | No classical-only fallback |
| File encryption | AES-256-GCM chunked (V7) | V7 is the ONLY wire format — v4–v6 removed |
| Key commitment | BLAKE2b-256(content_key ‖ file_iv) | Prevents partitioning-oracle attacks |
| Chunk integrity | HMAC-SHA256 (chunk-indexed) | Key: `HKDF(content_key, "chunk-hmac-v1")` |
| Filename encryption | AES-GCM-SIV (deterministic nonce) | Same filename + key → same ciphertext |
| Key derivation | HKDF-SHA256 | `"SecureCloud v6"` info string names the KEM construction, not a format — kept for V7 interop. |

The HKDF `info` strings still contain `"SecureCloud"` because they are part of
the V7 wire format. Renaming them would break ciphertext interoperability. The
rename to "Wattcloud" is cosmetic/UX only; protocol identifiers stay as-is.

## sdk-core Constraints

- `#![deny(clippy::unwrap_used, clippy::expect_used)]` — no panics.
- All public functions return `Result<T, SdkError>`.
- No `unsafe` without `# Safety` doc + fuzz coverage.
- Slice/array access via `.get()` only, never direct indexing.
- No base64 in sdk-core — encode/decode at the WASM boundary.
- Key types derive `Zeroize` + `ZeroizeOnDrop`, never impl `Clone`.
- `Debug` impls print `[REDACTED]`.

## Frontend Constraints

- All crypto goes through the Web Worker via `sdk-wasm`; the main thread never
  sees raw key bytes.
- OAuth config is loaded at runtime from `/config.json`, not at build time.
  `deploy-vps.sh` writes this file from the `.env`. Served with
  `Cache-Control: no-store`. SPA validates shape and fails closed on mismatch.

## Build & Test

```bash
# SDK native tests
cargo test --manifest-path sdk/sdk-core/Cargo.toml

# SDK WASM build (emits to frontend/src/pkg/)
pnpm run build:sdk-wasm

# BYO TS package
cd byo && npm test

# Frontend
cd frontend && npm run dev
cd frontend && npm run build

# Convenience: same command sequence the CI workflow runs.
./scripts/ci.sh --mode byo
```

## CI/CD

Canonical pipeline is **GitHub Actions**. Two workflows under `.github/workflows/`:

- `ci.yml` — on push/PR: lint + test + build (sdk cargo test, byo-server cargo
  test, byo npm test, frontend npm test, wasm-pack build).
- `release.yml` — on `v*.*.*` tag: builds the image, pushes to
  `ghcr.io/wattzupbyte/wattcloud`, emits the `@sha256:…` digest in the release
  notes. VPS then runs `./scripts/update.sh <digest>` to roll forward.

All third-party actions are pinned by commit SHA (not by tag) to neutralize
supply-chain risk. `.github/dependabot.yml` keeps those pinned SHAs current.

`scripts/ci.sh` and `scripts/release.sh` remain as local convenience wrappers;
they run the same commands the workflows invoke. `scripts/update.sh` runs on the
VPS and is the only piece that is *not* invoked by Actions.

## Directory Rules

- **Do not add** managed-mode modules (auth, session, files, vault, sharing,
  trusted_device, upload, workspace, state) to `sdk-core`. They were pruned on
  purpose. If a BYO feature needs similar functionality, add it under
  `sdk-core/src/byo/`.
- **Do not add** `sdk-ffi` / Android bindings. Android stays in SecureCloud.
- Changes under `sdk-core/src/crypto/` require a coordinated PR in SecureCloud.
