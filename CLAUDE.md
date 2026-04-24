# CLAUDE.md — Wattcloud

Zero-knowledge, Bring-Your-Own-storage cloud file manager. The relay server
never sees plaintext or key material; all crypto runs client-side inside a
WebAssembly module.

Wattcloud's relay is near-stateless by design. It holds no plaintext, no
key material, and no user identity beyond per-device enrollment tokens.
The one exception is **share storage**: the relay parks V7 ciphertext
blobs (single-file and bundle shares) so recipients can download without
provider access. Blobs carry hard expiries and are sweeper-purged —
never durable state. Do not introduce server-side user accounts,
centralized primary storage, or session state beyond this surface.

**Access control (restricted enrollment)** — `WATTCLOUD_ENROLLMENT_MODE`
(open|restricted, default open on upgrades, restricted on fresh installs
via deploy-vps.sh) gates every operational relay path behind a
`wattcloud_device` JWT cookie. Admin surface at `/relay/admin/*`
(claim/redeem/invite/devices/me/signout) is the only source of device
enrollments — additions here must preserve the "single funnel on
`/relay/auth/challenge`" invariant so restricted mode can't be bypassed.
See SECURITY.md §15.

## Project Layout

| Path | Stack | Purpose |
|------|-------|---------|
| `/sdk/sdk-core` | Rust | Pure crypto + business logic. No I/O, no `unwrap`, no panics. |
| `/sdk/sdk-wasm` | Rust → wasm-bindgen | Browser crypto kernel. Compiled with wasm-pack. |
| `/byo-relay` | Rust, Axum | Near-stateless relay (enrollment, SFTP, share storage, stats). |
| `/frontend` | Svelte + Vite | Browser SPA. `@wattcloud/sdk` lives at `frontend/src/lib/sdk/` (StorageProvider dispatcher, Web Worker client, vault journal). Single entry point (`src/main.ts`, `index.html`). |
| `/scripts` | Bash | `install.sh` + `deploy-vps.sh` (app install, also wires `wattcloud claim-token` / `regenerate-claim-token` CLI) + `harden-vps.sh` (opt-in VPS hardening via `sudo wattcloud harden`) + `update.sh` + `oauth-setup.sh` + `uninstall.sh` + `lib.sh` (ship inside the release tarball); `ci.sh` + `byo-smoke.sh` (local dev). |
| `/packaging` | Assets | `wattcloud.service` (systemd unit), `Caddyfile.tmpl`, `config.json.tmpl`. Shipped in the tarball. |

## Authoritative References

| Document | Scope |
|----------|-------|
| `SPEC.md` | BYO protocol, vault format, enrollment, OAuth flow, provider APIs. |
| `SECURITY.md` | Threat model, key hierarchy, zeroization policy. |
| `DESIGN.md` | Visual design system, layout, interaction patterns, vault motif. |
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

## Protocol Stability

`sdk/sdk-core/src/crypto/` and `sdk/sdk-core/src/byo/` contain the V7 wire
format and BYO vault layout. Once deployed, every HKDF info string,
AES-GCM nonce derivation, vault root folder path, and manifest field name
is a protocol constant. Changing any of them makes existing users' vaults
undecryptable. A change to these files is a **protocol version bump** —
design a migration, don't just refactor.

## Cryptographic Primitives

| Function | Algorithm | Notes |
|----------|-----------|-------|
| KDF | Argon2id (64 MB, 3 iter, 4 parallel) | Client-side only |
| Key agreement | Hybrid X25519 + ML-KEM-1024 | No classical-only fallback |
| File encryption | AES-256-GCM chunked (V7) | V7 is the ONLY wire format — v4–v6 removed |
| Key commitment | BLAKE2b-256(content_key ‖ file_iv) | Prevents partitioning-oracle attacks |
| Chunk integrity | HMAC-SHA256 (chunk-indexed) | Key: `HKDF(content_key, "chunk-hmac-v1")` |
| Filename encryption | AES-GCM-SIV (deterministic nonce) | Same filename + key → same ciphertext |
| Key derivation | HKDF-SHA256 | Info string literals include `"SecureCloud v6"` and `"SecureCloud BYO …"` — frozen protocol identifiers, NOT product branding. |

HKDF `info` strings still contain the literal bytes `"SecureCloud v6"`,
`"SecureCloud BYO …"`, etc.: these are frozen V7 protocol identifiers and
MUST NOT be renamed. Wattcloud-era additions live alongside them and are
equally frozen — treat the set as append-only:

- `"SecureCloud BYO key_versions wrap v1"` — AES-GCM wrapping key for
  `key_versions` private-key rows, derived from `vault_key` (SECURITY.md
  §BYO "Key Versions").
- `"Wattcloud device key v1"` — AES-GCM wrapping key for the per-vault
  device key when WebAuthn/PRF gate is enabled, derived from the
  authenticator's PRF output (SECURITY.md §BYO "Passkey-gated device
  key").
- `"Wattcloud vault_key wrap v1"` — AES-GCM wrapping key for the opt-in
  "passkey unlocks without passphrase" mode. Derived from the same PRF
  output as the device-key wrap but with a distinct HKDF info, so the two
  wrapping keys are guaranteed independent (SECURITY.md §BYO "Passkey
  replaces passphrase").

The on-disk vault root folder was `SecureCloud/` in earlier builds and
has since been renamed to `WattcloudVault/` — any new provider
implementation must use the current name. The SFTP provider also
accepts an optional `sftpBasePath` that prefixes the vault root on the
remote server (e.g. `/wattcloud` → vault at `/wattcloud/WattcloudVault`).

## sdk-core Constraints

- `#![deny(clippy::unwrap_used, clippy::expect_used)]` — no panics.
- All public functions return `Result<T, SdkError>`.
- No `unsafe` without `# Safety` doc + fuzz coverage.
- Slice/array access via `.get()` only, never direct indexing.
- No base64 in sdk-core — encode/decode at the WASM boundary.
- Key types derive `Zeroize` + `ZeroizeOnDrop`, never impl `Clone`.
- `Debug` impls print `[REDACTED]`.
- Provider I/O for files streams both directions: `download_stream_*` +
  `upload_stream_*` (HTTP providers use `RangedDownloadBuffer` + per-protocol
  resumable/chunked upload sessions; SFTP uses relay v3 read verbs + v2 write
  verbs). New providers MUST implement real streaming — buffer-and-forward
  stubs are not acceptable in production. See SPEC.md §Range-Based Download
  Streaming and §SFTP Streaming Download (Relay v3).

## Frontend Constraints

- All crypto goes through the Web Worker via `sdk-wasm`; the main thread never
  sees raw key bytes.
- OAuth config is loaded at runtime from `/config.json`, not at build time.
  `deploy-vps.sh` writes this file from the `.env`. Served with
  `Cache-Control: no-store`. SPA validates shape and fails closed on mismatch.
- Device-local state lives in the `sc-byo` IndexedDB (`frontend/src/lib/byo/
  DeviceKeyStore.ts`). Stores: `device_keys`, `device_crypto_keys`, `wal`,
  `dirty_flags`, `provider_configs`. Provider configs are AES-GCM-wrapped by
  the per-vault non-extractable device `CryptoKey`; see `ProviderConfigStore.ts`
  and SECURITY.md §12 "Credential Handling (BYO)". Do not add server-side
  persistence for provider configs — the store is explicitly on-device.
- File-sized payloads (owner download, share upload) stream end-to-end. Use
  `streamToDisk` for saves and the helpers in
  `frontend/src/lib/byo/shareUploadStreaming.ts` for share uploads; don't
  introduce new `fetch(..., body: <FullUint8Array>)` paths for ciphertext.

## Build & Test

```bash
# SDK native tests
cargo test --manifest-path sdk/sdk-core/Cargo.toml

# SDK WASM build (emits to frontend/src/pkg/)
pnpm run build:sdk-wasm

# Frontend (includes @wattcloud/sdk under src/lib/sdk/)
cd frontend && npm run dev
cd frontend && npm test
cd frontend && npm run build

# Convenience: same command sequence the CI workflow runs.
./scripts/ci.sh
```

## CI/CD

Canonical pipeline is **GitHub Actions**. Two workflows under `.github/workflows/`:

- `ci.yml` — on push/PR: lint + test + build. Runs `cargo test` for the sdk
  workspace and byo-relay, `npm test` for the frontend (incl. `@wattcloud/sdk`),
  `wasm-pack build`, `systemd-analyze verify packaging/wattcloud.service`,
  `caddy validate` on the rendered Caddyfile, and `scripts/byo-smoke.sh`.
- `release.yml` — on `v*.*.*` tag: cross-compiles byo-relay for
  x86_64-unknown-linux-gnu + aarch64-unknown-linux-gnu via `cross`, builds
  the frontend, assembles per-arch release tarballs in the install layout
  (bin/ web/ scripts/ packaging/), **sigstore/cosign sign-blob** each
  tarball + `install.sh` + `CHECKSUMS.txt` keyless via Actions OIDC,
  publishes the GitHub Release. Tags with a prerelease suffix (e.g.
  `v1.0.0-rc.1`) are flagged so they don't feed `/releases/latest/download`.

All third-party actions are pinned by commit SHA. `dependabot.yml` keeps
those SHAs current.

**Default deploy is tarball + systemd + Caddy.** Operators bootstrap with
`install.sh` (one GitHub release asset), which cosign-verifies the tarball
against a pinned signer-identity regex, extracts to
`/opt/wattcloud/releases/vX.Y.Z/`, and hands off to the tarball's
`deploy-vps.sh`. `deploy-vps.sh` is **app-only** — Caddy, env, systemd,
services, health check. VPS hardening (UFW, fail2ban, SSH lockdown, R5
logging, swap, earlyoom, disk-watchdog, AIDE, msmtp) lives in
`harden-vps.sh`, invoked separately via `sudo wattcloud harden`; the
standard install makes no system-wide config changes.  Upgrades run
`wattcloud-update`, which re-verifies the new tarball, swaps a symlink,
and auto-reverts if `/health` doesn't come back within 30 s. Forks
override the signer identity via `TRUSTED_SIGNER_IDENTITY` in
`/etc/wattcloud/wattcloud.env` — no script patching required.

The Docker path (`Dockerfile`, `make docker-image`) is a supported
self-builder option for contributors who specifically want to run in a
container, but there's no GHCR publish, no `compose.yml`, and no
Traefik — those were removed with the carveout.

`scripts/ci.sh` mirrors the Actions `ci.yml` command set for local runs.

## Directory Rules

- `sdk-core` holds only BYO + crypto. Any new relay/client feature goes
  under `sdk-core/src/byo/`; do not add auth, session, vault, sharing,
  upload, workspace, or state modules.
- Wattcloud is browser-only. No FFI bindings, no native mobile targets.
- Changes under `sdk-core/src/crypto/` or `sdk-core/src/byo/` are protocol
  version bumps; design a migration before editing.
- Production deploys run `byo-relay` directly as a systemd service behind
  Caddy — there is no Docker container in the default path. `packaging/`
  owns the unit file and Caddyfile template; treat them as production
  config.
