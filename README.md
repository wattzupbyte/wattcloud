# Wattcloud

Self-hosted, zero-knowledge, Bring-Your-Own-storage (BYO) cloud file manager.
Users keep their files on a storage provider they already own (Google Drive,
Dropbox, OneDrive, Box, pCloud, WebDAV, SFTP, or S3-compatible); Wattcloud is a
small relay server plus a browser SPA that encrypts everything client-side
before it leaves the device.

Wattcloud is a BYO-only carveout of SecureCloud. The cryptographic primitives
(V7 wire format, ZK-1…ZK-7 invariants, R5 zero-logging posture) must remain
**byte-for-byte identical** across both repos so V7 ciphertext remains
interoperable.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Operator Quickstart](#operator-quickstart)
4. [OAuth Provider Setup](#oauth-provider-setup)
5. [CI/CD](#cicd)
6. [Deployment](#deployment)
7. [Security Model](#security-model)
8. [Development](#development)
9. [Contributing](#contributing)

---

## Overview

- **Client-side crypto** — all AES-256-GCM encryption, ML-KEM-1024 + X25519
  hybrid key agreement, Argon2id KDF happens in a WebAssembly module running
  inside a Web Worker. The main thread never sees raw key material.
- **Zero-knowledge relay** — the Wattcloud server only forwards opaque frames
  during device enrollment and WebDAV/SFTP/share traffic. No user accounts, no
  password database, no uploaded ciphertext is persisted server-side.
- **BYO storage** — vaults live on the user's own Google Drive / Dropbox /
  OneDrive / Box / pCloud / WebDAV / SFTP / S3 bucket. Every provider stores
  the same V7 ciphertext format; cross-provider replication and migration
  work verbatim.

See [SPEC.md](SPEC.md) for the full protocol spec and [SECURITY.md](SECURITY.md)
for the threat model.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Browser SPA (Svelte + Vite)                                  │
│   ├─ Web Worker (sdk-wasm)  — all crypto, V7 pipeline        │
│   └─ byo TS package         — StorageProvider dispatcher     │
└───────────────┬────────────────────────────────┬─────────────┘
                │                                │
                ▼                                ▼
   ┌──────────────────────┐      ┌─────────────────────────────┐
   │ Wattcloud relay      │      │ User's own storage provider │
   │  (byo-server, Rust)  │      │  (GDrive, Dropbox, S3, …)   │
   │  - enrollment WS     │      │  - opaque V7 ciphertext     │
   │  - SFTP relay        │      │  - no plaintext ever        │
   │  - share pointers    │      └─────────────────────────────┘
   │  - R5 zero-logging   │
   └──────────────────────┘
```

| Path | Stack | Purpose |
|------|-------|---------|
| `sdk/sdk-core` | Rust | Cryptographic core — no I/O, no panics. Feeds wasm & (future) FFI. |
| `sdk/sdk-wasm` | Rust → wasm-bindgen | Browser crypto kernel loaded by the Web Worker. |
| `byo-server` | Rust, Axum | Stateless relay (enrollment, SFTP, share pointers, stats). |
| `byo` | TypeScript | `@wattcloud/sdk` — storage-provider dispatcher, vault journal, Web Worker client. |
| `frontend` | Svelte + Vite | Browser SPA. |
| `scripts` | Bash | `deploy-vps.sh`, `release.sh`, `update.sh`, `ci.sh`. |

## Operator Quickstart

Prerequisites: a Linux VPS (Ubuntu 22.04+) with a public domain and Docker
installed. See [Deployment](#deployment) for the full hardening pass.

```bash
# On the VPS (TBD in upcoming deploy script rewrite).
git clone https://github.com/wattzupbyte/wattcloud.git
cd wattcloud
cp .env.example .env
$EDITOR .env                    # fill in the five BYO_*_CLIENT_ID values + signing keys
./scripts/deploy-vps.sh         # bootstraps UFW, Traefik, Docker, pulls the pinned image
```

After bootstrap, `./scripts/update.sh <digest>` pulls the digest-pinned image
from GHCR and rolls the compose stack.

## OAuth Provider Setup

Wattcloud's SPA uses PKCE + public OAuth client IDs (no client secrets). All
five provider IDs are served to the SPA at boot via `/config.json`, which
`deploy-vps.sh` generates from the `.env` at provision time.

| Provider    | Console | Required scope | Notes |
|-------------|---------|----------------|-------|
| Google Drive | <https://console.cloud.google.com>             | `drive.file`             | Restrict to Web app; redirect URI = `https://$BYO_DOMAIN`. |
| Dropbox      | <https://www.dropbox.com/developers/apps>      | `files.content.read/write` | Choose "Scoped access", App folder or Full Dropbox. |
| OneDrive     | <https://portal.azure.com> → App registrations | `Files.ReadWrite`        | Redirect URI must exactly match `$BYO_BASE_URL`. |
| Box          | <https://app.box.com/developers/console>       | `root_readwrite`         | "OAuth 2.0 with PKCE" app type. |
| pCloud       | <https://docs.pcloud.com/my_apps/>             | Manage files            | EU vs US endpoint auto-detected at login. |

WebDAV, SFTP, and S3/R2 work without OAuth (user provides credentials directly).

## CI/CD

No GitHub Actions. The project uses a home-grown bash pipeline:

- `scripts/ci.sh --mode byo` — lint + test + build the whole repo locally.
- `scripts/release.sh <version>` — build the image, push to
  `ghcr.io/wattzupbyte/wattcloud`, emit the resulting `@sha256:…` digest.
- `scripts/update.sh <digest>` — on the VPS: update `docker-compose.byo-prod.yml`
  to pin the new digest, `docker compose pull`, restart, health-check.

## Deployment

The forked `deploy-vps.sh` handles UFW (22/80/443), fail2ban, unattended-upgrades,
SSH hardening (drop-in config, custom port, no root, no passwords), R5
zero-logging (journald volatile, UFW logging off, rsyslog off), Docker +
Compose, swap, Docker log rotation, GHCR `docker login`, and digest-pinned image
pull.

## Security Model

See [SECURITY.md](SECURITY.md) for the full invariants. Highlights:

- **Zero-knowledge**: the Wattcloud relay never handles plaintext, keys, or
  anything cleartext. ZK-1…ZK-7 enforced throughout (see SPEC.md).
- **R5 zero-logging**: all operator-side logging is disabled by default so the
  relay cannot keep records a subpoena could seize.
- **V7 interop invariant**: Wattcloud's crypto primitives are byte-for-byte
  identical to SecureCloud's so V7 ciphertext is decryptable across both repos.
  Do not modify `sdk/sdk-core/src/crypto/` without propagating the change.

## Development

Rust toolchain (1.80+), Node 20+, wasm-pack, pnpm 9+. See [SPEC.md](SPEC.md) for
the protocol spec and [CLAUDE.md](CLAUDE.md) for the repo conventions consumed
by Claude Code / opencode.

```bash
# SDK tests (native)
cargo test --manifest-path sdk/sdk-core/Cargo.toml

# SDK WASM build
cd sdk/sdk-wasm && wasm-pack build --release --target web

# BYO TS package
cd byo && npm test

# Frontend dev server
cd frontend && npm run dev
```

## Contributing

This is a personal project, not open to unsolicited PRs yet. If you want to run
Wattcloud on your own infrastructure, fork freely. The upstream will consider
patches that improve security, the BYO protocol, or provider coverage once the
license is finalized.
