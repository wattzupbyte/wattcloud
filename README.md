<p align="center">
  <img src=".github/assets/wattcloud-hero.svg" width="280" alt="Wattcloud" />
</p>

<p align="center">
  <strong>Post-quantum, end-to-end-encrypted file manager for storage you already own.</strong><br/>
  Files are sealed in your browser; the relay you self-host never sees a plaintext byte.
</p>

<p align="center">
  <a href="https://docs.wattcloud.de"><img src="https://img.shields.io/badge/docs-docs.wattcloud.de-2EB860?style=flat" alt="Documentation" /></a>
  <a href="https://github.com/wattzupbyte/wattcloud/releases/latest"><img src="https://img.shields.io/github/v/release/wattzupbyte/wattcloud?display_name=tag&sort=semver" alt="Latest release" /></a>
  <a href="https://github.com/wattzupbyte/wattcloud/actions/workflows/ci.yml"><img src="https://github.com/wattzupbyte/wattcloud/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/wattzupbyte/wattcloud?color=2EB860" alt="AGPL-3.0-or-later" /></a>
</p>

<p align="center">
  <a href="https://docs.wattcloud.de"><strong>Operator handbook → docs.wattcloud.de</strong></a> &nbsp;·&nbsp;
  <a href="SECURITY.md">Threat model</a> &nbsp;·&nbsp;
  <a href="SPEC.md">Protocol spec</a>
</p>

> **Status:** personal project, production-shaped packaging, **not third-party
> audited**. Run on data you could afford to lose, or keep an independent
> backup. See [Status & licensing](#status--licensing).

---

## What Wattcloud is

Point Wattcloud at storage you already run — a Synology / QNAP / TrueNAS /
Unraid box over WebDAV or SFTP, a Hetzner Storage Box, an S3-compatible
bucket — and you get a browser-accessible vault with end-to-end encryption,
multi-device access, and share links. You host the coordinating server
yourself, you own the storage, and the server never holds plaintext, key
material, or anything that identifies you beyond a per-device enrollment
cookie.

All encryption runs in your browser. Files are sealed with AES-256-GCM, and
the key exchange combines classical elliptic curves (X25519) with a
NIST-standardized post-quantum KEM (ML-KEM-1024). Your passphrase is
stretched with Argon2id before it ever contributes to a key. The crypto
core runs as a sandboxed WebAssembly module inside a Web Worker; the main
UI thread never touches key material.

The server side is a single Rust binary (`byo-relay`) running under a
hardened systemd unit behind Caddy, which handles TLS via Let's Encrypt
automatically. ~60 MB on disk, single-digit MB of RAM at rest.

## Who it's for

- **Home-NAS owners** who want a remote, HTTPS-accessible front door to
  their box without exposing SMB, the admin panel, or installing a second
  vendor's desktop agent.
- **Cloud-storage users who want their provider kept dumb** — a Hetzner
  Storage Box, an S3 bucket, anything with WebDAV / SFTP / S3 API, with a
  proper browser UI on top that doesn't trust the storage vendor.
- **Small teams and families.** One host, many invited devices, per-device
  revocation. The host cannot decrypt a member's files.
- **People who need auditable posture.** No user database, no password
  hashes, no client IPs on disk. The full threat model is in
  [`SECURITY.md`](SECURITY.md).
- **Self-hosters who want something light.** One systemd service, one
  Caddy site, ~60 MB of binary. Auto-rolls back on a failed health check.

## What it is not

- Not a storage provider — you bring the backend.
- Browser-only — no native desktop sync agent, no mobile app.
- Invite-only by default — you decide who gets in.

## Supported storage backends

- **WebDAV** — Synology, QNAP, TrueNAS, Unraid, ownCloud, Nextcloud, any
  spec-compliant server. → [docs](https://docs.wattcloud.de/providers/webdav/)
- **SFTP** — any SSH-reachable host: NASes, Hetzner Storage Box, plain
  Linux. → [docs](https://docs.wattcloud.de/providers/sftp/)
- **S3-compatible** — AWS S3, Cloudflare R2, Backblaze B2, Wasabi, MinIO,
  Storj. → [docs](https://docs.wattcloud.de/providers/s3/)

The on-disk encrypted format is shared across backends, so replicating or
migrating between providers is a straight file copy — no re-encrypt pass.

## Features at a glance

- **Files & photos.** Drag-and-drop multi-file/folder upload, streaming
  range-based downloads, search with type filters, EXIF-grouped photo
  timeline, hand-curated encrypted collections.
- **Sharing.** Single-file and bundle shares, end-to-end encrypted, parked
  on the relay as opaque V7 ciphertext that sweeper-purges on expiry.
  Time-bound (1 h / 1 d / 7 d / 30 d), optional Argon2id-protected
  password.
- **Multi-device.** QR-based pairing with a SAS code shown on both screens
  (no relay-in-the-middle). Owner / member roles, per-device revocation.
- **Identity & recovery.** Passphrase + Argon2id; one-time recovery key;
  optional passkey unlock (presence factor or full PRF-derived key wrap).
- **On-device privacy.** Provider credentials live in IndexedDB wrapped by
  a non-extractable per-vault `CryptoKey`, never on the relay. *Forget on
  this device* drops them locally without touching the remote vault.
- **Cross-provider move** — decrypts in the browser, re-uploads to the new
  backend, ciphertext never round-trips through the relay.

Full list with screenshots and rationale on
[**docs.wattcloud.de**](https://docs.wattcloud.de).

## Quickstart (local trial, contributors)

Try it on your laptop before touching a VPS. Requires Rust 1.80+, Node
20+, wasm-pack, pnpm 9+.

```bash
git clone https://github.com/wattzupbyte/wattcloud
cd wattcloud
make dev
```

That starts `byo-relay` on `127.0.0.1:8443` and Vite on `:5173`, with Vite
proxying the relay so the SPA talks to it same-origin. Open
<http://localhost:5173/>, claim the printed bootstrap token (`make
claim-token` in another shell), connect a WebDAV / SFTP / S3 endpoint, and
you have a working vault. `make dev-stop` tears the stack down.

## Production install

One command, on a fresh Ubuntu 22.04+ VPS with DNS pointing at it:

```bash
curl -sSLO https://github.com/wattzupbyte/wattcloud/releases/latest/download/install.sh
less install.sh                       # ~150 lines — read before running
sudo bash install.sh cloud.example.com
```

`install.sh` cosign-verifies the release tarball against a pinned Sigstore
identity, extracts it, and hands off to `deploy-vps.sh` from inside the
verified tarball. That provisions Caddy + TLS, generates signing keys,
installs the sandboxed systemd unit, and health-checks `/health`.

Then claim ownership:

```bash
sudo wattcloud status                  # service + install state
sudo wattcloud claim-token             # one-time bootstrap token
```

Full walkthrough — what lands on disk, non-interactive flags, fork-signer
overrides, recovery flow — in
[**docs.wattcloud.de/install/one-command-install/**](https://docs.wattcloud.de/install/one-command-install/).
Access control (invite-only mode, claiming, revoking, recovery) is at
[**/install/access-control/**](https://docs.wattcloud.de/install/access-control/).
Upgrades and auto-rollback are at
[**/install/upgrades/**](https://docs.wattcloud.de/install/upgrades/).

## Security headlines

The full threat model is in [`SECURITY.md`](SECURITY.md). The five things
worth knowing before you read it:

- **Post-quantum key exchange.** Hybrid X25519 + ML-KEM-1024. Both
  components have to fail for a break. Captured-today traffic stays
  unreadable when quantum hardware matures.
- **The server never sees plaintext** — passphrase, decryption keys
  (not even a fragment), private keys, file content, filenames, recovery
  code. The seven invariants (ZK-1…ZK-7) are enumerated in
  [`SECURITY.md`](SECURITY.md).
- **Modern file encryption.** AES-256-GCM chunked, per-file commitment
  (no partitioning oracle), AES-GCM-SIV deterministic filenames.
- **Privacy-minimized logging.** Caddy strips client IPs and credentials.
  The relay never writes client IPs anywhere. The in-memory rate-limiter
  is the only per-IP state, and it never touches disk.
- **Sandboxed runtime.** `DynamicUser=yes`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute=yes`, all capabilities dropped, strict seccomp
  filter. Every release tarball is keyless cosign-signed via Actions OIDC
  and verified before install — `install.sh` aborts on a swapped asset.

VPS hardening (UFW, fail2ban, sshd lockdown, R5 logging, swap, earlyoom,
AIDE, msmtp) is opt-in via `sudo wattcloud harden` — full walkthrough at
[**docs.wattcloud.de/operations/hardening/**](https://docs.wattcloud.de/operations/hardening/).
The standard install makes no system-wide config changes.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Browser SPA (Svelte + Vite)                                  │
│   ├─ Web Worker (sdk-wasm) — all crypto, V7 pipeline         │
│   └─ @wattcloud/sdk        — StorageProvider dispatcher      │
└───────────────┬────────────────────────────────┬─────────────┘
                │                                │
                ▼                                ▼
   ┌──────────────────────────┐  ┌─────────────────────────────┐
   │ Caddy (TLS + ACME)       │  │ User's storage backend      │
   │   └─ reverse_proxy       │  │  (WebDAV, SFTP, S3-compat)  │
   │      127.0.0.1:8443      │  │  - opaque V7 ciphertext     │
   │         │                │  │  - no plaintext ever        │
   │         ▼                │  └─────────────────────────────┘
   │ byo-relay (systemd)      │
   │  - device enrollment     │
   │  - SFTP relay            │
   │  - share storage (V7)    │
   │  - minimal logs (no IPs) │
   └──────────────────────────┘
```

| Path | Stack | Purpose |
|------|-------|---------|
| `sdk/sdk-core` | Rust | Cryptographic core. No I/O, no panics, no `unwrap`. Feeds sdk-wasm. |
| `sdk/sdk-wasm` | Rust → wasm-bindgen | Browser crypto kernel loaded by the Web Worker. |
| `byo-relay` | Rust, Axum | Near-stateless relay (enrollment, SFTP, share storage, stats). Single release binary. |
| `frontend` | Svelte + Vite | SPA. `@wattcloud/sdk` at `frontend/src/lib/sdk/` — StorageProvider dispatcher, Web Worker client, vault journal. |
| `docs` | Astro + Starlight | Operator handbook published at [docs.wattcloud.de](https://docs.wattcloud.de). |
| `packaging` | Assets | Systemd unit, Caddyfile template, `config.json` template. Shipped inside the tarball. |
| `scripts` | Bash | `install.sh`, `deploy-vps.sh`, `harden-vps.sh`, `update.sh`, `uninstall.sh`, `lib.sh` (tarball-shipped); `ci.sh`, `byo-smoke.sh` (dev). |

Deeper references: [`SPEC.md`](SPEC.md) (protocol),
[`SECURITY.md`](SECURITY.md) (threat model), [`DESIGN.md`](DESIGN.md)
(visual + UX system), [`CLAUDE.md`](CLAUDE.md) (repo conventions).

## Development

`make help` lists every target. These are contributor and self-builder
tools; operators running a production install never touch Make.

```bash
make dev               # byo-relay (:8443) + Vite (:5173), foreground
make dev-stop          # SIGTERM a running stack (via PID file)
make dev-frontend      # Vite only — use when a relay is already running
make dev-relay         # byo-relay only — bootstraps .env.dev on first run
make claim-token       # dev parity with `sudo wattcloud claim-token`
make build             # wasm-pack + Vite build, in order
make test              # cargo + npm across the repo
make lint              # cargo clippy + eslint
make ci                # full local CI (mirrors GitHub Actions)
```

`make dev` runs `scripts/dev.sh`, which generates a gitignored `.env.dev`
on first run with ephemeral JWT/HMAC signing keys, starts the relay,
waits for `/health`, then launches Vite. Vite proxies `/relay/*`,
`/health`, and `/ready` so the SPA talks same-origin — no CORS plumbing.
Delete `.env.dev` to rotate; you'll need to re-enroll.

Packaging and release artifacts (cosign signing happens in CI — it needs
Actions OIDC and is not available locally):

```bash
make tarball           # host-arch tarball → dist/
make tarball-all       # cross-compile x86_64 + aarch64 (needs `cross`)
make smoke-tarball     # scripts/byo-smoke.sh against the local build
make verify-tarball TARBALL=… SIG=… CERT=…   # cosign-verify a downloaded asset
make docker-image      # self-builder-only Docker image (not a release artifact)
```

Real releases flow through a signed `v*.*.*` tag → `release.yml`.

## CI/CD and release integrity

Three workflows under `.github/workflows/`:

- **`ci.yml`** — push/PR: `cargo test` + clippy + fmt for the sdk
  workspace and `byo-relay`; `npm test` + lint + build for the frontend;
  `wasm-pack build`; `systemd-analyze verify` on the unit; `caddy
  validate` on the rendered Caddyfile; `scripts/byo-smoke.sh`.
- **`release.yml`** — on `v*.*.*` tag: cross-compile for
  `x86_64`/`aarch64-unknown-linux-gnu`, build the frontend, assemble
  per-arch tarballs, **keyless cosign sign-blob** each tarball +
  `install.sh` + `CHECKSUMS.txt` via Actions OIDC, publish the GitHub
  Release. Prerelease tags (any `-` suffix) don't feed
  `/releases/latest/download`.
- **`docs.yml`** — push to `main` affecting `docs/**`: build the Astro
  Starlight site and deploy to GitHub Pages
  ([docs.wattcloud.de](https://docs.wattcloud.de)).

All third-party actions are pinned by commit SHA; `dependabot.yml` keeps
those SHAs current. The release trust chain is in `SECURITY.md §13`:
`install.sh` and `wattcloud-update` run `cosign verify-blob` against
`TRUSTED_SIGNER_IDENTITY` before extraction. A swapped GitHub release
asset fails verification and the scripts abort.

`scripts/ci.sh` mirrors the Actions `ci.yml` command set for local runs.

## Status & licensing

**Status.** Personal project. The encrypted on-disk format and the
zero-knowledge invariants are stable — changes would make existing vaults
undecryptable, so they're treated as protocol version bumps, not
refactors. Install flow and packaging are production-shaped and
exercised in CI. The codebase has **not** had a third-party security
audit; run it on data you could afford to lose, or keep an independent
backup.

**Roadmap.** WebDAV and SFTP are shipping. S3-compatible is in active
development. OAuth-based providers (Google Drive, Dropbox, OneDrive, Box,
pCloud) are gated behind a feature flag and not currently exposed in the
SPA. The full operator handbook — install, access control, hardening,
backups, troubleshooting, recovery, security model, sharing, multi-device,
identity, FAQ — lives on
[docs.wattcloud.de](https://docs.wattcloud.de).

**Development style.** Wattcloud is developed with extensive AI
pair-programming ("vibe coding"). Design-level decisions — protocol,
cryptographic choices, threat model, license — are the maintainer's.
Implementation-level diffs are reviewed for behavior and spot-checked
before they land, but are not line-by-line hand-audited. The label is
used honestly; weight the codebase accordingly and treat the lack of a
third-party security audit as load-bearing.

**License.** AGPL-3.0-or-later — see [`LICENSE`](LICENSE). You are free
to use, study, modify, and distribute Wattcloud under the GNU Affero GPL
v3. The notable wrinkle versus plain GPL: if you run a modified version
as a network-accessible service, you must make your modifications
available to the users of that service under the same license. Running
unmodified signed releases on your own infrastructure for your own use
triggers no extra obligations.

The Wattcloud name and wordmark are not covered by the AGPL and are
reserved by the project — forks must be renamed.

## Contributing

This is a personal project and patches are not being actively solicited
yet. Security findings are welcome — please open a GitHub security
advisory rather than a public issue;
[`SECURITY.md`](SECURITY.md) documents the intake process. When the
project opens up further, contributions that improve security, the BYO
protocol, or provider coverage will be most welcome. All contributions
are accepted under the project's AGPL-3.0 license; by opening a PR you
agree your work is licensed on the same terms. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).
