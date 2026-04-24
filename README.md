# Wattcloud

**Turn your NAS — or any cloud storage you already own — into an
end-to-end-encrypted cloud drive, with post-quantum crypto and no vendor
in the middle.** Files are sealed in your browser before they ever touch
a server. You run the small coordinating server yourself; it never sees
a plaintext byte.

**Status:** personal project, production-shaped packaging, not third-party
audited. See [Licensing & status](#licensing--status) before parking
irreplaceable data.

## What Wattcloud is

Point Wattcloud at something you already run — a Synology / QNAP /
TrueNAS / Unraid box over WebDAV or SFTP, a Hetzner Storage Box, or an
S3-compatible bucket (Cloudflare R2, Wasabi, MinIO, Backblaze B2) — and
you get a browser-accessible vault with end-to-end encryption, multi-device access, and share links. You host the coordinating server yourself, you own the storage, and the server never holds plaintext, key
material, or anything that identifies you beyond a per-device enrollment cookie.

All encryption runs in your browser. Files are sealed with AES-256, and the key exchange combines classical elliptic curves (X25519) with a NIST-standardized post-quantum algorithm (ML-KEM-1024). Your passphrase is stretched with Argon2id before it ever contributes to a key. The crypto core runs as a sandboxed WebAssembly module inside a Web Worker; the main UI thread never touches key material.

The server side is a single Rust binary (`byo-relay`) running under a
hardened systemd unit behind Caddy, which handles TLS certificates
automatically via Let's Encrypt. Around 60 MB on disk, some megabytes
of RAM at rest.

## Who it's for

**Home-NAS owners.** You've got a Synology, QNAP, TrueNAS, or Unraid box
sitting in your home network. Wattcloud gives you a remote, HTTPS-accessible front door to it — without exposing SMB,
without putting the NAS's admin panel on the public internet, and
without installing a second vendor's desktop agent. Point Wattcloud at
your NAS's WebDAV or SFTP share and your files stay exactly where they
already live, only now they're encrypted end-to-end and reachable from
any browser.

**Cloud-storage users who want their provider kept dumb.** You have a
Hetzner Storage Box, a Scaleway object store, or a Backblaze bucket.
You want a real browser UI on top of it without trusting a vendor — or
a second vendor layered on the first — with either the storage or the
access layer.

**Small teams and families.** One host, many invited devices, per-device
revocation. The host cannot decrypt a member's files — the
zero-knowledge property is enforced by math in the browser, not by
admin policy on the server.

**People who need auditable posture.** No user database, no password
hashes, no client IPs on disk. The server runs under a heavily
sandboxed systemd unit (unprivileged dynamic user, read-only root
filesystem, no writable+executable memory pages, strict syscall filter)
and every release tarball is cryptographically signed and verified
before install. The full threat model is written down in
[`SECURITY.md`](SECURITY.md).

**Self-hosters who want something light.** One systemd service, one
Caddy site, around 60 MB of binary. Redeploys in seconds; auto-rolls
back on a failed health check.

## What it is not

- Not a storage provider — you bring the backend.
- Browser-only — no native desktop sync agent, no mobile app. You open
  the web app, you work with your vault.
- Invite-only by default — you decide who gets in.

## Supported storage backends today

- **WebDAV** — Synology, QNAP, TrueNAS, Unraid, ownCloud, Nextcloud,
  any spec-compliant WebDAV server.
- **SFTP** — any SSH-reachable host, including NASes that only expose
  SSH, Hetzner Storage Boxes, ...
- **S3-compatible object stores** — AWS S3, Cloudflare R2, Wasabi,
  MinIO, Backblaze B2, Storj, ...

All backends store the same encrypted on-disk format, so replicating or
migrating between providers is a straight file copy — no re-encrypt pass.

---

## Table of Contents

1. [Quickstart (local trial)](#quickstart-local-trial)
2. [Production install](#production-install)
3. [Access control](#access-control)
4. [Security model](#security-model)
5. [VPS hardening (optional)](#vps-hardening-optional)
6. [Upgrade & rollback](#upgrade--rollback)
7. [Architecture](#architecture)
8. [Development](#development)
9. [CI/CD and release integrity](#cicd-and-release-integrity)
10. [Licensing & status](#licensing--status)
11. [Contributing](#contributing)

---

## Quickstart (local trial)

Try it on your laptop before you touch a VPS. Requires Rust 1.80+, Node 20+,
wasm-pack, and pnpm 9+.

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

Full dev notes — how the proxy works, how to rotate dev keys, running the
relay or the SPA in isolation — are under [Development](#development).

## Production install

Prerequisites: a fresh Ubuntu 22.04+ VPS with DNS A/AAAA pointing at it.
Install is one command:

```bash
curl -sSLO https://github.com/wattzupbyte/wattcloud/releases/latest/download/install.sh
less install.sh                       # ~150 lines — read before running
sudo bash install.sh cloud.example.com
```

`install.sh` downloads the signed release tarball, `cosign verify-blob`s it
against the pinned Sigstore identity, extracts to
`/opt/wattcloud/releases/vX.Y.Z/`, and delegates to the tarball's
`deploy-vps.sh`. That provisions Caddy for TLS, writes
`/etc/wattcloud/wattcloud.env` with freshly generated signing keys, installs
the sandboxed systemd unit, starts `wattcloud.service`, and health-checks
`/health`. No prompts, no firewall changes, no SSH edits.

Then claim ownership of the instance:

```bash
sudo wattcloud status                  # service + install-tree state
sudo wattcloud claim-token             # prints the one-time bootstrap token
```

Open `https://cloud.example.com`, paste the token into the bootstrap screen,
name the device, and you're the owner. Everything else — invites, revokes,
recovery — lives in *Settings → Access Control*.

Non-interactive install (CI / Ansible / scripted setup):

```bash
sudo bash install.sh cloud.example.com --yes
```

## Access control

Fresh installs run in **invite-only** mode. The gate is enforced server-side
on every operational path — there is no client-side JS check that can be
bypassed via devtools.

`WATTCLOUD_ENROLLMENT_MODE` controls the posture:

| Value                                | Behaviour |
|--------------------------------------|-----------|
| `restricted` (fresh-install default) | Every relay path requires a `wattcloud_device` cookie. Strangers land on an invite-entry screen. |
| `open` (unset default on upgrades)   | No gate. Anyone with the URL can use the relay. |
| Malformed value                      | Treated as `open` with a warning in the log — fail-open so a typo can't lock operators out. Pin the value explicitly if you need strict behaviour. |

Upgrades of pre-existing installs are **not** silently flipped to restricted.
To lock down an existing install, add
`WATTCLOUD_ENROLLMENT_MODE=restricted` to `/etc/wattcloud/wattcloud.env` and
`systemctl restart wattcloud`.

### Claiming ownership (first run)

Restricted mode + zero owners → the relay writes a single-use 32-byte
bootstrap token under its `0700` state dir (expires after 24 h):

```bash
sudo wattcloud claim-token             # prints the token + unlinks the file
```

Paste it into the bootstrap screen at `https://<your-domain>`, choose a
device name, and that device becomes the first owner.

### Inviting additional devices

*Settings → Access Control → Invites*:

1. **Generate invite**, set a label and TTL (1 h / 24 h / 7 d).
2. The server displays the 11-character code **once** in the reveal modal
   (4-4-3 format, e.g. `A7KB-X9MQ-R4S`). After close, only its HMAC hash
   remains on the server — you can revoke but not re-display.
3. Share the code over your preferred channel (Signal, SMS, in person).
4. Invitee opens `https://<your-domain>`, enters the code on the
   invite-entry screen, picks a device name, and is enrolled.

Invite codes are single-use, TTL-bounded, HMAC-hashed at rest. Brute-force
is rate-limited at 5 attempts / 5 min + 10 / hour per IP (counters held in
memory — no IP is persisted to disk; see [Security model](#security-model)).
With 31¹¹ ≈ 3×10¹⁶ entropy the cap is effectively a memory-bound guard.

### Revoking + signing out

*Settings → Access Control → Enrolled devices* lists every enrolled device
(owner + members) with last-seen bucketed to the hour. Clicking **Revoke**
flips the row server-side; the cookie clears on that device's next request.
The sole owner can't revoke themselves from the web path — the backend
returns `409 last_owner`; use the CLI recovery flow below.

**Sign out on this device** (under *This session*) revokes the current
browser's cookie server-side, so a captured cookie cannot be replayed after
sign-out. To come back on that browser, you need a fresh invite.

### Recovery: "I've locked myself out"

Scenario: you were the sole owner, lost access (lost device, cleared
browser, etc.), and no one can mint you an invite.

```bash
sudo wattcloud regenerate-claim-token  # fresh 24h bootstrap token;
                                       # existing owners stay enrolled
sudo wattcloud claim-token             # read + consume the new token
```

Open the bootstrap screen, paste the token, and the new device joins as an
additional owner. Revoke the stale device afterwards from *Access Control*.

### Session lifecycle

- Claim or redeem → 90-day cookie.
- Any relay action within 7 days of expiry triggers a sliding refresh; the
  server mints a new 90-day cookie in the same response. Active users never
  re-enroll.
- 90 days of silence → cookie expires. The web app shows a dedicated
  *session expired* screen explaining how to come back (fresh invite).
  Vault data on the storage provider is untouched.
- Explicit **Sign out on this device** revokes server-side and wipes the
  local hint.

## Security model

See [`SECURITY.md`](SECURITY.md) for the full threat model. The headlines:

- **Post-quantum key exchange.** Every session key is derived from a
  hybrid of X25519 (elliptic-curve Diffie-Hellman) and ML-KEM-1024
  (the NIST-standardized post-quantum KEM, formerly known as Kyber).
  Both components have to fail for a break, and there is no
  classical-only downgrade path. This matters because a well-resourced
  adversary can record your encrypted traffic today and wait — the
  "harvest now, decrypt later" problem. With a post-quantum KEM in
  the handshake, today's captured traffic stays unreadable when
  quantum hardware eventually matures.
- **The server never sees plaintext.** Not your passphrase, not your
  decryption keys (not even a single fragment of them), not your
  private keys, not your file contents, not your filenames, not your
  recovery code. Every request that goes over the wire carries
  encrypted blobs, one-way auth tokens, or public keys — nothing
  reversible. The seven specific invariants are enumerated as
  ZK-1…ZK-7 in `SECURITY.md` for auditors who want to trace them
  through the code.
- **Modern file encryption.** Files are chunked and sealed with
  AES-256-GCM; each chunk is independently authenticated, and each
  file carries a commitment that prevents an attacker from swapping
  keys mid-stream (a "partitioning oracle" attack). Filenames are
  encrypted with a deterministic scheme (AES-GCM-SIV) so the same
  name produces the same ciphertext — that's what lets WebDAV and
  SFTP sync work without re-encrypting a whole directory on every
  change. The on-disk format is versioned; a future change is
  treated as a migration, not a silent rotate.
- **Passphrase hardening.** Your passphrase is stretched with
  Argon2id (64 MB memory, 3 iterations, 4-way parallel) before it
  ever contributes to a key. That's deliberately heavy to make
  brute-force searches expensive even for an attacker with GPU or
  ASIC hardware.
- **Admin access ≠ vault access.** If someone steals your admin
  cookie, they can invite devices or fill your disk — they cannot
  decrypt another member's files. The zero-knowledge guarantees are
  enforced by math in the browser, not by admin policy on the
  server.
- **Privacy-minimized logging.** Caddy strips every client IP and
  credential field from its access log. The relay itself never
  writes client IPs anywhere. journald is kept to 30 days, the
  window `fail2ban` needs to catch repeat offenders. The in-memory
  rate-limiter counters noted under Access Control are the only
  per-IP state anywhere, and they never touch disk. Full posture in
  `SECURITY.md §13.2`.
- **Sandboxed runtime.** The relay runs under a locked-down systemd
  unit: a fresh unprivileged user is minted on each start
  (`DynamicUser=yes`), the root filesystem is read-only
  (`ProtectSystem=strict`), memory pages cannot be both writable and
  executable (`MemoryDenyWriteExecute=yes`), all Linux capabilities
  are dropped, a strict seccomp filter is active, and unused address
  families are blocked. Full unit invariants in `SECURITY.md §13.1`.
- **Signed releases.** Every tarball, `install.sh`, and `CHECKSUMS.txt`
  is signed keyless via Sigstore/cosign and tied to the GitHub
  Actions workflow that built it. `install.sh` and `wattcloud-update`
  verify the signature against a pinned signer identity before
  extraction; if someone swaps a release asset after the fact, the
  install aborts. Forks override `TRUSTED_SIGNER_IDENTITY` in the
  env — no script patching.
- **On-device credential storage.** When you reconnect a storage
  backend on the same browser, the credentials live in the browser's
  IndexedDB wrapped by a non-extractable `CryptoKey` — readable only
  by that exact browser profile, and never sent to the relay.
  *Forget on this device* removes them locally without touching the
  remote vault.

## VPS hardening (optional)

`install.sh` leaves the host's base config untouched — no firewall changes,
no SSH edits, no package installs beyond Caddy and `byo-relay` dependencies.
Operators who want Wattcloud's opinionated hardening bundle run a separate
script:

```bash
sudo wattcloud harden
```

The script prompts per layer: UFW ingress allow-list, `fail2ban` (sshd +
recidive jails), SSH port change + pubkey-only auth, unattended security
updates, GDPR-bounded journald posture, swap sizing, `earlyoom` on low-RAM
hosts, `wattcloud-disk-watchdog` timer, optional AIDE baseline, optional
`msmtp` alerting. SSH changes go through a safety-net that keeps port 22
open until you confirm the new port works.

Non-interactive:

```bash
sudo wattcloud harden --yes \
  --ssh-pubkey ~/.ssh/id_ed25519.pub \
  --with-aide --with-msmtp smtps://user:pass@smtp.example.com:465
```

Selective opt-outs: `--no-ufw`, `--no-fail2ban`, `--no-ssh-harden`,
`--no-unattended-upgrades`, `--no-r5-logging`, `--no-swap`, `--no-earlyoom`,
`--no-disk-watchdog`. Re-running `wattcloud harden` is idempotent for
components that match your existing config.

## Upgrade & rollback

```bash
sudo wattcloud-update              # pull the latest stable release
sudo wattcloud-update vX.Y.Z       # pin to a specific tag
sudo wattcloud-update --rollback   # revert to the previous release
```

What it does:

1. `flock` so two invocations can't race.
2. Resolve the target tag via the GitHub API (stable only; prereleases
   skipped).
3. Download the tarball + `.sig` + `.cert` and `cosign verify-blob` against
   `TRUSTED_SIGNER_IDENTITY`.
4. Extract to `/opt/wattcloud/releases/vX.Y.Z/`.
5. Diff `.env.example` against the live env; abort with a human-readable
   list if required keys are missing.
6. Reinstall `wattcloud.service` only if the unit file changed, then
   `daemon-reload`.
7. Atomic symlink swap of `/opt/wattcloud/current`.
8. `systemctl reload-or-restart wattcloud`, poll `/health` for up to 30 s.
   If the new version doesn't come back, **the symlink and unit are rolled
   back and the service is restarted**. Broken deploys never persist as
   `current`.
9. Prune all but the last 3 release directories (override via
   `WC_KEEP_RELEASES`).

Past releases stay on disk, so `--rollback` is free.

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
| `packaging` | Assets | Systemd unit, Caddyfile template, `config.json` template. Shipped inside the tarball. |
| `scripts` | Bash | `install.sh`, `deploy-vps.sh`, `harden-vps.sh`, `update.sh`, `uninstall.sh`, `lib.sh` (tarball-shipped); `ci.sh`, `byo-smoke.sh` (dev). |

Deeper references: [`SPEC.md`](SPEC.md) for the protocol, [`SECURITY.md`](SECURITY.md)
for the threat model, [`DESIGN.md`](DESIGN.md) for the visual and UX system,
[`CLAUDE.md`](CLAUDE.md) for the repo conventions.

## Development

Rust 1.80+, Node 20+, wasm-pack, pnpm 9+. `make help` lists every target.
These are contributor and self-builder tools; operators running a production
install never touch Make.

```bash
make dev               # byo-relay (:8443) + Vite (:5173), foreground
make dev-stop          # SIGTERM a running stack (via PID file)
make dev-frontend      # Vite only — use when a relay is already running
make dev-relay         # byo-relay only — bootstraps .env.dev on first run
make claim-token       # dev parity with `sudo wattcloud claim-token`
make build             # wasm-pack + Vite build, in order
make test              # cargo + npm across the repo
make lint              # cargo clippy + eslint
make fmt               # cargo fmt
make ci                # full local CI (mirrors GitHub Actions)
```

`make dev` runs `scripts/dev.sh`, which:

- Generates `.env.dev` on first run (gitignored, persisted) with ephemeral
  JWT/HMAC signing keys. Delete it to rotate — you'll need to re-enroll.
- Starts `byo-relay` via `cargo run` on `127.0.0.1:8443`.
- Waits for `/health`, then launches Vite on `:5173`. Vite proxies
  `/relay/*`, `/health`, and `/ready` to the relay so the SPA talks
  same-origin — no CORS plumbing.
- Cleans up both processes on Ctrl-C.

On a laptop, `make dev` + Ctrl-C is the natural loop. On a dev VPS, wrap
`make dev` in your own tmux / screen / systemd — the Makefile doesn't own
lifecycle beyond the foreground process and its PID file.

Packaging and release artifacts (local build; cosign signing is not
available locally — it needs the Actions OIDC token):

```bash
make tarball           # host-arch tarball → dist/
make tarball-all       # cross-compile x86_64 + aarch64 (needs `cross`)
make smoke-tarball     # scripts/byo-smoke.sh against the local build
make verify-tarball TARBALL=… SIG=… CERT=…   # cosign-verify a downloaded asset
make docker-image      # self-builder-only Docker image (not a release artifact)
```

Real releases flow through a signed `v*.*.*` tag → `release.yml`.

Cleanup:

```bash
make clean             # cargo clean + rm node_modules / dist / pkg / target
make clean-docker      # prune dangling self-builder images
make clean-all         # both
```

## CI/CD and release integrity

Two workflows under `.github/workflows/`:

- **`ci.yml`** — on push/PR: `cargo test` + clippy + fmt for the sdk
  workspace and `byo-relay`; `npm test` + lint + build for the frontend;
  `wasm-pack build`; `systemd-analyze verify` on the unit; `caddy validate`
  on the rendered Caddyfile; `scripts/byo-smoke.sh` against the built
  release binary.
- **`release.yml`** — on `v*.*.*` tag: cross-compiles `byo-relay` for
  `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, builds the
  frontend, assembles per-arch tarballs in the install layout, **keyless
  cosign sign-blob** each tarball + `install.sh` + `CHECKSUMS.txt` via
  Actions OIDC, and publishes the GitHub Release. Prerelease tags (any `-`
  suffix — e.g. `v1.0.0-rc.1`) are flagged so they don't feed
  `/releases/latest/download`.
- **`dependabot.yml`** keeps pinned action SHAs, Cargo deps, and npm deps
  updated.

All third-party actions are pinned by commit SHA. The release trust chain
is specified in `SECURITY.md §13`: `install.sh` and `wattcloud-update` run
`cosign verify-blob` with a pinned `certificate-identity-regexp` before
extraction. A swapped GitHub release asset fails verification and the
scripts abort.

`scripts/ci.sh` mirrors the Actions `ci.yml` command set for local runs.

## Licensing & status

**Status.** Personal project. The encrypted on-disk format and the
zero-knowledge invariants are stable — changes would make existing
vaults undecryptable, so they're treated as protocol version bumps, not
refactors. Install flow and packaging are production-shaped and
exercised in CI. The codebase has not had a third-party security audit;
run it on data you could afford to lose, or keep an independent backup.

**Development style.** Wattcloud is developed with extensive AI
pair-programming ("vibe coding"). Design-level decisions — protocol,
cryptographic choices, threat model, license — are the maintainer's.
Implementation-level diffs are reviewed for behavior and spot-checked
before they land, but are not line-by-line hand-audited. The "vibe
coding" label is used honestly; weight the codebase accordingly and
treat the lack of a third-party security audit (noted above) as
load-bearing.

**License.** AGPL-3.0-or-later — see [`LICENSE`](LICENSE). You are free
to use, study, modify, and distribute Wattcloud under the terms of the
GNU Affero General Public License version 3. The notable wrinkle versus
plain GPL: if you run a modified version of Wattcloud as a
network-accessible service, you must make your modifications available
to the users of that service under the same license. Running unmodified
signed releases on your own infrastructure for your own use is standard
self-hosting and triggers no extra obligations.

The Wattcloud name and wordmark are not covered by the AGPL and are
reserved by the project — forks must be renamed.

## Contributing

This is a personal project and patches are not being actively solicited
yet. Security findings are welcome — please open a GitHub security
advisory rather than a public issue; `SECURITY.md` documents the intake
process. When the project opens up further, contributions that improve
security, the BYO protocol, or provider coverage will be most welcome.
All contributions are accepted under the project's AGPL-3.0 license; by
opening a PR you agree that your work is licensed on the same terms.
