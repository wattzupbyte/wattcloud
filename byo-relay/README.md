# byo-relay

Stateless relay server for BYO (Bring Your Own storage) mode.

Handles:
- WebSocket SFTP relay (`/relay/ws`)
- Share-link relay endpoints (`/relay/share/b1`, `/relay/share/b2`)
- Usage stats ingest (`/relay/stats`)
- Static SPA serving

## Configuration

All config is via environment variables.

| Env var | Default | Required? |
|---------|---------|-----------|
| `BIND_ADDR` | `0.0.0.0:8443` | no |
| `SPA_DIR` | `/app/dist` | no |
| `TLS_CERT` | — | yes (path to PEM cert) |
| `TLS_KEY` | — | yes (path to PEM key) |
| `JWT_SECRET` | — | yes (relay auth signing key) |
| `STATS_HMAC_KEY` | — | **yes** (hex or base64, ≥ 32 B) |
| `STATS_DB_PATH` | `/var/lib/byo-relay/stats.sqlite3` | no |
| `STATS_INGEST_PER_MIN` | `10` | no |
| `STATS_BATCH_MAX_EVENTS` | `200` | no |
| `STATS_MAX_BODY_BYTES` | `65536` | no |
| `SHARE_STORAGE_DIR` | `/var/lib/byo-relay/shares` | no |
| `SHARE_DB_PATH` | `/var/lib/byo-relay/shares.sqlite3` | no |
| `SHARE_DAILY_BYTES_PER_IP` | `53687091200` (50 GiB) | no |
| `RUST_LOG` | `warn` | no |

All state (`stats.sqlite3`, `shares.sqlite3`, `shares/*.v7` blobs) lives
under `/var/lib/byo-relay`. The Docker image declares that directory as
a `VOLUME`, so persisting a named volume across container rebuilds
(e.g. `-v wattcloud-data:/var/lib/byo-relay`) is all that's needed to
keep stats + active share blobs between restarts.

`STATS_HMAC_KEY` is required — the server refuses to start without it. This key
is used to HMAC-SHA256 device UUIDs before storing them in SQLite so that the
database contains no raw UUIDs.

## SFTP WebSocket verbs (`/relay/ws`)

JSON-RPC over a single WebSocket per client session. The handshake frame
includes a `relay_version` field that clients feature-detect against.

Current protocol version: **3**. Version history:

| Version | Added |
|---------|-------|
| 1 | Single-shot `write` verb (retired — clients now require v2+) |
| 2 | Streaming upload (`write_open` / `write_chunk` / `write_close` / `write_abort`) |
| 3 | Streaming download (`read_open` / `read_chunk` / `read_close`) |

**Streaming upload** (v2+). `write_open` returns a random 128-bit handle;
`write_chunk` frames are 16 MiB max; relay-side buffer aggregated across all
open sessions for a connection caps at 200 MiB.

**Streaming download** (v3). `read_open` opens an SFTP file handle on the
remote server and returns a random 128-bit handle; each `read_chunk` reads
up to 256 KiB and responds with a JSON header + binary frame (empty binary
signals EOF); `read_close` drops the session. Up to 8 concurrent open read
sessions per WebSocket connection. Handles left open when the client
disconnects are closed asynchronously via `russh_sftp::File::Drop`.

## Usage Statistics

Usage stats are aggregated in SQLite at `STATS_DB_PATH`. Clients POST batches of
events to `POST /relay/stats` every 60 seconds (and on tab hide). The server
hashes device IDs, validates and clamps all fields, and inserts only into
aggregate counter tables — no per-event rows are persisted.

### Admin CLI

The `byo-admin` binary ships in the same container image:

```bash
# View aggregated stats
docker compose exec byo-relay byo-admin log --granularity daily
docker compose exec byo-relay byo-admin log --granularity weekly
docker compose exec byo-relay byo-admin log --granularity monthly \
  --from 2026-01-01 --to 2026-04-01

# Wipe all stats rows (leaves schema intact)
docker compose exec -it byo-relay byo-admin clear
```

Or via the Makefile shortcuts:

```bash
make stats-log
make stats-log GRAN=weekly
make stats-log GRAN=monthly FROM=2026-01-01 TO=2026-04-01
make stats-clear
```

### Privacy

- No IP addresses are logged or stored anywhere in the stats path.
- Device UUIDs are HMAC-SHA256 hashed before storage (`STATS_HMAC_KEY`).
- `bytes` fields only accept ciphertext sizes (V7 frames, relay blobs, SFTP frames).
- No filenames, user IDs, or plaintext content can enter the wire format.

## Build

```bash
# Local
cargo build --release

# Docker (static musl binary)
docker build -t byo-relay .
```

## Tests

```bash
cargo test
cargo test --bin byo-admin
```
