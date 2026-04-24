# packaging/dev-host — Caddy setup for dev.wattcloud.de

Files in this directory configure the dedicated dev VPS at
`dev.wattcloud.de` (host: `85.215.218.41`). They are **not** part of the
production tarball layout — that lives one directory up
(`packaging/Caddyfile.tmpl`, rendered by `scripts/deploy-vps.sh`).

Use when you want a persistent `make dev` reachable over HTTPS at a stable
hostname, without going through the full tarball + systemd + cosign
production path.

## Layout

| File | Role |
|------|------|
| `Caddyfile` | TLS termination for `dev.wattcloud.de` + reverse proxy to Vite on 127.0.0.1:5173. |
| `config.json` | SPA runtime config override served at `/config.json` (pins `baseUrl` to `https://dev.wattcloud.de`). |
| `install.sh` | Idempotent installer: apt-installs Caddy, drops the above files into place, validates, stops+removes the old Traefik container, starts Caddy. |

## How it fits together

```
Browser ──HTTPS──▶ Caddy (:443)
                     │
                     ├─ /config.json  →  /var/www/wattcloud-dev-overrides/config.json
                     │                   (baseUrl = https://dev.wattcloud.de)
                     │
                     └─ everything else →  127.0.0.1:5173 (Vite, started by `make dev`)
                                           │
                                           └─ /relay/*, /health, /ready  →  127.0.0.1:8443 (byo-relay)
```

`frontend/public/config.json` in the repo stays pinned to
`http://localhost:5173` — correct for a developer running `make dev` on a
laptop. Caddy intercepts `/config.json` on this host only and serves the
host-tailored file, so neither file needs to be machine-specific in git.

## Install

```bash
sudo bash packaging/dev-host/install.sh
```

Then (as `appuser`):

```bash
cd /home/appuser/projects/wattcloud
make dev     # or: `make dev` inside tmux / screen so it survives disconnect
```

Verify:

```bash
curl -I https://dev.wattcloud.de/                 # 200 (index.html)
curl    https://dev.wattcloud.de/config.json      # baseUrl = https://dev.wattcloud.de
curl    https://dev.wattcloud.de/health           # "ok" (via Vite → byo-relay proxy)
```

## Rollback

Traefik's ACME state (`/home/appuser/projects/secure-cloud/traefik/acme.json`)
is a bind-mount and was left untouched. To revert:

```bash
sudo systemctl stop caddy
docker compose -f /home/appuser/projects/secure-cloud/docker-compose.yml \
                -f /home/appuser/projects/secure-cloud/docker-compose.dev.yml \
                up -d traefik
```

## Caveats

- `make dev` must be running for `/` to serve anything — Caddy returns 502
  from `reverse_proxy` when Vite is down. Consider a `tmux new -s dev` +
  `make dev` session so a dropped SSH connection doesn't kill the app.
- Re-running `docker compose up` in the `secure-cloud` project will try to
  start Traefik again and fail to bind :80/:443. Don't.
- OAuth providers (Google / Dropbox / …) need their console-side redirect
  URI updated to `https://dev.wattcloud.de/oauth/callback` before the
  corresponding `BYO_*_CLIENT_ID` in `config.json` will produce a working
  sign-in flow.
