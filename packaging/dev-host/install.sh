#!/usr/bin/env bash
# install.sh — replace Traefik with Caddy on the dev.wattcloud.de host.
#
# Idempotent. Run once as root (sudo). Leaves Traefik's acme.json in place
# so a rollback is a matter of `docker compose -f … start traefik` after
# stopping Caddy.
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVERRIDE_DIR=/var/www/wattcloud-dev-overrides

step() { printf '\n\033[1;36m[%s]\033[0m %s\n' "$1" "$2"; }

# 1. Install Caddy from its official apt repo (Ubuntu 24.04).
if ! command -v caddy >/dev/null 2>&1; then
  step "1/6" "Installing Caddy from cloudsmith.io..."
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update
  apt-get install -y caddy
else
  step "1/6" "Caddy already installed: $(caddy version | head -1)"
fi

# 2. Deploy Caddyfile and SPA config override.
step "2/6" "Deploying /etc/caddy/Caddyfile + $OVERRIDE_DIR/config.json"
install -d -m 0755 /etc/caddy
install -m 0644 "$HERE/Caddyfile" /etc/caddy/Caddyfile
install -d -m 0755 "$OVERRIDE_DIR"
install -m 0644 "$HERE/config.json" "$OVERRIDE_DIR/config.json"

# 3. Validate before touching anything that can affect traffic.
step "3/6" "Validating Caddyfile..."
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

# 4. Stop + remove the Traefik container (compose project: secure-cloud).
#    acme.json is a bind-mount into the host filesystem, so it stays put
#    and can be re-mounted if the user ever wants to roll back.
step "4/6" "Stopping + removing secure-cloud-traefik (acme.json preserved on host)..."
if docker ps -a --format '{{.Names}}' | grep -qx 'secure-cloud-traefik'; then
  docker stop  secure-cloud-traefik >/dev/null
  docker rm -f secure-cloud-traefik >/dev/null
else
  echo "     (secure-cloud-traefik not present — skipping)"
fi

# 5. Enable + (re)start Caddy. systemctl restart covers the case where
#    caddy.service auto-started on install and bound-failed because of Traefik.
step "5/6" "Enabling + starting caddy.service..."
systemctl enable caddy >/dev/null 2>&1 || true
systemctl restart caddy

# 6. Report status.
step "6/6" "Done. caddy status:"
systemctl --no-pager --lines=0 status caddy | head -5
echo
echo "Next: start the app with 'make dev' (as appuser, in /home/appuser/projects/wattcloud)."
echo "Then: curl -I https://dev.wattcloud.de/"
