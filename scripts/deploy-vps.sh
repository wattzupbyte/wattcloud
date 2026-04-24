#!/usr/bin/env bash
# deploy-vps.sh — first-run app provisioning for a Wattcloud VPS.
#
# Invoked by install.sh after the signed tarball has been extracted to
# /opt/wattcloud/releases/<version>/. Can also be run standalone from
# inside an extracted tarball for manual reprovisioning.
#
# Scope is intentionally narrow: install Caddy, write env + config, install
# systemd unit, start services, health-check. VPS hardening (UFW, fail2ban,
# SSH lockdown, R5 logging, swap, earlyoom, disk-watchdog, AIDE, msmtp) is
# a separate opt-in step — run `sudo wattcloud harden` after install.
set -euo pipefail

# ---------------------------------------------------------------------------
# Bootstrap: locate script home + load lib.sh
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WC_EXTRACTED_DIR="${WC_EXTRACTED_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

# ---------------------------------------------------------------------------
# Args & flags
# ---------------------------------------------------------------------------
usage() {
  cat <<'USAGE'
Usage: deploy-vps.sh DOMAIN [flags]

Required:
  DOMAIN                      FQDN serving the SPA + relay (e.g. cloud.example.com)

Flags:
  --email EMAIL               Let's Encrypt email (default: admin@DOMAIN)
  --yes, --non-interactive    (reserved; app install never prompts)
  --trusted-signer REGEX      cosign identity for future updates
  --help

VPS hardening (UFW, fail2ban, SSH lockdown, R5 logging, swap, earlyoom,
disk-watchdog, AIDE, msmtp) is a separate opt-in step. After this install
completes, run:   sudo wattcloud harden
USAGE
}

DOMAIN=""
EMAIL=""
NON_INTERACTIVE=0
TRUSTED_SIGNER="${WC_SIGNER_IDENTITY:-$WC_DEFAULT_SIGNER_IDENTITY}"

while [ $# -gt 0 ]; do
  case "$1" in
    --email)                EMAIL="$2"; shift 2 ;;
    --yes|--non-interactive) NON_INTERACTIVE=1; shift ;;
    --trusted-signer)       TRUSTED_SIGNER="$2"; shift 2 ;;
    --help|-h)              usage; exit 0 ;;
    --*)                    warn "unknown flag ignored: $1"; shift ;;
    *)
      if [ -z "$DOMAIN" ]; then DOMAIN="$1"; shift
      else die "unexpected positional argument: $1"
      fi
      ;;
  esac
done

[ -n "$DOMAIN" ]          || { usage; exit 1; }
[ -z "$EMAIL" ] && EMAIL="admin@$DOMAIN"
require_root

VERSION_SLUG="${WC_INSTALL_VERSION:-$(basename "$WC_EXTRACTED_DIR")}"

# ---------------------------------------------------------------------------
# App provisioning
# ---------------------------------------------------------------------------
install_caddy() {
  if command -v caddy >/dev/null 2>&1; then
    ok "Caddy already installed: $(caddy version | head -1)"
    return 0
  fi
  info "Installing Caddy via Cloudsmith repository..."
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https >/dev/null
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy >/dev/null
  ok "Caddy installed: $(caddy version | head -1)"
}

write_env_file() {
  install -d -m 0700 "$WC_ENV_DIR"
  if [ ! -f "$WC_ENV_FILE" ]; then
    info "Generating initial $WC_ENV_FILE..."
    touch "$WC_ENV_FILE"
    chmod 0600 "$WC_ENV_FILE"

    env_set "BYO_DOMAIN"                "$DOMAIN"                           "$WC_ENV_FILE"
    env_set "BYO_BASE_URL"              "https://$DOMAIN"                   "$WC_ENV_FILE"
    env_set "ENVIRONMENT"               "production"                        "$WC_ENV_FILE"
    env_set "RELAY_SIGNING_KEY"         "$(openssl rand -base64 48)"        "$WC_ENV_FILE"
    env_set "RELAY_SHARE_SIGNING_KEY"   "$(openssl rand -base64 48)"        "$WC_ENV_FILE"
    env_set "STATS_HMAC_KEY"            "$(openssl rand -hex 32)"           "$WC_ENV_FILE"
    env_set "TRUSTED_PROXY_IPS"         "127.0.0.1,::1"                     "$WC_ENV_FILE"
    env_set "TRUSTED_SIGNER_IDENTITY"   "$TRUSTED_SIGNER"                   "$WC_ENV_FILE"
    env_set "ACME_EMAIL"                "$EMAIL"                            "$WC_ENV_FILE"
    # Access Control (§Access Control in README). Fresh installs default to
    # invite-only so a random page visitor can't drive the relay. Set to
    # `open` (or delete the line) to run a public instance. Operators on
    # existing installs that upgrade will NOT get this written — env-absent
    # preserves Open, matching backcompat. See SPEC.md §/relay/info.
    env_set "WATTCLOUD_ENROLLMENT_MODE"  "restricted"                        "$WC_ENV_FILE"
    # OAuth client IDs — deferred. Placeholders kept so the file shape matches
    # what oauth-setup.sh expects when the OAuth flow is re-enabled.
    env_set "BYO_GDRIVE_CLIENT_ID"      ""                                  "$WC_ENV_FILE"
    env_set "BYO_DROPBOX_CLIENT_ID"     ""                                  "$WC_ENV_FILE"
    env_set "BYO_ONEDRIVE_CLIENT_ID"    ""                                  "$WC_ENV_FILE"
    env_set "BYO_BOX_CLIENT_ID"         ""                                  "$WC_ENV_FILE"
    env_set "BYO_PCLOUD_CLIENT_ID"      ""                                  "$WC_ENV_FILE"
    ok "$WC_ENV_FILE created (0600 root)."
  else
    ok "$WC_ENV_FILE exists — preserving existing values."
    # Keep TRUSTED_SIGNER_IDENTITY in sync with what was passed.
    env_set "TRUSTED_SIGNER_IDENTITY" "$TRUSTED_SIGNER" "$WC_ENV_FILE"
  fi
}

install_systemd_unit() {
  install -m 0644 "$WC_EXTRACTED_DIR/packaging/wattcloud.service" "$WC_SYSTEMD_UNIT"
  systemctl daemon-reload
  ok "systemd unit installed → $WC_SYSTEMD_UNIT"
}

install_caddyfile() {
  install -d -m 0755 /etc/caddy
  sed -e "s|@@DOMAIN@@|$DOMAIN|g" \
      -e "s|@@ACME_EMAIL@@|$EMAIL|g" \
      "$WC_EXTRACTED_DIR/packaging/Caddyfile.tmpl" > "$WC_CADDYFILE"
  chmod 0644 "$WC_CADDYFILE"
  if command -v caddy >/dev/null 2>&1; then
    caddy validate --config "$WC_CADDYFILE" >/dev/null 2>&1 \
      || die "Caddyfile validation failed — check $WC_CADDYFILE."
  fi
  ok "Caddyfile installed → $WC_CADDYFILE"
}

write_runtime_config_json() {
  # shellcheck disable=SC1090
  set -a; source "$WC_ENV_FILE"; set +a
  local out="$WC_EXTRACTED_DIR/web/config.json"
  sed -e "s|@@DOMAIN@@|$DOMAIN|g" \
      -e "s|@@BYO_GDRIVE_CLIENT_ID@@|${BYO_GDRIVE_CLIENT_ID:-}|g" \
      -e "s|@@BYO_DROPBOX_CLIENT_ID@@|${BYO_DROPBOX_CLIENT_ID:-}|g" \
      -e "s|@@BYO_ONEDRIVE_CLIENT_ID@@|${BYO_ONEDRIVE_CLIENT_ID:-}|g" \
      -e "s|@@BYO_BOX_CLIENT_ID@@|${BYO_BOX_CLIENT_ID:-}|g" \
      -e "s|@@BYO_PCLOUD_CLIENT_ID@@|${BYO_PCLOUD_CLIENT_ID:-}|g" \
      "$WC_EXTRACTED_DIR/packaging/config.json.tmpl" > "$out"
  chmod 0644 "$out"
  command -v jq >/dev/null 2>&1 && jq -e . < "$out" >/dev/null \
    || warn "config.json validation skipped (jq not installed)."
  ok "Runtime config.json written → $out"
}

swap_current_symlink() {
  ln -sfn "$WC_EXTRACTED_DIR" "$WC_CURRENT_LINK.new"
  mv -T "$WC_CURRENT_LINK.new" "$WC_CURRENT_LINK"
  ok "Symlink $WC_CURRENT_LINK → $WC_EXTRACTED_DIR"
}

install_cli_wrappers() {
  # wattcloud-update: hardlink / copy of update.sh for ease of discovery.
  install -m 0755 "$WC_EXTRACTED_DIR/scripts/update.sh" /usr/local/bin/wattcloud-update
  # wattcloud: small dispatcher wrapper.
  cat > /usr/local/bin/wattcloud <<'CLI'
#!/usr/bin/env bash
# wattcloud — dispatcher for /opt/wattcloud/current/scripts/*.sh
set -euo pipefail
CURRENT="/opt/wattcloud/current"
# Default path fallbacks — must match packaging/wattcloud.service's
# Environment= overrides. Rust's bare-binary defaults are
# /var/lib/byo-relay/* (Docker volume convention); systemd rewrites them
# under StateDirectory=wattcloud so ProtectSystem=strict doesn't block.
# The wrapper mirrors the systemd choice so `sudo wattcloud claim-token`
# looks in the same spot the relay writes to.
BOOTSTRAP_TOKEN_PATH="${BOOTSTRAP_TOKEN_PATH:-/var/lib/wattcloud/bootstrap.txt}"
ENROLLMENT_DB_PATH="${ENROLLMENT_DB_PATH:-/var/lib/wattcloud/enrollment.sqlite3}"
ENV_FILE="${WATTCLOUD_ENV_FILE:-/etc/wattcloud/wattcloud.env}"

case "${1:-status}" in
  oauth-setup|setup-oauth) exec "$CURRENT/scripts/oauth-setup.sh" "${@:2}" ;;
  harden)                  exec "$CURRENT/scripts/harden-vps.sh" "${@:2}" ;;
  update)                  exec /usr/local/bin/wattcloud-update "${@:2}" ;;
  rollback)                exec /usr/local/bin/wattcloud-update --rollback "${@:2}" ;;
  claim-token)
    # Print the bootstrap token (written by byo-relay at startup in restricted
    # mode, or by `wattcloud regenerate-claim-token`), then unlink the file.
    # Single-use + short-TTL semantics are enforced by the relay; unlinking
    # removes the plaintext copy from disk on first read.
    if [[ -f "$BOOTSTRAP_TOKEN_PATH" ]]; then
      tok="$(cat "$BOOTSTRAP_TOKEN_PATH")"
      rm -f "$BOOTSTRAP_TOKEN_PATH" || true
      printf '%s\n' "$tok"
    else
      echo "No bootstrap token at $BOOTSTRAP_TOKEN_PATH." >&2
      echo "The token has already been consumed, or the relay is in open mode." >&2
      echo "To mint a fresh one:" >&2
      echo "  sudo wattcloud regenerate-claim-token" >&2
      exit 1
    fi
    ;;
  regenerate-claim-token)
    # Non-destructive recovery: mint a fresh bootstrap token so a new owner
    # device can claim (existing owners stay enrolled). Requires the relay
    # signing key; read it from the env file if present.
    if [[ -r "$ENV_FILE" ]]; then
      # shellcheck disable=SC1090
      set -a; . "$ENV_FILE"; set +a
    fi
    if [[ -z "${RELAY_SIGNING_KEY:-}" ]]; then
      echo "error: RELAY_SIGNING_KEY not set (checked $ENV_FILE)" >&2
      exit 1
    fi
    exec "$CURRENT/bin/byo-admin" regenerate-bootstrap-token \
      --enrollment-db "$ENROLLMENT_DB_PATH" \
      --token-path "$BOOTSTRAP_TOKEN_PATH" \
      --signing-key "$RELAY_SIGNING_KEY" \
      "${@:2}"
    ;;
  status)
    echo "Wattcloud: $(readlink -f "$CURRENT" 2>/dev/null || echo 'not installed')"
    systemctl is-active wattcloud 2>/dev/null && echo "service: active" || echo "service: inactive"
    ;;
  uninstall)              exec "$CURRENT/scripts/uninstall.sh" "${@:2}" ;;
  *)
    cat >&2 <<USAGE
wattcloud <command>

Commands:
  status                     show install + service state (default)
  claim-token                read + consume the bootstrap token file
  regenerate-claim-token     mint a fresh bootstrap token (recovery)
  harden                     apply the opinionated VPS hardening bundle (opt-in)
  update                     upgrade to the latest release (or pass a version)
  rollback                   revert to the previous release
  oauth-setup                interactive OAuth provider wizard (when OAuth ships)
  uninstall                  remove Wattcloud from this host
USAGE
    exit 1
    ;;
esac
CLI
  chmod 0755 /usr/local/bin/wattcloud
  ok "CLI wrappers installed: /usr/local/bin/wattcloud, /usr/local/bin/wattcloud-update"
}

enable_services() {
  systemctl enable --now wattcloud >/dev/null 2>&1
  systemctl enable --now caddy >/dev/null 2>&1
  ok "wattcloud + caddy services enabled."
}

health_check() {
  info "Waiting for /health on 127.0.0.1:8443..."
  local i
  for i in $(seq 1 30); do
    if curl -fsS --max-time 2 "http://127.0.0.1:8443/health" 2>/dev/null | grep -q ok; then
      ok "/health → ok (after ${i}s)"
      return 0
    fi
    sleep 1
  done
  warn "byo-relay /health did not respond within 30s. Check 'journalctl -u wattcloud -e'."
  return 1
}

provision_app() {
  info "Provisioning Wattcloud app (Caddy + byo-relay)."
  install_caddy
  write_env_file
  install_systemd_unit
  install_caddyfile
  write_runtime_config_json
  swap_current_symlink
  install_cli_wrappers
  enable_services
  health_check || warn "Continuing despite health-check timeout; inspect logs post-deploy."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
  local active; active="$(systemctl is-active wattcloud 2>/dev/null || echo inactive)"
  local caddy_active; caddy_active="$(systemctl is-active caddy 2>/dev/null || echo inactive)"

  echo "" >&2
  printf '%s\n' "$(_color '0;32' '============================================')" >&2
  printf '%s\n' "$(_color '0;32' ' Wattcloud app installed')" >&2
  printf '%s\n' "$(_color '0;32' '============================================')" >&2
  echo "  version:          $VERSION_SLUG" >&2
  echo "  domain:           https://$DOMAIN" >&2
  echo "  env file:         $WC_ENV_FILE" >&2
  echo "  systemd unit:     $WC_SYSTEMD_UNIT ($active)" >&2
  echo "  caddy:            $WC_CADDYFILE ($caddy_active)" >&2
  echo "  install tree:     $WC_INSTALL_DIR (current → $(readlink "$WC_CURRENT_LINK" 2>/dev/null || echo '?'))" >&2
  echo "" >&2

  echo "  Next steps:" >&2
  echo "   1. Ensure DNS A/AAAA for $DOMAIN points to this VPS (Caddy needs it for ACME)." >&2
  echo "   2. Verify from outside:  curl -I https://$DOMAIN  (should 200 once DNS + cert propagates)." >&2
  echo "   3. Claim ownership on this box:" >&2
  echo "        sudo wattcloud claim-token   # prints the one-time bootstrap token" >&2
  echo "      Then open https://$DOMAIN in your browser and paste it into the" >&2
  echo "      bootstrap screen. See README §Access Control for the full flow." >&2
  echo "   4. (optional) Apply the opinionated VPS hardening bundle:  sudo wattcloud harden" >&2
  echo "   5. Upgrade later with:  sudo wattcloud-update" >&2
  echo "" >&2
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
info "Wattcloud deploy-vps.sh starting — domain=$DOMAIN version=$VERSION_SLUG (non_interactive=$NON_INTERACTIVE)"

provision_app
print_summary

ok "App install complete."
