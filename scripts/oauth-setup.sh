#!/usr/bin/env bash
# oauth-setup.sh — interactive OAuth provider configuration wizard.
#
# Invoked by `wattcloud oauth-setup`. Walks the operator through each
# provider's developer console (URL, required scope, redirect URI
# pre-filled with this host's DOMAIN), reads back the client IDs, writes
# them atomically into /etc/wattcloud/wattcloud.env, regenerates
# config.json, and reloads byo-relay so the SPA picks up the change.
#
# Provider-side steps (creating the OAuth app, accepting the ToS, etc.) are
# not scriptable from a headless VPS. This wizard reduces the operator
# work to: click the link, create the app with the listed scope and
# redirect URI, paste the client ID back here.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'USAGE'
Usage: wattcloud oauth-setup [--reconfigure]

  (no flags)        configure any providers that are currently empty
  --reconfigure     reset + prompt for all providers (including configured)
  --help
USAGE
}

RECONFIGURE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --reconfigure) RECONFIGURE=1; shift ;;
    --help|-h)     usage; exit 0 ;;
    *)             die "unknown arg: $1" ;;
  esac
done

require_root
[ -f "$WC_ENV_FILE" ] || die "$WC_ENV_FILE not found — is Wattcloud installed?"
[ -L "$WC_CURRENT_LINK" ] || die "$WC_CURRENT_LINK missing — is Wattcloud installed?"

DOMAIN="$(env_get BYO_DOMAIN "$WC_ENV_FILE")"
[ -n "$DOMAIN" ] || die "BYO_DOMAIN not set in $WC_ENV_FILE"

TEMPLATE="$WC_CURRENT_LINK/packaging/config.json.tmpl"
CONFIG_OUT="$WC_CURRENT_LINK/web/config.json"
[ -f "$TEMPLATE" ] || die "config.json template missing: $TEMPLATE"

# ---------------------------------------------------------------------------
# Provider catalog — pipe-separated: key|name|console|scope|regex
# ---------------------------------------------------------------------------
PROVIDERS=(
  "GDRIVE|Google Drive|https://console.cloud.google.com/apis/credentials|drive.file (sensitive scope)|^[0-9]+-[A-Za-z0-9_]+\.apps\.googleusercontent\.com$"
  "DROPBOX|Dropbox|https://www.dropbox.com/developers/apps|Scoped access · files.content.read + files.content.write|^[A-Za-z0-9]{12,20}$"
  "ONEDRIVE|OneDrive|https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade|Files.ReadWrite (Microsoft Graph)|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
  "BOX|Box|https://app.box.com/developers/console|root_readwrite · OAuth 2.0 with PKCE|^[A-Za-z0-9]{20,64}$"
  "PCLOUD|pCloud|https://docs.pcloud.com/my_apps/|Manage files|^[A-Za-z0-9]{6,40}$"
)

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
changed=0
echo "" >&2
printf '%s\n' "$(_color '0;34' 'Wattcloud OAuth setup')" >&2
echo "Domain:       https://$DOMAIN" >&2
echo "Env file:     $WC_ENV_FILE" >&2
[ "$RECONFIGURE" -eq 1 ] && echo "Mode:         reconfigure (all providers)" >&2
echo "" >&2

for entry in "${PROVIDERS[@]}"; do
  IFS='|' read -r key name console scope regex <<< "$entry"
  envvar="BYO_${key}_CLIENT_ID"
  current="$(env_get "$envvar" "$WC_ENV_FILE")"

  if [ -n "$current" ] && [ "$RECONFIGURE" -eq 0 ]; then
    ok "$name: already configured ($envvar), skipping. Use --reconfigure to change."
    continue
  fi

  echo "" >&2
  printf '%s\n' "$(_color '1;33' "── ${name} ──")" >&2
  echo "  1. Open: $console" >&2
  echo "  2. Create an OAuth 2.0 client with the scope:" >&2
  echo "       $scope" >&2
  echo "  3. Register this redirect URI (EXACT match):" >&2
  echo "       https://$DOMAIN" >&2
  echo "" >&2
  echo "  Paste the client ID here (or press Enter to skip $name):" >&2
  printf '    %s = ' "$envvar" >&2
  read -r cid
  cid="${cid// /}"  # strip whitespace

  if [ -z "$cid" ]; then
    warn "$name skipped."
    continue
  fi

  if ! [[ "$cid" =~ $regex ]]; then
    warn "That doesn't look like a valid $name client ID (regex: $regex)."
    printf '    Use it anyway? [y/N]: ' >&2
    read -r confirm
    [ "${confirm,,}" = "y" ] || { warn "$name skipped."; continue; }
  fi

  env_set "$envvar" "$cid" "$WC_ENV_FILE"
  ok "$name: $envvar written."
  changed=1
done

if [ "$changed" -eq 0 ]; then
  echo "" >&2
  ok "No changes made."
  exit 0
fi

# ---------------------------------------------------------------------------
# Regenerate config.json + reload byo-relay
# ---------------------------------------------------------------------------
echo "" >&2
info "Regenerating $CONFIG_OUT..."
# shellcheck disable=SC1090
set -a; source "$WC_ENV_FILE"; set +a
sed -e "s|@@DOMAIN@@|$DOMAIN|g" \
    -e "s|@@BYO_GDRIVE_CLIENT_ID@@|${BYO_GDRIVE_CLIENT_ID:-}|g" \
    -e "s|@@BYO_DROPBOX_CLIENT_ID@@|${BYO_DROPBOX_CLIENT_ID:-}|g" \
    -e "s|@@BYO_ONEDRIVE_CLIENT_ID@@|${BYO_ONEDRIVE_CLIENT_ID:-}|g" \
    -e "s|@@BYO_BOX_CLIENT_ID@@|${BYO_BOX_CLIENT_ID:-}|g" \
    -e "s|@@BYO_PCLOUD_CLIENT_ID@@|${BYO_PCLOUD_CLIENT_ID:-}|g" \
    "$TEMPLATE" > "$CONFIG_OUT"
chmod 0644 "$CONFIG_OUT"

if command -v jq >/dev/null 2>&1 && ! jq -e . < "$CONFIG_OUT" >/dev/null 2>&1; then
  die "generated $CONFIG_OUT is not valid JSON — aborting before reload."
fi
ok "$CONFIG_OUT regenerated."

info "Reloading byo-relay..."
systemctl reload wattcloud 2>/dev/null \
  || systemctl restart wattcloud \
  || warn "systemctl reload/restart failed — SPA will pick up config on next page load regardless."
ok "Done. New providers are now available in the SPA."
