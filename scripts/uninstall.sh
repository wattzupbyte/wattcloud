#!/usr/bin/env bash
# uninstall.sh — remove Wattcloud from this host.
#
# Usage:
#   sudo /opt/wattcloud/current/scripts/uninstall.sh        # keep .env + stats
#   sudo /opt/wattcloud/current/scripts/uninstall.sh --purge # remove everything
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    --help|-h)
      sed -n '1,10p' "$0"; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

require_root

info "Stopping services..."
systemctl disable --now wattcloud 2>/dev/null || true
systemctl disable --now wattcloud-disk-watchdog.timer 2>/dev/null || true
systemctl reload caddy 2>/dev/null || true

info "Removing systemd unit + Caddyfile + CLI wrappers..."
rm -f "$WC_SYSTEMD_UNIT"
rm -f "$WC_CADDYFILE"
rm -f /usr/local/bin/wattcloud /usr/local/bin/wattcloud-update
rm -f /etc/systemd/system/wattcloud-disk-watchdog.service \
      /etc/systemd/system/wattcloud-disk-watchdog.timer \
      /usr/local/sbin/wattcloud-disk-watchdog.sh
systemctl daemon-reload

info "Removing install tree..."
rm -rf "$WC_INSTALL_DIR"

if [ "$PURGE" -eq 1 ]; then
  info "Purging env + state..."
  rm -rf "$WC_ENV_DIR" "$WC_STATE_DIR"
  ok "Wattcloud fully removed (including secrets and stats DB)."
else
  ok "Wattcloud removed. Preserved:"
  echo "    $WC_ENV_FILE      (contains your signing keys + OAuth IDs)" >&2
  echo "    $WC_STATE_DIR     (stats database)" >&2
  echo "  Re-run with --purge to delete these too." >&2
fi
