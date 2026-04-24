#!/usr/bin/env bash
# update.sh — roll Wattcloud forward (or back) to a signed release.
#
# Invoked directly on the VPS via /usr/local/bin/wattcloud-update (installed
# by deploy-vps.sh). Also exec'd by `wattcloud update`.
#
# Usage:
#   sudo wattcloud-update                    # upgrade to latest stable
#   sudo wattcloud-update vX.Y.Z             # pin to a specific version
#   sudo wattcloud-update --rollback         # revert to previous release
#   sudo wattcloud-update --force vX.Y.Z     # allow same-version or downgrade
#
# Safety:
#   - flock prevents concurrent invocations from racing the symlink swap.
#   - cosign verify-blob against the installed TRUSTED_SIGNER_IDENTITY runs
#     before extraction — a compromised mirror cannot roll the host forward.
#   - new required env keys abort the upgrade with a human-readable list.
#   - /health is polled for 30s after restart; if it never responds, the
#     symlink is rolled back to the previous release and the service
#     restarted. Broken deploys never persist as "current".
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'USAGE'
Usage: wattcloud-update [version] [--rollback] [--force]

  (no args)       upgrade to the latest stable release
  vX.Y.Z          pin to a specific tag
  --rollback      revert to the previous installed release
  --force         allow same-version or downgrade installs
  --help          show this message
USAGE
}

TARGET_VERSION=""
ROLLBACK=0
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rollback) ROLLBACK=1; shift ;;
    --force)    FORCE=1; shift ;;
    --help|-h)  usage; exit 0 ;;
    --*)        die "unknown flag: $1" ;;
    *)
      if [ -z "$TARGET_VERSION" ]; then TARGET_VERSION="$1"; shift
      else die "unexpected positional argument: $1"
      fi
      ;;
  esac
done

require_root

# ---------------------------------------------------------------------------
# Lock — only one update.sh at a time
# ---------------------------------------------------------------------------
exec 9>"$WC_UPDATE_LOCK"
if ! flock -n 9; then
  die "another wattcloud-update is already running (lock: $WC_UPDATE_LOCK)"
fi

# ---------------------------------------------------------------------------
# State: must be installed
# ---------------------------------------------------------------------------
is_wattcloud_installed \
  || die "Wattcloud is not installed on this host. Use install.sh instead."

CURRENT_VERSION="$(current_installed_version)"
[ -n "$CURRENT_VERSION" ] || die "Cannot determine current version — $WC_CURRENT_LINK is missing."
info "Current version: $CURRENT_VERSION"

# Load signer identity override (if operator edited .env).
SIGNER_IDENTITY="$(env_get TRUSTED_SIGNER_IDENTITY "$WC_ENV_FILE")"
[ -z "$SIGNER_IDENTITY" ] && SIGNER_IDENTITY="$WC_DEFAULT_SIGNER_IDENTITY"

# ---------------------------------------------------------------------------
# Rollback path
# ---------------------------------------------------------------------------
if [ "$ROLLBACK" -eq 1 ]; then
  [ -z "$TARGET_VERSION" ] || die "--rollback and explicit version are mutually exclusive."
  PREV="$(find "$WC_RELEASES_DIR" -maxdepth 1 -mindepth 1 -type d \
            -not -name "$CURRENT_VERSION" -printf '%f\n' 2>/dev/null \
          | sort -V | tail -1)"
  [ -n "$PREV" ] || die "No previous release found under $WC_RELEASES_DIR."
  TARGET_VERSION="$PREV"
  info "Rolling back: $CURRENT_VERSION → $TARGET_VERSION"
fi

# ---------------------------------------------------------------------------
# Resolve target version
# ---------------------------------------------------------------------------
if [ -z "$TARGET_VERSION" ]; then
  info "Resolving latest stable release..."
  TARGET_VERSION="$(resolve_latest_release)"
  ok "Latest: $TARGET_VERSION"
fi
valid_release_tag "$TARGET_VERSION" \
  || die "invalid version '$TARGET_VERSION' (expected vN.N.N or vN.N.N-suffix)"

if [ "$TARGET_VERSION" = "$CURRENT_VERSION" ] && [ "$FORCE" -eq 0 ]; then
  ok "Already on $CURRENT_VERSION. Use --force to reinstall."
  exit 0
fi

# ---------------------------------------------------------------------------
# Either reuse existing extracted release dir, or download + verify + extract
# ---------------------------------------------------------------------------
TARGET_DIR="$WC_RELEASES_DIR/$TARGET_VERSION"

prepare_release() {
  if [ -d "$TARGET_DIR" ] && [ -f "$TARGET_DIR/bin/byo-relay" ]; then
    ok "Release $TARGET_VERSION already extracted — skipping download."
    return 0
  fi

  local arch tarball base work
  arch="$(detect_arch)"
  tarball="wattcloud-${TARGET_VERSION}-${arch}.tar.gz"
  base="https://github.com/${WC_GH_OWNER}/${WC_GH_REPO}/releases/download/${TARGET_VERSION}"

  install_cosign
  work="$(mktemp -d -t wattcloud-update.XXXXXX)"
  trap "rm -rf '$work'" EXIT

  info "Downloading $tarball..."
  curl -fsSL "$base/$tarball"       -o "$work/$tarball"       || die "tarball download failed: $base/$tarball"
  curl -fsSL "$base/$tarball.sig"   -o "$work/$tarball.sig"   || die "signature download failed"
  curl -fsSL "$base/$tarball.cert"  -o "$work/$tarball.cert"  || die "certificate download failed"

  cosign_verify_blob "$work/$tarball" "$work/$tarball.sig" "$work/$tarball.cert" "$SIGNER_IDENTITY"

  install -d -m 0755 "$TARGET_DIR"
  tar -xzf "$work/$tarball" -C "$TARGET_DIR" --strip-components=1
  for expected in bin/byo-relay web/index.html scripts/deploy-vps.sh packaging/wattcloud.service; do
    [ -e "$TARGET_DIR/$expected" ] || die "extracted tarball missing: $expected"
  done
  ok "Extracted to $TARGET_DIR."
}

# ---------------------------------------------------------------------------
# Env-file compatibility diff: abort on new REQUIRED keys
# ---------------------------------------------------------------------------
check_env_compat() {
  local new_example="$TARGET_DIR/.env.example"
  [ -f "$new_example" ] || return 0

  # A "required" key in .env.example is one whose value is empty after '='.
  # Keys with non-empty defaults are safe; deploy-vps.sh inherits them.
  local missing=()
  while IFS= read -r line; do
    [[ "$line" =~ ^# ]] && continue
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
      local key="${BASH_REMATCH[1]}" example_val="${BASH_REMATCH[2]}"
      [ -n "$example_val" ] && continue
      # OAuth client IDs are optional — always allowed to be empty.
      [[ "$key" == BYO_*_CLIENT_ID ]] && continue
      local current_val; current_val="$(env_get "$key" "$WC_ENV_FILE")"
      [ -z "$current_val" ] && missing+=("$key")
    fi
  done < "$new_example"

  if [ "${#missing[@]}" -gt 0 ] && [ "$FORCE" -eq 0 ]; then
    err "Release $TARGET_VERSION adds required env keys missing from $WC_ENV_FILE:"
    for k in "${missing[@]}"; do err "    $k"; done
    err "Add them (or re-run with --force to skip this gate) before upgrading."
    exit 2
  fi
}

# ---------------------------------------------------------------------------
# Systemd unit compatibility: reinstall only if changed
# ---------------------------------------------------------------------------
maybe_update_unit() {
  local new_unit="$TARGET_DIR/packaging/wattcloud.service"
  [ -f "$new_unit" ] || die "Release $TARGET_VERSION is missing packaging/wattcloud.service"
  if ! cmp -s "$new_unit" "$WC_SYSTEMD_UNIT"; then
    info "Systemd unit changed — reinstalling."
    install -m 0644 "$new_unit" "$WC_SYSTEMD_UNIT"
    systemctl daemon-reload
    ok "systemd unit updated."
  fi
}

# ---------------------------------------------------------------------------
# Atomic symlink swap + restart + health poll + auto-revert
# ---------------------------------------------------------------------------
atomic_swap_and_restart() {
  local previous="$CURRENT_VERSION"
  ln -sfn "$TARGET_DIR" "$WC_CURRENT_LINK.new"
  mv -T "$WC_CURRENT_LINK.new" "$WC_CURRENT_LINK"
  ok "Symlink swapped: current → $TARGET_VERSION"

  systemctl reload-or-restart wattcloud \
    || {
      err "systemctl restart failed — rolling back."
      ln -sfn "$WC_RELEASES_DIR/$previous" "$WC_CURRENT_LINK.new"
      mv -T "$WC_CURRENT_LINK.new" "$WC_CURRENT_LINK"
      systemctl restart wattcloud || true
      die "upgrade aborted, reverted to $previous"
    }

  info "Polling /health on 127.0.0.1:8443 (30s)..."
  local i
  for i in $(seq 1 30); do
    if curl -fsS --max-time 2 "http://127.0.0.1:8443/health" 2>/dev/null | grep -q ok; then
      ok "/health → ok (after ${i}s). Running $TARGET_VERSION."
      return 0
    fi
    sleep 1
  done

  err "/health did not respond within 30s — auto-reverting to $previous."
  ln -sfn "$WC_RELEASES_DIR/$previous" "$WC_CURRENT_LINK.new"
  mv -T "$WC_CURRENT_LINK.new" "$WC_CURRENT_LINK"
  install -m 0644 "$WC_RELEASES_DIR/$previous/packaging/wattcloud.service" "$WC_SYSTEMD_UNIT" 2>/dev/null || true
  systemctl daemon-reload
  systemctl restart wattcloud || true

  for i in $(seq 1 15); do
    if curl -fsS --max-time 2 "http://127.0.0.1:8443/health" 2>/dev/null | grep -q ok; then
      ok "Reverted to $previous. /health back."
      exit 3
    fi
    sleep 1
  done
  die "auto-revert also failed — inspect 'journalctl -u wattcloud -e' immediately."
}

# ---------------------------------------------------------------------------
# Prune old releases (keep last N, never the current)
# ---------------------------------------------------------------------------
prune_old_releases() {
  local keep="$WC_KEEP_RELEASES"
  mapfile -t dirs < <(find "$WC_RELEASES_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' | sort -V)
  local total="${#dirs[@]}"
  [ "$total" -le "$keep" ] && return 0
  local to_remove=$((total - keep))
  local current; current="$(current_installed_version)"
  for d in "${dirs[@]:0:$to_remove}"; do
    [ "$d" = "$current" ] && continue
    rm -rf "${WC_RELEASES_DIR:?}/${d:?}"
    info "Pruned old release: $d"
  done
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
prepare_release
check_env_compat
maybe_update_unit
atomic_swap_and_restart
prune_old_releases

ok "Upgrade complete: $CURRENT_VERSION → $TARGET_VERSION"
