#!/usr/bin/env bash
# scripts/lib.sh — shared helpers for Wattcloud install/deploy/update.
# Sourced, not executed directly. All constants are idempotently re-defined
# so sourcing twice is safe.

if [ -n "${WC_LIB_LOADED:-}" ]; then
  return 0 2>/dev/null || true
fi
WC_LIB_LOADED=1

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------
WC_INSTALL_DIR="${WC_INSTALL_DIR:-/opt/wattcloud}"
WC_RELEASES_DIR="$WC_INSTALL_DIR/releases"
WC_CURRENT_LINK="$WC_INSTALL_DIR/current"
WC_ENV_DIR="${WC_ENV_DIR:-/etc/wattcloud}"
WC_ENV_FILE="$WC_ENV_DIR/wattcloud.env"
WC_STATE_DIR="${WC_STATE_DIR:-/var/lib/wattcloud}"
WC_RELAY_BIND="${WC_RELAY_BIND:-127.0.0.1:8443}"
WC_SYSTEMD_UNIT="/etc/systemd/system/wattcloud.service"
WC_CADDYFILE="/etc/caddy/Caddyfile"
WC_UPDATE_LOCK="/var/run/wattcloud-update.lock"
WC_KEEP_RELEASES="${WC_KEEP_RELEASES:-3}"

# GitHub repo coordinates (overridable for forks)
WC_GH_OWNER="${WC_GH_OWNER:-thewattlabs}"
WC_GH_REPO="${WC_GH_REPO:-wattcloud}"
WC_GH_API="https://api.github.com/repos/${WC_GH_OWNER}/${WC_GH_REPO}"
WC_GH_RELEASES="https://github.com/${WC_GH_OWNER}/${WC_GH_REPO}/releases"

# Cosign signer identity. Forks override via TRUSTED_SIGNER_IDENTITY in
# /etc/wattcloud/wattcloud.env.
WC_DEFAULT_SIGNER_IDENTITY="^https://github\.com/${WC_GH_OWNER}/${WC_GH_REPO}/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$"
WC_OIDC_ISSUER="https://token.actions.githubusercontent.com"

# Pinned cosign version. sha256 is fetched from the upstream release itself
# (not hardcoded) to avoid silent drift across cosign releases.
WC_COSIGN_VERSION="${WC_COSIGN_VERSION:-v2.4.1}"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
_color() {
  local code="$1"; shift
  if [ -t 2 ]; then
    printf '\033[%sm%s\033[0m' "$code" "$*"
  else
    printf '%s' "$*"
  fi
}
info() { printf '%s  %s\n' "$(_color '0;34' '[INFO]')" "$*" >&2; }
ok()   { printf '%s    %s\n' "$(_color '0;32' '[OK]')" "$*" >&2; }
warn() { printf '%s  %s\n' "$(_color '1;33' '[WARN]')" "$*" >&2; }
err()  { printf '%s %s\n' "$(_color '0;31' '[ERROR]')" "$*" >&2; }
die()  { err "$*"; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "This script must be run as root."
}

# ---------------------------------------------------------------------------
# Arch detection
# ---------------------------------------------------------------------------
# Emits the tarball arch slug used in release assets:
#   wattcloud-<VERSION>-<ARCH>-linux.tar.gz
detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64)  echo "x86_64-linux" ;;
    aarch64|arm64) echo "aarch64-linux" ;;
    *) die "unsupported architecture: $m (supported: x86_64, aarch64)" ;;
  esac
}

# ---------------------------------------------------------------------------
# GitHub release resolution
# ---------------------------------------------------------------------------
# Resolves the latest stable (non-prerelease) release tag.
resolve_latest_release() {
  local tag
  tag="$(curl -fsSL "$WC_GH_API/releases/latest" 2>/dev/null \
          | grep -oE '"tag_name":[[:space:]]*"[^"]+"' \
          | head -1 | cut -d'"' -f4)"
  [ -n "$tag" ] || die "Failed to resolve latest release from $WC_GH_API/releases/latest"
  echo "$tag"
}

# True iff $1 looks like vN.N.N or vN.N.N-suffix
valid_release_tag() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]
}

# ---------------------------------------------------------------------------
# Port / prerequisite checks
# ---------------------------------------------------------------------------
# Fail if :80 or :443 are in use by a process that is neither Caddy nor
# byo-relay (idempotent re-run still OK).
check_web_ports_free() {
  command -v ss >/dev/null 2>&1 || return 0
  local lines
  lines="$(ss -Hlntp '( sport = :80 or sport = :443 )' 2>/dev/null || true)"
  [ -z "$lines" ] && return 0
  if echo "$lines" | grep -qvE '"caddy"|"byo-relay"|"wattcloud"'; then
    die "ports :80/:443 are in use by another process. Free them before installing:
$lines"
  fi
}

# ---------------------------------------------------------------------------
# .env file helpers (atomic)
# ---------------------------------------------------------------------------
# env_set KEY VALUE FILE — set or replace KEY=VALUE in FILE.
# Preserves comments, ordering, and other keys. Creates FILE if missing.
env_set() {
  local key="$1" value="$2" file="$3"
  local tmp
  # Caller is responsible for creating the parent directory with appropriate
  # perms (typically /etc/wattcloud at 0700).
  tmp="$(mktemp "${file}.XXXXXX")"
  if [ -f "$file" ] && grep -qE "^${key}=" "$file"; then
    sed "s|^${key}=.*|${key}=${value}|" "$file" > "$tmp"
  else
    [ -f "$file" ] && cat "$file" > "$tmp"
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  chmod 0600 "$tmp"
  mv -f "$tmp" "$file"
}

# env_get KEY FILE — prints value, empty if missing.
env_get() {
  local key="$1" file="$2"
  [ -f "$file" ] || return 0
  grep -E "^${key}=" "$file" | head -1 | cut -d= -f2-
}

# ---------------------------------------------------------------------------
# Cosign install + verify wrappers
# ---------------------------------------------------------------------------
install_cosign() {
  local version="${1:-$WC_COSIGN_VERSION}"
  if command -v cosign >/dev/null 2>&1 \
      && cosign version 2>/dev/null | grep -q "GitVersion:[[:space:]]*$version"; then
    ok "cosign $version already installed."
    return 0
  fi

  local bin url checksums expected actual tmp
  case "$(uname -m)" in
    x86_64|amd64)  bin="cosign-linux-amd64" ;;
    aarch64|arm64) bin="cosign-linux-arm64" ;;
    *) die "cosign: unsupported architecture $(uname -m)" ;;
  esac

  url="https://github.com/sigstore/cosign/releases/download/$version/$bin"
  checksums="https://github.com/sigstore/cosign/releases/download/$version/cosign_checksums.txt"

  tmp="$(mktemp)"
  # Clean up the temp file on any exit from this function.
  trap "rm -f '$tmp'" RETURN

  info "Downloading cosign $version ($bin)..."
  curl -fsSL "$url" -o "$tmp" || die "cosign download failed: $url"

  info "Fetching cosign checksums..."
  expected="$(curl -fsSL "$checksums" | awk -v bin="$bin" '$2==bin {print $1; exit}')"
  [ -n "$expected" ] || die "cosign_checksums.txt: no entry for $bin"

  actual="$(sha256sum "$tmp" | awk '{print $1}')"
  [ "$expected" = "$actual" ] \
    || die "cosign sha256 mismatch: expected $expected, got $actual"

  install -m 0755 "$tmp" /usr/local/bin/cosign
  ok "cosign $version installed (sha256 verified)."
}

# cosign_verify_blob TARBALL SIG CERT [SIGNER_IDENTITY_REGEX]
cosign_verify_blob() {
  local tarball="$1" sig="$2" cert="$3"
  local identity="${4:-$WC_DEFAULT_SIGNER_IDENTITY}"
  info "Verifying signature for $(basename "$tarball")..."
  cosign verify-blob \
    --certificate "$cert" \
    --signature "$sig" \
    --certificate-identity-regexp "$identity" \
    --certificate-oidc-issuer "$WC_OIDC_ISSUER" \
    "$tarball" \
    >/dev/null 2>&1 \
    || die "cosign verify-blob FAILED for $(basename "$tarball"). Refusing to install."
  ok "Signature verified ($(basename "$tarball"))."
}

# ---------------------------------------------------------------------------
# Current install state
# ---------------------------------------------------------------------------
current_installed_version() {
  if [ -L "$WC_CURRENT_LINK" ]; then
    basename "$(readlink -f "$WC_CURRENT_LINK")"
  else
    echo ""
  fi
}

is_wattcloud_installed() {
  [ -L "$WC_CURRENT_LINK" ] || [ -f "$WC_ENV_FILE" ] || [ -f "$WC_SYSTEMD_UNIT" ]
}
