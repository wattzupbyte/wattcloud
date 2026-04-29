#!/usr/bin/env bash
# install.sh — one-shot bootstrap for a Wattcloud VPS install.
#
# Usage:
#   curl -sSLO https://github.com/thewattlabs/wattcloud/releases/latest/download/install.sh
#   less install.sh      # audit before running
#   sudo bash install.sh cloud.example.com
#
# Installs the Wattcloud app only (Caddy + byo-relay + systemd). VPS
# hardening (UFW, fail2ban, SSH lockdown, R5 logging, …) is a separate
# opt-in step — after this finishes, run `sudo wattcloud harden`.
#
# This script bootstraps trust: download, cosign-verify, extract, hand
# off to the tarball's deploy-vps.sh. Script + tarball policy both live
# under the signed release asset.
#
# Flags:
#   --version vX.Y.Z         pin a specific release (default: latest stable)
#   --tarball PATH           use a locally-downloaded tarball (audit/offline)
#   --sig PATH               .sig file for --tarball
#   --cert PATH              .cert file for --tarball
#   --trusted-signer REGEX   cosign identity regex (default: upstream)
#   --yes                    non-interactive (accept defaults)
#   --no-provision           skip deploy-vps.sh hand-off (bootstrap only)
#   --help                   show this message
set -euo pipefail

# ---------------------------------------------------------------------------
# Output helpers — duplicated from scripts/lib.sh because this script runs
# BEFORE any tarball has been extracted. Keep in sync.
# ---------------------------------------------------------------------------
_c() { [ -t 2 ] && printf '\033[%sm%s\033[0m' "$1" "$2" || printf '%s' "$2"; }
info() { printf '%s  %s\n' "$(_c '0;34' '[INFO]')" "$*" >&2; }
ok()   { printf '%s    %s\n' "$(_c '0;32' '[OK]')" "$*" >&2; }
warn() { printf '%s  %s\n' "$(_c '1;33' '[WARN]')" "$*" >&2; }
err()  { printf '%s %s\n' "$(_c '0;31' '[ERROR]')" "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Constants — forks override via --trusted-signer + WC_GH_OWNER / WC_GH_REPO.
# ---------------------------------------------------------------------------
WC_GH_OWNER="${WC_GH_OWNER:-thewattlabs}"
WC_GH_REPO="${WC_GH_REPO:-wattcloud}"
WC_GH_API="https://api.github.com/repos/${WC_GH_OWNER}/${WC_GH_REPO}"
WC_GH_RELEASES="https://github.com/${WC_GH_OWNER}/${WC_GH_REPO}/releases"
WC_INSTALL_DIR="${WC_INSTALL_DIR:-/opt/wattcloud}"
WC_RELEASES_DIR="$WC_INSTALL_DIR/releases"
WC_CURRENT_LINK="$WC_INSTALL_DIR/current"
WC_ENV_FILE="${WC_ENV_FILE:-/etc/wattcloud/wattcloud.env}"
WC_SYSTEMD_UNIT="/etc/systemd/system/wattcloud.service"
WC_OIDC_ISSUER="https://token.actions.githubusercontent.com"
WC_COSIGN_VERSION="${WC_COSIGN_VERSION:-v2.4.1}"
WC_DEFAULT_SIGNER_IDENTITY="^https://github\.com/${WC_GH_OWNER}/${WC_GH_REPO}/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$"

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
DOMAIN=""
VERSION=""
LOCAL_TARBALL=""
LOCAL_SIG=""
LOCAL_CERT=""
TRUSTED_SIGNER="$WC_DEFAULT_SIGNER_IDENTITY"
YES=0
NO_PROVISION=0
PASSTHROUGH_ARGS=()

usage() {
  cat <<'USAGE'
Usage:
  curl -sSLO https://github.com/thewattlabs/wattcloud/releases/latest/download/install.sh
  less install.sh      # audit before running
  sudo bash install.sh DOMAIN [flags]

Required:
  DOMAIN                   fully-qualified hostname (e.g. cloud.example.com)

Flags:
  --version vX.Y.Z         pin a specific release (default: latest stable)
  --tarball PATH           use a locally-downloaded tarball (audit/offline)
  --sig PATH               .sig file for --tarball
  --cert PATH              .cert file for --tarball
  --trusted-signer REGEX   cosign identity regex (default: upstream)
  --yes                    non-interactive (accept defaults)
  --no-provision           skip deploy-vps.sh hand-off (bootstrap only)
  --help                   show this message

All other flags are passed through to the extracted deploy-vps.sh.

VPS hardening is NOT part of this install. To apply the opinionated
hardening bundle (UFW, fail2ban, SSH lockdown, R5 logging, swap,
earlyoom, disk-watchdog, AIDE, msmtp), run after install completes:

  sudo wattcloud harden
USAGE
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)         VERSION="$2"; shift 2 ;;
    --tarball)         LOCAL_TARBALL="$2"; shift 2 ;;
    --sig)             LOCAL_SIG="$2"; shift 2 ;;
    --cert)            LOCAL_CERT="$2"; shift 2 ;;
    --trusted-signer)  TRUSTED_SIGNER="$2"; shift 2 ;;
    --yes)             YES=1; PASSTHROUGH_ARGS+=(--yes); shift ;;
    --no-provision)    NO_PROVISION=1; shift ;;
    --help|-h)         usage 0 ;;
    --*)               PASSTHROUGH_ARGS+=("$1"); shift ;;
    *)
      if [ -z "$DOMAIN" ]; then DOMAIN="$1"; shift
      else die "unexpected positional argument: $1 (DOMAIN already set to '$DOMAIN')"
      fi
      ;;
  esac
done

[ -n "$DOMAIN" ]             || { err "DOMAIN is required"; usage 1; }
[ "$(id -u)" -eq 0 ]         || die "install.sh must be run as root."
[[ "$DOMAIN" == *.* ]]       || die "DOMAIN must be a FQDN (got '$DOMAIN')."

# ---------------------------------------------------------------------------
# Pre-existing install detection
# ---------------------------------------------------------------------------
if [ -L "$WC_CURRENT_LINK" ] || [ -f "$WC_ENV_FILE" ] || [ -f "$WC_SYSTEMD_UNIT" ]; then
  die "Wattcloud is already installed on this host. Use 'sudo wattcloud-update' to upgrade. \
If you genuinely want to reinstall, run '/opt/wattcloud/current/scripts/uninstall.sh' first."
fi

# ---------------------------------------------------------------------------
# Port pre-flight (Caddy needs :80 and :443)
# ---------------------------------------------------------------------------
if command -v ss >/dev/null 2>&1; then
  in_use="$(ss -Hlntp '( sport = :80 or sport = :443 )' 2>/dev/null || true)"
  if [ -n "$in_use" ] && ! echo "$in_use" | grep -qE '"caddy"|"byo-relay"|"wattcloud"'; then
    die "ports :80/:443 are in use by another process. Free them before installing:
$in_use"
  fi
fi

# ---------------------------------------------------------------------------
# Resolve architecture + target version
# ---------------------------------------------------------------------------
case "$(uname -m)" in
  x86_64|amd64)   ARCH="x86_64-linux" ;;
  aarch64|arm64)  ARCH="aarch64-linux" ;;
  *) die "unsupported architecture: $(uname -m) (supported: x86_64, aarch64)" ;;
esac

if [ -z "$VERSION" ] && [ -z "$LOCAL_TARBALL" ]; then
  info "Resolving latest stable release..."
  VERSION="$(curl -fsSL "$WC_GH_API/releases/latest" 2>/dev/null \
             | grep -oE '"tag_name":[[:space:]]*"[^"]+"' | head -1 | cut -d'"' -f4)"
  [ -n "$VERSION" ] || die "Could not resolve latest release from $WC_GH_API/releases/latest"
  ok "Latest release: $VERSION"
fi
if [ -n "$VERSION" ] && ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
  die "invalid version tag '$VERSION' (expected vN.N.N or vN.N.N-suffix)"
fi

WORK="$(mktemp -d -t wattcloud-install.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Obtain tarball + signature + certificate
# ---------------------------------------------------------------------------
TARBALL_NAME="wattcloud-${VERSION:-local}-${ARCH}.tar.gz"

if [ -n "$LOCAL_TARBALL" ]; then
  [ -f "$LOCAL_TARBALL" ] || die "--tarball file not found: $LOCAL_TARBALL"
  [ -n "$LOCAL_SIG" ]  && [ -f "$LOCAL_SIG" ]  || die "--sig is required with --tarball"
  [ -n "$LOCAL_CERT" ] && [ -f "$LOCAL_CERT" ] || die "--cert is required with --tarball"
  cp "$LOCAL_TARBALL" "$WORK/$TARBALL_NAME"
  cp "$LOCAL_SIG"     "$WORK/${TARBALL_NAME}.sig"
  cp "$LOCAL_CERT"    "$WORK/${TARBALL_NAME}.cert"
  ok "Using local tarball: $LOCAL_TARBALL"
else
  BASE="https://github.com/${WC_GH_OWNER}/${WC_GH_REPO}/releases/download/${VERSION}"
  info "Downloading $TARBALL_NAME..."
  curl -fsSL "${BASE}/${TARBALL_NAME}"       -o "$WORK/$TARBALL_NAME"       || die "tarball download failed: ${BASE}/${TARBALL_NAME}"
  curl -fsSL "${BASE}/${TARBALL_NAME}.sig"   -o "$WORK/${TARBALL_NAME}.sig" || die "signature download failed"
  curl -fsSL "${BASE}/${TARBALL_NAME}.cert"  -o "$WORK/${TARBALL_NAME}.cert" || die "certificate download failed"
  ok "Downloaded $TARBALL_NAME (+ .sig, .cert)"
fi

# ---------------------------------------------------------------------------
# Install cosign (pinned, sha256 verified against upstream checksums file)
# ---------------------------------------------------------------------------
ensure_cosign() {
  if command -v cosign >/dev/null 2>&1 \
      && cosign version 2>/dev/null | grep -q "GitVersion:[[:space:]]*$WC_COSIGN_VERSION"; then
    ok "cosign $WC_COSIGN_VERSION already installed."
    return 0
  fi
  local bin url checksums expected actual tmp
  case "$(uname -m)" in
    x86_64|amd64)  bin="cosign-linux-amd64" ;;
    aarch64|arm64) bin="cosign-linux-arm64" ;;
    *) die "cosign: unsupported arch $(uname -m)" ;;
  esac
  url="https://github.com/sigstore/cosign/releases/download/${WC_COSIGN_VERSION}/${bin}"
  checksums="https://github.com/sigstore/cosign/releases/download/${WC_COSIGN_VERSION}/cosign_checksums.txt"
  tmp="$WORK/cosign"
  info "Downloading cosign $WC_COSIGN_VERSION ($bin)..."
  curl -fsSL "$url" -o "$tmp" || die "cosign download failed: $url"
  expected="$(curl -fsSL "$checksums" | awk -v b="$bin" '$2==b {print $1; exit}')"
  [ -n "$expected" ] || die "cosign_checksums.txt: no entry for $bin"
  actual="$(sha256sum "$tmp" | awk '{print $1}')"
  [ "$expected" = "$actual" ] || die "cosign sha256 mismatch (expected $expected, got $actual)"
  install -m 0755 "$tmp" /usr/local/bin/cosign
  ok "cosign $WC_COSIGN_VERSION installed (sha256 verified)."
}
ensure_cosign

# ---------------------------------------------------------------------------
# Verify tarball signature against pinned signer identity
# ---------------------------------------------------------------------------
info "Verifying signature (identity=$TRUSTED_SIGNER)..."
cosign verify-blob \
  --certificate "$WORK/${TARBALL_NAME}.cert" \
  --signature   "$WORK/${TARBALL_NAME}.sig" \
  --certificate-identity-regexp "$TRUSTED_SIGNER" \
  --certificate-oidc-issuer     "$WC_OIDC_ISSUER" \
  "$WORK/$TARBALL_NAME" >/dev/null 2>&1 \
  || die "cosign verify-blob FAILED. Refusing to install — this is the trust anchor."
ok "Signature verified."

# ---------------------------------------------------------------------------
# Extract to /opt/wattcloud/releases/<VERSION>/
# ---------------------------------------------------------------------------
install -d -m 0755 "$WC_RELEASES_DIR"
TARGET_DIR="$WC_RELEASES_DIR/${VERSION:-local}"
if [ -d "$TARGET_DIR" ]; then
  die "$TARGET_DIR already exists (but /opt/wattcloud/current didn't exist above?). Refusing to overwrite."
fi
info "Extracting to $TARGET_DIR..."
install -d -m 0755 "$TARGET_DIR"
tar -xzf "$WORK/$TARBALL_NAME" -C "$TARGET_DIR" --strip-components=1
ok "Extracted."

# Sanity check the extracted layout.
for expected in bin/byo-relay web/index.html scripts/deploy-vps.sh scripts/lib.sh packaging/wattcloud.service; do
  [ -e "$TARGET_DIR/$expected" ] || die "extracted tarball missing expected file: $expected"
done
ok "Tarball layout verified."

# ---------------------------------------------------------------------------
# Hand off to the (signed) deploy-vps.sh inside the tarball
# ---------------------------------------------------------------------------
export WC_SIGNER_IDENTITY="$TRUSTED_SIGNER"
export WC_INSTALL_VERSION="${VERSION:-local}"
export WC_EXTRACTED_DIR="$TARGET_DIR"

if [ "$NO_PROVISION" -eq 1 ]; then
  ok "Bootstrap complete. --no-provision supplied; skipping deploy-vps.sh."
  info "Tarball extracted to $TARGET_DIR. To finish the install yourself,"
  info "run: $TARGET_DIR/scripts/deploy-vps.sh $DOMAIN ${PASSTHROUGH_ARGS[*]:-}"
  exit 0
fi

info "Handing off to deploy-vps.sh inside the verified tarball..."
exec "$TARGET_DIR/scripts/deploy-vps.sh" "$DOMAIN" "${PASSTHROUGH_ARGS[@]}"
