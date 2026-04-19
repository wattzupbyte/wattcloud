#!/usr/bin/env bash
# update.sh — VPS-side image roll-out with sigstore/cosign verification.
#
# Usage: scripts/update.sh <image-digest>
#   e.g. scripts/update.sh ghcr.io/wattzupbyte/wattcloud@sha256:abc123...
#
# Flow:
#   1. Validate the digest shape.
#   2. cosign verify — assert the image at this digest was signed by the
#      wattzupbyte/wattcloud release.yml workflow running on a v*.*.* tag,
#      using the Actions OIDC issuer. A swap at the registry fails here.
#   3. Pin the digest into docker-compose.yml.
#   4. docker compose pull (anonymous — GHCR image is public; no PAT needed).
#   5. docker compose up -d, then health-check /health on 127.0.0.1:8443.
#
# Prerequisites (installed by deploy-vps.sh):
#   - docker + compose
#   - cosign binary in $PATH (>=2.4)
#   - curl for the health probe

set -euo pipefail

DIGEST="${1:-}"
if [[ -z "$DIGEST" ]]; then
  echo "usage: $0 <image-digest>   e.g. ghcr.io/wattzupbyte/wattcloud@sha256:..." >&2
  exit 2
fi

if ! [[ "$DIGEST" =~ ^ghcr\.io/wattzupbyte/wattcloud@sha256:[0-9a-f]{64}$ ]]; then
  echo "ERROR: digest must be of the form ghcr.io/wattzupbyte/wattcloud@sha256:<64-hex>" >&2
  echo "Got: $DIGEST" >&2
  exit 2
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "ERROR: cosign not found in PATH. Install it first (deploy-vps.sh does this at provision time):" >&2
  echo "  curl -fsSL https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64 -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign" >&2
  exit 3
fi

# Verify the cosign signature BEFORE touching the compose file. If the image
# at this digest was not signed by the wattzupbyte/wattcloud release workflow
# from a v*.*.* tag (or was swapped at the registry), verification fails and
# we exit without pulling anything.
#
# Identity-regexp pins:
#   - org:  wattzupbyte
#   - repo: wattcloud
#   - file: .github/workflows/release.yml
#   - ref:  refs/tags/v*.*.* (anything else — main branch, other tag,
#           fork — fails the regex)
echo "Verifying cosign signature on $DIGEST..."
IDENTITY_REGEXP='^https://github\.com/wattzupbyte/wattcloud/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$'
OIDC_ISSUER='https://token.actions.githubusercontent.com'

if ! cosign verify \
     --certificate-identity-regexp "$IDENTITY_REGEXP" \
     --certificate-oidc-issuer "$OIDC_ISSUER" \
     "$DIGEST" \
     > /tmp/cosign-verify.json 2>&1; then
  echo "ERROR: cosign verify failed for $DIGEST" >&2
  echo "---- cosign output ----" >&2
  cat /tmp/cosign-verify.json >&2
  echo "-----------------------" >&2
  echo "Refusing to deploy. Possible causes:" >&2
  echo "  - image at this digest was not built by wattzupbyte/wattcloud release.yml on a v*.*.* tag" >&2
  echo "  - registry compromise substituted the image" >&2
  echo "  - signature was revoked" >&2
  exit 4
fi
echo "OK: signature verified (identity matches release.yml @ v*.*.*)."

cd "$(dirname "$0")/.."

if ! [[ -f docker-compose.yml ]]; then
  echo "ERROR: docker-compose.yml not found" >&2
  exit 2
fi

# Idempotent sed — only rewrites the byo-server image line (matches any
# existing ghcr.io/wattzupbyte/wattcloud:TAG or @sha256:… reference, plus the
# legacy ${BYO_IMAGE:-…} placeholder we ship in docker-compose.yml). Traefik's
# image line does NOT match this pattern and is preserved.
sed -i -E "s|^(\s*image:\s*).*(ghcr\.io/wattzupbyte/wattcloud|BYO_IMAGE:-).*$|\1${DIGEST}|" docker-compose.yml
if ! grep -qF "$DIGEST" docker-compose.yml; then
  echo "ERROR: failed to pin digest into docker-compose.yml (byo-server image line not found or regex mismatch)" >&2
  exit 5
fi
echo "Pinned compose image to: $DIGEST"

docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d

sleep 5
if curl -fsS http://127.0.0.1:8443/health >/dev/null 2>&1; then
  echo "OK: byo-server /health returned 200."
else
  echo "WARN: /health probe failed — check 'docker compose logs byo-server'." >&2
  exit 1
fi
