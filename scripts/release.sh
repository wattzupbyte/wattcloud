#!/usr/bin/env bash
# release.sh — LOCAL build + push of the Wattcloud image. Does NOT cosign-sign
# (keyless signing needs the Actions OIDC token, which is only available inside
# .github/workflows/release.yml). An image pushed by this script will fail
# `cosign verify` on the VPS — use only for development or emergency manual
# roll-outs where you accept skipping the signature check.
#
# For production, prefer: push a v*.*.* tag → Actions runs release.yml.
#
# Usage: scripts/release.sh <version-tag>
#   e.g. scripts/release.sh v0.1.0-manual
#
# Prerequisite: `docker login ghcr.io` with a PAT that has write:packages scope
# (only for this local-push path; the GHCR image served to end-users is still
# public anonymous-pull).

set -euo pipefail

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  echo "usage: $0 <version-tag>" >&2
  exit 2
fi

IMAGE="ghcr.io/wattzupbyte/wattcloud"
FULL_TAG="${IMAGE}:${TAG}"

cd "$(dirname "$0")/.."

# Frontend + WASM build. Writes into byo-relay/dist/ so the Dockerfile's
# `COPY dist/ /app/dist/` step has something to copy.
command -v wasm-pack >/dev/null 2>&1 || { echo "wasm-pack not installed"; exit 2; }
(cd sdk/sdk-wasm && wasm-pack build --release --target web \
    --out-dir ../../frontend/src/pkg --out-name wattcloud_sdk_wasm)
(cd frontend && npm ci --silent && npm run build)

# Dockerfile is byo-relay-centric (context = byo-relay/). `dist/` lives at
# byo-relay/dist/ (emitted by the vite build above).
docker build -t "$FULL_TAG" -f byo-relay/Dockerfile byo-relay
docker push "$FULL_TAG"

DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$FULL_TAG")

echo
echo "Pushed: $FULL_TAG"
echo "Digest: $DIGEST"
echo
echo "WARNING: this image is NOT cosign-signed. update.sh will reject it."
echo "Use Actions (tag-triggered release.yml) for production deploys."
