#!/usr/bin/env bash
# =============================================================================
# verify-byo-bundle.sh — Assert the BYO SPA bundle contains no managed code.
# Run after `npm run build:byo` (and `make byo-prod-wasm` for WASM check).
# Exits 1 if any managed symbol is found.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$APP_DIR/byo-server/dist/assets"

if [ ! -d "$DIST_DIR" ]; then
    echo -e "${RED}[VERIFY]${NC} byo-server/dist/assets not found — run 'npm run build:byo' first"
    exit 1
fi

JS_FILES=("$DIST_DIR"/*.js)
if [ ${#JS_FILES[@]} -eq 0 ] || [ ! -f "${JS_FILES[0]}" ]; then
    echo -e "${RED}[VERIFY]${NC} No JS files in $DIST_DIR"
    exit 1
fi

ERRORS=0

echo "[VERIFY] Scanning BYO bundle for managed symbols..."

# ---------------------------------------------------------------------------
# JS bundle scan — two categories:
#
# 1. Svelte component names: class/function names preserved even after minification.
#    Each names a managed-only UI screen that must never ship in BYO.
#
# 2. Managed backend URL prefixes (denylist).
#    BYO talks only to /relay/* on byo-server and to external provider APIs.
#    Any /api/auth/*, /api/admin/*, or /api/files/* literal is a managed leak.
#    This covers the full managed API surface without a hand-maintained method list.
# ---------------------------------------------------------------------------
MANAGED_SVELTE_COMPONENTS=(
    "RegistrationWizard"
    "AdminShell"
    "AdminSetup"
    "TotpEnrollment"
    "EmailVerification"
    "SessionManager"
    "DeviceUnlockFlow"
    "TrustDeviceFlow"
    "UploadQueue"
    "UploadCommand"
    "decrypt_and_build_workspace"
)

MANAGED_URL_PREFIXES=(
    "/api/auth/"
    "/api/admin/"
    "/api/files/"
)

for pattern in "${MANAGED_SVELTE_COMPONENTS[@]}"; do
    if grep -ql "$pattern" "$DIST_DIR"/*.js 2>/dev/null; then
        echo -e "${RED}[FAIL]${NC} Managed Svelte component '$pattern' found in BYO JS bundle"
        ERRORS=$((ERRORS + 1))
    fi
done

for pattern in "${MANAGED_URL_PREFIXES[@]}"; do
    if grep -ql "$pattern" "$DIST_DIR"/*.js 2>/dev/null; then
        echo -e "${RED}[FAIL]${NC} Managed URL prefix '$pattern' found in BYO JS bundle"
        ERRORS=$((ERRORS + 1))
    fi
done

# ---------------------------------------------------------------------------
# WASM JS glue scan — grep the wasm-bindgen JS file for managed export names.
#
# `wasm-pack build --target web` produces frontend/src/pkg/wattcloud_sdk_wasm.js
# with each Rust #[wasm_bindgen] export as a named JS export.  These names are
# preserved verbatim by the bindgen contract and survive wasm-opt / --release.
# Scanning the JS glue is more reliable than grepping the raw .wasm binary
# (where debug/module-path strings are stripped by wasm-opt in release builds).
# ---------------------------------------------------------------------------
JS_GLUE="$APP_DIR/frontend/src/pkg/wattcloud_sdk_wasm.js"
if [ -f "$JS_GLUE" ]; then
    echo "[VERIFY] Scanning WASM JS glue for managed Rust exports..."
    # These exports belong to features that are stripped in BYO WASM builds
    # (sdk-core features: trusted_device, upload, workspace — all managed-only).
    WASM_MANAGED_EXPORTS=(
        "trust_device_"
        "upload_queue_"
        "device_unlock_"
        "decrypt_workspace"
    )
    for pattern in "${WASM_MANAGED_EXPORTS[@]}"; do
        if grep -q "$pattern" "$JS_GLUE" 2>/dev/null; then
            echo -e "${RED}[FAIL]${NC} Managed WASM export '$pattern' found in BYO WASM JS glue"
            ERRORS=$((ERRORS + 1))
        fi
    done
else
    echo -e "${YELLOW}[WARN]${NC} WASM JS glue not found at frontend/src/pkg/wattcloud_sdk_wasm.js — skipping WASM scan."
    echo -e "${YELLOW}[WARN]${NC} Run 'make byo-prod-wasm' before verify for a complete check."
fi

# ---------------------------------------------------------------------------
# Size budget: BYO bundle JS should not exceed 3 MB (8 MB was too loose)
# ---------------------------------------------------------------------------
TOTAL_JS_BYTES=$(du -sb "$DIST_DIR"/*.js 2>/dev/null | awk '{s+=$1} END {print s}')
LIMIT_BYTES=$((3 * 1024 * 1024))
WARN_BYTES=$((2 * 1024 * 1024))

if [ "${TOTAL_JS_BYTES:-0}" -gt "$LIMIT_BYTES" ]; then
    echo -e "${RED}[FAIL]${NC} BYO JS bundle exceeds 3 MB size limit ($(( TOTAL_JS_BYTES / 1024 ))KB)"
    ERRORS=$((ERRORS + 1))
elif [ "${TOTAL_JS_BYTES:-0}" -gt "$WARN_BYTES" ]; then
    echo -e "${YELLOW}[WARN]${NC} BYO JS bundle is large: $(( TOTAL_JS_BYTES / 1024 ))KB (warn threshold: 2 MB)"
fi

if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}[OK]${NC} BYO bundle clean — no managed symbols found."
    exit 0
else
    echo -e "${RED}[FAIL]${NC} BYO bundle check failed ($ERRORS error(s))."
    exit 1
fi
