#!/usr/bin/env bash
# =============================================================================
# ci.sh — Local CI pipeline for Wattcloud.
#
# Mirrors the command set in .github/workflows/ci.yml so you can reproduce a
# red job on your machine without waiting for runners. Canonical pipeline is
# still GitHub Actions; this is convenience tooling.
#
# Usage:
#   ./scripts/ci.sh                 # full run (lint + test + build + docker)
#   CI_SKIP_DISK_CHECK=1 ./ci.sh    # skip the preflight disk check
#   CI_SKIP_DOCKER=1 ./ci.sh        # skip the docker image + smoke-test step
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[CI]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ERRORS=0

# Accept (and silently ignore) positional args so the script works both
# directly and as a git pre-push hook (which passes remote + URL).
while [[ $# -gt 0 ]]; do
    case "$1" in
        --*) echo "Unknown flag: $1" >&2; exit 1 ;;
        *)   shift ;;
    esac
done

step() { info "━━━ $1 ━━━"; }

record_fail() {
    fail "$1"
    ERRORS=$((ERRORS + 1))
}

# cargo-audit only reads audit.toml from the CURRENT working directory, so we
# cd to $APP_DIR before invoking it. Running from any other cwd silently
# bypasses the ignore list.
run_audit() {
    local label="$1" lockfile="$2"
    if command -v cargo-audit &>/dev/null; then
        if [ -f "$lockfile" ]; then
            if (cd "$APP_DIR" && cargo audit --file "$lockfile") 2>&1; then
                ok "$label audit clean."
            else
                record_fail "$label has vulnerabilities."
            fi
        else
            warn "$lockfile not found — skipping $label audit."
        fi
    else
        warn "cargo-audit not installed — skipping $label audit. Install: cargo install cargo-audit"
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight: disk-space check.
# A prior run failed mid-build with "no space left on device" after 30+
# minutes of Rust compilation. Fail fast if / has less than MIN_FREE_GB.
# Override via CI_MIN_FREE_GB or bypass with CI_SKIP_DISK_CHECK=1.
# ---------------------------------------------------------------------------
MIN_FREE_GB="${CI_MIN_FREE_GB:-10}"
if [[ "${CI_SKIP_DISK_CHECK:-0}" != "1" ]]; then
    free_kb=$(df -Pk / | awk 'NR==2 {print $4}')
    free_gb=$(( free_kb / 1024 / 1024 ))
    if (( free_gb < MIN_FREE_GB )); then
        fail "Pre-flight: / has only ${free_gb} GiB free (< ${MIN_FREE_GB} GiB required)."
        if command -v docker &>/dev/null && docker info &>/dev/null; then
            warn "Docker disk usage:"
            docker system df 2>&1 | sed 's/^/  /' || true
            warn "Quick fixes: docker builder prune -f --filter 'until=168h' / docker image prune -a -f"
        fi
        warn "Override with CI_MIN_FREE_GB=<n> or CI_SKIP_DISK_CHECK=1 if intentional."
        exit 1
    fi
    ok "Pre-flight: ${free_gb} GiB free on /."
fi

# =========================================================================
# 1. SDK (sdk-core + sdk-wasm): clippy + test + audit + wasm-pack build
# =========================================================================
step "SDK — clippy"
if cargo clippy --manifest-path "$APP_DIR/sdk/sdk-core/Cargo.toml" \
   --no-default-features --features "crypto byo providers" \
   --all-targets -- -D warnings 2>&1; then
    ok "SDK clippy clean."
else
    record_fail "SDK clippy has warnings/errors."
fi

step "SDK — tests"
if cargo test --manifest-path "$APP_DIR/sdk/sdk-core/Cargo.toml" \
   --no-default-features --features "crypto byo providers" 2>&1; then
    ok "SDK tests passed."
else
    record_fail "SDK tests failed."
fi

step "SDK — cargo audit"
run_audit "SDK" "$APP_DIR/Cargo.lock"

step "SDK — wasm-pack build"
if command -v wasm-pack &>/dev/null; then
    if (cd "$APP_DIR/sdk/sdk-wasm" && \
        wasm-pack build --release --target web \
          --out-dir ../../frontend/src/pkg --out-name wattcloud_sdk_wasm) 2>&1; then
        ok "wasm-pack build succeeded."
    else
        record_fail "wasm-pack build failed."
    fi
else
    warn "wasm-pack not installed — skipping. Install: cargo install wasm-pack"
fi

# =========================================================================
# 2. byo-relay: clippy + test + audit
# =========================================================================
step "byo-relay — clippy"
if cargo clippy --manifest-path "$APP_DIR/byo-relay/Cargo.toml" \
   --all-targets -- -D warnings 2>&1; then
    ok "byo-relay clippy clean."
else
    record_fail "byo-relay clippy has warnings/errors."
fi

step "byo-relay — tests"
if cargo test --manifest-path "$APP_DIR/byo-relay/Cargo.toml" 2>&1; then
    ok "byo-relay tests passed."
else
    record_fail "byo-relay tests failed."
fi

step "byo-relay — cargo audit"
run_audit "byo-relay" "$APP_DIR/byo-relay/Cargo.lock"

# =========================================================================
# 3. Frontend (incl. @wattcloud/sdk under src/lib/sdk): lint + test + build
# =========================================================================
step "Frontend — lint + test + build"
if command -v npm &>/dev/null; then
    if (cd "$APP_DIR/frontend" && npm ci --silent && \
        npm run lint && npm test && npm run build) 2>&1; then
        ok "Frontend checks passed."
    else
        record_fail "Frontend checks failed."
    fi
else
    warn "npm not installed — skipping frontend checks."
fi

# =========================================================================
# 4. Docker: build byo-relay image + optional smoke test
# =========================================================================
if [[ "${CI_SKIP_DOCKER:-0}" != "1" ]]; then
    step "Docker — build byo-relay image"
    if command -v docker &>/dev/null && docker info &>/dev/null; then
        if (cd "$APP_DIR" && docker build -t wattcloud:ci -f byo-relay/Dockerfile byo-relay) 2>&1; then
            ok "byo-relay image built (tag wattcloud:ci)."
        else
            record_fail "byo-relay image build failed."
        fi

        step "Docker — smoke test"
        if bash "$SCRIPT_DIR/byo-smoke.sh" 2>&1; then
            ok "Smoke test passed."
        else
            record_fail "Smoke test failed."
        fi
    else
        warn "Docker not available — skipping image build + smoke."
    fi
fi

# =========================================================================
# Post-run: age-gated Docker builder cache prune (only on success).
# Reclaims cache older than 7 days so a warm cache today survives tomorrow
# but stale layers from retired branches don't accumulate. Skip with
# CI_SKIP_PRUNE=1.
# =========================================================================
post_run_prune() {
    [[ "${CI_SKIP_PRUNE:-0}" == "1" ]] && return 0
    command -v docker &>/dev/null && docker info &>/dev/null || return 0
    step "Post-run — builder cache prune (> 7 days)"
    docker builder prune -f --filter 'until=168h' 2>&1 | tail -5 || true
}

echo ""
if [ "$ERRORS" -eq 0 ]; then
    post_run_prune
    echo -e "${GREEN}━━━ CI passed ━━━${NC}"
    exit 0
else
    echo -e "${RED}━━━ CI failed ($ERRORS error(s)) ━━━${NC}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Git hook setup (optional):
#   Pre-push hook (runs CI before each push):
#     ln -sf ../../scripts/ci.sh .git/hooks/pre-push
# ---------------------------------------------------------------------------
