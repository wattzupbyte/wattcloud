#!/usr/bin/env bash
# =============================================================================
# ci.sh — Local CI pipeline for Wattcloud
# Run manually or wire into a git hook (see bottom of file).
# Excludes: /android
#
# Usage:
#   ./scripts/ci.sh              # full mode (default)
#   ./scripts/ci.sh --mode byo   # BYO-only mode (skips backend + managed images)
#   ./scripts/ci.sh --mode full  # explicit full mode
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

# Resolve symlinks (handles being called via .git/hooks/pre-push symlink)
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ERRORS=0

# ---------------------------------------------------------------------------
# Parse --mode flag
# ---------------------------------------------------------------------------
MODE="full"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            MODE="${2:-}"
            shift 2
            ;;
        --*)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--mode byo|full]" >&2
            exit 1
            ;;
        *)
            # Git pre-push hook passes <remote-name> <remote-url> as positional args.
            # Silently skip them so this script works both directly and as a hook.
            shift
            ;;
    esac
done

if [[ "$MODE" != "byo" && "$MODE" != "full" ]]; then
    echo "Invalid mode '$MODE'. Use 'byo' or 'full'." >&2
    exit 1
fi

info "Mode: $MODE"

step() {
    info "━━━ $1 ━━━"
}

# ---------------------------------------------------------------------------
# Pre-flight: disk space check.
#
# A previous run failed with "no space left on device" during the frontend
# Docker COPY, after 30+ minutes of Rust compilation. Fail fast instead:
# reject the run up front if / has less than MIN_FREE_GB available.
#
# Override via CI_MIN_FREE_GB (e.g. CI_MIN_FREE_GB=5 for a tight environment).
# Set CI_SKIP_DISK_CHECK=1 to bypass entirely.
# ---------------------------------------------------------------------------
MIN_FREE_GB="${CI_MIN_FREE_GB:-10}"
if [[ "${CI_SKIP_DISK_CHECK:-0}" != "1" ]]; then
    # BSD/macOS df lacks -B; use portable POSIX fields and do the math here.
    free_kb=$(df -Pk / | awk 'NR==2 {print $4}')
    free_gb=$(( free_kb / 1024 / 1024 ))
    if (( free_gb < MIN_FREE_GB )); then
        fail "Pre-flight: / has only ${free_gb} GiB free (< ${MIN_FREE_GB} GiB required)."
        if command -v docker &>/dev/null && docker info &>/dev/null; then
            warn "Docker disk usage (reclaimable shown in parentheses):"
            docker system df 2>&1 | sed 's/^/  /' || true
            warn "Quick fixes:"
            warn "  docker builder prune -f --filter 'until=168h'  # age-gated cache"
            warn "  docker image prune -a -f                       # untagged images"
        fi
        warn "Override with CI_MIN_FREE_GB=<n> or CI_SKIP_DISK_CHECK=1 if intentional."
        exit 1
    else
        ok "Pre-flight: ${free_gb} GiB free on / (>= ${MIN_FREE_GB} GiB)."
    fi
fi

record_fail() {
    fail "$1"
    ERRORS=$((ERRORS + 1))
}

# Run cargo-audit as a hard failure (not warn-only).
#
# cargo-audit only reads `audit.toml` from the CURRENT working directory —
# it does NOT search parents or look at `.cargo/audit.toml`. The repo keeps
# a single `audit.toml` at $APP_DIR with documented ignores (e.g. transitive
# RSA Marvin + rustls-pemfile informational), so we must cd there before
# invoking cargo audit. Running from any other cwd silently bypasses the
# ignore list and fails on known-accepted advisories.
run_audit() {
    local label="$1"
    local lockfile="$2"
    if command -v cargo-audit &>/dev/null; then
        if [ -f "$lockfile" ]; then
            if (cd "$APP_DIR" && cargo audit --file "$lockfile") 2>&1; then
                ok "$label audit clean."
            else
                record_fail "$label has vulnerabilities (cargo-audit failed)."
            fi
        else
            warn "$lockfile not found — skipping $label audit."
        fi
    else
        warn "cargo-audit not installed — skipping $label audit. Install: cargo install cargo-audit"
    fi
}

# =========================================================================
# 1. Backend: clippy, test, audit  (full mode only)
# =========================================================================
if [[ "$MODE" == "full" ]]; then
    step "Backend — clippy"
    if cargo clippy --manifest-path "$APP_DIR/backend/Cargo.toml" -- -D warnings 2>&1; then
        ok "Backend clippy clean."
    else
        record_fail "Backend clippy has warnings/errors."
    fi

    step "Backend — tests"
    if cargo test --manifest-path "$APP_DIR/backend/Cargo.toml" 2>&1; then
        ok "Backend tests passed (unit + integration)."
    else
        record_fail "Backend tests failed."
    fi

    step "Backend — cargo audit"
    run_audit "Backend" "$APP_DIR/backend/Cargo.lock"
fi

# =========================================================================
# 2. SDK: clippy, test, audit, WASM build
# =========================================================================
step "SDK — clippy"
if cargo clippy --manifest-path "$APP_DIR/sdk/Cargo.toml" --workspace -- -D warnings 2>&1; then
    ok "SDK clippy clean."
else
    record_fail "SDK clippy has warnings/errors."
fi

step "SDK — tests (default features)"
if cargo test --manifest-path "$APP_DIR/sdk/Cargo.toml" --workspace 2>&1; then
    ok "SDK tests passed."
else
    record_fail "SDK tests failed."
fi

step "SDK — BYO provider tests (--features providers)"
if cargo test --manifest-path "$APP_DIR/sdk/Cargo.toml" --workspace --features providers 2>&1; then
    ok "SDK provider tests passed."
else
    record_fail "SDK provider tests failed."
fi

if [[ "$MODE" == "byo" ]]; then
    step "SDK — BYO-only build (no managed code)"
    # Verify sdk-core compiles without managed feature (hard BYO-only check)
    if cargo test --manifest-path "$APP_DIR/sdk/Cargo.toml" -p sdk-core \
        --no-default-features --features "crypto byo providers" 2>&1; then
        ok "sdk-core BYO-only tests passed."
    else
        record_fail "sdk-core BYO-only tests failed."
    fi

    step "SDK — sdk-wasm BYO-only cargo build"
    # BYO features (crypto, byo, providers) are wired via sdk-wasm/Cargo.toml deps.
    # sdk-wasm itself only exposes a 'managed' feature; no extra flags needed here.
    if command -v wasm-pack &>/dev/null; then
        if (cd "$APP_DIR/sdk/sdk-wasm" && wasm-pack build --target web --release) 2>&1; then
            ok "sdk-wasm BYO-only WASM build succeeded."
        else
            record_fail "sdk-wasm BYO-only WASM build failed."
        fi
    else
        # Fallback: cargo build for the target (no wasm-pack needed)
        if cargo build --manifest-path "$APP_DIR/sdk/sdk-wasm/Cargo.toml" \
            --target wasm32-unknown-unknown --release 2>&1; then
            ok "sdk-wasm BYO-only cargo build succeeded."
        else
            record_fail "sdk-wasm BYO-only cargo build failed."
        fi
    fi
fi

step "SDK — cargo audit"
run_audit "SDK" "$APP_DIR/sdk/Cargo.lock"

step "SDK — WASM build"
if command -v wasm-pack &>/dev/null; then
    if (cd "$APP_DIR/sdk/sdk-wasm" && wasm-pack build --target web) 2>&1; then
        ok "WASM build succeeded."
    else
        record_fail "WASM build failed."
    fi
else
    warn "wasm-pack not installed — skipping WASM build. Install: cargo install wasm-pack"
fi

# =========================================================================
# 3. byo-server: clippy, test, audit
# =========================================================================
step "byo-server — clippy"
if cargo clippy --manifest-path "$APP_DIR/byo-server/Cargo.toml" -- -D warnings 2>&1; then
    ok "byo-server clippy clean."
else
    record_fail "byo-server clippy has warnings/errors."
fi

step "byo-server — tests"
if cargo test --manifest-path "$APP_DIR/byo-server/Cargo.toml" 2>&1; then
    ok "byo-server tests passed."
else
    record_fail "byo-server tests failed."
fi

step "byo-server — cargo audit"
run_audit "byo-server" "$APP_DIR/byo-server/Cargo.lock"

# =========================================================================
# 4. byo package: TypeScript tests
# =========================================================================
step "byo package — tests"
if command -v npm &>/dev/null; then
    if (cd "$APP_DIR/byo" && npm ci --silent && npm test) 2>&1; then
        ok "byo package tests passed."
    else
        record_fail "byo package tests failed."
    fi
else
    warn "npm not installed — skipping byo package tests."
fi

# =========================================================================
# 5. Frontend: tests + builds
# =========================================================================
step "Frontend — tests"
if command -v npm &>/dev/null; then
    if (cd "$APP_DIR/frontend" && npm ci --silent && npm test) 2>&1; then
        ok "Frontend tests passed."
    else
        record_fail "Frontend tests failed."
    fi
else
    warn "npm not installed — skipping frontend tests."
fi

if [[ "$MODE" == "full" ]]; then
    step "Frontend — managed build"
    if command -v npm &>/dev/null; then
        # Copy full WASM pkg for managed build (rm first to prevent cp -r nesting)
        if [ -d "$APP_DIR/sdk/sdk-wasm/pkg" ]; then
            rm -rf "$APP_DIR/frontend/src/pkg"
            cp -r "$APP_DIR/sdk/sdk-wasm/pkg" "$APP_DIR/frontend/src/pkg"
        fi
        if (cd "$APP_DIR/frontend" && npm run build) 2>&1; then
            ok "Frontend managed build succeeded."
        else
            record_fail "Frontend managed build failed."
        fi
    else
        warn "npm not installed — skipping frontend managed build."
    fi
fi

step "Frontend — BYO build (→ byo-server/dist)"
# Always rebuild BYO-only WASM before the BYO frontend build. In full mode the
# managed build step puts the full-feature WASM in frontend/src/pkg; using that
# for the BYO build would include managed symbols. BYO features are wired in
# sdk-wasm/Cargo.toml (sdk-core deps); no extra --features flags needed here.
if command -v wasm-pack &>/dev/null; then
    if (cd "$APP_DIR/sdk/sdk-wasm" && wasm-pack build --target web --release) 2>&1; then
        rm -rf "$APP_DIR/frontend/src/pkg"
        cp -r "$APP_DIR/sdk/sdk-wasm/pkg" "$APP_DIR/frontend/src/pkg"
        ok "BYO-only WASM rebuilt for BYO frontend build."
    else
        record_fail "BYO-only WASM build failed."
    fi
else
    warn "wasm-pack not installed — BYO WASM not rebuilt; bundle may contain managed symbols."
fi
if command -v npm &>/dev/null; then
    if (cd "$APP_DIR/frontend" && npm run build:byo) 2>&1; then
        ok "Frontend BYO build succeeded."
    else
        record_fail "Frontend BYO build failed."
    fi
    step "Frontend — verify BYO bundle (no managed symbols)"
    if bash "$SCRIPT_DIR/verify-byo-bundle.sh" 2>&1; then
        ok "BYO bundle verification passed."
    else
        record_fail "BYO bundle contains managed symbols or exceeds size limit."
    fi
fi

# =========================================================================
# 6. Docker: build images
# =========================================================================
step "Docker — build BYO image (byo-server)"
if command -v docker &>/dev/null && docker info &>/dev/null; then
    if (cd "$APP_DIR" && docker compose --profile byo build byo-server) 2>&1; then
        ok "byo-server Docker image built."
    else
        record_fail "byo-server Docker image build failed."
    fi
else
    warn "Docker not available — skipping BYO image build."
fi

if [[ "$MODE" == "byo" ]]; then
    step "Docker — BYO smoke test"
    if command -v docker &>/dev/null && docker info &>/dev/null; then
        if bash "$SCRIPT_DIR/byo-smoke.sh" 2>&1; then
            ok "BYO smoke test passed."
        else
            record_fail "BYO smoke test failed."
        fi
    else
        warn "Docker not available — skipping BYO smoke test."
    fi
fi

if [[ "$MODE" == "full" ]]; then
    step "Docker — build managed images (backend, frontend, backup)"
    if command -v docker &>/dev/null && docker info &>/dev/null; then
        if (cd "$APP_DIR" && docker compose --profile managed build backend frontend backup) 2>&1; then
            ok "Managed Docker images built."
        else
            record_fail "Managed Docker image build failed."
        fi
    else
        warn "Docker not available — skipping managed image build."
    fi
fi

# =========================================================================
# Post-run: age-gated Docker builder cache prune (only on success).
#
# Reclaims build-cache entries that haven't been used in a week, so a run
# that hits a warm cache today still hits it tomorrow but stale layers from
# long-retired branches don't accumulate indefinitely.
#
# Deliberately:
#   - Only on success: failed runs may leave half-built layers that a retry
#     wants to reuse after the fix.
#   - No `--all` / no `-a`: that evicts EVERYTHING unused right now,
#     including the Rust build cache we just warmed, tripling the next run.
#   - No `docker volume prune`: volume prune targets ALL unused volumes at
#     the prune moment and can eat DB / certs / backup targets when their
#     containers are stopped. If volume hygiene is ever needed, enumerate
#     by label instead of a blind prune.
#   - No `docker image prune -a`: that's a bigger hammer; let the operator
#     run it manually when disk is tight.
#
# Skip with CI_SKIP_PRUNE=1.
# =========================================================================
post_run_prune() {
    if [[ "${CI_SKIP_PRUNE:-0}" == "1" ]]; then
        return 0
    fi
    if ! command -v docker &>/dev/null || ! docker info &>/dev/null; then
        return 0
    fi
    step "Post-run — age-gated builder cache prune (> 7 days)"
    # `until=168h` keeps the last week of builder cache warm. Errors here
    # are non-fatal — a prune failure shouldn't fail a passing CI run.
    if docker builder prune -f --filter 'until=168h' 2>&1 | tail -5; then
        ok "Builder cache pruned (entries older than 7 days)."
    else
        warn "Builder prune failed (non-fatal)."
    fi
}

# =========================================================================
# Summary
# =========================================================================
echo ""
if [ "$ERRORS" -eq 0 ]; then
    post_run_prune
    echo -e "${GREEN}━━━ CI passed (mode: $MODE) ━━━${NC}"
    exit 0
else
    echo -e "${RED}━━━ CI failed ($ERRORS error(s), mode: $MODE) ━━━${NC}"
    exit 1
fi

# =========================================================================
# Git hook setup (optional):
#
#   Pre-push hook (runs CI before each push):
#     ln -sf ../../scripts/ci.sh .git/hooks/pre-push
#
#   Post-receive hook (for a bare repo on the VPS):
#     #!/bin/bash
#     WORK_TREE=/opt/wattcloud
#     GIT_DIR=/opt/wattcloud.git
#     git --work-tree=$WORK_TREE --git-dir=$GIT_DIR checkout -f
#     cd $WORK_TREE && ./scripts/ci.sh --mode byo && ./scripts/deploy.sh
# =========================================================================
