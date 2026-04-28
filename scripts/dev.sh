#!/usr/bin/env bash
# dev.sh — full-stack local dev: byo-relay + Vite on localhost.
#
# - Bootstraps .env.dev on first run (gitignored, persisted across restarts
#   so enrollment tokens survive).
# - Runs byo-relay on 127.0.0.1:8443 via `cargo run`.
# - Runs Vite dev server on :5173; vite.config.ts proxies /relay, /health,
#   and /ready to the relay so same-origin fetches Just Work.
# - Cleans up both processes on Ctrl-C or any exit.
# - Writes a PID file at .dev-state/dev.pid so `make dev-stop` can find the
#   stack from another shell.
#
# Modes (env vars):
#   (default)         — run the stack in the foreground (make dev).
#   DEV_STOP=1        — SIGTERM the running stack via its PID file.
#   DEV_RELAY_ONLY=1  — relay only, no Vite (make dev-relay).
#
# tmux / screen / systemd lifecycle is the user's concern. If you want the
# stack to survive your SSH session on a VPS, start your own tmux session
# first and run `make dev` inside it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ENV_FILE="$APP_DIR/.env.dev"
STATE_DIR="$APP_DIR/.dev-state"
PID_FILE="$STATE_DIR/dev.pid"
RELAY_HOST="${DEV_RELAY_HOST:-127.0.0.1}"
RELAY_PORT="${DEV_RELAY_PORT:-8443}"
MAX_WAIT="${MAX_WAIT:-60}"
# Origin check in byo-relay rejects any browser Origin that isn't
# `https://$BYO_DOMAIN`. Set WC_DOMAIN=dev.wattcloud.de when the SPA is loaded
# from a real domain (e.g. Caddy on a dev VPS); leave unset for localhost.
BYO_DOMAIN_VALUE="${WC_DOMAIN:-localhost}"

YELLOW='\033[1;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${YELLOW}[dev]${NC} $*"; }
ok()   { echo -e "${GREEN}[dev]${NC} $*"; }
fail() { echo -e "${RED}[dev] FAIL:${NC} $*" >&2; exit 1; }

# --- Stop mode -------------------------------------------------------------
# Runs before the toolchain checks — stopping shouldn't require cargo/npm.
if [ "${DEV_STOP:-}" = "1" ]; then
  if [ ! -f "$PID_FILE" ]; then
    info "No $PID_FILE — the stack isn't running (or wasn't started by 'make dev')."
    exit 0
  fi
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    info "Stale PID file (pid=${pid:-empty} not running). Cleaning up."
    rm -f "$PID_FILE"
    exit 0
  fi
  info "Sending SIGTERM to dev.sh pid $pid..."
  kill "$pid"
  # Wait up to ~5s for the trap-driven cleanup to run and tear down children.
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$pid" 2>/dev/null; then
    fail "pid $pid still alive after 5s. Inspect manually (ps / kill -9)."
  fi
  ok "Stack stopped."
  exit 0
fi

command -v cargo     >/dev/null 2>&1 || fail "cargo not in PATH."
command -v npm       >/dev/null 2>&1 || fail "npm not in PATH."
command -v openssl   >/dev/null 2>&1 || fail "openssl not in PATH."

# --- Already-running guard -------------------------------------------------
if [ -f "$PID_FILE" ]; then
  existing="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$existing" ] && kill -0 "$existing" 2>/dev/null; then
    fail "wattcloud dev stack already running (pid $existing). Stop it first: 'make dev-stop'."
  fi
  rm -f "$PID_FILE"
fi

# --- Bootstrap .env.dev (first run only) -----------------------------------
if [ ! -f "$ENV_FILE" ]; then
  info "First run — generating $ENV_FILE with ephemeral signing keys."
  mkdir -p "$STATE_DIR"
  umask 077
  cat > "$ENV_FILE" <<EOF
# Wattcloud local dev env — generated $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Gitignored via .env.*. Delete to regenerate (you'll need to re-enroll).
BIND_ADDR=$RELAY_HOST:$RELAY_PORT
SPA_DIR=$STATE_DIR/web-stub
STATS_DB_PATH=$STATE_DIR/stats.sqlite3
SHARE_STORAGE_DIR=$STATE_DIR/shares
SHARE_DB_PATH=$STATE_DIR/shares.sqlite3
ENROLLMENT_DB_PATH=$STATE_DIR/enrollment.sqlite3
BOOTSTRAP_TOKEN_PATH=$STATE_DIR/bootstrap.txt
# Dev mirrors prod: invite-only by default. Flip to "open" here if you
# want to reproduce the pre-phase-1 behaviour without the bootstrap /
# invite flow.
WATTCLOUD_ENROLLMENT_MODE=restricted
BYO_DOMAIN=$BYO_DOMAIN_VALUE
RELAY_SIGNING_KEY=$(openssl rand -base64 48)
RELAY_SHARE_SIGNING_KEY=$(openssl rand -base64 48)
STATS_HMAC_KEY=$(openssl rand -hex 32)
RUST_LOG=warn
EOF
  umask 022
fi

# --- Migrate existing .env.dev files --------------------------------------
# Pre-shares .env.dev files fall through to the relay's production defaults
# (/var/lib/byo-relay/...) which are unwritable by the dev user. Append any
# missing paths so `cargo run` picks them up. Each block runs at most once
# — idempotent re-entry on later dev sessions.

if [ -f "$ENV_FILE" ] && ! grep -q '^SHARE_STORAGE_DIR=' "$ENV_FILE"; then
  info "Patching $ENV_FILE with share-store paths (one-time migration)."
  umask 077
  cat >> "$ENV_FILE" <<EOF
SHARE_STORAGE_DIR=$STATE_DIR/shares
SHARE_DB_PATH=$STATE_DIR/shares.sqlite3
EOF
  umask 022
fi

if [ -f "$ENV_FILE" ] && ! grep -q '^ENROLLMENT_DB_PATH=' "$ENV_FILE"; then
  info "Patching $ENV_FILE with enrollment-store paths (one-time migration)."
  umask 077
  cat >> "$ENV_FILE" <<EOF
ENROLLMENT_DB_PATH=$STATE_DIR/enrollment.sqlite3
BOOTSTRAP_TOKEN_PATH=$STATE_DIR/bootstrap.txt
EOF
  umask 022
fi

if [ -f "$ENV_FILE" ] && ! grep -q '^WATTCLOUD_ENROLLMENT_MODE=' "$ENV_FILE"; then
  info "Patching $ENV_FILE with WATTCLOUD_ENROLLMENT_MODE=restricted (matches prod default)."
  umask 077
  printf 'WATTCLOUD_ENROLLMENT_MODE=restricted\n' >> "$ENV_FILE"
  umask 022
fi

# --- Detect BYO_DOMAIN / WC_DOMAIN mismatch --------------------------------
# $ENV_FILE pins BYO_DOMAIN at first-run bootstrap. If WC_DOMAIN is now set
# to something different in the current shell, the relay's Origin check
# (byo-relay/src/relay_ws.rs) will reject every browser request from the
# hostname the SPA is actually served from — producing a non-obvious
# "ws upgrade denied: Origin header missing or mismatched" in the relay
# log. Fail fast with a fix command rather than starting a broken stack.
if [ -n "${WC_DOMAIN:-}" ] && [ -f "$ENV_FILE" ]; then
  pinned_domain="$(grep -E '^BYO_DOMAIN=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)"
  if [ -n "$pinned_domain" ] && [ "$pinned_domain" != "$WC_DOMAIN" ]; then
    echo -e "${RED}[dev] BYO_DOMAIN / WC_DOMAIN mismatch:${NC}" >&2
    echo -e "${RED}[dev]${NC}   $ENV_FILE pins BYO_DOMAIN=$pinned_domain" >&2
    echo -e "${RED}[dev]${NC}   current shell has WC_DOMAIN=$WC_DOMAIN" >&2
    echo -e "${RED}[dev]${NC}   Browser Origin from https://$WC_DOMAIN would be rejected" >&2
    echo -e "${RED}[dev]${NC}   by byo-relay's Origin check. Fix with:" >&2
    echo -e "${RED}[dev]${NC}     sed -i 's|^BYO_DOMAIN=.*|BYO_DOMAIN=$WC_DOMAIN|' '$ENV_FILE'" >&2
    echo -e "${RED}[dev]${NC}   (or rm '$ENV_FILE' to regenerate from the current WC_DOMAIN)." >&2
    fail "aborting — fix the mismatch or unset WC_DOMAIN."
  fi
fi

# Stub SPA dir — Vite serves the real SPA on :5173; the relay's ServeDir is a
# fallback we don't hit in dev.
mkdir -p "$STATE_DIR/web-stub"
if [ ! -f "$STATE_DIR/web-stub/index.html" ]; then
  cat > "$STATE_DIR/web-stub/index.html" <<'HTML'
<!doctype html><title>byo-relay (dev stub)</title>
<p>Dev SPA is served by Vite at <a href="http://localhost:5173/">http://localhost:5173/</a>.</p>
HTML
fi

# Build WASM bundle if missing (first run).
if [ ! -f "$APP_DIR/frontend/src/pkg/wattcloud_sdk_wasm_bg.wasm" ]; then
  info "WASM bundle missing — building via make build-sdk-wasm..."
  make -C "$APP_DIR" build-sdk-wasm
fi

# --- Cleanup ---------------------------------------------------------------
RELAY_PID=""
VITE_PID=""
cleanup() {
  local ec=$?
  for pid in "$VITE_PID" "$RELAY_PID"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -f "$PID_FILE"
  exit "$ec"
}
trap cleanup EXIT INT TERM

# Record our PID so `make dev-stop` can SIGTERM us from another shell.
mkdir -p "$STATE_DIR"
echo $$ > "$PID_FILE"

# --- Log files -------------------------------------------------------------
# Tee relay + Vite output to files under $STATE_DIR so diagnostics (e.g.
# "what did the relay log when I clicked Connect?") don't require access to
# the live foreground terminal. Truncated each dev.sh run — each session has
# its own log.
RELAY_LOG="$STATE_DIR/relay.log"
VITE_LOG="$STATE_DIR/vite.log"
: > "$RELAY_LOG"
: > "$VITE_LOG"

# --- Start byo-relay -------------------------------------------------------
info "Starting byo-relay on $RELAY_HOST:$RELAY_PORT (cargo run, first build may be slow)..."
info "  → logs: $RELAY_LOG"
(
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  exec cargo run --manifest-path "$APP_DIR/byo-relay/Cargo.toml" --bin byo-relay
) > >(tee -a "$RELAY_LOG") 2> >(tee -a "$RELAY_LOG" >&2) &
RELAY_PID=$!

info "Waiting for relay /health (max ${MAX_WAIT}s)..."
healthy=0
for _ in $(seq 1 "$MAX_WAIT"); do
  if ! kill -0 "$RELAY_PID" 2>/dev/null; then
    fail "byo-relay exited during startup. Re-run to see the error."
  fi
  if curl -fsS --max-time 1 "http://$RELAY_HOST:$RELAY_PORT/health" >/dev/null 2>&1; then
    healthy=1; break
  fi
  sleep 1
done
[ "$healthy" = "1" ] || fail "relay /health did not respond within ${MAX_WAIT}s."
ok "byo-relay is live on http://$RELAY_HOST:$RELAY_PORT"

# --- Relay-only mode (make dev-relay) --------------------------------------
if [ "${DEV_RELAY_ONLY:-}" = "1" ]; then
  ok "Relay-only mode. Start the frontend separately with 'make dev-frontend'."
  wait "$RELAY_PID"
  exit $?
fi

# --- Start Vite ------------------------------------------------------------
info "Starting Vite dev server on :5173 (proxies /relay + /health + /ready to the relay)..."
info "  → logs: $VITE_LOG"
(cd "$APP_DIR/frontend" && DEV_RELAY_URL="http://$RELAY_HOST:$RELAY_PORT" npm run dev) \
  > >(tee -a "$VITE_LOG") 2> >(tee -a "$VITE_LOG" >&2) &
VITE_PID=$!

ok "Full stack up. Open http://localhost:5173/  —  Ctrl-C to stop both (or 'make dev-stop' from another shell)."
wait -n
