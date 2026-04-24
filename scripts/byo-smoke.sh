#!/usr/bin/env bash
# byo-smoke.sh — locally start byo-relay against the tarball layout and
# verify the main HTTP surfaces. No Docker, no systemd required — just builds
# the release artifacts into a scratch dir and runs the binary with a
# throwaway env. Cleans up on exit.
#
# Runs two scenarios back-to-back:
#   1. Open mode        — /health, /ready, no-IP-in-logs regression.
#   2. Restricted mode  — enrollment gate end-to-end (claim → invite →
#                         redeem → device list → sign out).
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "[SMOKE] $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BYO_BIN="${BYO_BIN:-$APP_DIR/byo-relay/target/release/byo-relay}"
SPA_DIST="${SPA_DIST:-$APP_DIR/byo-relay/dist}"
PORT="${PORT:-18443}"   # non-default so smoke can run alongside a real instance
RESTRICTED_PORT="${RESTRICTED_PORT:-18444}"
MAX_WAIT="${MAX_WAIT:-30}"

SMOKE_DIR="$(mktemp -d -t wattcloud-smoke.XXXXXX)"
RELAY_PID=""

cleanup() {
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null && wait "$RELAY_PID" 2>/dev/null || true
  rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT

# --- Build artifacts if missing --------------------------------------------
if [ ! -x "$BYO_BIN" ]; then
  info "byo-relay binary not found — building..."
  (cd "$APP_DIR/byo-relay" && cargo build --release --bin byo-relay) \
    || { fail "byo-relay build failed"; exit 1; }
fi

if [ ! -f "$SPA_DIST/index.html" ]; then
  if [ -d "$APP_DIR/frontend" ]; then
    info "SPA dist missing — skipping (tarball layout uses web/ but frontend build is a separate concern for smoke)."
    install -d -m 0755 "$SMOKE_DIR/web"
    # Minimal placeholder so byo-relay's ServeDir has something to serve.
    printf '<!doctype html><title>smoke</title>OK\n' > "$SMOKE_DIR/web/index.html"
  fi
else
  cp -r "$SPA_DIST" "$SMOKE_DIR/web"
fi

# --- Assemble scratch tarball layout ---------------------------------------
install -d -m 0755 "$SMOKE_DIR/bin"
cp "$BYO_BIN" "$SMOKE_DIR/bin/byo-relay"
install -d -m 0755 "$SMOKE_DIR/state"

SIGNING_KEY="$(openssl rand -base64 48)"
SHARE_SIGNING_KEY="$(openssl rand -base64 48)"
HMAC_KEY="$(openssl rand -hex 32)"

# ──────────────────────────────────────────────────────────────────────────
# Scenario 1 — Open mode: basic health + ready + IP-leak regression.
# ──────────────────────────────────────────────────────────────────────────

start_relay() {
  local port="$1"
  shift
  (
    set -a
    BIND_ADDR="127.0.0.1:$port"
    SPA_DIR="$SMOKE_DIR/web"
    STATS_DB_PATH="$SMOKE_DIR/state/stats.sqlite3"
    SHARE_DB_PATH="$SMOKE_DIR/state/shares.sqlite3"
    SHARE_STORAGE_DIR="$SMOKE_DIR/state/shares"
    ENROLLMENT_DB_PATH="$SMOKE_DIR/state/enrollment.sqlite3"
    BOOTSTRAP_TOKEN_PATH="$SMOKE_DIR/state/bootstrap.txt"
    BYO_DOMAIN="localhost"
    RELAY_SIGNING_KEY="$SIGNING_KEY"
    RELAY_SHARE_SIGNING_KEY="$SHARE_SIGNING_KEY"
    STATS_HMAC_KEY="$HMAC_KEY"
    RUST_LOG="warn"
    for kv in "$@"; do export "$kv"; done
    set +a
    "$SMOKE_DIR/bin/byo-relay" >"$SMOKE_DIR/relay.log" 2>&1 &
    echo $! > "$SMOKE_DIR/relay.pid"
  )
  RELAY_PID="$(cat "$SMOKE_DIR/relay.pid")"

  local resp=""
  for i in $(seq 1 "$MAX_WAIT"); do
    resp="$(curl -fsS --max-time 2 "http://127.0.0.1:$port/health" 2>/dev/null || true)"
    [ "$resp" = "ok" ] && break
    sleep 1
  done
  if [ "$resp" != "ok" ]; then
    fail "relay on :$port never became healthy (last 20 log lines):"
    tail -20 "$SMOKE_DIR/relay.log" >&2
    exit 1
  fi
}

stop_relay() {
  [ -n "$RELAY_PID" ] || return 0
  kill "$RELAY_PID" 2>/dev/null || true
  wait "$RELAY_PID" 2>/dev/null || true
  RELAY_PID=""
}

info "── Scenario 1: Open mode ──"
start_relay "$PORT"
ok "/health = ok on :$PORT"

ready_code="$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
              "http://127.0.0.1:$PORT/ready" 2>/dev/null || echo "000")"
[ "$ready_code" = "200" ] || { fail "/ready = HTTP $ready_code"; exit 1; }
ok "/ready = 200"

info_open="$(curl -fsS --max-time 2 "http://127.0.0.1:$PORT/relay/info" 2>/dev/null || true)"
echo "$info_open" | grep -q '"mode":"open"' \
  || { fail "/relay/info did not report mode=open: $info_open"; exit 1; }
ok "/relay/info = open"

info "Checking for IP leakage in logs..."
# Drop the single startup line that carries BIND_ADDR — that's intentional
# (operator-facing config log, not a per-request IP).
if grep -v 'byo-relay starting on' "$SMOKE_DIR/relay.log" \
   | grep -qE 'client_ip|([0-9]{1,3}\.){3}[0-9]{1,3}'; then
  warn "Possible IP in relay logs — review manually:"
  grep -v 'byo-relay starting on' "$SMOKE_DIR/relay.log" \
    | grep -E 'client_ip|([0-9]{1,3}\.){3}[0-9]{1,3}' | head -5
fi

stop_relay
# Wipe state between scenarios so the restricted run starts from a fresh DB.
rm -rf "$SMOKE_DIR/state"
install -d -m 0755 "$SMOKE_DIR/state"
: > "$SMOKE_DIR/relay.log"

# PoW helper: fetches a challenge at the given purpose, solves it
# (sha256(nonce ‖ purpose ‖ answer_le64) with ≥12 leading zero bits —
# matching the relay's minimum), prints `nonce_id answer`. 12 bits =
# ~4096 expected iterations which completes in milliseconds. Python is
# available on every CI runner we target.
solve_pow() {
  local relay="$1" purpose="$2"
  local path
  case "$purpose" in
    admin:claim)  path="/relay/admin/claim/challenge"  ;;
    admin:redeem) path="/relay/admin/redeem/challenge" ;;
    *) fail "unknown purpose: $purpose"; return 1 ;;
  esac
  local challenge
  challenge="$(curl -fsS --max-time 3 "${relay}${path}")"
  python3 - "$challenge" "$purpose" <<'PY'
import hashlib, json, struct, sys
challenge = json.loads(sys.argv[1])
purpose = sys.argv[2]
nonce = bytes.fromhex(challenge["nonce"])
difficulty = int(challenge["difficulty"])
answer = 0
while True:
    h = hashlib.sha256(nonce + purpose.encode() + struct.pack('<Q', answer)).digest()
    bits = 0
    for b in h:
        if b == 0:
            bits += 8
        else:
            bits += 8 - b.bit_length()
            break
    if bits >= difficulty:
        print(f'{challenge["nonce_id"]} {answer}')
        break
    answer += 1
PY
}

# ──────────────────────────────────────────────────────────────────────────
# Scenario 2 — Restricted mode: full enrollment flow.
# ──────────────────────────────────────────────────────────────────────────

info "── Scenario 2: Restricted enrollment ──"
start_relay "$RESTRICTED_PORT" "WATTCLOUD_ENROLLMENT_MODE=restricted"
RELAY_URL="http://127.0.0.1:$RESTRICTED_PORT"

# /relay/info: mode=restricted, bootstrapped=false
info_body="$(curl -fsS --max-time 2 "$RELAY_URL/relay/info")"
echo "$info_body" | grep -q '"mode":"restricted"' \
  || { fail "expected mode=restricted, got: $info_body"; exit 1; }
echo "$info_body" | grep -q '"bootstrapped":false' \
  || { fail "expected bootstrapped=false, got: $info_body"; exit 1; }
ok "/relay/info = restricted, bootstrapped=false"

# /relay/auth/challenge: without cookie → 401 (middleware gate)
gate_code="$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
              "$RELAY_URL/relay/auth/challenge?purpose=sftp:00000000000000000000000000000000" \
              2>/dev/null || echo "000")"
[ "$gate_code" = "401" ] || {
  fail "/relay/auth/challenge ungated in restricted mode: HTTP $gate_code"; exit 1;
}
ok "/relay/auth/challenge = 401 (gated)"

# Read bootstrap token off disk.
for i in $(seq 1 5); do
  [ -s "$SMOKE_DIR/state/bootstrap.txt" ] && break
  sleep 1
done
BOOT_TOKEN="$(cat "$SMOKE_DIR/state/bootstrap.txt" 2>/dev/null || true)"
[ -n "$BOOT_TOKEN" ] || { fail "bootstrap token file never appeared"; exit 1; }
ok "bootstrap token minted"

# Claim ownership. Device cookie comes back as Set-Cookie. PoW solved
# inline via the python helper above.
OWNER_JAR="$SMOKE_DIR/state/owner_cookies.txt"
read -r CLAIM_NID CLAIM_ANS < <(solve_pow "$RELAY_URL" "admin:claim")
claim_body=$(cat <<JSON
{"token":"$BOOT_TOKEN","label":"Smoke Owner","pubkey_b64":"$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')","nonce_id":"$CLAIM_NID","answer":$CLAIM_ANS}
JSON
)
claim_resp="$(curl -fsS --max-time 5 -c "$OWNER_JAR" \
              -H 'Content-Type: application/json' \
              -d "$claim_body" \
              "$RELAY_URL/relay/admin/claim")"
echo "$claim_resp" | grep -q '"is_owner":true' \
  || { fail "claim did not return is_owner=true: $claim_resp"; exit 1; }
grep -q 'wattcloud_device' "$OWNER_JAR" || { fail "owner cookie not set"; exit 1; }
ok "/relay/admin/claim → owner cookie (PoW-gated)"

# Claim without PoW fields → 403 bad_pow. (We'd need a fresh bootstrap
# token to retest the rest, so we just exercise the gate with a fake
# nonce.)
no_pow_code="$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' \
               -H 'Content-Type: application/json' \
               -d '{"token":"x","label":"y","pubkey_b64":"AAAA","nonce_id":"missing","answer":0}' \
               "$RELAY_URL/relay/admin/claim" 2>/dev/null || echo "000")"
[ "$no_pow_code" = "403" ] || {
  fail "claim without valid PoW should 403, got $no_pow_code"; exit 1;
}
ok "/relay/admin/claim without valid PoW = 403"

# bootstrapped flips true.
info_after="$(curl -fsS --max-time 2 "$RELAY_URL/relay/info")"
echo "$info_after" | grep -q '"bootstrapped":true' \
  || { fail "bootstrapped did not flip: $info_after"; exit 1; }
ok "bootstrapped=true"

# /relay/admin/me → should report this device.
me_body="$(curl -fsS --max-time 2 -b "$OWNER_JAR" "$RELAY_URL/relay/admin/me")"
echo "$me_body" | grep -q '"is_owner":true' \
  || { fail "me did not return is_owner=true: $me_body"; exit 1; }
ok "/relay/admin/me = owner device"

# Mint an invite (owner-only).
invite_body=$(cat <<JSON
{"label":"Smoke Member","ttl_secs":3600}
JSON
)
invite_resp="$(curl -fsS --max-time 5 -b "$OWNER_JAR" \
               -H 'Content-Type: application/json' \
               -d "$invite_body" \
               "$RELAY_URL/relay/admin/invite")"
INVITE_CODE="$(echo "$invite_resp" | sed -n 's/.*"code":"\([^"]*\)".*/\1/p')"
[ -n "$INVITE_CODE" ] || { fail "could not extract code from: $invite_resp"; exit 1; }
ok "/relay/admin/invite → code $INVITE_CODE"

# Redeem from a fresh jar (separate "device"). Each redeem attempt needs
# its own PoW nonce since the server consumes single-use.
MEMBER_JAR="$SMOKE_DIR/state/member_cookies.txt"
read -r REDEEM_NID REDEEM_ANS < <(solve_pow "$RELAY_URL" "admin:redeem")
redeem_body=$(cat <<JSON
{"code":"$INVITE_CODE","label":"Smoke Member","pubkey_b64":"$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')","nonce_id":"$REDEEM_NID","answer":$REDEEM_ANS}
JSON
)
redeem_resp="$(curl -fsS --max-time 5 -c "$MEMBER_JAR" \
              -H 'Content-Type: application/json' \
              -d "$redeem_body" \
              "$RELAY_URL/relay/admin/redeem")"
echo "$redeem_resp" | grep -q '"is_owner":false' \
  || { fail "redeem did not return is_owner=false: $redeem_resp"; exit 1; }
ok "/relay/admin/redeem → member cookie (PoW-gated)"

# Replay of the same code → 401 invalid_invite. Need a fresh PoW since
# the previous one was consumed.
read -r REPLAY_NID REPLAY_ANS < <(solve_pow "$RELAY_URL" "admin:redeem")
replay_body=$(cat <<JSON
{"code":"$INVITE_CODE","label":"Smoke Member","pubkey_b64":"$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')","nonce_id":"$REPLAY_NID","answer":$REPLAY_ANS}
JSON
)
replay_code="$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' \
               -H 'Content-Type: application/json' \
               -d "$replay_body" \
               "$RELAY_URL/relay/admin/redeem" 2>/dev/null || echo "000")"
[ "$replay_code" = "401" ] || {
  fail "invite replay should 401, got $replay_code"; exit 1;
}
ok "invite code replay = 401 (single-use enforced)"

# Owner lists devices — expect 2 rows.
devs="$(curl -fsS --max-time 3 -b "$OWNER_JAR" "$RELAY_URL/relay/admin/devices")"
dev_count="$(echo "$devs" | grep -o '"device_id"' | wc -l | tr -d '[:space:]')"
[ "$dev_count" = "2" ] || {
  fail "expected 2 devices, got $dev_count: $devs"; exit 1;
}
ok "/relay/admin/devices = 2 rows"

# Member tries admin list → 403.
forbidden="$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' \
             -b "$MEMBER_JAR" "$RELAY_URL/relay/admin/devices" 2>/dev/null || echo "000")"
[ "$forbidden" = "403" ] || {
  fail "member should get 403 on owner endpoint, got $forbidden"; exit 1;
}
ok "/relay/admin/devices as member = 403"

# Member signs out — cookie invalidated, admin-me returns no device.
signout="$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' \
           -X POST -b "$MEMBER_JAR" -c "$MEMBER_JAR" \
           "$RELAY_URL/relay/admin/signout" 2>/dev/null || echo "000")"
[ "$signout" = "204" ] || { fail "signout = $signout"; exit 1; }
me_after="$(curl -fsS --max-time 2 -b "$MEMBER_JAR" "$RELAY_URL/relay/admin/me")"
echo "$me_after" | grep -q '"device":null' \
  || { fail "me after signout should be null, got: $me_after"; exit 1; }
ok "/relay/admin/signout → 204, cookie revoked"

# Operational route still blocked for the signed-out member.
op_after="$(curl -sS --max-time 3 -o /dev/null -w '%{http_code}' \
            -b "$MEMBER_JAR" \
            "$RELAY_URL/relay/auth/challenge?purpose=sftp:00000000000000000000000000000000" \
            2>/dev/null || echo "000")"
[ "$op_after" = "401" ] || { fail "post-signout /auth/challenge = $op_after (expected 401)"; exit 1; }
ok "operational route stays gated post-signout"

stop_relay

echo ""
echo -e "${GREEN}━━━ byo-smoke passed (open + restricted) ━━━${NC}"
