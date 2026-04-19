#!/usr/bin/env bash
# =============================================================================
# byo-smoke.sh — Spin up a BYO container and verify /health + byo-admin.
# Run after `make byo-prod-image`. Exits 1 on any failure.
# Cleans up on exit (healthy or not).
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ENV_SMOKE="$APP_DIR/.env.smoke"
MAX_WAIT=90

# Namespace the Compose project so volumes/networks are isolated from any real
# deployment running on the same host.  -v in cleanup only destroys this project's
# named volumes (byo-smoke-<pid>_byo-stats-data), never prod's wattcloud_byo-stats-data.
export COMPOSE_PROJECT_NAME="byo-smoke-$$"

# The smoke overlay uses `!override` / `!reset null` (Compose ≥ 2.24) to:
#   - drop `env_file: - .env` so production secrets never enter the smoke container
#   - drop `container_name` so Compose autonumbers per-project
# Without these tags, Compose silently appends/ignores — refuse to run.
COMPOSE_VER=$(docker compose version --short 2>/dev/null || echo "0.0.0")
COMPOSE_MAJOR=$(echo "$COMPOSE_VER" | cut -d. -f1)
COMPOSE_MINOR=$(echo "$COMPOSE_VER" | cut -d. -f2)
if [ "${COMPOSE_MAJOR:-0}" -lt 2 ] || { [ "${COMPOSE_MAJOR:-0}" -eq 2 ] && [ "${COMPOSE_MINOR:-0}" -lt 24 ]; }; then
    echo -e "${RED}[FAIL]${NC} docker compose ≥ 2.24 required (found: $COMPOSE_VER)"
    exit 1
fi

compose() {
    docker compose \
        --env-file "$ENV_SMOKE" \
        -f "$APP_DIR/docker-compose.yml" \
        -f "$APP_DIR/docker-compose.byo-smoke.yml" \
        --profile byo \
        "$@"
}

# ---------------------------------------------------------------------------
# Cleanup — always tear down the smoke stack on exit
# ---------------------------------------------------------------------------
cleanup() {
    echo "[SMOKE] Tearing down smoke stack (project: $COMPOSE_PROJECT_NAME)..."
    compose down -v --remove-orphans 2>/dev/null || true
    rm -f "$ENV_SMOKE"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Generate throwaway secrets — never touch any existing .env
# ---------------------------------------------------------------------------
echo "[SMOKE] Generating throwaway smoke environment..."
cat > "$ENV_SMOKE" <<EOF
RELAY_SIGNING_KEY=$(openssl rand -base64 48)
RELAY_SHARE_SIGNING_KEY=$(openssl rand -base64 48)
BYO_STATS_HMAC_KEY=$(openssl rand -base64 48)
BYO_DOMAIN=localhost
BYO_IMAGE=${BYO_IMAGE:-byo-server:local}
EOF
chmod 600 "$ENV_SMOKE"

# ---------------------------------------------------------------------------
# Bring up byo-server only (--no-deps skips Traefik and any other services
# that would otherwise bind to host ports 80/443)
# ---------------------------------------------------------------------------
echo "[SMOKE] Starting byo-server (project: $COMPOSE_PROJECT_NAME)..."
compose up -d --no-deps byo-server

# Resolve the actual container ID — never assume a naming pattern, since the
# base compose pins `container_name` and the overlay resets it via `!reset null`.
CONTAINER=$(compose ps -q byo-server)
if [ -z "$CONTAINER" ]; then
    echo -e "${RED}[FAIL]${NC} could not resolve byo-server container id"
    compose ps
    exit 1
fi

# ---------------------------------------------------------------------------
# Poll for healthy status
# ---------------------------------------------------------------------------
echo "[SMOKE] Waiting for byo-server to become healthy (max ${MAX_WAIT}s)..."
ELAPSED=0
HEALTH=""
while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
    HEALTH=$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo "missing")
    if [ "$HEALTH" = "healthy" ]; then
        break
    fi
    sleep 3
    ELAPSED=$((ELAPSED + 3))
done

if [ "$HEALTH" != "healthy" ]; then
    echo -e "${RED}[FAIL]${NC} byo-server did not become healthy within ${MAX_WAIT}s (status: $HEALTH)"
    docker logs "$CONTAINER" 2>&1 | tail -20
    exit 1
fi
echo -e "${GREEN}[OK]${NC} byo-server healthy."

# ---------------------------------------------------------------------------
# /health endpoint
# ---------------------------------------------------------------------------
echo "[SMOKE] Checking /health..."
HEALTH_RESP=$(docker exec "$CONTAINER" \
    wget -qO- --no-check-certificate "http://127.0.0.1:8443/health" 2>/dev/null || true)
if [ "$HEALTH_RESP" != "ok" ]; then
    echo -e "${RED}[FAIL]${NC} /health returned: '$HEALTH_RESP' (expected 'ok')"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} /health = ok"

# ---------------------------------------------------------------------------
# /ready endpoint — must return 200 when stats DB is reachable
# ---------------------------------------------------------------------------
echo "[SMOKE] Checking /ready..."
READY_CODE=$(docker exec "$CONTAINER" \
    wget -qO- --server-response "http://127.0.0.1:8443/ready" 2>&1 | grep "HTTP/" | awk '{print $2}' || true)
if [ "$READY_CODE" != "200" ]; then
    echo -e "${RED}[FAIL]${NC} /ready returned HTTP $READY_CODE (expected 200)"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} /ready = 200"

# ---------------------------------------------------------------------------
# byo-admin stats CLI
# ---------------------------------------------------------------------------
echo "[SMOKE] Checking byo-admin log --granularity daily..."
if docker exec "$CONTAINER" byo-admin log --granularity daily 2>&1; then
    echo -e "${GREEN}[OK]${NC} byo-admin log succeeded."
else
    echo -e "${RED}[FAIL]${NC} byo-admin log --granularity daily exited non-zero."
    exit 1
fi

# ---------------------------------------------------------------------------
# IP-log regression check: no client IP in container logs
# ---------------------------------------------------------------------------
echo "[SMOKE] Checking for IP address leakage in logs..."
LOG_LINES=$(docker logs "$CONTAINER" 2>&1)
if echo "$LOG_LINES" | grep -qE 'client_ip|([0-9]{1,3}\.){3}[0-9]{1,3}'; then
    echo -e "${YELLOW}[WARN]${NC} Possible IP found in byo-server logs — review manually:"
    echo "$LOG_LINES" | grep -E 'client_ip|([0-9]{1,3}\.){3}[0-9]{1,3}' | head -5
fi

echo ""
echo -e "${GREEN}━━━ BYO smoke passed ━━━${NC}"
