#!/usr/bin/env bash
# BlockHarbor Docker Quickstart Helper
#
# - Generates .env if missing (random APP_KEY + DB passwords)
# - Detects HTTP port conflicts and prompts for an alternate (or --auto-port)
# - Builds image, starts stack, runs migrations + seed
# - Prints the final URL
#
# Modes:
#   bash bin/docker-up.sh              # interactive
#   bash bin/docker-up.sh --auto-port  # picks next free port automatically
set -euo pipefail

cd "$(dirname "$0")/.."

DEFAULT_PORT=8090

c_ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
c_step() { printf '\033[36m▶\033[0m %s\n' "$*"; }
c_warn() { printf '\033[33m⚠\033[0m %s\n' "$*"; }

# 1. Hydrate .env if missing
if [[ ! -f .env ]]; then
    cp .env.example .env
    if command -v openssl >/dev/null 2>&1; then
        sed -i "s/change-me-32-byte-random-hex/$(openssl rand -hex 32)/" .env
        sed -i "s/change-me-strong-random/$(openssl rand -hex 16)/g" .env
    else
        c_warn "openssl not found — .env contains placeholder secrets, edit before production"
    fi
    c_ok "Generated .env from .env.example"
fi

# 2. Decide HTTP_PORT
HTTP_PORT="$(awk -F= '/^HTTP_PORT=/{print $2; exit}' .env || true)"
HTTP_PORT="${HTTP_PORT:-$DEFAULT_PORT}"

port_in_use() {
    if command -v ss >/dev/null 2>&1; then
        ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
    else
        return 1
    fi
}

AUTO=0
if [[ "${1:-}" == "--auto-port" || ! -t 0 ]]; then
    AUTO=1
fi

while port_in_use "$HTTP_PORT"; do
    if [[ "$AUTO" == "1" ]]; then
        NEXT=$((HTTP_PORT + 1))
        c_warn "Port $HTTP_PORT busy; trying $NEXT"
        HTTP_PORT="$NEXT"
        continue
    fi
    c_warn "Port $HTTP_PORT is already in use on this host."
    NEXT=$((HTTP_PORT + 1))
    read -r -p "  Enter a different port [$NEXT]: " new_port
    HTTP_PORT="${new_port:-$NEXT}"
done

# 3. Persist HTTP_PORT
if grep -q '^HTTP_PORT=' .env; then
    sed -i "s/^HTTP_PORT=.*/HTTP_PORT=$HTTP_PORT/" .env
else
    printf '\nHTTP_PORT=%s\n' "$HTTP_PORT" >> .env
fi
c_ok "Using HTTP_PORT=$HTTP_PORT"

# 4. Build + start
c_step "docker compose up -d --build  (first build ~5 min: composer + npm)"
docker compose up -d --build

# 5. Wait for postgres healthy (60s max)
c_step "Waiting for postgres to become healthy..."
for _ in $(seq 1 30); do
    state="$(docker compose ps --format json postgres 2>/dev/null \
        | grep -oE '"Health":"[^"]*"' | head -1 | cut -d'"' -f4 || true)"
    [[ "$state" == "healthy" ]] && break
    sleep 2
done

# 6. Migrate + seed (idempotent — re-run safe)
c_step "phinx migrate"
docker compose exec -T php vendor/bin/phinx migrate

c_step "phinx seed:run"
docker compose exec -T php vendor/bin/phinx seed:run

echo
c_ok "BlockHarbor is up at http://localhost:$HTTP_PORT/login"
echo "    Login:   admin / changeme-p1-seed"
echo "    Stop:    docker compose down"
echo "    Logs:    docker compose logs -f"
echo "    Reset:   docker compose down -v"
