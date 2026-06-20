#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# 0. Require Docker
if ! command -v docker &>/dev/null; then
    echo ""
    echo "ERROR: Docker is not installed on this system."
    echo ""
    echo "Install it with:"
    echo "  Ubuntu/Debian:  sudo apt install docker.io -y && sudo systemctl enable --now docker"
    echo "  Then re-run:    bash bin/docker-up.sh"
    echo ""
    exit 1
fi

# Require docker compose (v2 plugin)
if ! docker compose version &>/dev/null; then
    echo ""
    echo "ERROR: 'docker compose' plugin not found."
    echo ""
    echo "Install it with:"
    echo "  sudo apt install docker-compose-v2 -y"
    echo ""
    exit 1
fi

# 1. Hydrate .env if missing
if [[ ! -f .env ]]; then
    cp .env.example .env
    echo "✓ Created .env from .env.example"
fi

# 2. Port conflict detection
HTTP_PORT="$(grep -oP '(?<=^HTTP_PORT=)\S+' .env 2>/dev/null || true)"
HTTP_PORT="${HTTP_PORT:-8090}"

port_in_use() {
    ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
}

AUTO=0
[[ "${1:-}" == "--auto-port" || ! -t 0 ]] && AUTO=1

while port_in_use "$HTTP_PORT"; do
    if [[ "$AUTO" == "1" ]]; then
        HTTP_PORT=$((HTTP_PORT + 1))
        continue
    fi
    echo "⚠ Port $HTTP_PORT is already in use."
    read -rp "  Enter a different port [default: $((HTTP_PORT + 1))]: " new_port
    HTTP_PORT="${new_port:-$((HTTP_PORT + 1))}"
done

if grep -q '^HTTP_PORT=' .env; then
    sed -i "s/^HTTP_PORT=.*/HTTP_PORT=$HTTP_PORT/" .env
else
    echo "HTTP_PORT=$HTTP_PORT" >> .env
fi
echo "✓ Using HTTP_PORT=$HTTP_PORT"

# 3. Build + start
echo "▶ docker compose up -d --build  (first build ~3-5 min)"
docker compose up -d --build

echo ""
echo "✓ BlockHarbor is up at http://localhost:$HTTP_PORT/blacklist/cyberwebeyeos/"
echo "  Login: admin / admin  (change your password on first login)"
echo "  Stop:  docker compose down"
echo "  Logs:  docker compose logs -f"
echo "  Reset: docker compose down -v && bash bin/docker-up.sh"
