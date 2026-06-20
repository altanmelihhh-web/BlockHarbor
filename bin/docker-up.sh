#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# ── helpers ──────────────────────────────────────────────────────────────────
need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "  (running as non-root — using sudo)"
        SUDO="sudo"
    else
        SUDO=""
    fi
}

install_docker_debian() {
    echo "▶ Installing Docker (apt)..."
    need_root
    $SUDO apt-get update -qq
    $SUDO apt-get install -y docker.io docker-compose-v2
    $SUDO systemctl enable --now docker
    # Add current user to docker group so they can run docker without sudo
    if [[ -n "${SUDO_USER:-}" ]]; then
        $SUDO usermod -aG docker "$SUDO_USER"
        echo "  Added $SUDO_USER to the 'docker' group."
        echo "  NOTE: Log out and back in (or run: newgrp docker) for group to take effect."
    fi
    echo "✓ Docker installed"
}

# ── 0. Ensure Docker is present ───────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo ""
    echo "Docker is not installed. Installing now..."
    if command -v apt-get &>/dev/null; then
        install_docker_debian
    else
        echo "ERROR: Auto-install only supports apt-based systems (Ubuntu/Debian)."
        echo "Please install Docker manually: https://docs.docker.com/engine/install/"
        exit 1
    fi
fi

# Ensure docker compose v2 plugin
if ! docker compose version &>/dev/null 2>&1; then
    echo ""
    echo "docker compose plugin not found. Installing..."
    if command -v apt-get &>/dev/null; then
        need_root
        $SUDO apt-get install -y docker-compose-v2
        echo "✓ docker compose installed"
    else
        echo "ERROR: Please install docker-compose-v2 manually."
        exit 1
    fi
fi

# ── 1. Hydrate .env ───────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
    cp .env.example .env
    echo "✓ Created .env from .env.example"
fi

# ── 2. Port conflict detection ────────────────────────────────────────────────
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

# ── 3. Build + start ──────────────────────────────────────────────────────────
echo "▶ docker compose up -d --build  (first build ~3-5 min)"
docker compose up -d --build

echo ""
echo "✓ BlockHarbor is up at http://localhost:$HTTP_PORT/blacklist/cyberwebeyeos/"
echo "  Login: admin / admin  (change your password on first login)"
echo "  Stop:  docker compose down"
echo "  Logs:  docker compose logs -f"
echo "  Reset: docker compose down -v && bash bin/docker-up.sh"
