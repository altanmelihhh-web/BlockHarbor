# BlockHarbor — Threat Intelligence Panel

A self-hosted threat intelligence panel for managing IP/domain blacklists, CVE watchlists, and IoC pivoting.

## Quick Start

### Step 1 — Install Docker (if not already installed)

```bash
# Ubuntu / Debian
sudo apt install docker.io docker-compose-v2 -y
sudo systemctl enable --now docker
```

### Step 2 — Run

```bash
git clone https://github.com/altanmelihhh-web/BlockHarbor.git
cd BlockHarbor
bash bin/docker-up.sh
```

The script:
- Creates `.env` from `.env.example` automatically
- Detects port conflicts and prompts for a different port if needed
- Builds the image and starts the container

Access at: **http://localhost:8090/blacklist/cyberwebeyeos/**

Default login: `admin` / `admin` — change your password immediately after first login.

> **Non-interactive / CI:** `bash bin/docker-up.sh --auto-port` (skips prompts, auto-picks next free port)

---

## Configuration

Copy `.env.example` to `.env` and set:

| Variable | Description |
|---|---|
| `HTTP_PORT` | Host port (default: 8090) |
| `CWE_ADMIN_USERNAME` | Admin username (default: admin) |
| `CWE_ADMIN_PASSWORD_HASH` | bcrypt hash of admin password |
| `CWE_VT_API_KEY` | VirusTotal v3 API key (optional) |
| `CWE_GREYNOISE_API_KEY` | GreyNoise community key (optional, 50/day) |
| `CWE_IPGEOLOCATION_API_KEY` | ipgeolocation.io key (optional) |
| `CWE_API_KEYS` | JSON array of REST API keys (optional) |

Generate a password hash:
```bash
docker compose exec app php -r "echo password_hash('yourpassword', PASSWORD_BCRYPT) . PHP_EOL;"
```

## Data Persistence

All runtime data (feeds, blacklist, state files) is stored in the `cwe_data` Docker named volume. It survives container restarts.

To reset all data:
```bash
docker compose down -v
bash bin/docker-up.sh
```

## Scheduled Jobs (Cron)

Feed fetching and CVE sync are defined in `cron/cyberwebeyeos-tip`. To install on the host:

```bash
sudo cp cron/cyberwebeyeos-tip /etc/cron.d/cyberwebeyeos-tip
sudo systemctl reload cron
```

## REST API

Pass `X-API-Key: <key>` header. Keys are configured via `CWE_API_KEYS` env var.

```bash
curl -H "X-API-Key: your-key" http://localhost:8090/blacklist/cyberwebeyeos/api.php?action=list
```

## TAXII 2.1

Discovery endpoint: `GET /blacklist/cyberwebeyeos/taxii2/`

## Production Notes

- Run behind a reverse proxy (nginx/caddy) that terminates TLS
- Rotate `CWE_API_KEYS` before exposing to external clients
- Set `CWE_ADMIN_PASSWORD_HASH` to a strong bcrypt hash in `.env`
