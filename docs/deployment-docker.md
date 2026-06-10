# Deploying BlockHarbor with Docker Compose

For developers, evaluators, and CI environments. For production self-hosted
deployments, see [deployment-apache.md](deployment-apache.md) — Apache is the
first-class deployment path.

## TL;DR

```bash
git clone https://github.com/altanmelihhh-web/BlockHarbor.git
cd BlockHarbor
cp .env.example .env
# edit .env: set APP_KEY (openssl rand -hex 32), DB_PASSWORD
docker compose up -d
docker compose exec php composer install
docker compose exec php vendor/bin/phinx migrate
docker compose exec php vendor/bin/phinx seed:run
# Browser → https://localhost:8443/login
# default: admin / changeme-p1-seed (rotate after first login!)
```

## Services

- `postgres:14-alpine` — database
- `php:8.1-fpm-alpine` (multi-stage build with composer + npm at build time)
- `nginx:alpine` — TLS terminator + static file server, proxies PHP to FPM

## Production compose

`docker/compose.prod.yml` (Bundle 5) differs from `docker-compose.yml`:
- Source code is COPIED into the image, not mounted (immutable)
- Secrets via Docker secrets, not env vars
- Read-only filesystem where possible
- Resource limits (cpus + memory)

## Backups

Inside the container:
```bash
docker compose exec php bin/backup.sh   # Bundle 2
```

The backup file lands in `/var/backups/blockharbor/` inside the container —
mount it as a volume to host for persistence.

## Limitations

- Docker installation is NOT canonical for production — many production-grade
  features (fail2ban, logrotate, systemd timers, AppArmor) require host-level
  integration. Use Apache for production.
- HTTPS uses self-signed cert in the container; replace with your own or
  terminate TLS at an upstream proxy (Cloudflare, AWS ALB, traefik).
