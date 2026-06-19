# Docker assets

Docker Compose stack for evaluating BlockHarbor in 2 commands (see
`bin/docker-up.sh`). The native host install (Apache + mod_php + host
PG via `bin/install.sh`) is the primary production path.

## Files

- `Dockerfile` — `php:8.1-fpm-alpine` baked with composer deps + built npm assets
- `php-fpm.conf` — FPM pool config
- `nginx.conf` — HTTP-only on `:80`, proxies to `php:9000` (TLS terminates upstream)
- `postgres-init/01_create_migrator.sh` — first-run PG init: creates `blockharbor_migrator` role + DDL grants
- `apache/blockharbor.conf.template` — first-class Apache vhost (port 8443, native install)

## Bring up the stack

The fastest path is `bash bin/docker-up.sh` from the repo root — it
handles `.env` hydration, port-conflict detection, build, migrate,
seed. Manual sequence:

```bash
cp .env.example .env
sed -i "s/change-me-32-byte-random-hex/$(openssl rand -hex 32)/" .env
sed -i "s/change-me-strong-random/$(openssl rand -hex 16)/g" .env
# Set HTTP_PORT in .env if 8090 is busy:
#   echo "HTTP_PORT=9091" >> .env

docker compose up -d --build
docker compose exec -T php vendor/bin/phinx migrate
docker compose exec -T php vendor/bin/phinx seed:run
```

Browse <http://localhost:8090/login> (admin / changeme-p1-seed).

## TLS

The Compose stack is HTTP-only by design. In production, terminate TLS
at an upstream reverse proxy (apache, nginx, cloud load balancer). The
native install (`bin/install.sh`) configures apache with TLS+HSTS on
port 8443 directly — that's the production path.

## Production (Docker)

For a Docker-based prod deploy, layer a `docker/compose.prod.yml`
override (planned) that:

- Uses Docker secrets for `.env` values
- Sets CPU + memory limits
- Read-only root filesystem
- Reverse-proxy TLS layer in front of nginx:80
