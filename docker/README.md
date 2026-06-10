# Docker assets

This directory holds the Docker Compose deployment artifacts. The native
host install (Apache + mod_php + host PG) is the primary production path;
Docker is the developer-onboarding alternative.

## Files

- `Dockerfile` — `php:8.1-fpm-alpine` base with required PHP extensions
- `php-fpm.conf` — FPM pool config
- `nginx.conf` — TLS terminator on :80/:443, proxies to `php:9000`
- `apache/blockharbor.conf.template` — first-class Apache vhost (port 8443)

## Self-signed cert for dev

Before `docker compose up`, generate a dev TLS cert into `docker/ssl/`:

```bash
mkdir -p docker/ssl
openssl req -x509 -newkey rsa:2048 -keyout docker/ssl/server.key \
  -out docker/ssl/server.crt -days 365 -nodes \
  -subj "/CN=localhost"
chmod 600 docker/ssl/server.key
```

The `docker/ssl/` directory is gitignored — never commit certs/keys.

## Bring up the stack

```bash
docker compose up -d --build
docker compose exec php composer install
docker compose exec php vendor/bin/phinx migrate
docker compose exec php vendor/bin/phinx seed:run
```

Browse: <https://localhost:8443/login>

## Production

For production, use `docker compose -f docker-compose.yml` with separate
production overrides (planned: `docker/compose.prod.yml`) that:
- Bake source into image (no source mount)
- Use Docker secrets for `.env` values
- Set CPU + memory limits
- Read-only root filesystem
