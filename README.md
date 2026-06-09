# cwe-admin

Threat intelligence management panel — PostgreSQL-backed, Argon2id auth, hash-chained audit log, MIT licensed.

> **Status:** P1 (Foundation + Auth Core) in development. See implementation plans in `docs/superpowers/plans/`.

## Quick start

### Native (Apache + host PostgreSQL — production default)

```bash
# Pre-reqs on the host:
#   - Apache 2.4 + mod_php8.1 (or PHP-FPM)
#   - PostgreSQL 14+
#   - composer 2, node 20+
# Create cwe_admin DB + cwe_app user, set DB_PASSWORD in .env

cp .env.example .env
# edit .env: set DB_PASSWORD, APP_KEY, etc.
composer install
npm install && npm run build
vendor/bin/phinx migrate
vendor/bin/phinx seed:run

# Install Apache vhost (see docker/apache/cwe-admin.conf.template),
# then: sudo a2ensite cwe-admin && sudo systemctl reload apache2
# Browse: https://<host>:8443/login   (admin / changeme-p1-seed)
```

### Docker Compose (for evaluators / GitHub portability)

```bash
docker compose up -d
docker compose exec php composer install
docker compose exec php vendor/bin/phinx migrate
docker compose exec php vendor/bin/phinx seed:run
# Browse: https://localhost:8443/login
```

## Architecture

See `docs/architecture.md` (added in P7) and the design spec at
`docs/superpowers/specs/2026-06-07-cwe-admin-db-migration-design.md`.

## License

MIT — see `LICENSE`.
