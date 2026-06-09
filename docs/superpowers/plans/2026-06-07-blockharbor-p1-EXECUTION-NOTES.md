# P1 Execution Notes — Host Mode Adaptation

> Read this BEFORE executing `2026-06-07-blockharbor-p1-foundation-auth-core.md`.
> The plan was written for Docker Compose. This document captures the deviations
> required to execute on the live host (`10.20.20.50`), which has no Docker
> installed but already runs Apache 2 + PostgreSQL 14 + PHP 8.1.

**Status:** Hybrid mode — Docker files stay committed in repo for GitHub portability;
THIS server executes natively on Apache + mod_php / php-fpm + host PostgreSQL.

---

## 1. Environment baseline (as of 2026-06-09)

| Resource | Status | Notes |
|---|---|---|
| OS | Ubuntu 22.04 LTS (jammy) | apt available |
| Apache | 2.4 running on `:443` (existing site) and `:80` | MPM prefork, mod_php8.1 loaded, mod_rewrite, mod_proxy, mod_proxy_http |
| PHP CLI | 8.1.2 with `pdo`, `pdo_pgsql`, `mbstring`, `json`, `pgsql` | sufficient for P1; argon2id is built into PHP 8.1 |
| Composer | 2.x at `/usr/local/bin/composer` | global install |
| Node / npm | Node 20.20.2, npm 10.x | global install |
| PostgreSQL | 14 at `127.0.0.1:5432` | already serving other apps |
| Docker | **NOT installed** | intentionally — host mode |
| Existing DB user | `portaluser` | untouched |
| New DB | `blockharbor` (owner `blockharbor_app`) | **created** by controller prep |
| New DB role | `blockharbor_app` with login | **created**; password in `/tmp/.blockharbor_db_pass` (0600) |
| Port 443 | Apache (existing blacklist site) | DO NOT touch |
| Port 8443 | **free — use for new blockharbor vhost** | |

**PHP version phasing (user-approved 2026-06-09):**
- **P1-P2:** develop PHP 8.1 compatible. `composer.json` PHP constraint = `"^8.1"`
  (works on 8.1/8.2/8.3/8.4). No PHP 8.3-only syntax (no `readonly class`,
  no typed class constants).
- **P3-P4:** staging tests complete on 8.1 runtime.
- **P7 (or separate maintenance window):** install `php8.3-fpm` via
  `ppa:ondrej/php` side-by-side with 8.1. Existing blacklist site stays on 8.1.
- **After 8.3 install:** switch new `blockharbor` vhost to use `php8.3-fpm`
  via `SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"`.
  Old site unchanged.

This phasing avoids touching the production host before P1 functionality is
proven and provides a clean cutover point for the runtime upgrade.

---

## 2. Plan deviations — command substitutions

Every step in the plan that uses Docker should be replaced with the host
equivalent. The plan FILES themselves (`docker-compose.yml`, `docker/Dockerfile`,
`docker/nginx.conf`, `docker/php-fpm.conf`) **are still created and committed**
so GitHub users can `docker compose up`. But none of them are *executed*
during P1 on this server.

### 2.1 Universal substitutions

| Plan says | Run on host instead |
|---|---|
| `docker compose exec php composer X` | `composer X` (from `/var/www/blockharbor/`) |
| `docker compose exec php composer test` | `composer test` |
| `docker compose exec php vendor/bin/phinx <cmd>` | `vendor/bin/phinx <cmd>` |
| `docker compose exec postgres psql -U blockharbor_app -d blockharbor ...` | `PGPASSWORD="$(cat /tmp/.blockharbor_db_pass)" psql -h 127.0.0.1 -U blockharbor_app -d blockharbor ...` |
| `docker run --rm composer:2 install` | `composer install` |
| `docker run --rm node:20-alpine npm install` | `npm install` |
| `docker compose up -d --build` | n/a — skip; verify Apache + PG running |
| `docker compose restart nginx` | `sudo systemctl reload apache2` |

### 2.2 `.env` adjustments (Task 3 → write `.env` for host)

```text
APP_ENV=production
APP_DEBUG=false
APP_URL=https://10.20.20.50:8443
APP_TIMEZONE=UTC

DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=blockharbor
DB_USER=blockharbor_app
DB_PASSWORD=<contents of /tmp/.blockharbor_db_pass>
DB_SSLMODE=disable     # local socket / loopback — no TLS needed in P1

SESSION_NAME=CWE_ADMIN_SESSION
SESSION_LIFETIME=1800
SESSION_ABSOLUTE_LIFETIME=28800

PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_MIXED_CASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_HISTORY_COUNT=5

LOGIN_MAX_FAILS_PER_IP_5MIN=10
LOGIN_MAX_FAILS_PER_USER_1H=5
LOGIN_LOCKOUT_MINUTES=15

APP_KEY=<openssl rand -hex 32>

LOG_PATH=/var/log/blockharbor/app.log
LOG_LEVEL=info
```

Mode `0600`, owner `www-data:www-data` (the user Apache runs as):
```bash
sudo chown www-data:www-data /var/www/blockharbor/.env
sudo chmod 600 /var/www/blockharbor/.env
```

### 2.3 Apache vhost replaces nginx.conf (Task 3)

Create `/etc/apache2/sites-available/blockharbor.conf`:
```apache
Listen 8443

<VirtualHost *:8443>
    ServerName  10.20.20.50
    DocumentRoot /var/www/blockharbor/public
    DirectoryIndex index.php

    SSLEngine on
    SSLCertificateFile      /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile   /etc/ssl/private/ssl-cert-snakeoil.key
    SSLProtocol             -all +TLSv1.2 +TLSv1.3

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    <Directory /var/www/blockharbor/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog  ${APACHE_LOG_DIR}/blockharbor-error.log
    CustomLog ${APACHE_LOG_DIR}/blockharbor-access.log combined
</VirtualHost>
```

Enable + reload:
```bash
sudo a2enmod ssl headers rewrite
sudo a2ensite blockharbor
sudo apachectl configtest && sudo systemctl reload apache2
```

Note: `ssl-cert-snakeoil.pem` is Ubuntu's default self-signed cert (in
`ssl-cert` package). Replace with Let's Encrypt in P7 production hardening.

### 2.4 First-class: docs/apache.conf

Because the user designated Apache deployment first-class:

- Add `docker/apache/blockharbor.conf.template` to the repo (the vhost above,
  with `{{APP_URL}}`/`{{DOCUMENT_ROOT}}` placeholders for portability)
- Add to README "Deployment" section: Apache install path is the recommended
  default; Docker Compose is the developer-onboarding alternative
- `docs/deployment.md` (P7) covers both equally

### 2.5 Task 19 seeder runs differently

Instead of `./bin/seed`, run on host:
```bash
cd /var/www/blockharbor
vendor/bin/phinx seed:run
```

`bin/seed` shell script should be written to use the same pattern; the docker
exec line is replaced with direct invocation. Suggested `bin/seed`:
```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
vendor/bin/phinx seed:run "$@"
```

(`bin/migrate` analogously: cd .. then `vendor/bin/phinx migrate "$@"`.)

### 2.6 Filesystem ownership

After `git init` in `/var/www/blockharbor/`, set permissions so Apache (www-data)
can read but the developer (root or actual user) can edit:

```bash
sudo chown -R www-data:www-data /var/www/blockharbor
sudo chmod -R u+rwX,g+rwX,o-rwx /var/www/blockharbor
sudo chmod 600 /var/www/blockharbor/.env
```

Subagents executing tasks should be run as root (current shell) to write the
files, then re-set ownership at the end (or per-task as the plan creates new
files).

---

## 3. Files added by these notes (vs. plan)

In addition to everything in the plan, the supplement requires:

```text
docker/apache/
└── blockharbor.conf.template          # first-class Apache deployment artifact
docs/deployment-apache.md            # short P1-version of the Apache install steps
                                     # (full version in P7)
```

These should be added in Task 3 alongside the Docker files.

---

## 4. Task-by-task overrides

Only tasks that actually change are listed. Unlisted tasks execute as
written, with the universal command substitutions from §2.1.

### Task 1 — no change
Skeleton creation works identically on host.

### Task 2 — host commands
```bash
cd /var/www/blockharbor
composer install --no-progress --prefer-dist
npm install --no-audit --no-fund
```

### Task 3 — Apache replaces nginx
- Docker files: write `docker/Dockerfile`, `docker/docker-compose.yml`,
  `docker/nginx.conf`, `docker/php-fpm.conf` (commit but DO NOT execute).
- ALSO write `docker/apache/blockharbor.conf.template` (the vhost above).
- ALSO write `.env` populated from `/tmp/.blockharbor_db_pass`.
- Verify host: `php -v`, `psql -h 127.0.0.1 -U blockharbor_app -d blockharbor -c '\dt'`.
- Install Apache vhost (the commands in §2.3 above).
- Skip "docker compose up" step.

### Task 5 — bin/migrate must use host phinx
Replace bin/migrate content per §2.5.

### Task 8 — AuditChainTest connection
Test uses `DB_HOST=127.0.0.1` not `DB_HOST=postgres`. The test code as
written reads `getenv('DB_HOST')`; controller exports correct env when
invoking PHPUnit:
```bash
DB_HOST=127.0.0.1 DB_PASSWORD="$(cat /tmp/.blockharbor_db_pass)" \
  composer test -- --filter=AuditChainTest
```

### Task 19 — bin/seed per §2.5

### Task 20 — manual smoke
Browser path is `https://10.20.20.50:8443/login` (port 8443, host IP).

### Task 21 — CI workflow unchanged
GitHub Actions runs in its own Linux runner with postgres service container.
The workflow file ships unchanged for the GitHub use case.

### Task 22 — verification
- Local smoke via `https://10.20.20.50:8443/login`
- Old system at `https://10.20.20.50/blacklist/cyberwebeyeos/` MUST still
  work unchanged. Verify after cutover prep.
- Git tag as written.

---

## 5. Pre-execution checklist (controller verified)

- [x] PostgreSQL 14 running, accepting connections on `127.0.0.1:5432`
- [x] Database `blockharbor` exists, owner `blockharbor_app`
- [x] Role `blockharbor_app` exists; password in `/tmp/.blockharbor_db_pass` (mode 0600)
- [x] `/var/www/` writable by controller (root)
- [x] Apache running, mod_rewrite + mod_proxy enabled
- [ ] `mod_ssl` will be enabled in Task 3 (`a2enmod ssl headers`)
- [x] Composer 2 available
- [x] Node 20 + npm available
- [x] PHP 8.1.2 with required extensions

---

## 6. Rollback plan

If anything during P1 execution damages the running system:

```bash
# Disable new vhost
sudo a2dissite blockharbor
sudo systemctl reload apache2

# Drop new DB (only if you're sure)
sudo -u postgres dropdb blockharbor
sudo -u postgres dropuser blockharbor_app

# Remove new project files
sudo rm -rf /var/www/blockharbor

# Existing site at port 443 is untouched throughout.
```

If port conflict (only 8443 should be used; if not, edit Listen line in
`/etc/apache2/ports.conf` or pick a different port).

---

## 7. Hand-off to executing agent

When dispatching implementer subagents for P1 tasks, include this document
as context alongside the task text. Specifically tell the subagent:

> "Execution mode is HOST (not Docker). See
> `docs/superpowers/plans/2026-06-07-blockharbor-p1-EXECUTION-NOTES.md` —
> apply the command substitutions in §2.1 to every step. Apache vhost
> replaces nginx. Working directory is `/var/www/blockharbor/`. DB password
> is in `/tmp/.blockharbor_db_pass`."

---

## 8. APPENDIX — BlockHarbor rename (2026-06-09)

Project renamed to **BlockHarbor** post-Task 1. GitHub remote set up + initial
commits pushed. All subsequent tasks operate on the new identifiers.

### Identifier substitution table (apply to ALL remaining plan steps)

| Original (plan) | New (post-rename) |
|---|---|
| `/var/www/blockharbor` | `/var/www/blockharbor` |
| `blockharbor` (in code/docs) | `blockharbor` (lowercase) or `BlockHarbor` (display) |
| `CWE\` (PHP namespace) | `BlockHarbor\` |
| `blockharbor` (DB) | `blockharbor` |
| `blockharbor_app` (DB role) | `blockharbor_app` (runtime) |
| (new) | `blockharbor_migrator` (DDL — used by phinx) |
| `CWE_ADMIN_SESSION` | `BLOCKHARBOR_SESSION` |
| `cwe.conf` (Apache) | `blockharbor.conf` |
| `altanmelihhh/blockharbor` (composer) | `blockharbor/blockharbor` (composer) |
| `/tmp/.blockharbor_db_pass` | `/tmp/.blockharbor_db_pass` |

### Plan Task 2 composer.json overrides

The composer.json `name` field MUST be `"blockharbor/blockharbor"` (not
`"altanmelihhh-web/blockharbor"`). Rationale: leaves room for sibling
packages under the `blockharbor/` vendor namespace (sdk-php, api-client,
exporter, feed-usom, etc.) in the future.

### GitHub remote (already configured)

```text
origin: git@github.com:altanmelihhh-web/BlockHarbor.git
authenticated as: altanmelihhh-web (ed25519 key /root/.ssh/id_ed25519_github)
```

Pushed commits (initial):
- `14a63cf` chore: initialize repository skeleton (Task 1 base)
- `2576575` chore: rename project to BlockHarbor
- `05a39af` chore: update DB names in .env.example
- `751c654` chore: add migrator role + runtime separation in .env.example

### Test-DB strategy revision

`phinx.php` `testing` environment should also be added — DB name suffix `_test`
(e.g., `blockharbor_test`). Subagent dispatching Task 5 should pre-create
`blockharbor_test` DB with the same migrator role.

### Logs + backups directories (pre-created)

```text
/var/log/blockharbor/    drwxr-x--- www-data:www-data 750
/var/backups/blockharbor/ drwxr-x--- www-data:www-data 750
```

### Future systemd / sub-projects

User-articulated namespace conventions (apply when added in P4-P7):
```text
systemd:    blockharbor-worker.service
sub-pkgs:   blockharbor/sdk-php, blockharbor/api-client,
            blockharbor-feed-usom, blockharbor-exporter
```
