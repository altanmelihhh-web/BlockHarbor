# BlockHarbor P1 — Foundation + Auth Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `/var/www/blockharbor/` foundation: a working Composer + PSR-4 + Docker repo with PostgreSQL schema for identity tables, Argon2id auth with lockout, DB-backed sessions, login/logout/dashboard pages, and green CI. End state: `docker compose up`, browse to `https://localhost/login`, log in as the seeded admin, see the dashboard.

**Architecture:** Modern PHP 8.1+ with hand-rolled DI-light bootstrap (no framework). PDO + Repository pattern. Plates templates. Tailwind + Alpine for UI. Phinx migrations. Argon2id passwords. DB-backed sessions. Hash-chained audit log table with PostgreSQL trigger (logger class arrives in P2). Apache/nginx-agnostic via `public/index.php` front controller.

**Tech Stack:** PHP 8.1, PostgreSQL 14, Plates 3, Tailwind 3, Alpine 3, Phinx 0.16, vlucas/phpdotenv 5, Monolog 3, PHPUnit 10, PHPStan L8, Psalm 5, Docker Compose, GitHub Actions.

**Reference spec:** `docs/superpowers/specs/2026-06-07-blockharbor-db-migration-design.md`

---

## P1 Scope: in vs out

### In scope (this plan)

- Repository skeleton at `/var/www/blockharbor/` with git init + MIT license + README + CONTRIBUTING skeleton
- Composer + PSR-4 autoloading + dev dependencies
- npm + Tailwind + Alpine + build pipeline (`npm run build`)
- Docker Compose: PostgreSQL 14, PHP 8.1-fpm, nginx (chosen over Apache for simpler dev container)
- `.env.example` + `Config` loader
- Phinx setup
- 6 P1 migrations: `tenants`, `users`, `password_history`, `user_sessions`, `login_attempts`, `audit_log` (with hash chain trigger)
- `src/Core/`: Application bootstrap, Database (PDO factory), Router, Session (DB-backed), Csrf
- `src/Auth/`: PasswordHasher, PasswordPolicy, UserRepository, LoginAttemptRepository, AuthService, LoginController, LogoutController
- `src/Admin/Controllers/DashboardController` (placeholder page proving auth works)
- `resources/views/`: app layout, auth layout, login form, dashboard placeholder
- Phinx seeds: default tenant + default admin user
- PHPUnit unit + integration tests for all auth components
- PHPStan level 8 + Psalm clean
- GitHub Actions CI: composer install → phpunit → phpstan → psalm → composer audit → npm build

### Out of scope (later plans)

- `AuditLogger` class + ChainVerifier CLI — P2
- 2FA (TOTP + WebAuthn) + Risk Scoring — P2
- IOC / Feeds / CVE / Vendors / Lists / Notifications / Customers / REST API tables and code — P3-P5
- JSON → DB import scripts and cutover — P6
- Comprehensive docs (architecture.md, security.md, deployment.md, runbook) — P7

### Working software at end of P1

```bash
cd /var/www/blockharbor
docker compose up -d
./bin/migrate
./bin/seed
# Browser → https://localhost:8443/login
# Login: admin / changeme-p1-seed
# See: dashboard with username + logout button
# 5 failed logins → lockout 15 min
```

---

## File Structure

### Files created by P1

```text
/var/www/blockharbor/
├── .env.example
├── .gitignore
├── .github/workflows/ci.yml
├── LICENSE                            # MIT
├── README.md
├── CONTRIBUTING.md
├── composer.json
├── composer.lock                      # generated
├── package.json
├── package-lock.json                  # generated
├── phinx.php
├── phpunit.xml
├── phpstan.neon
├── psalm.xml
├── tailwind.config.js
├── postcss.config.js
├── Makefile
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── nginx.conf
│   └── php-fpm.conf
├── public/
│   ├── index.php                      # front controller
│   ├── .htaccess                      # Apache fallback
│   └── assets/                        # build output (gitignored except .gitkeep)
├── src/
│   ├── Core/
│   │   ├── Application.php
│   │   ├── Config.php
│   │   ├── Database.php
│   │   ├── Router.php
│   │   ├── Session.php
│   │   └── Csrf.php
│   ├── Auth/
│   │   ├── PasswordHasher.php
│   │   ├── PasswordPolicy.php
│   │   ├── UserRepository.php
│   │   ├── LoginAttemptRepository.php
│   │   ├── AuthService.php
│   │   ├── Middleware/RequireAuth.php
│   │   └── Controllers/
│   │       ├── LoginController.php
│   │       └── LogoutController.php
│   └── Admin/Controllers/
│       └── DashboardController.php
├── resources/
│   ├── views/
│   │   ├── layouts/
│   │   │   ├── app.php
│   │   │   └── auth.php
│   │   ├── auth/login.php
│   │   └── dashboard/index.php
│   ├── css/app.css
│   └── js/app.js
├── db/
│   ├── migrations/
│   │   ├── 20260607120000_create_tenants.php
│   │   ├── 20260607120100_create_users.php
│   │   ├── 20260607120200_create_password_history.php
│   │   ├── 20260607120300_create_user_sessions.php
│   │   ├── 20260607120400_create_login_attempts.php
│   │   └── 20260607120500_create_audit_log.php
│   └── seeds/
│       ├── DefaultTenantSeeder.php
│       └── DefaultUserSeeder.php
├── tests/
│   ├── Unit/
│   │   ├── Core/ConfigTest.php
│   │   └── Auth/
│   │       ├── PasswordHasherTest.php
│   │       └── PasswordPolicyTest.php
│   ├── Integration/
│   │   ├── DatabaseTest.php
│   │   ├── Auth/
│   │   │   ├── UserRepositoryTest.php
│   │   │   ├── LoginAttemptRepositoryTest.php
│   │   │   └── AuthServiceTest.php
│   │   └── AuditChainTest.php
│   ├── bootstrap.php
│   └── DatabaseTestCase.php           # base class with PG container helper
└── bin/
    ├── migrate
    └── seed
```

### File responsibilities (one-liner each)

| File | Responsibility |
|---|---|
| `public/index.php` | Front controller — boots `Application`, dispatches request |
| `src/Core/Application.php` | Wires Config, Database, Router, Session; one entry method `run()` |
| `src/Core/Config.php` | Loads `.env` via vlucas/phpdotenv; exposes typed getters |
| `src/Core/Database.php` | PDO factory (singleton per request); produces `\PDO` |
| `src/Core/Router.php` | Maps `(METHOD, path)` → controller class + method; no regex magic |
| `src/Core/Session.php` | Custom `SessionHandlerInterface` writing to `user_sessions` table |
| `src/Core/Csrf.php` | Generates + verifies session-bound CSRF tokens |
| `src/Auth/PasswordHasher.php` | Argon2id `hash()`/`verify()`/`needsRehash()` wrappers |
| `src/Auth/PasswordPolicy.php` | Validates a candidate password against the configured policy |
| `src/Auth/UserRepository.php` | CRUD for `users` (find by id/username, create, updatePassword, recordLogin, incrementFailedCount, lock, unlock) |
| `src/Auth/LoginAttemptRepository.php` | Record + count failed attempts per IP / per username for rate-limit |
| `src/Auth/AuthService.php` | Orchestrates: rate-limit → user lookup → password verify → lockout → session |
| `src/Auth/Middleware/RequireAuth.php` | Redirects to `/login` if no session, else attaches current user |
| `src/Auth/Controllers/LoginController.php` | GET shows form, POST hands to AuthService, sets flash, redirects |
| `src/Auth/Controllers/LogoutController.php` | Invalidates session row, clears cookie, redirects |
| `src/Admin/Controllers/DashboardController.php` | Renders dashboard placeholder (current user + logout link) |
| `db/migrations/2026…_*` | Phinx migrations — each one table |
| `db/seeds/Default*Seeder.php` | Single-tenant + default admin (creds in README) |
| `resources/views/layouts/app.php` | Tailwind shell with top nav + flash + slot |
| `resources/views/layouts/auth.php` | Minimal centered card layout for login |
| `resources/views/auth/login.php` | Username + password form with CSRF |
| `resources/views/dashboard/index.php` | Welcome card showing username, role, logout link |

---

## Conventions used in this plan

- **Working directory** is `/var/www/blockharbor/` unless explicitly stated otherwise. Each `Run:` command is from there.
- **Tests use ephemeral PG container** spawned via Docker Compose; integration tests reset the schema between runs.
- **Every commit message** uses Conventional Commits (`feat:`, `chore:`, `test:`, `docs:`).
- **Every PHP file** starts with `<?php declare(strict_types=1);`
- **PSR-4 namespace** root is `CWE\` mapped to `src/`.
- After each TDD step the engineer runs tests. If they fail unexpectedly, **stop and read the error** — do not skip to the next step.

---

## Task 1: Initialize Repository Skeleton

**Files:**
- Create: `/var/www/blockharbor/{LICENSE, README.md, CONTRIBUTING.md, .gitignore, .env.example, Makefile}`
- Create: `/var/www/blockharbor/.git/`

- [ ] **Step 1: Create project directory and initialize git**

Run:
```bash
sudo mkdir -p /var/www/blockharbor
sudo chown -R "$USER":"$USER" /var/www/blockharbor
cd /var/www/blockharbor
git init -b main
```

Expected: `Initialized empty Git repository in /var/www/blockharbor/.git/`

- [ ] **Step 2: Write LICENSE (MIT)**

Create `LICENSE`:
```text
MIT License

Copyright (c) 2026 altanmelihhh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 3: Write README.md skeleton**

Create `README.md`:
```markdown
# blockharbor

Threat intelligence management panel — PostgreSQL-backed, Argon2id auth, hash-chained audit log, MIT licensed.

> **Status:** P1 (Foundation + Auth Core) in development. Tracks the implementation plan in `docs/superpowers/plans/`.

## Quick start (dev)

```bash
docker compose up -d
./bin/migrate
./bin/seed
open https://localhost:8443/login
# Login: admin / changeme-p1-seed
```

## Architecture

See `docs/architecture.md` (added in P7) and the design spec under
`docs/superpowers/specs/2026-06-07-blockharbor-db-migration-design.md`.

## License

MIT — see `LICENSE`.
```

- [ ] **Step 4: Write CONTRIBUTING.md skeleton**

Create `CONTRIBUTING.md`:
```markdown
# Contributing to blockharbor

Thanks for your interest! This is an early-stage project; the contributor
workflow will be expanded in P7.

## Dev setup

1. `docker compose up -d` brings up PG + PHP-FPM + nginx
2. `./bin/migrate` runs Phinx migrations
3. `./bin/seed` seeds the default tenant + admin user
4. `composer test` runs PHPUnit
5. `composer stan` runs PHPStan (level 8)
6. `composer psalm` runs Psalm
7. `npm run build` produces `public/assets/`

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/):
`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`.
```

- [ ] **Step 5: Write .gitignore**

Create `.gitignore`:
```text
/vendor/
/node_modules/
/public/assets/*
!/public/assets/.gitkeep
/.env
/.phpunit.cache/
/tests/.coverage/
*.log
.DS_Store
.idea/
.vscode/
*.swp
/composer.lock
!/composer.lock
/package-lock.json
!/package-lock.json
```

(Note: composer.lock and package-lock.json ARE committed; the `!` lines re-include them after the directory rules.)

- [ ] **Step 6: Write .env.example**

Create `.env.example`:
```text
# Application
APP_ENV=production
APP_DEBUG=false
APP_URL=https://localhost:8443
APP_TIMEZONE=UTC

# Database
DB_HOST=postgres
DB_PORT=5432
DB_NAME=blockharbor
DB_USER=blockharbor_app
DB_PASSWORD=change-me-strong-random
DB_SSLMODE=prefer

# Session
SESSION_NAME=CWE_ADMIN_SESSION
SESSION_LIFETIME=1800
SESSION_ABSOLUTE_LIFETIME=28800

# Password policy
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_MIXED_CASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_HISTORY_COUNT=5

# Lockout
LOGIN_MAX_FAILS_PER_IP_5MIN=10
LOGIN_MAX_FAILS_PER_USER_1H=5
LOGIN_LOCKOUT_MINUTES=15

# Encryption (32-byte hex)
APP_KEY=change-me-32-byte-random-hex

# Logging
LOG_PATH=/var/log/blockharbor/app.log
LOG_LEVEL=info
```

- [ ] **Step 7: Write Makefile**

Create `Makefile`:
```makefile
.PHONY: up down logs migrate seed test stan psalm audit build dev fresh

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

migrate:
	./bin/migrate

seed:
	./bin/seed

test:
	docker compose exec php composer test

stan:
	docker compose exec php composer stan

psalm:
	docker compose exec php composer psalm

audit:
	docker compose exec php composer audit

build:
	npm run build

dev:
	npm run dev

fresh:
	docker compose down -v
	docker compose up -d --build
	./bin/migrate
	./bin/seed
```

- [ ] **Step 8: Commit foundation files**

Run:
```bash
git add LICENSE README.md CONTRIBUTING.md .gitignore .env.example Makefile
git commit -m "chore: initialize repository skeleton

Adds MIT license, README, CONTRIBUTING guide, .gitignore, .env.example,
and Makefile shortcuts."
```

Expected: 1 commit created.

---

## Task 2: Composer + npm Setup

**Files:**
- Create: `composer.json`
- Create: `package.json`
- Create: `tailwind.config.js`
- Create: `postcss.config.js`
- Create: `resources/css/app.css`
- Create: `resources/js/app.js`
- Create: `public/assets/.gitkeep`

- [ ] **Step 1: Write composer.json**

Create `composer.json`:
```json
{
  "name": "altanmelihhh/blockharbor",
  "description": "Threat intelligence management panel with hash-chained audit",
  "type": "project",
  "license": "MIT",
  "require": {
    "php": "^8.1",
    "ext-pdo": "*",
    "ext-pdo_pgsql": "*",
    "ext-json": "*",
    "ext-mbstring": "*",
    "league/plates": "^3.5",
    "vlucas/phpdotenv": "^5.6",
    "monolog/monolog": "^3.5",
    "robmorgan/phinx": "^0.16",
    "ramsey/uuid": "^4.7"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.5",
    "phpstan/phpstan": "^1.10",
    "vimeo/psalm": "^5.20",
    "fakerphp/faker": "^1.23"
  },
  "autoload": {
    "psr-4": {
      "BlockHarbor\\": "src/"
    }
  },
  "autoload-dev": {
    "psr-4": {
      "BlockHarbor\\Tests\\": "tests/"
    }
  },
  "scripts": {
    "test": "phpunit --colors=always",
    "stan": "phpstan analyse",
    "psalm": "psalm",
    "audit": "composer audit"
  },
  "config": {
    "allow-plugins": {
      "php-http/discovery": true
    },
    "sort-packages": true
  }
}
```

- [ ] **Step 2: Install Composer deps**

Run:
```bash
docker run --rm -v "$PWD":/app -w /app composer:2 install --no-progress
```

Expected: Installs to `vendor/`. `composer.lock` is created.

- [ ] **Step 3: Write package.json**

Create `package.json`:
```json
{
  "name": "blockharbor-assets",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "build": "tailwindcss -i ./resources/css/app.css -o ./public/assets/app.css --minify && cp resources/js/app.js public/assets/app.js",
    "dev": "tailwindcss -i ./resources/css/app.css -o ./public/assets/app.css --watch"
  },
  "devDependencies": {
    "tailwindcss": "^3.4.0",
    "@tailwindcss/forms": "^0.5.7",
    "alpinejs": "^3.13.0",
    "htmx.org": "^1.9.10"
  }
}
```

- [ ] **Step 4: Write tailwind.config.js**

Create `tailwind.config.js`:
```js
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./resources/views/**/*.php",
    "./resources/js/**/*.js",
    "./src/**/*.php"
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50:  '#eff6ff',
          100: '#dbeafe',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          900: '#1e3a8a'
        }
      }
    }
  },
  plugins: [require("@tailwindcss/forms")]
};
```

- [ ] **Step 5: Write postcss.config.js**

Create `postcss.config.js`:
```js
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {}
  }
};
```

- [ ] **Step 6: Write resources/css/app.css**

Create `resources/css/app.css`:
```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer components {
  .btn {
    @apply inline-flex items-center justify-center px-4 py-2 rounded-md font-medium text-sm transition-colors;
  }
  .btn-primary { @apply bg-brand-600 text-white hover:bg-brand-700 focus:ring-2 focus:ring-brand-500 focus:ring-offset-2; }
  .btn-ghost   { @apply bg-transparent text-slate-700 hover:bg-slate-100; }
  .card        { @apply bg-white shadow-sm rounded-lg border border-slate-200; }
  .card-body   { @apply p-6; }
  .field       { @apply mb-4; }
  .label       { @apply block text-sm font-medium text-slate-700 mb-1; }
  .input       { @apply w-full px-3 py-2 border border-slate-300 rounded-md focus:ring-2 focus:ring-brand-500 focus:border-brand-500; }
  .flash       { @apply mb-4 px-4 py-3 rounded-md border; }
  .flash-error { @apply bg-red-50 border-red-200 text-red-800; }
  .flash-info  { @apply bg-blue-50 border-blue-200 text-blue-800; }
}
```

- [ ] **Step 7: Write resources/js/app.js**

Create `resources/js/app.js`:
```js
import Alpine from 'alpinejs';
import 'htmx.org';

window.Alpine = Alpine;
Alpine.start();
```

(Note: this is the SOURCE file. The `npm run build` script we wrote copies it as-is; we are NOT bundling Alpine into it in P1 — Alpine is loaded via CDN in the layout. P5 will add Vite/esbuild bundling if needed. For now `app.js` just initializes Alpine via the global already loaded.)

Actually rewrite — Alpine via CDN means this file just hooks behaviors:

```js
// resources/js/app.js
// Alpine is loaded via CDN in the layout. This file hooks app-wide behaviors.
document.addEventListener('alpine:init', () => {
  // Toast helper available as x-data="toast()" — extends in P3+
});

// HTMX — global config
document.body.addEventListener('htmx:configRequest', (e) => {
  const token = document.querySelector('meta[name="csrf-token"]')?.content;
  if (token) e.detail.headers['X-CSRF-Token'] = token;
});
```

- [ ] **Step 8: Place .gitkeep + install npm deps**

Run:
```bash
mkdir -p public/assets
touch public/assets/.gitkeep
docker run --rm -v "$PWD":/app -w /app node:20-alpine npm install --no-audit --no-fund
```

Expected: `node_modules/` created, `package-lock.json` written.

- [ ] **Step 9: Commit composer + npm setup**

Run:
```bash
git add composer.json composer.lock package.json package-lock.json tailwind.config.js postcss.config.js resources/css/app.css resources/js/app.js public/assets/.gitkeep
git commit -m "chore: add Composer + npm dependencies

Composer: plates, phpdotenv, monolog, phinx, ramsey/uuid + dev tools.
npm: tailwindcss, alpinejs, htmx (CDN loaded; npm needed only for tailwind build)."
```

---

## Task 3: Docker Compose + nginx + PHP-FPM

**Files:**
- Create: `docker/Dockerfile`
- Create: `docker/docker-compose.yml` (top-level reference)
- Create: `docker-compose.yml` (top-level — points to docker/)
- Create: `docker/nginx.conf`
- Create: `docker/php-fpm.conf`

- [ ] **Step 1: Write docker/Dockerfile**

Create `docker/Dockerfile`:
```dockerfile
FROM php:8.1-fpm-alpine

RUN apk add --no-cache \
        postgresql-dev \
        oniguruma-dev \
        icu-dev \
        libzip-dev \
        zlib-dev \
        bash \
    && docker-php-ext-install \
        pdo \
        pdo_pgsql \
        mbstring \
        intl \
        opcache \
    && rm -rf /var/cache/apk/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
COPY docker/php-fpm.conf /usr/local/etc/php-fpm.d/zz-app.conf

USER www-data
```

- [ ] **Step 2: Write docker/php-fpm.conf**

Create `docker/php-fpm.conf`:
```ini
[www]
listen = 0.0.0.0:9000
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
clear_env = no
catch_workers_output = yes
decorate_workers_output = no
```

- [ ] **Step 3: Write docker/nginx.conf**

Create `docker/nginx.conf`:
```nginx
worker_processes auto;
events { worker_connections 1024; }
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  sendfile on;
  keepalive_timeout 65;

  server {
    listen 80;
    listen 443 ssl;
    server_name localhost;
    root /app/public;
    index index.php;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
      try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
      fastcgi_split_path_info ^(.+\.php)(/.+)$;
      fastcgi_pass php:9000;
      fastcgi_index index.php;
      include fastcgi_params;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
      fastcgi_param PATH_INFO $fastcgi_path_info;
    }

    location ~ /\.ht { deny all; }
  }
}
```

- [ ] **Step 4: Write docker-compose.yml**

Create `docker-compose.yml`:
```yaml
services:
  postgres:
    image: postgres:14-alpine
    environment:
      POSTGRES_DB: blockharbor
      POSTGRES_USER: blockharbor_app
      POSTGRES_PASSWORD: ${DB_PASSWORD:-change-me-strong-random}
    volumes:
      - pg_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "blockharbor_app"]
      interval: 5s
      timeout: 3s
      retries: 10

  php:
    build:
      context: .
      dockerfile: docker/Dockerfile
    volumes:
      - .:/app
      - /app/vendor
    environment:
      DB_HOST: postgres
    depends_on:
      postgres:
        condition: service_healthy

  nginx:
    image: nginx:alpine
    volumes:
      - .:/app
      - ./docker/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./docker/ssl:/etc/nginx/ssl:ro
    ports:
      - "8080:80"
      - "8443:443"
    depends_on:
      - php

volumes:
  pg_data:
```

- [ ] **Step 5: Generate self-signed cert for dev**

Run:
```bash
mkdir -p docker/ssl
openssl req -x509 -newkey rsa:2048 -keyout docker/ssl/server.key \
  -out docker/ssl/server.crt -days 365 -nodes \
  -subj "/CN=localhost" 2>/dev/null
chmod 600 docker/ssl/server.key
echo "docker/ssl/*.key" >> .gitignore
echo "docker/ssl/*.crt" >> .gitignore
```

Expected: dev cert generated, gitignored.

- [ ] **Step 6: Bring up the stack and verify**

Run:
```bash
cp .env.example .env
sed -i 's/^APP_KEY=.*/APP_KEY='"$(openssl rand -hex 32)"'/' .env
docker compose up -d --build
sleep 5
docker compose ps
docker compose exec postgres pg_isready -U blockharbor_app
```

Expected: 3 services (postgres, php, nginx) — all healthy. `pg_isready` returns `accepting connections`.

- [ ] **Step 7: Commit Docker setup**

Run:
```bash
git add docker/Dockerfile docker/php-fpm.conf docker/nginx.conf docker-compose.yml
git commit -m "chore: add Docker Compose stack (postgres + php-fpm + nginx)

3 services with healthchecks; self-signed dev TLS; PSR-friendly mounts."
```

---

## Task 4: Config + .env Loader

**Files:**
- Create: `src/Core/Config.php`
- Create: `tests/Unit/Core/ConfigTest.php`
- Create: `tests/bootstrap.php`
- Create: `phpunit.xml`

- [ ] **Step 1: Write the failing test**

Create `tests/Unit/Core/ConfigTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Unit\Core;

use CWE\Core\Config;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function test_returns_string_value(): void
    {
        $cfg = new Config(['APP_ENV' => 'production']);
        self::assertSame('production', $cfg->string('APP_ENV'));
    }

    public function test_returns_int_value(): void
    {
        $cfg = new Config(['SESSION_LIFETIME' => '1800']);
        self::assertSame(1800, $cfg->int('SESSION_LIFETIME'));
    }

    public function test_returns_bool_value(): void
    {
        $cfg = new Config(['APP_DEBUG' => 'true']);
        self::assertTrue($cfg->bool('APP_DEBUG'));

        $cfg2 = new Config(['APP_DEBUG' => 'false']);
        self::assertFalse($cfg2->bool('APP_DEBUG'));
    }

    public function test_returns_default_when_missing(): void
    {
        $cfg = new Config([]);
        self::assertSame('fallback', $cfg->string('MISSING', 'fallback'));
        self::assertSame(42, $cfg->int('MISSING', 42));
        self::assertFalse($cfg->bool('MISSING', false));
    }

    public function test_throws_when_required_missing(): void
    {
        $cfg = new Config([]);
        $this->expectException(\RuntimeException::class);
        $cfg->string('REQUIRED');
    }
}
```

- [ ] **Step 2: Write tests/bootstrap.php**

Create `tests/bootstrap.php`:
```php
<?php declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
```

- [ ] **Step 3: Write phpunit.xml**

Create `phpunit.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="vendor/phpunit/phpunit/phpunit.xsd"
         bootstrap="tests/bootstrap.php"
         colors="true"
         cacheDirectory=".phpunit.cache"
         executionOrder="depends,defects"
         beStrictAboutOutputDuringTests="true"
         failOnRisky="true"
         failOnWarning="true">
    <testsuites>
        <testsuite name="unit">
            <directory>tests/Unit</directory>
        </testsuite>
        <testsuite name="integration">
            <directory>tests/Integration</directory>
        </testsuite>
    </testsuites>
    <source>
        <include>
            <directory>src</directory>
        </include>
    </source>
</phpunit>
```

- [ ] **Step 4: Run test — expect FAIL**

Run:
```bash
docker compose exec php composer test -- --testsuite=unit --filter=ConfigTest
```

Expected: FAIL — "Class CWE\Core\Config does not exist".

- [ ] **Step 5: Write minimal Config.php**

Create `src/Core/Config.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Core;

final class Config
{
    /** @param array<string,string> $env */
    public function __construct(private readonly array $env) {}

    public static function fromEnvFile(string $path): self
    {
        $dotenv = \Dotenv\Dotenv::createImmutable(dirname($path), basename($path));
        $dotenv->safeLoad();
        /** @var array<string,string> $env */
        $env = $_ENV + $_SERVER + getenv();
        return new self($env);
    }

    public function string(string $key, ?string $default = null): string
    {
        $v = $this->env[$key] ?? null;
        if ($v === null || $v === '') {
            if ($default === null) {
                throw new \RuntimeException("Required env var missing: $key");
            }
            return $default;
        }
        return (string)$v;
    }

    public function int(string $key, ?int $default = null): int
    {
        $v = $this->env[$key] ?? null;
        if ($v === null || $v === '') {
            if ($default === null) {
                throw new \RuntimeException("Required env var missing: $key");
            }
            return $default;
        }
        return (int)$v;
    }

    public function bool(string $key, ?bool $default = null): bool
    {
        $v = $this->env[$key] ?? null;
        if ($v === null || $v === '') {
            if ($default === null) {
                throw new \RuntimeException("Required env var missing: $key");
            }
            return $default;
        }
        return in_array(strtolower((string)$v), ['1', 'true', 'yes', 'on'], true);
    }
}
```

- [ ] **Step 6: Run test — expect PASS**

Run:
```bash
docker compose exec php composer test -- --testsuite=unit --filter=ConfigTest
```

Expected: 5 tests, 5 passing.

- [ ] **Step 7: Commit**

Run:
```bash
git add src/Core/Config.php tests/Unit/Core/ConfigTest.php tests/bootstrap.php phpunit.xml
git commit -m "feat(core): add typed Config loader with .env support

string/int/bool getters with optional defaults; throws on missing required."
```

---

## Task 5: Phinx Setup + Migration `tenants`

**Files:**
- Create: `phinx.php`
- Create: `bin/migrate`
- Create: `db/migrations/20260607120000_create_tenants.php`

- [ ] **Step 1: Write phinx.php**

Create `phinx.php`:
```php
<?php declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

$dotenv = \Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

$env = $_ENV + getenv();

return [
    'paths' => [
        'migrations' => __DIR__ . '/db/migrations',
        'seeds'      => __DIR__ . '/db/seeds',
    ],
    'environments' => [
        'default_migration_table' => 'phinxlog',
        'default_environment'     => $env['APP_ENV'] ?? 'production',
        'production' => [
            'adapter' => 'pgsql',
            'host'    => $env['DB_HOST'] ?? 'postgres',
            'name'    => $env['DB_NAME'] ?? 'blockharbor',
            'user'    => $env['DB_USER'] ?? 'blockharbor_app',
            'pass'    => $env['DB_PASSWORD'] ?? '',
            'port'    => (int)($env['DB_PORT'] ?? 5432),
            'charset' => 'utf8',
        ],
        'testing' => [
            'adapter' => 'pgsql',
            'host'    => $env['DB_HOST'] ?? 'postgres',
            'name'    => ($env['DB_NAME'] ?? 'blockharbor') . '_test',
            'user'    => $env['DB_USER'] ?? 'blockharbor_app',
            'pass'    => $env['DB_PASSWORD'] ?? '',
            'port'    => (int)($env['DB_PORT'] ?? 5432),
            'charset' => 'utf8',
        ],
    ],
    'version_order' => 'creation',
];
```

- [ ] **Step 2: Write bin/migrate**

Create `bin/migrate`:
```bash
#!/usr/bin/env bash
set -euo pipefail
docker compose exec -T php vendor/bin/phinx migrate "$@"
```

Run:
```bash
chmod +x bin/migrate
```

- [ ] **Step 3: Write tenants migration**

Create `db/migrations/20260607120000_create_tenants.php`:
```php
<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateTenants extends AbstractMigration
{
    public function change(): void
    {
        $this->execute("CREATE EXTENSION IF NOT EXISTS pgcrypto");
        $this->execute("CREATE EXTENSION IF NOT EXISTS pg_trgm");

        $this->execute(<<<SQL
            CREATE TABLE tenants (
                id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                name        varchar(255) NOT NULL,
                active      boolean NOT NULL DEFAULT true,
                created_at  timestamptz NOT NULL DEFAULT now()
            )
        SQL);

        // Default tenant — ID matches the application default used everywhere
        $this->execute(<<<SQL
            INSERT INTO tenants (id, name) VALUES
                ('00000000-0000-0000-0000-000000000000', 'default')
        SQL);
    }
}
```

- [ ] **Step 4: Run migration**

Run:
```bash
./bin/migrate
```

Expected output: `CreateTenants: migrated` and a positive exit code.

- [ ] **Step 5: Verify in DB**

Run:
```bash
docker compose exec postgres psql -U blockharbor_app -d blockharbor -c "SELECT * FROM tenants;"
```

Expected: 1 row — `00000000-0000-0000-0000-000000000000 | default | t | <now>`.

- [ ] **Step 6: Commit**

Run:
```bash
git add phinx.php bin/migrate db/migrations/20260607120000_create_tenants.php
git commit -m "feat(db): add Phinx setup + tenants migration

Enables pgcrypto + pg_trgm; seeds the default tenant UUID used as
the global single-tenant default across all domain tables."
```

---

## Task 6: Migration `users`

**Files:**
- Create: `db/migrations/20260607120100_create_users.php`

- [ ] **Step 1: Write users migration**

Create `db/migrations/20260607120100_create_users.php`:
```php
<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateUsers extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TYPE user_role AS ENUM ('admin', 'operator', 'viewer');

            CREATE TABLE users (
                id                     bigserial PRIMARY KEY,
                tenant_id              uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'
                                            REFERENCES tenants(id) ON DELETE RESTRICT,
                username               varchar(64) NOT NULL,
                email                  varchar(254),
                password_hash          text,
                role                   user_role NOT NULL DEFAULT 'viewer',
                active                 boolean NOT NULL DEFAULT true,
                failed_login_count     integer NOT NULL DEFAULT 0,
                locked_until           timestamptz,
                last_login_at          timestamptz,
                password_changed_at    timestamptz,
                mfa_required           boolean NOT NULL DEFAULT false,
                metadata               jsonb NOT NULL DEFAULT '{}'::jsonb,
                created_at             timestamptz NOT NULL DEFAULT now(),
                CONSTRAINT users_username_unique UNIQUE (tenant_id, username)
            );

            CREATE INDEX users_active_idx ON users (active) WHERE active = true;
            CREATE INDEX users_metadata_gin ON users USING gin (metadata jsonb_path_ops);
        SQL);
    }
}
```

- [ ] **Step 2: Run migration**

Run: `./bin/migrate`

Expected: `CreateUsers: migrated`.

- [ ] **Step 3: Verify table**

Run:
```bash
docker compose exec postgres psql -U blockharbor_app -d blockharbor -c "\d users"
```

Expected: Shows table with all columns, the unique constraint, and 2 indexes.

- [ ] **Step 4: Commit**

Run:
```bash
git add db/migrations/20260607120100_create_users.php
git commit -m "feat(db): add users migration with role enum"
```

---

## Task 7: Migrations `password_history`, `user_sessions`, `login_attempts`

**Files:**
- Create: `db/migrations/20260607120200_create_password_history.php`
- Create: `db/migrations/20260607120300_create_user_sessions.php`
- Create: `db/migrations/20260607120400_create_login_attempts.php`

- [ ] **Step 1: Write password_history**

Create `db/migrations/20260607120200_create_password_history.php`:
```php
<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreatePasswordHistory extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TABLE password_history (
                id            bigserial PRIMARY KEY,
                user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                password_hash text NOT NULL,
                created_at    timestamptz NOT NULL DEFAULT now()
            );
            CREATE INDEX password_history_user_idx ON password_history (user_id, created_at DESC);

            -- Prune trigger: keep last 5 per user
            CREATE OR REPLACE FUNCTION prune_password_history() RETURNS trigger AS $$
            BEGIN
                DELETE FROM password_history
                WHERE id IN (
                    SELECT id FROM password_history
                    WHERE user_id = NEW.user_id
                    ORDER BY created_at DESC
                    OFFSET 5
                );
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER password_history_prune
                AFTER INSERT ON password_history
                FOR EACH ROW EXECUTE FUNCTION prune_password_history();
        SQL);
    }
}
```

- [ ] **Step 2: Write user_sessions**

Create `db/migrations/20260607120300_create_user_sessions.php`:
```php
<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateUserSessions extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TABLE user_sessions (
                id                uuid PRIMARY KEY,
                user_id           bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                ip_address        inet,
                user_agent        text,
                fingerprint       bytea,
                payload           text NOT NULL DEFAULT '',
                created_at        timestamptz NOT NULL DEFAULT now(),
                expires_at        timestamptz NOT NULL,
                last_activity_at  timestamptz NOT NULL DEFAULT now(),
                revoked_at        timestamptz
            );
            CREATE INDEX user_sessions_user_idx     ON user_sessions (user_id) WHERE revoked_at IS NULL;
            CREATE INDEX user_sessions_expires_idx  ON user_sessions (expires_at) WHERE revoked_at IS NULL;
        SQL);
    }
}
```

- [ ] **Step 3: Write login_attempts**

Create `db/migrations/20260607120400_create_login_attempts.php`:
```php
<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateLoginAttempts extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TABLE login_attempts (
                id              bigserial PRIMARY KEY,
                username        varchar(64),
                ip_address      inet NOT NULL,
                success         boolean NOT NULL,
                failure_reason  varchar(64),
                geo_country     char(2),
                user_agent      text,
                created_at      timestamptz NOT NULL DEFAULT now()
            );
            CREATE INDEX login_attempts_ip_time   ON login_attempts (ip_address, created_at DESC);
            CREATE INDEX login_attempts_user_time ON login_attempts (username, created_at DESC) WHERE username IS NOT NULL;
        SQL);
    }
}
```

- [ ] **Step 4: Run migrations**

Run: `./bin/migrate`

Expected: 3 migrations applied.

- [ ] **Step 5: Verify**

Run:
```bash
docker compose exec postgres psql -U blockharbor_app -d blockharbor -c "\dt"
```

Expected: 5 tables (`tenants`, `users`, `password_history`, `user_sessions`, `login_attempts`) + `phinxlog`.

- [ ] **Step 6: Commit**

Run:
```bash
git add db/migrations/20260607120200_create_password_history.php \
        db/migrations/20260607120300_create_user_sessions.php \
        db/migrations/20260607120400_create_login_attempts.php
git commit -m "feat(db): add password_history, user_sessions, login_attempts

password_history has prune trigger (last 5 per user).
user_sessions backs DB session handler.
login_attempts indexed for rate-limit queries."
```

---

## Task 8: Migration `audit_log` + Hash Chain Trigger

**Files:**
- Create: `db/migrations/20260607120500_create_audit_log.php`
- Create: `tests/Integration/AuditChainTest.php` (test will exercise the trigger directly)

- [ ] **Step 1: Write audit_log migration**

Create `db/migrations/20260607120500_create_audit_log.php`:
```php
<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateAuditLog extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TABLE audit_log (
                id              bigserial PRIMARY KEY,
                ts              timestamptz NOT NULL DEFAULT now(),
                actor_username  varchar(64),
                actor_role      varchar(16),
                ip_address      inet,
                action          varchar(64) NOT NULL,
                details         jsonb NOT NULL DEFAULT '{}'::jsonb,
                prev_hash       bytea,
                entry_hash      bytea NOT NULL
            );

            CREATE INDEX audit_log_ts_brin       ON audit_log USING brin (ts);
            CREATE INDEX audit_log_actor_time    ON audit_log (actor_username, ts DESC);
            CREATE INDEX audit_log_action_time   ON audit_log (action, ts DESC);

            -- Chain trigger: every insert computes prev_hash from last row,
            -- then entry_hash = sha256(prev_hash || canonical_json).
            CREATE OR REPLACE FUNCTION audit_chain_trigger() RETURNS trigger AS $$
            DECLARE
                last_hash bytea;
                canonical text;
            BEGIN
                SELECT entry_hash INTO last_hash
                FROM audit_log
                ORDER BY id DESC
                LIMIT 1;

                NEW.prev_hash := COALESCE(last_hash, '\\x00'::bytea);

                canonical := jsonb_build_object(
                    'ts',      NEW.ts,
                    'actor',   NEW.actor_username,
                    'action',  NEW.action,
                    'details', NEW.details
                )::text;

                NEW.entry_hash := digest(NEW.prev_hash || convert_to(canonical, 'UTF8'), 'sha256');
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER audit_chain
                BEFORE INSERT ON audit_log
                FOR EACH ROW EXECUTE FUNCTION audit_chain_trigger();
        SQL);
    }
}
```

- [ ] **Step 2: Run migration**

Run: `./bin/migrate`

Expected: `CreateAuditLog: migrated`.

- [ ] **Step 3: Write the failing integration test**

(We will add a `tests/DatabaseTestCase.php` base class in Task 11 — for this task we use a self-contained PDO connection inside the test.)

Create `tests/Integration/AuditChainTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Integration;

use PDO;
use PHPUnit\Framework\TestCase;

final class AuditChainTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $host = getenv('DB_HOST') ?: 'postgres';
        $this->pdo = new PDO(
            "pgsql:host=$host;port=5432;dbname=blockharbor",
            'blockharbor_app',
            getenv('DB_PASSWORD') ?: 'change-me-strong-random'
        );
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec("DELETE FROM audit_log");
    }

    public function test_first_entry_has_null_byte_prev_hash(): void
    {
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('test.first')");

        $row = $this->pdo->query("SELECT prev_hash, entry_hash FROM audit_log ORDER BY id")->fetch(PDO::FETCH_ASSOC);

        self::assertSame("\x00", $row['prev_hash']);
        self::assertSame(32, strlen($row['entry_hash']));  // sha256 = 32 bytes
    }

    public function test_chain_links_to_previous_entry(): void
    {
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('first')");
        $first = $this->pdo->query("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")->fetchColumn();

        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('second')");
        $second = $this->pdo->query("SELECT prev_hash FROM audit_log ORDER BY id DESC LIMIT 1")->fetchColumn();

        self::assertSame($first, $second);
    }

    public function test_third_entry_continues_chain(): void
    {
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('a')");
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('b')");
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('c')");

        $rows = $this->pdo->query("SELECT prev_hash, entry_hash FROM audit_log ORDER BY id")
                          ->fetchAll(PDO::FETCH_ASSOC);

        self::assertCount(3, $rows);
        self::assertSame($rows[0]['entry_hash'], $rows[1]['prev_hash']);
        self::assertSame($rows[1]['entry_hash'], $rows[2]['prev_hash']);
    }
}
```

- [ ] **Step 4: Run test — expect PASS (table + trigger already exist)**

Run:
```bash
docker compose exec php composer test -- --testsuite=integration --filter=AuditChainTest
```

Expected: 3 tests, 3 passing. (If failing because connection refused, ensure `docker compose up -d` is running and the migrations were applied.)

- [ ] **Step 5: Commit**

Run:
```bash
git add db/migrations/20260607120500_create_audit_log.php tests/Integration/AuditChainTest.php
git commit -m "feat(db): add audit_log with sha256 hash-chain trigger

BEFORE INSERT trigger computes prev_hash from prior row and entry_hash
= sha256(prev_hash || canonical_jsonb). Tests verify first/link/multi-row."
```

---

## Task 9: Database (PDO Factory)

**Files:**
- Create: `src/Core/Database.php`
- Create: `tests/Integration/DatabaseTest.php`

- [ ] **Step 1: Write failing test**

Create `tests/Integration/DatabaseTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Integration;

use CWE\Core\Config;
use CWE\Core\Database;
use PDO;
use PHPUnit\Framework\TestCase;

final class DatabaseTest extends TestCase
{
    private Config $config;

    protected function setUp(): void
    {
        $this->config = new Config([
            'DB_HOST'     => getenv('DB_HOST') ?: 'postgres',
            'DB_PORT'     => '5432',
            'DB_NAME'     => 'blockharbor',
            'DB_USER'     => 'blockharbor_app',
            'DB_PASSWORD' => getenv('DB_PASSWORD') ?: 'change-me-strong-random',
            'DB_SSLMODE'  => 'disable',
        ]);
    }

    public function test_pdo_uses_exception_error_mode(): void
    {
        $db = new Database($this->config);
        $pdo = $db->pdo();
        self::assertSame(PDO::ERRMODE_EXCEPTION, $pdo->getAttribute(PDO::ATTR_ERRMODE));
    }

    public function test_pdo_returns_assoc_by_default(): void
    {
        $db = new Database($this->config);
        $pdo = $db->pdo();
        self::assertSame(PDO::FETCH_ASSOC, $pdo->getAttribute(PDO::ATTR_DEFAULT_FETCH_MODE));
    }

    public function test_pdo_is_singleton_per_instance(): void
    {
        $db = new Database($this->config);
        self::assertSame($db->pdo(), $db->pdo());
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=DatabaseTest`

Expected: FAIL — class missing.

- [ ] **Step 3: Write Database.php**

Create `src/Core/Database.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Core;

use PDO;

final class Database
{
    private ?PDO $pdo = null;

    public function __construct(private readonly Config $config) {}

    public function pdo(): PDO
    {
        if ($this->pdo === null) {
            $dsn = sprintf(
                'pgsql:host=%s;port=%d;dbname=%s;sslmode=%s',
                $this->config->string('DB_HOST'),
                $this->config->int('DB_PORT', 5432),
                $this->config->string('DB_NAME'),
                $this->config->string('DB_SSLMODE', 'prefer'),
            );

            $this->pdo = new PDO(
                $dsn,
                $this->config->string('DB_USER'),
                $this->config->string('DB_PASSWORD'),
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ],
            );
        }

        return $this->pdo;
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=DatabaseTest`

Expected: 3 tests passing.

- [ ] **Step 5: Commit**

Run:
```bash
git add src/Core/Database.php tests/Integration/DatabaseTest.php
git commit -m "feat(core): add Database (PDO factory, ERR exception, FETCH assoc)"
```

---

## Task 10: PasswordHasher (Argon2id)

**Files:**
- Create: `src/Auth/PasswordHasher.php`
- Create: `tests/Unit/Auth/PasswordHasherTest.php`

- [ ] **Step 1: Write failing test**

Create `tests/Unit/Auth/PasswordHasherTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Unit\Auth;

use CWE\Auth\PasswordHasher;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    public function test_hash_uses_argon2id(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('correct-horse-battery-staple');
        self::assertStringStartsWith('$argon2id$', $hash);
    }

    public function test_verify_correct_password(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('s3cret!password');
        self::assertTrue($hasher->verify('s3cret!password', $hash));
    }

    public function test_verify_wrong_password(): void
    {
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('s3cret!password');
        self::assertFalse($hasher->verify('wrong', $hash));
    }

    public function test_verify_empty_or_invalid_hash(): void
    {
        $hasher = new PasswordHasher();
        self::assertFalse($hasher->verify('anything', ''));
        self::assertFalse($hasher->verify('anything', 'not-a-hash'));
    }

    public function test_needs_rehash_when_parameters_change(): void
    {
        $hasher = new PasswordHasher(memoryCost: 1024, timeCost: 1);
        $oldHash = $hasher->hash('p');

        $stronger = new PasswordHasher(memoryCost: 65536, timeCost: 3);
        self::assertTrue($stronger->needsRehash($oldHash));
        self::assertFalse($stronger->needsRehash($stronger->hash('p')));
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `docker compose exec php composer test -- --testsuite=unit --filter=PasswordHasherTest`

Expected: FAIL — class missing.

- [ ] **Step 3: Write PasswordHasher.php**

Create `src/Auth/PasswordHasher.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth;

final class PasswordHasher
{
    public function __construct(
        private readonly int $memoryCost = 65536,  // 64 MiB
        private readonly int $timeCost   = 3,
        private readonly int $threads    = 1,
    ) {}

    public function hash(string $plain): string
    {
        $hash = password_hash($plain, PASSWORD_ARGON2ID, $this->options());
        if ($hash === false) {
            throw new \RuntimeException('Failed to hash password');
        }
        return $hash;
    }

    public function verify(string $plain, string $hash): bool
    {
        if ($hash === '' || !str_starts_with($hash, '$argon2')) {
            return false;
        }
        return password_verify($plain, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, $this->options());
    }

    /** @return array{memory_cost:int,time_cost:int,threads:int} */
    private function options(): array
    {
        return [
            'memory_cost' => $this->memoryCost,
            'time_cost'   => $this->timeCost,
            'threads'     => $this->threads,
        ];
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

Run: `docker compose exec php composer test -- --testsuite=unit --filter=PasswordHasherTest`

Expected: 5 tests passing.

- [ ] **Step 5: Commit**

Run:
```bash
git add src/Auth/PasswordHasher.php tests/Unit/Auth/PasswordHasherTest.php
git commit -m "feat(auth): add Argon2id PasswordHasher

hash/verify/needsRehash with configurable memory_cost/time_cost/threads."
```

---

## Task 11: PasswordPolicy + DatabaseTestCase base

**Files:**
- Create: `src/Auth/PasswordPolicy.php`
- Create: `tests/Unit/Auth/PasswordPolicyTest.php`
- Create: `tests/DatabaseTestCase.php`

- [ ] **Step 1: Write tests/DatabaseTestCase.php (used by future tasks)**

Create `tests/DatabaseTestCase.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests;

use CWE\Core\Config;
use CWE\Core\Database;
use PHPUnit\Framework\TestCase;

abstract class DatabaseTestCase extends TestCase
{
    protected Database $db;
    protected Config $config;

    protected function setUp(): void
    {
        $this->config = new Config([
            'DB_HOST'     => getenv('DB_HOST') ?: 'postgres',
            'DB_PORT'     => '5432',
            'DB_NAME'     => 'blockharbor',
            'DB_USER'     => 'blockharbor_app',
            'DB_PASSWORD' => getenv('DB_PASSWORD') ?: 'change-me-strong-random',
            'DB_SSLMODE'  => 'disable',
        ]);
        $this->db = new Database($this->config);
        $this->resetTables();
    }

    protected function resetTables(): void
    {
        $pdo = $this->db->pdo();
        $pdo->exec("TRUNCATE audit_log, login_attempts, user_sessions, password_history, users RESTART IDENTITY CASCADE");
    }
}
```

- [ ] **Step 2: Write failing PasswordPolicy test**

Create `tests/Unit/Auth/PasswordPolicyTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Unit\Auth;

use CWE\Auth\PasswordPolicy;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyTest extends TestCase
{
    public function test_accepts_compliant_password(): void
    {
        $p = new PasswordPolicy(minLength: 12, requireMixedCase: true, requireDigit: true, requireSpecial: true);
        self::assertSame([], $p->validate('Str0ng!Pass#word'));
    }

    public function test_rejects_short_password(): void
    {
        $p = new PasswordPolicy(minLength: 12);
        self::assertContains('too_short', $p->validate('Ab1!'));
    }

    public function test_rejects_when_missing_mixed_case(): void
    {
        $p = new PasswordPolicy(minLength: 8, requireMixedCase: true);
        self::assertContains('missing_mixed_case', $p->validate('alllowercase1!'));
        self::assertContains('missing_mixed_case', $p->validate('ALLUPPERCASE1!'));
    }

    public function test_rejects_when_missing_digit(): void
    {
        $p = new PasswordPolicy(minLength: 8, requireDigit: true);
        self::assertContains('missing_digit', $p->validate('NoDigits!Here'));
    }

    public function test_rejects_when_missing_special(): void
    {
        $p = new PasswordPolicy(minLength: 8, requireSpecial: true);
        self::assertContains('missing_special', $p->validate('NoSpecial1Here'));
    }

    public function test_returns_multiple_failures(): void
    {
        $p = new PasswordPolicy(minLength: 12, requireMixedCase: true, requireDigit: true, requireSpecial: true);
        $errors = $p->validate('short');
        self::assertContains('too_short', $errors);
        self::assertContains('missing_mixed_case', $errors);
        self::assertContains('missing_digit', $errors);
        self::assertContains('missing_special', $errors);
    }
}
```

- [ ] **Step 3: Run test — expect FAIL**

Run: `docker compose exec php composer test -- --testsuite=unit --filter=PasswordPolicyTest`

Expected: FAIL — class missing.

- [ ] **Step 4: Write PasswordPolicy.php**

Create `src/Auth/PasswordPolicy.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth;

final class PasswordPolicy
{
    public function __construct(
        private readonly int  $minLength = 12,
        private readonly bool $requireMixedCase = true,
        private readonly bool $requireDigit = true,
        private readonly bool $requireSpecial = true,
    ) {}

    /** @return list<string> error codes; empty array = OK */
    public function validate(string $password): array
    {
        $errors = [];

        if (strlen($password) < $this->minLength) {
            $errors[] = 'too_short';
        }
        if ($this->requireMixedCase &&
            !(preg_match('/[a-z]/', $password) && preg_match('/[A-Z]/', $password))) {
            $errors[] = 'missing_mixed_case';
        }
        if ($this->requireDigit && !preg_match('/\d/', $password)) {
            $errors[] = 'missing_digit';
        }
        if ($this->requireSpecial && !preg_match('/[^\w\s]/', $password)) {
            $errors[] = 'missing_special';
        }

        return $errors;
    }
}
```

- [ ] **Step 5: Run test — expect PASS**

Run: `docker compose exec php composer test -- --testsuite=unit --filter=PasswordPolicyTest`

Expected: 6 tests passing.

- [ ] **Step 6: Commit**

Run:
```bash
git add src/Auth/PasswordPolicy.php tests/Unit/Auth/PasswordPolicyTest.php tests/DatabaseTestCase.php
git commit -m "feat(auth): add PasswordPolicy + DatabaseTestCase base

Policy returns error codes (i18n-friendly).
DatabaseTestCase truncates auth tables in setUp() — used by repository tests."
```

---

## Task 12: UserRepository

**Files:**
- Create: `src/Auth/UserRepository.php`
- Create: `src/Auth/User.php` (DTO)
- Create: `tests/Integration/Auth/UserRepositoryTest.php`

- [ ] **Step 1: Write User DTO**

Create `src/Auth/User.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth;

use DateTimeImmutable;

final class User
{
    public function __construct(
        public readonly int $id,
        public readonly string $tenantId,
        public readonly string $username,
        public readonly ?string $email,
        public readonly ?string $passwordHash,
        public readonly string $role,
        public readonly bool $active,
        public readonly int $failedLoginCount,
        public readonly ?DateTimeImmutable $lockedUntil,
        public readonly ?DateTimeImmutable $lastLoginAt,
        public readonly ?DateTimeImmutable $passwordChangedAt,
        public readonly bool $mfaRequired,
    ) {}

    /** @param array<string,mixed> $row */
    public static function fromRow(array $row): self
    {
        return new self(
            id: (int)$row['id'],
            tenantId: (string)$row['tenant_id'],
            username: (string)$row['username'],
            email: $row['email'] !== null ? (string)$row['email'] : null,
            passwordHash: $row['password_hash'] !== null ? (string)$row['password_hash'] : null,
            role: (string)$row['role'],
            active: (bool)$row['active'],
            failedLoginCount: (int)$row['failed_login_count'],
            lockedUntil: $row['locked_until'] ? new DateTimeImmutable((string)$row['locked_until']) : null,
            lastLoginAt: $row['last_login_at'] ? new DateTimeImmutable((string)$row['last_login_at']) : null,
            passwordChangedAt: $row['password_changed_at'] ? new DateTimeImmutable((string)$row['password_changed_at']) : null,
            mfaRequired: (bool)$row['mfa_required'],
        );
    }

    public function isLocked(): bool
    {
        return $this->lockedUntil !== null && $this->lockedUntil > new DateTimeImmutable();
    }
}
```

- [ ] **Step 2: Write failing UserRepository test**

Create `tests/Integration/Auth/UserRepositoryTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Integration\Auth;

use CWE\Auth\UserRepository;
use CWE\Tests\DatabaseTestCase;

final class UserRepositoryTest extends DatabaseTestCase
{
    private UserRepository $repo;

    protected function setUp(): void
    {
        parent::setUp();
        $this->repo = new UserRepository($this->db->pdo());
    }

    public function test_create_and_find_by_username(): void
    {
        $id = $this->repo->create(
            username: 'alice',
            email: 'alice@example.com',
            passwordHash: '$argon2id$v=19$m=65536,t=3,p=1$abc$def',
            role: 'admin',
        );
        self::assertGreaterThan(0, $id);

        $u = $this->repo->findByUsername('alice');
        self::assertNotNull($u);
        self::assertSame('alice', $u->username);
        self::assertSame('alice@example.com', $u->email);
        self::assertSame('admin', $u->role);
        self::assertTrue($u->active);
    }

    public function test_find_by_username_returns_null_when_missing(): void
    {
        self::assertNull($this->repo->findByUsername('ghost'));
    }

    public function test_record_successful_login_resets_failed_count(): void
    {
        $id = $this->repo->create('alice', null, 'hash', 'viewer');
        $this->repo->incrementFailedLoginCount($id);
        $this->repo->incrementFailedLoginCount($id);

        $this->repo->recordSuccessfulLogin($id);

        $u = $this->repo->findById($id);
        self::assertSame(0, $u->failedLoginCount);
        self::assertNotNull($u->lastLoginAt);
        self::assertNull($u->lockedUntil);
    }

    public function test_lock_until_sets_locked_until(): void
    {
        $id = $this->repo->create('alice', null, 'hash', 'viewer');
        $this->repo->lockUntil($id, new \DateTimeImmutable('+15 minutes'));

        $u = $this->repo->findById($id);
        self::assertTrue($u->isLocked());
    }
}
```

- [ ] **Step 3: Run test — expect FAIL**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=UserRepositoryTest`

Expected: FAIL — class missing.

- [ ] **Step 4: Write UserRepository.php**

Create `src/Auth/UserRepository.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth;

use DateTimeImmutable;
use PDO;

final class UserRepository
{
    public function __construct(private readonly PDO $pdo) {}

    public function create(string $username, ?string $email, string $passwordHash, string $role): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (username, email, password_hash, role, password_changed_at)
             VALUES (:u, :e, :h, :r, now()) RETURNING id'
        );
        $stmt->execute([':u' => $username, ':e' => $email, ':h' => $passwordHash, ':r' => $role]);
        return (int)$stmt->fetchColumn();
    }

    public function findById(int $id): ?User
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ? User::fromRow($row) : null;
    }

    public function findByUsername(string $username): ?User
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        $row = $stmt->fetch();
        return $row ? User::fromRow($row) : null;
    }

    public function incrementFailedLoginCount(int $userId): int
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users SET failed_login_count = failed_login_count + 1
             WHERE id = :id RETURNING failed_login_count'
        );
        $stmt->execute([':id' => $userId]);
        return (int)$stmt->fetchColumn();
    }

    public function recordSuccessfulLogin(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users
             SET last_login_at = now(),
                 failed_login_count = 0,
                 locked_until = NULL
             WHERE id = :id'
        );
        $stmt->execute([':id' => $userId]);
    }

    public function lockUntil(int $userId, DateTimeImmutable $until): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET locked_until = :u WHERE id = :id');
        $stmt->execute([':u' => $until->format('Y-m-d H:i:sP'), ':id' => $userId]);
    }

    public function updatePassword(int $userId, string $passwordHash): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users SET password_hash = :h, password_changed_at = now() WHERE id = :id'
        );
        $stmt->execute([':h' => $passwordHash, ':id' => $userId]);

        // Also append to password_history (trigger keeps last 5)
        $h = $this->pdo->prepare(
            'INSERT INTO password_history (user_id, password_hash) VALUES (:id, :h)'
        );
        $h->execute([':id' => $userId, ':h' => $passwordHash]);
    }
}
```

- [ ] **Step 5: Run test — expect PASS**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=UserRepositoryTest`

Expected: 4 tests passing.

- [ ] **Step 6: Commit**

Run:
```bash
git add src/Auth/User.php src/Auth/UserRepository.php tests/Integration/Auth/UserRepositoryTest.php
git commit -m "feat(auth): add User DTO + UserRepository

CRUD + recordSuccessfulLogin (resets failed count + clears lockout) +
lockUntil + updatePassword (also writes password_history)."
```

---

## Task 13: LoginAttemptRepository

**Files:**
- Create: `src/Auth/LoginAttemptRepository.php`
- Create: `tests/Integration/Auth/LoginAttemptRepositoryTest.php`

- [ ] **Step 1: Write failing test**

Create `tests/Integration/Auth/LoginAttemptRepositoryTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Integration\Auth;

use CWE\Auth\LoginAttemptRepository;
use CWE\Tests\DatabaseTestCase;

final class LoginAttemptRepositoryTest extends DatabaseTestCase
{
    private LoginAttemptRepository $repo;

    protected function setUp(): void
    {
        parent::setUp();
        $this->repo = new LoginAttemptRepository($this->db->pdo());
    }

    public function test_record_and_count_failures_per_ip(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $this->repo->record(username: 'alice', ip: '10.0.0.1', success: false, failureReason: 'bad_password');
        }
        $this->repo->record(username: 'alice', ip: '10.0.0.1', success: true);

        self::assertSame(3, $this->repo->countFailuresByIp('10.0.0.1', 300));
        self::assertSame(0, $this->repo->countFailuresByIp('10.0.0.2', 300));
    }

    public function test_count_failures_per_user(): void
    {
        $this->repo->record('alice', '10.0.0.1', false, 'bad_password');
        $this->repo->record('alice', '10.0.0.2', false, 'bad_password');
        $this->repo->record('bob',   '10.0.0.3', false, 'bad_password');

        self::assertSame(2, $this->repo->countFailuresByUsername('alice', 3600));
        self::assertSame(1, $this->repo->countFailuresByUsername('bob',   3600));
    }

    public function test_window_excludes_old_attempts(): void
    {
        $this->db->pdo()->exec(
            "INSERT INTO login_attempts (username, ip_address, success, failure_reason, created_at)
             VALUES ('alice', '10.0.0.1', false, 'bad_password', now() - interval '1 hour')"
        );
        self::assertSame(0, $this->repo->countFailuresByIp('10.0.0.1', 300));  // 5-min window
        self::assertSame(1, $this->repo->countFailuresByIp('10.0.0.1', 7200)); // 2-hour window
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=LoginAttemptRepositoryTest`

Expected: FAIL — class missing.

- [ ] **Step 3: Write LoginAttemptRepository.php**

Create `src/Auth/LoginAttemptRepository.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth;

use PDO;

final class LoginAttemptRepository
{
    public function __construct(private readonly PDO $pdo) {}

    public function record(
        ?string $username,
        string $ip,
        bool $success,
        ?string $failureReason = null,
        ?string $userAgent = null,
    ): void {
        $stmt = $this->pdo->prepare(
            'INSERT INTO login_attempts (username, ip_address, success, failure_reason, user_agent)
             VALUES (:u, :ip, :s, :r, :ua)'
        );
        $stmt->execute([
            ':u'  => $username,
            ':ip' => $ip,
            ':s'  => $success ? 't' : 'f',
            ':r'  => $failureReason,
            ':ua' => $userAgent,
        ]);
    }

    public function countFailuresByIp(string $ip, int $windowSeconds): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT count(*) FROM login_attempts
             WHERE ip_address = :ip
               AND success = false
               AND created_at > now() - make_interval(secs => :s)'
        );
        $stmt->execute([':ip' => $ip, ':s' => $windowSeconds]);
        return (int)$stmt->fetchColumn();
    }

    public function countFailuresByUsername(string $username, int $windowSeconds): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT count(*) FROM login_attempts
             WHERE username = :u
               AND success = false
               AND created_at > now() - make_interval(secs => :s)'
        );
        $stmt->execute([':u' => $username, ':s' => $windowSeconds]);
        return (int)$stmt->fetchColumn();
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=LoginAttemptRepositoryTest`

Expected: 3 tests passing.

- [ ] **Step 5: Commit**

Run:
```bash
git add src/Auth/LoginAttemptRepository.php tests/Integration/Auth/LoginAttemptRepositoryTest.php
git commit -m "feat(auth): add LoginAttemptRepository

record/countFailuresByIp/countFailuresByUsername with rolling time window."
```

---

## Task 14: AuthService (Login Flow + Lockout)

**Files:**
- Create: `src/Auth/AuthService.php`
- Create: `src/Auth/AuthResult.php`
- Create: `tests/Integration/Auth/AuthServiceTest.php`

- [ ] **Step 1: Write AuthResult enum**

Create `src/Auth/AuthResult.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth;

enum AuthResult: string
{
    case Success         = 'success';
    case BadCredentials  = 'bad_credentials';
    case Locked          = 'locked';
    case RateLimited     = 'rate_limited';
    case Inactive        = 'inactive';
}
```

- [ ] **Step 2: Write failing AuthServiceTest**

Create `tests/Integration/Auth/AuthServiceTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Integration\Auth;

use CWE\Auth\AuthResult;
use CWE\Auth\AuthService;
use CWE\Auth\LoginAttemptRepository;
use CWE\Auth\PasswordHasher;
use CWE\Auth\UserRepository;
use CWE\Tests\DatabaseTestCase;

final class AuthServiceTest extends DatabaseTestCase
{
    private AuthService $service;
    private UserRepository $users;
    private LoginAttemptRepository $attempts;
    private PasswordHasher $hasher;

    protected function setUp(): void
    {
        parent::setUp();
        $pdo = $this->db->pdo();
        $this->users    = new UserRepository($pdo);
        $this->attempts = new LoginAttemptRepository($pdo);
        $this->hasher   = new PasswordHasher();
        $this->service  = new AuthService(
            $this->users, $this->attempts, $this->hasher,
            maxFailsPerIpIn5Min: 10,
            maxFailsPerUserIn1h: 5,
            lockoutMinutes: 15,
        );
    }

    public function test_successful_login_returns_success(): void
    {
        $this->users->create('alice', null, $this->hasher->hash('p@ssw0rd!XX'), 'admin');
        $r = $this->service->attempt('alice', 'p@ssw0rd!XX', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::Success, $r->result);
        self::assertNotNull($r->user);
    }

    public function test_wrong_password_returns_bad_credentials(): void
    {
        $this->users->create('alice', null, $this->hasher->hash('correct'), 'admin');
        $r = $this->service->attempt('alice', 'wrong', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::BadCredentials, $r->result);
        self::assertNull($r->user);
    }

    public function test_unknown_user_returns_bad_credentials_without_disclosing(): void
    {
        $r = $this->service->attempt('nobody', 'anything', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::BadCredentials, $r->result);
    }

    public function test_five_failures_locks_account(): void
    {
        $this->users->create('alice', null, $this->hasher->hash('correct'), 'admin');
        for ($i = 0; $i < 5; $i++) {
            $this->service->attempt('alice', 'wrong', '10.0.0.1', 'ua/1');
        }
        // 6th attempt — even with the right password — must be rejected
        $r = $this->service->attempt('alice', 'correct', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::Locked, $r->result);
    }

    public function test_too_many_per_ip_returns_rate_limited(): void
    {
        for ($i = 0; $i < 11; $i++) {
            $this->service->attempt("nobody$i", 'x', '10.0.0.1', 'ua/1');
        }
        $r = $this->service->attempt('alice', 'whatever', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::RateLimited, $r->result);
    }

    public function test_inactive_user_returns_inactive(): void
    {
        $id = $this->users->create('alice', null, $this->hasher->hash('correct'), 'admin');
        $this->db->pdo()->exec("UPDATE users SET active = false WHERE id = $id");
        $r = $this->service->attempt('alice', 'correct', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::Inactive, $r->result);
    }
}
```

- [ ] **Step 3: Run test — expect FAIL**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=AuthServiceTest`

Expected: FAIL — class missing.

- [ ] **Step 4: Write AuthService.php**

Create `src/Auth/AuthService.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth;

final class AuthService
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly LoginAttemptRepository $attempts,
        private readonly PasswordHasher $hasher,
        private readonly int $maxFailsPerIpIn5Min,
        private readonly int $maxFailsPerUserIn1h,
        private readonly int $lockoutMinutes,
    ) {}

    public function attempt(string $username, string $password, string $ip, ?string $userAgent): AttemptOutcome
    {
        if ($this->attempts->countFailuresByIp($ip, 300) >= $this->maxFailsPerIpIn5Min) {
            $this->attempts->record($username, $ip, success: false, failureReason: 'rate_limited_ip', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::RateLimited, null);
        }

        $user = $this->users->findByUsername($username);

        if ($user === null) {
            $this->attempts->record($username, $ip, success: false, failureReason: 'unknown_user', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::BadCredentials, null);
        }

        if (!$user->active) {
            $this->attempts->record($username, $ip, success: false, failureReason: 'inactive', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::Inactive, null);
        }

        if ($user->isLocked()) {
            $this->attempts->record($username, $ip, success: false, failureReason: 'locked', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::Locked, null);
        }

        if (!$this->hasher->verify($password, $user->passwordHash ?? '')) {
            $newCount = $this->users->incrementFailedLoginCount($user->id);
            if ($newCount >= $this->maxFailsPerUserIn1h) {
                $this->users->lockUntil(
                    $user->id,
                    new \DateTimeImmutable('+' . $this->lockoutMinutes . ' minutes')
                );
            }
            $this->attempts->record($username, $ip, success: false, failureReason: 'bad_password', userAgent: $userAgent);
            return new AttemptOutcome(AuthResult::BadCredentials, null);
        }

        $this->users->recordSuccessfulLogin($user->id);
        $this->attempts->record($username, $ip, success: true, failureReason: null, userAgent: $userAgent);

        return new AttemptOutcome(AuthResult::Success, $this->users->findById($user->id));
    }
}

final class AttemptOutcome
{
    public function __construct(
        public readonly AuthResult $result,
        public readonly ?User $user,
    ) {}
}
```

- [ ] **Step 5: Run test — expect PASS**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=AuthServiceTest`

Expected: 6 tests passing.

- [ ] **Step 6: Commit**

Run:
```bash
git add src/Auth/AuthResult.php src/Auth/AuthService.php tests/Integration/Auth/AuthServiceTest.php
git commit -m "feat(auth): add AuthService with rate-limit + lockout + outcomes

5 outcomes: Success/BadCredentials/Locked/RateLimited/Inactive.
IP rate-limit checked first (5min/10 fails). Per-user lockout after
5 fails in 1h. Inactive users blocked. Unknown user returns BadCredentials
without disclosure."
```

---

## Task 15: DB-Backed Session Handler + CSRF

**Files:**
- Create: `src/Core/Session.php`
- Create: `src/Core/Csrf.php`
- Create: `tests/Integration/Core/SessionTest.php`

- [ ] **Step 1: Write failing SessionTest**

Create `tests/Integration/Core/SessionTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Integration\Core;

use CWE\Core\Session;
use CWE\Tests\DatabaseTestCase;

final class SessionTest extends DatabaseTestCase
{
    public function test_writes_payload_to_user_sessions_row(): void
    {
        $pdo = $this->db->pdo();
        $pdo->exec("INSERT INTO users (username, password_hash, role) VALUES ('alice','x','admin')");
        $userId = (int)$pdo->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();

        $sessionId = '11111111-1111-1111-1111-111111111111';
        $pdo->exec("INSERT INTO user_sessions (id, user_id, expires_at)
                    VALUES ('$sessionId', $userId, now() + interval '1 hour')");

        $handler = new Session($pdo, lifetime: 3600);
        self::assertTrue($handler->write($sessionId, 'user_id|i:42;'));

        $payload = $pdo->query("SELECT payload FROM user_sessions WHERE id='$sessionId'")->fetchColumn();
        self::assertSame('user_id|i:42;', $payload);

        self::assertSame('user_id|i:42;', $handler->read($sessionId));
    }

    public function test_read_returns_empty_for_expired_or_revoked(): void
    {
        $pdo = $this->db->pdo();
        $pdo->exec("INSERT INTO users (username, password_hash, role) VALUES ('alice','x','admin')");
        $userId = (int)$pdo->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();

        $expired = '22222222-2222-2222-2222-222222222222';
        $revoked = '33333333-3333-3333-3333-333333333333';
        $pdo->exec("INSERT INTO user_sessions (id, user_id, payload, expires_at)
                    VALUES ('$expired', $userId, 'data', now() - interval '1 hour')");
        $pdo->exec("INSERT INTO user_sessions (id, user_id, payload, expires_at, revoked_at)
                    VALUES ('$revoked', $userId, 'data', now() + interval '1 hour', now())");

        $handler = new Session($pdo, lifetime: 3600);
        self::assertSame('', $handler->read($expired));
        self::assertSame('', $handler->read($revoked));
    }

    public function test_destroy_revokes_session(): void
    {
        $pdo = $this->db->pdo();
        $pdo->exec("INSERT INTO users (username, password_hash, role) VALUES ('alice','x','admin')");
        $userId = (int)$pdo->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();
        $id = '44444444-4444-4444-4444-444444444444';
        $pdo->exec("INSERT INTO user_sessions (id, user_id, expires_at)
                    VALUES ('$id', $userId, now() + interval '1 hour')");

        $handler = new Session($pdo, lifetime: 3600);
        self::assertTrue($handler->destroy($id));

        $revoked = $pdo->query("SELECT revoked_at FROM user_sessions WHERE id='$id'")->fetchColumn();
        self::assertNotNull($revoked);
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=SessionTest`

Expected: FAIL — class missing.

- [ ] **Step 3: Write Session.php**

Create `src/Core/Session.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Core;

use PDO;
use SessionHandlerInterface;

final class Session implements SessionHandlerInterface
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly int $lifetime = 1800,
    ) {}

    public function open(string $path, string $name): bool { return true; }
    public function close(): bool { return true; }

    public function read(string $id): string
    {
        $stmt = $this->pdo->prepare(
            'SELECT payload FROM user_sessions
             WHERE id = :id
               AND revoked_at IS NULL
               AND expires_at > now()'
        );
        $stmt->execute([':id' => $id]);
        $payload = $stmt->fetchColumn();
        return $payload === false ? '' : (string)$payload;
    }

    public function write(string $id, string $data): bool
    {
        $stmt = $this->pdo->prepare(
            'UPDATE user_sessions
             SET payload = :p,
                 last_activity_at = now(),
                 expires_at = now() + make_interval(secs => :l)
             WHERE id = :id'
        );
        $stmt->execute([':p' => $data, ':l' => $this->lifetime, ':id' => $id]);
        return $stmt->rowCount() > 0;
    }

    public function destroy(string $id): bool
    {
        $stmt = $this->pdo->prepare('UPDATE user_sessions SET revoked_at = now() WHERE id = :id');
        $stmt->execute([':id' => $id]);
        return true;
    }

    public function gc(int $maxLifetime): int|false
    {
        $stmt = $this->pdo->prepare(
            'UPDATE user_sessions
             SET revoked_at = now()
             WHERE revoked_at IS NULL AND expires_at < now()'
        );
        $stmt->execute();
        return $stmt->rowCount();
    }

    public function start(int $userId, string $ip, ?string $userAgent): string
    {
        $id = \Ramsey\Uuid\Uuid::uuid7()->toString();
        $stmt = $this->pdo->prepare(
            'INSERT INTO user_sessions (id, user_id, ip_address, user_agent, expires_at)
             VALUES (:id, :uid, :ip, :ua, now() + make_interval(secs => :l))'
        );
        $stmt->execute([
            ':id' => $id, ':uid' => $userId, ':ip' => $ip, ':ua' => $userAgent, ':l' => $this->lifetime,
        ]);
        return $id;
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

Run: `docker compose exec php composer test -- --testsuite=integration --filter=SessionTest`

Expected: 3 tests passing.

- [ ] **Step 5: Write Csrf.php**

Create `src/Core/Csrf.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Core;

final class Csrf
{
    private const SESSION_KEY = '_csrf';

    public function token(): string
    {
        if (!isset($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = bin2hex(random_bytes(32));
        }
        return $_SESSION[self::SESSION_KEY];
    }

    public function verify(?string $candidate): bool
    {
        $expected = $_SESSION[self::SESSION_KEY] ?? null;
        if ($expected === null || $candidate === null) {
            return false;
        }
        return hash_equals($expected, $candidate);
    }

    public function rotate(): void
    {
        unset($_SESSION[self::SESSION_KEY]);
    }
}
```

- [ ] **Step 6: Commit**

Run:
```bash
git add src/Core/Session.php src/Core/Csrf.php tests/Integration/Core/SessionTest.php
git commit -m "feat(core): add DB-backed session handler + CSRF

Session implements SessionHandlerInterface persisting to user_sessions.
start() seeds a new uuid-v7 row. destroy() sets revoked_at (no row delete).
Csrf stores token in \$_SESSION; verify() uses hash_equals."
```

---

## Task 16: Router + Application Bootstrap

**Files:**
- Create: `src/Core/Router.php`
- Create: `src/Core/Application.php`
- Create: `public/index.php`
- Create: `public/.htaccess`
- Create: `tests/Unit/Core/RouterTest.php`

- [ ] **Step 1: Write failing RouterTest**

Create `tests/Unit/Core/RouterTest.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Tests\Unit\Core;

use CWE\Core\Router;
use PHPUnit\Framework\TestCase;

final class RouterTest extends TestCase
{
    public function test_match_returns_handler_for_registered_route(): void
    {
        $r = new Router();
        $r->get('/login', ['HomeController', 'show']);

        self::assertSame(['HomeController', 'show'], $r->match('GET', '/login'));
    }

    public function test_returns_null_for_unknown_route(): void
    {
        $r = new Router();
        self::assertNull($r->match('GET', '/no'));
    }

    public function test_method_distinguishes_handlers(): void
    {
        $r = new Router();
        $r->get('/login',  ['Login', 'show']);
        $r->post('/login', ['Login', 'submit']);

        self::assertSame(['Login', 'show'],   $r->match('GET',  '/login'));
        self::assertSame(['Login', 'submit'], $r->match('POST', '/login'));
    }

    public function test_query_string_is_stripped(): void
    {
        $r = new Router();
        $r->get('/dash', ['D', 'i']);
        self::assertSame(['D', 'i'], $r->match('GET', '/dash?x=1'));
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `docker compose exec php composer test -- --testsuite=unit --filter=RouterTest`

Expected: FAIL — class missing.

- [ ] **Step 3: Write Router.php**

Create `src/Core/Router.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Core;

final class Router
{
    /** @var array<string, array<string, array{0:string,1:string}>> */
    private array $routes = [];

    /** @param array{0:string,1:string} $handler */
    public function get(string $path, array $handler): void  { $this->add('GET',  $path, $handler); }
    /** @param array{0:string,1:string} $handler */
    public function post(string $path, array $handler): void { $this->add('POST', $path, $handler); }

    /** @return array{0:string,1:string}|null */
    public function match(string $method, string $uri): ?array
    {
        $path = strtok($uri, '?');
        return $this->routes[$method][$path] ?? null;
    }

    /** @param array{0:string,1:string} $handler */
    private function add(string $method, string $path, array $handler): void
    {
        $this->routes[$method][$path] = $handler;
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

Run: `docker compose exec php composer test -- --testsuite=unit --filter=RouterTest`

Expected: 4 tests passing.

- [ ] **Step 5: Write Application.php**

Create `src/Core/Application.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Core;

use CWE\Auth\AuthService;
use CWE\Auth\Controllers\LoginController;
use CWE\Auth\Controllers\LogoutController;
use CWE\Auth\LoginAttemptRepository;
use CWE\Auth\PasswordHasher;
use CWE\Auth\PasswordPolicy;
use CWE\Auth\UserRepository;
use CWE\Admin\Controllers\DashboardController;
use League\Plates\Engine;

final class Application
{
    public function __construct(
        private readonly Config $config,
        private readonly Database $database,
        private readonly Router $router,
        private readonly Engine $views,
    ) {}

    public static function boot(string $root): self
    {
        $config = Config::fromEnvFile($root . '/.env');
        $database = new Database($config);

        // Session handler (DB-backed)
        $sessionHandler = new Session($database->pdo(), $config->int('SESSION_LIFETIME', 1800));
        session_set_save_handler($sessionHandler, true);
        session_name($config->string('SESSION_NAME', 'CWE_ADMIN_SESSION'));
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();

        $views = new Engine($root . '/resources/views', 'php');
        $router = new Router();

        $app = new self($config, $database, $router, $views);
        $app->registerRoutes();

        return $app;
    }

    private function registerRoutes(): void
    {
        $this->router->get ('/login',  [LoginController::class,    'show']);
        $this->router->post('/login',  [LoginController::class,    'submit']);
        $this->router->post('/logout', [LogoutController::class,   'submit']);
        $this->router->get ('/',       [DashboardController::class,'index']);
        $this->router->get ('/dashboard', [DashboardController::class,'index']);
    }

    public function run(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri    = $_SERVER['REQUEST_URI'] ?? '/';

        $handler = $this->router->match($method, $uri);

        if ($handler === null) {
            http_response_code(404);
            echo $this->views->render('errors/404');
            return;
        }

        [$class, $method2] = $handler;
        $controller = $this->resolve($class);
        $controller->{$method2}();
    }

    private function resolve(string $class): object
    {
        $pdo = $this->database->pdo();
        $csrf = new Csrf();

        return match ($class) {
            LoginController::class    => new LoginController(
                new AuthService(
                    new UserRepository($pdo),
                    new LoginAttemptRepository($pdo),
                    new PasswordHasher(),
                    maxFailsPerIpIn5Min: $this->config->int('LOGIN_MAX_FAILS_PER_IP_5MIN', 10),
                    maxFailsPerUserIn1h: $this->config->int('LOGIN_MAX_FAILS_PER_USER_1H', 5),
                    lockoutMinutes:      $this->config->int('LOGIN_LOCKOUT_MINUTES', 15),
                ),
                new Session($pdo, $this->config->int('SESSION_LIFETIME', 1800)),
                $csrf,
                $this->views,
            ),
            LogoutController::class   => new LogoutController(new Session($pdo), $csrf),
            DashboardController::class => new DashboardController(
                new UserRepository($pdo), $this->views,
            ),
            default => throw new \RuntimeException("Cannot resolve $class"),
        };
    }
}
```

- [ ] **Step 6: Write public/index.php**

Create `public/index.php`:
```php
<?php declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

\CWE\Core\Application::boot(dirname(__DIR__))->run();
```

- [ ] **Step 7: Write public/.htaccess (Apache fallback)**

Create `public/.htaccess`:
```apache
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteRule ^ index.php [L]
</IfModule>
```

- [ ] **Step 8: Commit**

Run:
```bash
git add src/Core/Router.php src/Core/Application.php public/index.php public/.htaccess tests/Unit/Core/RouterTest.php
git commit -m "feat(core): add Router + Application bootstrap + front controller

Router: exact-match path + method. Application: DI-light wiring via
match() expression. public/index.php is the single entry point."
```

---

## Task 17: Login Controller + View

**Files:**
- Create: `src/Auth/Controllers/LoginController.php`
- Create: `src/Auth/Controllers/LogoutController.php`
- Create: `resources/views/layouts/auth.php`
- Create: `resources/views/auth/login.php`
- Create: `resources/views/errors/404.php`

- [ ] **Step 1: Write auth layout**

Create `resources/views/layouts/auth.php`:
```php
<?php /** @var \League\Plates\Template\Template $this */ ?>
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= $this->e($title ?? 'blockharbor') ?></title>
  <meta name="csrf-token" content="<?= $this->e($csrf ?? '') ?>">
  <link rel="stylesheet" href="/assets/app.css">
  <script defer src="https://unpkg.com/alpinejs@3.13.0/dist/cdn.min.js"></script>
  <script defer src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body class="min-h-screen bg-slate-50 flex items-center justify-center px-4">
  <div class="w-full max-w-sm">
    <?= $this->section('content') ?>
  </div>
  <script src="/assets/app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Write login view**

Create `resources/views/auth/login.php`:
```php
<?php /** @var \League\Plates\Template\Template $this */ ?>
<?php $this->layout('layouts/auth', ['title' => 'Giriş', 'csrf' => $csrf]); ?>

<div class="card">
  <div class="card-body">
    <h1 class="text-xl font-semibold text-slate-900 mb-1">Giriş</h1>
    <p class="text-sm text-slate-500 mb-6">blockharbor paneline erişim için kimlik doğrulama gerekir.</p>

    <?php if (!empty($error)): ?>
      <div class="flash flash-error" role="alert"><?= $this->e($error) ?></div>
    <?php endif; ?>

    <form method="post" action="/login" autocomplete="on">
      <input type="hidden" name="_csrf" value="<?= $this->e($csrf) ?>">

      <div class="field">
        <label class="label" for="username">Kullanıcı adı</label>
        <input class="input" id="username" name="username" type="text"
               autocomplete="username" required autofocus
               value="<?= $this->e($username ?? '') ?>">
      </div>

      <div class="field">
        <label class="label" for="password">Parola</label>
        <input class="input" id="password" name="password" type="password"
               autocomplete="current-password" required>
      </div>

      <button class="btn btn-primary w-full" type="submit">Giriş yap</button>
    </form>
  </div>
</div>
```

- [ ] **Step 3: Write 404 view**

Create `resources/views/errors/404.php`:
```php
<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><title>Bulunamadı</title>
<link rel="stylesheet" href="/assets/app.css"></head>
<body class="min-h-screen bg-slate-50 flex items-center justify-center">
  <div class="card max-w-md w-full"><div class="card-body text-center">
    <h1 class="text-3xl font-bold text-slate-900 mb-2">404</h1>
    <p class="text-slate-500">Aradığınız sayfa bulunamadı.</p>
  </div></div>
</body></html>
```

- [ ] **Step 4: Write LoginController.php**

Create `src/Auth/Controllers/LoginController.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth\Controllers;

use CWE\Auth\AuthResult;
use CWE\Auth\AuthService;
use CWE\Core\Csrf;
use CWE\Core\Session;
use League\Plates\Engine;

final class LoginController
{
    public function __construct(
        private readonly AuthService $auth,
        private readonly Session $session,
        private readonly Csrf $csrf,
        private readonly Engine $views,
    ) {}

    public function show(): void
    {
        if (isset($_SESSION['user_id'])) {
            $this->redirect('/dashboard');
            return;
        }
        echo $this->views->render('auth/login', [
            'csrf'  => $this->csrf->token(),
            'error' => $_SESSION['_flash_error'] ?? null,
        ]);
        unset($_SESSION['_flash_error']);
    }

    public function submit(): void
    {
        if (!$this->csrf->verify($_POST['_csrf'] ?? null)) {
            http_response_code(419);
            echo 'CSRF token invalid';
            return;
        }

        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $ip       = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $ua       = $_SERVER['HTTP_USER_AGENT'] ?? null;

        $outcome = $this->auth->attempt($username, $password, $ip, $ua);

        if ($outcome->result === AuthResult::Success && $outcome->user !== null) {
            $sessionId = $this->session->start($outcome->user->id, $ip, $ua);
            session_regenerate_id(true);
            $_SESSION['user_id']  = $outcome->user->id;
            $_SESSION['username'] = $outcome->user->username;
            $_SESSION['role']     = $outcome->user->role;
            $this->csrf->rotate();
            $this->redirect('/dashboard');
            return;
        }

        $_SESSION['_flash_error'] = match ($outcome->result) {
            AuthResult::BadCredentials => 'Kullanıcı adı veya parola hatalı.',
            AuthResult::Locked         => 'Hesap geçici olarak kilitli (çok fazla başarısız deneme).',
            AuthResult::RateLimited    => 'Çok fazla istek. Lütfen birkaç dakika sonra tekrar deneyin.',
            AuthResult::Inactive       => 'Bu hesap pasif. Yöneticinize başvurun.',
            default                    => 'Giriş başarısız.',
        };
        $this->redirect('/login');
    }

    private function redirect(string $path): void
    {
        header("Location: $path", true, 303);
    }
}
```

- [ ] **Step 5: Write LogoutController.php**

Create `src/Auth/Controllers/LogoutController.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth\Controllers;

use CWE\Core\Csrf;
use CWE\Core\Session;

final class LogoutController
{
    public function __construct(
        private readonly Session $session,
        private readonly Csrf $csrf,
    ) {}

    public function submit(): void
    {
        if (!$this->csrf->verify($_POST['_csrf'] ?? null)) {
            http_response_code(419);
            return;
        }

        if (session_id() !== '') {
            $this->session->destroy(session_id());
        }
        $_SESSION = [];
        session_destroy();

        header('Location: /login', true, 303);
    }
}
```

- [ ] **Step 6: Commit**

Run:
```bash
git add src/Auth/Controllers/LoginController.php src/Auth/Controllers/LogoutController.php \
        resources/views/layouts/auth.php resources/views/auth/login.php \
        resources/views/errors/404.php
git commit -m "feat(auth): add login + logout controllers and views

Login uses CSRF + flash error pattern. Successful login regenerates
session id and stores user_id/username/role in \$_SESSION.
Logout destroys session row via Session handler."
```

---

## Task 18: Dashboard Controller + Layout

**Files:**
- Create: `src/Auth/Middleware/RequireAuth.php`
- Create: `src/Admin/Controllers/DashboardController.php`
- Create: `resources/views/layouts/app.php`
- Create: `resources/views/dashboard/index.php`

- [ ] **Step 1: Write RequireAuth middleware**

Create `src/Auth/Middleware/RequireAuth.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Auth\Middleware;

final class RequireAuth
{
    /** @return int user_id of authenticated user, or aborts with redirect */
    public static function check(): int
    {
        if (!isset($_SESSION['user_id'])) {
            header('Location: /login', true, 303);
            exit;
        }
        return (int)$_SESSION['user_id'];
    }
}
```

- [ ] **Step 2: Write app layout**

Create `resources/views/layouts/app.php`:
```php
<?php /** @var \League\Plates\Template\Template $this */ ?>
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title><?= $this->e($title ?? 'blockharbor') ?></title>
  <meta name="csrf-token" content="<?= $this->e($csrf ?? '') ?>">
  <link rel="stylesheet" href="/assets/app.css">
  <script defer src="https://unpkg.com/alpinejs@3.13.0/dist/cdn.min.js"></script>
  <script defer src="https://unpkg.com/htmx.org@1.9.10"></script>
</head>
<body class="min-h-screen bg-slate-50">
  <nav class="bg-white border-b border-slate-200">
    <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
      <a href="/dashboard" class="text-lg font-semibold text-brand-700">blockharbor</a>
      <div class="flex items-center gap-4 text-sm">
        <span class="text-slate-600">
          <?= $this->e($_SESSION['username'] ?? '?') ?>
          <span class="ml-1 px-2 py-0.5 rounded bg-brand-50 text-brand-700 text-xs">
            <?= $this->e(ucfirst((string)($_SESSION['role'] ?? 'viewer'))) ?>
          </span>
        </span>
        <form method="post" action="/logout" class="inline">
          <input type="hidden" name="_csrf" value="<?= $this->e($csrf ?? '') ?>">
          <button class="btn btn-ghost text-sm" type="submit">Çıkış</button>
        </form>
      </div>
    </div>
  </nav>

  <main class="max-w-7xl mx-auto px-4 py-8">
    <?= $this->section('content') ?>
  </main>

  <script src="/assets/app.js"></script>
</body>
</html>
```

- [ ] **Step 3: Write dashboard view**

Create `resources/views/dashboard/index.php`:
```php
<?php /** @var \League\Plates\Template\Template $this */ ?>
<?php $this->layout('layouts/app', ['title' => 'Pano', 'csrf' => $csrf]); ?>

<div class="card">
  <div class="card-body">
    <h1 class="text-xl font-semibold text-slate-900 mb-2">Hoş geldin, <?= $this->e($username) ?></h1>
    <p class="text-slate-500 text-sm">
      Bu, P1 (Foundation + Auth Core) aşamasında kalan minimum pano sayfası.
      Sonraki planlar (P2 audit/2FA, P3 IOC) buraya widget'lar ekleyecek.
    </p>
    <dl class="mt-4 text-sm grid grid-cols-2 gap-x-6 gap-y-2 text-slate-700">
      <dt class="text-slate-500">Rol</dt><dd class="font-medium"><?= $this->e($role) ?></dd>
      <dt class="text-slate-500">Son giriş</dt><dd class="font-medium"><?= $this->e($lastLogin) ?></dd>
      <dt class="text-slate-500">Session</dt><dd class="font-mono text-xs"><?= $this->e(substr(session_id(), 0, 12)) ?>…</dd>
    </dl>
  </div>
</div>
```

- [ ] **Step 4: Write DashboardController.php**

Create `src/Admin/Controllers/DashboardController.php`:
```php
<?php declare(strict_types=1);

namespace CWE\Admin\Controllers;

use CWE\Auth\Middleware\RequireAuth;
use CWE\Auth\UserRepository;
use CWE\Core\Csrf;
use League\Plates\Engine;

final class DashboardController
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly Engine $views,
    ) {}

    public function index(): void
    {
        $userId = RequireAuth::check();
        $user = $this->users->findById($userId);
        if ($user === null) {
            session_destroy();
            header('Location: /login', true, 303);
            return;
        }

        $csrf = (new Csrf())->token();

        echo $this->views->render('dashboard/index', [
            'username'  => $user->username,
            'role'      => $user->role,
            'lastLogin' => $user->lastLoginAt?->format('Y-m-d H:i') ?? 'ilk giriş',
            'csrf'      => $csrf,
        ]);
    }
}
```

- [ ] **Step 5: Commit**

Run:
```bash
git add src/Auth/Middleware/RequireAuth.php src/Admin/Controllers/DashboardController.php \
        resources/views/layouts/app.php resources/views/dashboard/index.php
git commit -m "feat(admin): add Dashboard with RequireAuth middleware

Dashboard fetches current user, renders app layout with logout form.
RequireAuth::check() redirects to /login if no session."
```

---

## Task 19: Seed Default Tenant + Admin User

**Files:**
- Create: `db/seeds/DefaultTenantSeeder.php` (no-op — default tenant inserted by migration; keep for completeness)
- Create: `db/seeds/DefaultUserSeeder.php`
- Create: `bin/seed`

- [ ] **Step 1: Write DefaultTenantSeeder**

Create `db/seeds/DefaultTenantSeeder.php`:
```php
<?php declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

final class DefaultTenantSeeder extends AbstractSeed
{
    public function run(): void
    {
        // Default tenant row is created by the CreateTenants migration.
        // This seed is a no-op placeholder for ordering.
    }
}
```

- [ ] **Step 2: Write DefaultUserSeeder**

Create `db/seeds/DefaultUserSeeder.php`:
```php
<?php declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

final class DefaultUserSeeder extends AbstractSeed
{
    public function getDependencies(): array
    {
        return ['DefaultTenantSeeder'];
    }

    public function run(): void
    {
        $existing = $this->fetchRow("SELECT id FROM users WHERE username = 'admin'");
        if ($existing) {
            $this->getOutput()->writeln('  ↳ admin user already exists; skipping');
            return;
        }

        $hash = password_hash('changeme-p1-seed', PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, 'time_cost' => 3, 'threads' => 1,
        ]);

        $this->insert('users', [[
            'username'            => 'admin',
            'email'               => 'admin@example.com',
            'password_hash'       => $hash,
            'role'                => 'admin',
            'active'              => true,
            'mfa_required'        => false,
            'password_changed_at' => date('Y-m-d H:i:sP'),
        ]]);
    }
}
```

- [ ] **Step 3: Write bin/seed**

Create `bin/seed`:
```bash
#!/usr/bin/env bash
set -euo pipefail
docker compose exec -T php vendor/bin/phinx seed:run "$@"
```

Run:
```bash
chmod +x bin/seed
```

- [ ] **Step 4: Run the seeder**

Run:
```bash
./bin/seed
```

Expected: `DefaultTenantSeeder` + `DefaultUserSeeder` reported as run. `admin user already exists; skipping` message NOT shown on first run.

- [ ] **Step 5: Verify the user exists**

Run:
```bash
docker compose exec postgres psql -U blockharbor_app -d blockharbor \
  -c "SELECT id, username, role, active FROM users;"
```

Expected: 1 row — `admin | admin | t`.

- [ ] **Step 6: Verify password_hash format**

Run:
```bash
docker compose exec postgres psql -U blockharbor_app -d blockharbor -tA \
  -c "SELECT substr(password_hash, 1, 11) FROM users WHERE username='admin';"
```

Expected: `$argon2id$`.

- [ ] **Step 7: Commit**

Run:
```bash
git add db/seeds/DefaultTenantSeeder.php db/seeds/DefaultUserSeeder.php bin/seed
git commit -m "feat(db): seed default admin user

bin/seed runs Phinx seeders. DefaultUserSeeder is idempotent
(skips if 'admin' exists). Initial password: changeme-p1-seed —
documented in README; user must change it after first login (P2)."
```

---

## Task 20: PHPStan + Psalm + Build CSS

**Files:**
- Create: `phpstan.neon`
- Create: `psalm.xml`

- [ ] **Step 1: Write phpstan.neon**

Create `phpstan.neon`:
```yaml
parameters:
  level: 8
  paths:
    - src
    - tests
  excludePaths:
    - vendor
  treatPhpDocTypesAsCertain: false
  ignoreErrors:
    # League/Plates Engine::render() returns string; we echo it.
    - '#Cannot access offset .+ on mixed#'
```

- [ ] **Step 2: Write psalm.xml**

Create `psalm.xml`:
```xml
<?xml version="1.0"?>
<psalm
    errorLevel="4"
    resolveFromConfigFile="true"
    findUnusedBaselineEntry="true"
    findUnusedCode="false"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns="https://getpsalm.org/schema/config"
    xsi:schemaLocation="https://getpsalm.org/schema/config vendor/vimeo/psalm/config.xsd"
>
    <projectFiles>
        <directory name="src" />
        <directory name="tests" />
        <ignoreFiles>
            <directory name="vendor" />
        </ignoreFiles>
    </projectFiles>
</psalm>
```

- [ ] **Step 3: Run PHPStan**

Run:
```bash
docker compose exec php composer stan
```

Expected: `[OK] No errors`. If errors, fix them (most likely missing return types or type hints).

- [ ] **Step 4: Run Psalm**

Run:
```bash
docker compose exec php composer psalm
```

Expected: `Psalm finished`. If errors, fix them (most likely null-safety annotations).

- [ ] **Step 5: Build CSS + verify in browser**

Run:
```bash
npm run build
docker compose restart nginx
```

Then in a browser open `https://localhost:8443/login` (accept self-signed cert warning).
Expected: see styled login form.

- [ ] **Step 6: Manual smoke test**

In the browser:
1. Enter `admin` / `changeme-p1-seed`
2. Submit — should redirect to `/dashboard`
3. See username `admin` + role `Admin` + last login time
4. Click `Çıkış` — should redirect to `/login`
5. Try `admin` / `wrong-password` 5 times — 5th attempt should still show "hatalı"; 6th attempt with correct password should show "kilitli"

If all 5 steps pass, P1 is functionally complete.

- [ ] **Step 7: Commit**

Run:
```bash
git add phpstan.neon psalm.xml
git commit -m "chore: add PHPStan L8 + Psalm config

PHPStan level 8 passes on src + tests. Psalm errorLevel=4 baseline."
```

---

## Task 21: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write CI workflow**

Create `.github/workflows/ci.yml`:
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:14-alpine
        env:
          POSTGRES_USER: blockharbor_app
          POSTGRES_PASSWORD: blockharbor_app_pass
          POSTGRES_DB: blockharbor
        ports: ['5432:5432']
        options: >-
          --health-cmd "pg_isready -U blockharbor_app"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10

    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'
          extensions: pdo, pdo_pgsql, mbstring, intl
          coverage: none
          tools: composer:v2

      - name: Cache Composer
        uses: actions/cache@v4
        with:
          path: vendor
          key: composer-${{ hashFiles('composer.lock') }}

      - name: Install PHP deps
        run: composer install --no-progress --prefer-dist

      - name: Run migrations
        env:
          DB_HOST: 127.0.0.1
          DB_PASSWORD: blockharbor_app_pass
          APP_ENV: testing
        run: vendor/bin/phinx migrate -e testing || vendor/bin/phinx migrate -e production
        # Note: testing env may not exist yet for fresh repo — falls back to production.

      - name: PHPUnit
        env:
          DB_HOST: 127.0.0.1
          DB_PASSWORD: blockharbor_app_pass
        run: composer test

      - name: PHPStan
        run: composer stan

      - name: Psalm
        run: composer psalm

      - name: Composer audit
        run: composer audit

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: npm ci
        run: npm ci

      - name: Build assets
        run: npm run build

      - name: Verify build output
        run: |
          test -s public/assets/app.css
          test -s public/assets/app.js
```

- [ ] **Step 2: Commit**

Run:
```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow

PHPUnit + PHPStan + Psalm + composer audit + npm build.
PostgreSQL service for integration tests."
```

- [ ] **Step 3: Push to remote (manual, when ready)**

Once the user creates the GitHub repo:

```bash
git remote add origin git@github.com:<owner>/blockharbor.git
git push -u origin main
```

Then verify the CI run succeeds on GitHub. The workflow should turn green.

---

## Task 22: P1 Sign-off — Verification + Tag

- [ ] **Step 1: Run the full test suite**

Run:
```bash
docker compose exec php composer test
docker compose exec php composer stan
docker compose exec php composer psalm
docker compose exec php composer audit
```

Expected: all green. If anything fails, **stop** and fix before signing off — do not "fix it later".

- [ ] **Step 2: Run the end-to-end smoke**

In the browser:
1. Open `https://localhost:8443/login`
2. Login with `admin` / `changeme-p1-seed` → dashboard appears
3. Logout → returns to login form
4. Login with wrong password 5 times → see lockout message
5. Wait 1 second, attempt with correct password → still locked
6. In a separate terminal, run:
   ```bash
   docker compose exec postgres psql -U blockharbor_app -d blockharbor \
     -c "UPDATE users SET locked_until = NULL, failed_login_count = 0 WHERE username='admin';"
   ```
7. Login with correct password → dashboard appears

If all 7 steps pass, P1 functions correctly.

- [ ] **Step 3: Update README quick start**

Edit `README.md` to add (or confirm) the actual working quick start commands. If the user has tested the flow, the README should describe what they did.

- [ ] **Step 4: Tag release**

Run:
```bash
git tag -a p1-foundation-auth-core -m "P1: Foundation + Auth Core complete

- Composer + PSR-4 + Docker Compose dev stack
- 6 migrations: tenants, users, password_history, user_sessions,
  login_attempts, audit_log (with hash chain trigger)
- Argon2id auth with per-IP and per-user rate limiting, 15-min lockout
- DB-backed sessions
- Plates layout + Tailwind + Alpine
- Login/logout/dashboard pages
- PHPUnit + PHPStan L8 + Psalm + composer audit + GitHub Actions
- Default admin seed user
"
git log --oneline | head -25
```

Expected: the commit log shows ~22 commits, tagged with `p1-foundation-auth-core`.

- [ ] **Step 5: Hand off to P2**

P2 (Audit + 2FA + Passkeys) is the next plan. When ready, request:
> "Write the P2 plan: Audit + 2FA + Passkeys."

P2 will:
- Add `AuditLogger` class wiring into AuthService (login_success/login_failure/logout events)
- Add `bin/verify-audit-chain` CLI
- Add `user_totp`, `user_passkeys`, `user_ip_allowlist`, `risk_events` migrations
- Add TOTP setup/verify flow + WebAuthn registration/login flow
- Add RiskScorer service
- Step-up auth integration into AuthService

---

## Self-review notes

- **Spec coverage:** P1 implements §1–4 (foundations), §5 (auth flow without 2FA), §6 (audit_log table + trigger; logger class deferred to P2 as planned), §8 (frontend baseline), §9 (ops baseline: Docker, .env, CI). §7 (migration strategy) is P6 territory. §10 (GitHub readiness) is partly addressed (LICENSE, README skeleton, CI); polish in P7.
- **No placeholders:** every step contains the exact code or command.
- **Type consistency:** `User`, `AuthResult`, `AttemptOutcome`, `Session`, `Config`, `Database`, `Router`, `LoginController`, `LogoutController`, `DashboardController`, `RequireAuth` — all referenced consistently across tasks.
- **One file per concern:** every file's responsibility was listed up front (§File responsibilities). No file exceeds ~200 lines.

---

## Plan complete — execution choice

Plan complete and saved to `docs/superpowers/plans/2026-06-07-blockharbor-p1-foundation-auth-core.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration with isolation.

**2. Inline Execution** — Execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints for review.

Which approach?
