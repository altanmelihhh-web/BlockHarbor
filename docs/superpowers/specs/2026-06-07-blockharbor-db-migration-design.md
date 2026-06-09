# BlockHarbor — PostgreSQL Migration & Modern Rewrite

**Date:** 2026-06-07
**Status:** Approved design — ready for implementation planning
**Author:** Claude + altanmelihhh
**Source codebase:** `/var/www/blacklist/cyberwebeyeos/` (analysed via graphify — 407 nodes, 623 edges, 36 communities)
**Target repository:** `blockharbor` (will be published as MIT-licensed open source on GitHub)

---

## 1. Vision & Problem Statement

### 1.1 Vision

Build **`blockharbor`** — a corporate-grade, PostgreSQL-backed threat intelligence management panel. Modern PHP, advanced authentication, hash-chained audit log. Single-tenant by default, prepared for multi-tenant. Published as open source under MIT license.

### 1.2 The triggering bug

User created a user via the web UI, saw "✅ Kullanıcı eklendi" success message, but the user did not appear in the list. Root cause:

| Check | Finding |
|---|---|
| `users.json` ownership | `root:root` mode 644 — www-data has no write permission |
| Apache runtime user | `www-data` |
| `users.json` last modified | 2026-05-21 (untouched for weeks) |
| `audit.log` entries for `user_create` | 2 entries logged today — audit.log IS writable by www-data |
| `users.php:34-37` `save_users()` | Calls `file_put_contents()` without checking return value |
| `users.php:65-72` user-add path | Sets `$msg = '✅ ...'` unconditionally after the silent-failed write |

The bug is a symptom of deeper architectural problems with the JSON-file storage model.

### 1.3 Structural problems in the current system

- **Silent write failures** in 16 JSON-file stores (no return-value checks anywhere — pattern `file_put_contents(F, json_encode($d))`)
- **Race conditions** — no locking; concurrent writes lose data
- **Secrets in code** — `auth_config.php` contains username, password hash, API keys; committed to `.git`
- **Append-only log is a regular file** — `audit.log` can be deleted/edited despite hash chain
- **Monolithic admin file** — `cyberwebeyeosblacklistadmin.php` is 5682 lines, 311 KB
- **No schema versioning** — JSON files evolve ad-hoc, no migration mechanism
- **Coupled secrets** — VirusTotal, GreyNoise, ipgeolocation API keys mixed with auth config
- **No multi-tenant model** despite `customer_assets.json` having a schema for it
- **No rate limiting**, no account lockout, no 2FA, no risk-based access control

### 1.4 Success criteria

1. User creation succeeds atomically with verified persistence — no silent failures
2. All 16 JSON stores and `.txt` feed files normalized into 29 PostgreSQL tables across 6 domains
3. Argon2id passwords, TOTP 2FA, WebAuthn/Passkey support, risk-based step-up auth
4. Hash-chained audit log preserved (existing chain reconstructed from `audit.log`) and enforced as append-only at DB level
5. Existing firewall feed URLs continue to produce identical output (zero firewall reconfiguration)
6. Cutover with rollback path; original system kept intact for 7 days post-cutover
7. Repository structure is GitHub-presentable: `docker compose up` reaches a working demo
8. CI green: PHPUnit, PHPStan level 8, Psalm, composer audit, npm build

---

## 2. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | PHP 8.1+ | Continuity with existing knowledge; modern features (readonly, enum, fibers) |
| Database | PostgreSQL 14 | Already installed; JSONB, RLS, pgcrypto, transactional DDL |
| Access layer | PDO + Repository pattern | Framework-free, testable, transparent SQL |
| Migrations | Phinx | Composer, reversible, env-aware |
| Templating | Plates | Pure-PHP, Composer-installable, no Twig compiler |
| CSS | Tailwind CSS v3 | Close to existing UI, JIT build, no runtime |
| JS | Alpine.js v3 + HTMX (selective) | Minimum JS, server-friendly; HTMX for table refresh/pagination/search |
| Secrets | vlucas/phpdotenv | Standard `.env` pattern |
| Logging | Monolog | PSR-3, multiple handlers, log rotation |
| 2FA | spomky-labs/otphp + web-auth/webauthn-lib | OWASP-grade implementations |
| Tests | PHPUnit 10 (+ Pest optional) | Standard PHP test stack |
| Container | Docker Compose | Identical dev/prod runtime |
| CI | GitHub Actions | PHPUnit + PHPStan L8 + Psalm + composer-audit + npm build |
| Web server | Apache 2.4 (Nginx alternative) | Matches existing infrastructure |

### 2.1 Composer dependencies (minimum set)

```json
{
  "require": {
    "php": "^8.1",
    "league/plates": "^3.5",
    "vlucas/phpdotenv": "^5.6",
    "monolog/monolog": "^3.5",
    "spomky-labs/otphp": "^11.2",
    "web-auth/webauthn-lib": "^4.7",
    "ramsey/uuid": "^4.7",
    "robmorgan/phinx": "^0.16"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.5",
    "phpstan/phpstan": "^1.10",
    "vimeo/psalm": "^5.20",
    "fakerphp/faker": "^1.23"
  }
}
```

---

## 3. Repository Layout

```text
blockharbor/
├── public/                          # Apache DocumentRoot
│   ├── index.php                    # Front controller
│   ├── assets/                      # Build output (Tailwind, JS)
│   └── .htaccess
├── src/                             # PSR-4: CWE\
│   ├── Core/                        # Bootstrap, DI, Router, Request/Response
│   │   ├── Application.php
│   │   ├── Database.php             # PDO factory + connection management
│   │   ├── Config.php               # .env loader
│   │   ├── Router.php
│   │   ├── Csrf.php
│   │   └── Session.php              # DB-backed session handler
│   ├── Auth/                        # Identity & access
│   │   ├── UserRepository.php
│   │   ├── AuthService.php
│   │   ├── PasswordPolicy.php
│   │   ├── PasswordHasher.php       # Argon2id wrapper
│   │   ├── TotpService.php
│   │   ├── WebAuthnService.php
│   │   ├── RiskScorer.php
│   │   ├── LoginAttemptRepository.php
│   │   ├── ApiKeyRepository.php
│   │   └── Controllers/
│   ├── Audit/                       # Hash-chained append-only audit
│   │   ├── AuditLogger.php          # universal injection target
│   │   ├── AuditRepository.php
│   │   └── ChainVerifier.php
│   ├── Blacklist/                   # IOC domain (IP/CIDR/domain/URL/hash)
│   │   ├── IocRepository.php
│   │   ├── IocService.php
│   │   ├── IocValidator.php
│   │   ├── EnrichmentService.php    # VT, GreyNoise, Shodan, AbuseIPDB
│   │   ├── PendingWorkflow.php
│   │   ├── FalsePositiveService.php
│   │   ├── SightingService.php
│   │   └── Controllers/
│   ├── Feeds/                       # External sources (CSAF, USOM, TAXII, RSS)
│   │   ├── SourceRepository.php
│   │   ├── FeedFetcher.php
│   │   ├── FeedHealthService.php
│   │   ├── Fetchers/
│   │   │   ├── CsafFetcher.php
│   │   │   ├── TaxiiFetcher.php
│   │   │   ├── RssFetcher.php
│   │   │   └── PlainTextFetcher.php
│   │   └── Controllers/
│   ├── Cve/                         # Vulnerability domain
│   │   ├── CveRepository.php
│   │   ├── CveService.php
│   │   ├── KevSyncService.php
│   │   ├── CveActionRepository.php
│   │   └── Controllers/
│   ├── Vendors/                     # Vendor watchlist + PSIRT
│   │   ├── VendorRepository.php
│   │   └── Controllers/
│   ├── Lists/                       # Custom firewall feed lists
│   │   ├── CustomListRepository.php
│   │   ├── ListBuilder.php          # generates feed text from filter_rules
│   │   └── Controllers/
│   ├── Notifications/
│   │   ├── ChannelRepository.php
│   │   ├── NotificationDispatcher.php
│   │   └── Senders/
│   │       ├── SmtpSender.php
│   │       ├── SlackSender.php
│   │       └── WebhookSender.php
│   ├── Customers/                   # customer_assets domain
│   │   ├── CustomerRepository.php
│   │   └── Controllers/
│   ├── Admin/                       # Dashboard, settings, system
│   │   ├── DashboardService.php
│   │   ├── SettingsRepository.php
│   │   └── Controllers/
│   └── Api/                         # REST v1
│       ├── ApiAuthMiddleware.php
│       ├── RateLimiter.php
│       └── Controllers/
├── resources/
│   ├── views/
│   │   ├── layouts/
│   │   │   ├── app.php
│   │   │   └── auth.php
│   │   ├── auth/{login,2fa-totp,2fa-passkey,change-password,recovery}.php
│   │   ├── blacklist/{index,form,_row,detail}.php
│   │   ├── feeds/
│   │   ├── cve/
│   │   ├── audit/timeline.php
│   │   ├── dashboard/
│   │   └── components/{tabs,modal,toast,confirm,pagination}.php
│   ├── css/app.css                  # Tailwind directives
│   └── js/app.js                    # Alpine + HTMX init
├── db/
│   ├── migrations/                  # Phinx, timestamp-prefixed
│   │   ├── 20260607_120000_tenants.php
│   │   ├── 20260607_120100_users.php
│   │   ├── 20260607_120200_audit_log.php
│   │   ├── 20260607_120300_iocs.php
│   │   └── ... (30 migrations total — see §5)
│   ├── seeds/
│   │   ├── DefaultTenantSeeder.php
│   │   └── DemoDataSeeder.php       # for docker compose demo
│   ├── functions/                   # raw SQL: triggers, RLS policies
│   │   ├── audit_chain_trigger.sql
│   │   └── tenant_rls_policies.sql
│   └── import/                      # one-time JSON → DB migration scripts
│       ├── ImportUsers.php
│       ├── ImportAuditLog.php
│       ├── ImportIocs.php
│       └── ImportAll.php
├── config/
│   ├── app.php
│   ├── database.php
│   ├── auth.php
│   ├── feeds.php
│   └── notifications.php
├── bin/
│   ├── migrate                      # phinx wrapper
│   ├── import-from-json             # ./bin/import-from-json --source=users.json [--dry-run]
│   ├── verify-audit-chain
│   ├── diff-old-vs-new               # compare JSON output vs DB output
│   ├── rotate-api-keys
│   └── rollback-cutover
├── tests/
│   ├── Unit/
│   │   ├── Auth/
│   │   ├── Audit/
│   │   ├── Blacklist/
│   │   └── ...
│   └── Integration/
│       ├── AuthFlowTest.php
│       ├── IocCrudTest.php
│       └── AuditChainTest.php
├── docs/
│   ├── architecture.md              # condensed version of this spec
│   ├── security.md                  # threat model, audit chain, encryption
│   ├── deployment.md                # docker, bare metal, k8s
│   ├── migration-runbook.md         # JSON → DB step-by-step
│   ├── api.md                       # REST API reference + OpenAPI
│   └── adr/                         # Architecture Decision Records
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── docker-compose.prod.yml
│   ├── nginx.conf
│   └── php-fpm.conf
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   └── codeql.yml
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── .env.example                     # all required env vars documented
├── .gitignore                       # .env, vendor/, node_modules/, public/assets/
├── composer.json
├── phinx.php
├── package.json
├── tailwind.config.js
├── postcss.config.js
├── phpunit.xml
├── phpstan.neon
├── psalm.xml
├── Makefile                         # convenience: make up, make test, make build
├── LICENSE                          # MIT
├── README.md                        # hero, screenshots, quick start
├── CONTRIBUTING.md
├── SECURITY.md                      # disclosure email, supported versions
└── CODE_OF_CONDUCT.md
```

**Cardinal rule:** no secret enters git. `.env.example` is checked in with placeholder values; actual `.env` is in `.gitignore`, mode 0600, owned by `www-data`.

---

## 4. Database Schema

PostgreSQL 14. 29 tables in 6 domains. Single-tenant default; structure prepared for multi-tenant.

### 4.1 Design principles

| Decision | Rationale |
|---|---|
| Every table has `tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'` | Zero-migration path to multi-tenant. RLS enabled later. |
| `jsonb metadata` column on every domain table | Extensibility without migration. GIN-indexed. |
| `timestamptz` for all timestamps | UTC; no timezone bugs. |
| `inet`/`cidr` for IP fields | PG-native, indexable, native CIDR matching. |
| Sensitive fields stored as `bytea` + pgcrypto AES | TOTP secrets, WebAuthn keys, recovery codes encrypted at rest. |
| API keys stored as `sha256(key)` + 8-char prefix | Real key shown once at creation only. |
| Audit log enforced **append-only** | `BEFORE INSERT` chain trigger + `REVOKE UPDATE, DELETE` from app role. |
| Migration tool: **Phinx** | Composer-based, reversible, env-aware. |
| Foreign key defaults: `RESTRICT` | Prevents accidental cascading deletes. |

### 4.2 Legacy → New mapping

| Existing source | New table(s) |
|---|---|
| `users.json` | `users` |
| `audit.log` (hash chain) | `audit_log` (chain continues in DB) |
| `auth_config.php` → `api_keys` array | `api_keys` |
| `blacklist.txt` + `whitelist.txt` + `pending_ips.json` + all feed `.txt` files (firehol, spamhaus, ci-badguys, ...) | `iocs` (unified, discriminated by `list` and `source` columns) |
| `sources_config.json` | `feed_sources` |
| `feed_health_state.json` | `feed_health` + `feed_runs` (history) |
| `cve_state.json` (2.8 MB) | `cves` (normalized) + `cve_actions` |
| `cve_action_dismiss.json` | `cve_actions` |
| `lists.json` | `custom_lists` + optional `custom_list_items` cache |
| `vendor_watchlist.json` + `vendor_psirt.json` | `vendors` |
| `notifications.json` | `notification_channels` + `notifications_sent` |
| `customer_assets.json` | `customers` |
| `enrichment_cache/` directory + `greynoise_quota.json` | `enrichment_cache` + `api_quotas` |
| `fp_state.json` | `fp_reports` |
| `sighting_state.json` | `ioc_sightings` |
| `blacklist_meta.json` + ad-hoc settings | `system_settings` (key-value JSONB) |

### 4.3 Tables by domain

#### 4.3.1 Identity & Access (10 tables)

```sql
tenants               (id uuid PK, name varchar(255), active bool, created_at timestamptz)

users                 (id bigserial PK, tenant_id uuid,
                       username varchar(64) UNIQUE NOT NULL,
                       email varchar(254),
                       password_hash text,                   -- Argon2id; NULL if passkey-only
                       role enum('admin','operator','viewer') NOT NULL DEFAULT 'viewer',
                       active bool NOT NULL DEFAULT true,
                       failed_login_count int NOT NULL DEFAULT 0,
                       locked_until timestamptz,
                       last_login_at timestamptz,
                       password_changed_at timestamptz,
                       mfa_required bool NOT NULL DEFAULT false,
                       metadata jsonb DEFAULT '{}',
                       created_at timestamptz NOT NULL DEFAULT now())

password_history      (id bigserial PK, user_id bigint FK,
                       password_hash text, created_at timestamptz)
                      -- keeps last 5; older rows pruned by trigger

user_sessions         (id uuid PK, user_id bigint FK,
                       ip_address inet, user_agent text,
                       fingerprint bytea,                    -- sha256(user_agent + accept_language)
                       created_at timestamptz, expires_at timestamptz,
                       last_activity_at timestamptz, revoked_at timestamptz)
                      -- DB-backed PHP session handler

user_totp             (id bigserial PK, user_id bigint FK,
                       secret_encrypted bytea,               -- pgp_sym_encrypt
                       recovery_codes_encrypted bytea,
                       verified_at timestamptz, created_at timestamptz)

user_passkeys         (id bigserial PK, user_id bigint FK,
                       credential_id bytea UNIQUE,
                       public_key bytea, sign_count bigint,
                       transports text[], aaguid uuid,
                       label varchar(64),
                       last_used_at timestamptz, created_at timestamptz)

user_ip_allowlist     (id bigserial PK, user_id bigint FK,
                       cidr inet, label varchar(64), created_at timestamptz)

login_attempts        (id bigserial PK, username varchar(64),
                       ip_address inet, success bool,
                       failure_reason varchar(64),
                       geo_country char(2), user_agent text,
                       created_at timestamptz NOT NULL DEFAULT now())
                      -- INDEX (ip_address, created_at DESC), (username, created_at DESC)
                      -- partitioned by month for retention

risk_events           (id bigserial PK, user_id bigint FK,
                       session_id uuid FK, event_type varchar(64),
                       score smallint, details jsonb,
                       created_at timestamptz)

api_keys              (id bigserial PK, tenant_id uuid,
                       key_hash bytea UNIQUE,                -- sha256(raw_key)
                       prefix varchar(8),                    -- first 8 chars for display
                       role enum('admin','operator','viewer'),
                       owner varchar(255),
                       expires_at timestamptz, revoked_at timestamptz,
                       last_used_at timestamptz,
                       rate_limit_per_min int DEFAULT 60,
                       created_at timestamptz)
```

#### 4.3.2 Audit (1 table — append-only)

```sql
audit_log             (id bigserial PK,
                       ts timestamptz NOT NULL DEFAULT now(),
                       actor_username varchar(64),
                       actor_role varchar(16),
                       ip_address inet,
                       action varchar(64) NOT NULL,          -- 'user_create','ip_add','login_success',...
                       details jsonb DEFAULT '{}',
                       prev_hash bytea,                      -- previous row's entry_hash
                       entry_hash bytea NOT NULL)            -- sha256(prev_hash || canonical_json)
                      -- INDEX (ts), (actor_username, ts), (action, ts)
                      -- BRIN index on ts for append-only scaling
                      -- BEFORE INSERT trigger: compute prev_hash, entry_hash automatically
                      -- REVOKE UPDATE, DELETE ON audit_log FROM blockharbor_app;
```

**The cardinal property of `audit_log`:** the application role has no permission to mutate or remove rows. Only `postgres` superuser can do schema-level ops. The hash chain trigger is set-once.

```sql
-- functions/audit_chain_trigger.sql
CREATE OR REPLACE FUNCTION audit_chain_trigger() RETURNS trigger AS $$
DECLARE
  last_hash bytea;
BEGIN
  SELECT entry_hash INTO last_hash
  FROM audit_log
  ORDER BY id DESC LIMIT 1;

  NEW.prev_hash := COALESCE(last_hash, '\x00'::bytea);
  NEW.entry_hash := digest(
    NEW.prev_hash || convert_to(
      jsonb_build_object(
        'ts', NEW.ts,
        'actor', NEW.actor_username,
        'action', NEW.action,
        'details', NEW.details
      )::text, 'UTF8'),
    'sha256'
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_chain BEFORE INSERT ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_chain_trigger();
```

#### 4.3.3 IOC (Threat Intelligence — 4 tables)

```sql
iocs                  (id bigserial PK, tenant_id uuid,
                       value text NOT NULL,
                       value_normalized text NOT NULL,        -- lower(trim(value))
                       type enum('ip','cidr','domain','url','md5','sha1','sha256'),
                       list enum('blacklist','whitelist','pending','manual'),
                       source varchar(128) NOT NULL,          -- 'manual','spamhaus_drop','usom',...
                       confidence smallint,                    -- 0-100
                       severity enum('info','low','medium','high','critical'),
                       first_seen_at timestamptz NOT NULL DEFAULT now(),
                       last_seen_at timestamptz NOT NULL DEFAULT now(),
                       expires_at timestamptz,
                       approved bool DEFAULT false,
                       approved_by bigint FK users,
                       approved_at timestamptz,
                       added_by varchar(128),
                       comment text,
                       enrichment jsonb DEFAULT '{}',          -- VT, GreyNoise, Shodan results
                       tags text[],
                       metadata jsonb DEFAULT '{}',
                       UNIQUE (tenant_id, type, value_normalized, list))
                      -- INDEX (type, list), (source), (expires_at)
                      -- INDEX value_normalized text_pattern_ops (prefix search)
                      -- INDEX value_normalized gin_trgm_ops (substring search via pg_trgm)

ioc_sightings         (id bigserial PK, ioc_id bigint FK,
                       sighted_at timestamptz, sighting_source varchar(128),
                       count int DEFAULT 1,
                       metadata jsonb DEFAULT '{}')

ioc_history           (id bigserial PK, ioc_id bigint FK,
                       action enum('added','removed','approved','rejected','enriched','expired'),
                       actor varchar(128), ts timestamptz NOT NULL DEFAULT now(),
                       details jsonb)
                      -- append-only change history

ioc_provenance        (id bigserial PK, ioc_id bigint FK,
                       source varchar(128), source_url text,
                       fetched_at timestamptz,
                       raw_record jsonb)
                      -- chain of evidence
```

#### 4.3.4 Feeds (3 tables)

```sql
feed_sources          (id bigserial PK, tenant_id uuid,
                       name varchar(128), kind enum('blacklist','whitelist','csaf','rss','taxii','custom'),
                       url text, format enum('plain','json','xml','stix'),
                       schedule_cron varchar(64),
                       enabled bool DEFAULT true,
                       last_fetched_at timestamptz, last_status varchar(32),
                       last_error text, last_count int,
                       retention_days int DEFAULT 30,
                       settings jsonb DEFAULT '{}',
                       created_at timestamptz)

feed_runs             (id bigserial PK, feed_source_id bigint FK,
                       started_at timestamptz, finished_at timestamptz,
                       status enum('success','partial','failure'),
                       items_fetched int, items_added int,
                       items_updated int, items_removed int,
                       error_message text, duration_ms int)

feed_health           (feed_source_id bigint PK FK,
                       last_success_at timestamptz,
                       consecutive_failures int DEFAULT 0,
                       health_status enum('green','yellow','red') DEFAULT 'green',
                       updated_at timestamptz)
```

#### 4.3.5 Custom Lists, Vendors, CVE (4 tables)

```sql
custom_lists          (id bigserial PK, tenant_id uuid,
                       slug varchar(64),
                       name varchar(128), description text,
                       list_type enum('merged','ip','domain','url','ioc'),
                       public_url_token varchar(64),          -- the firewall feed URL token
                       format enum('plain','json'),
                       filter_rules jsonb,                     -- dynamic query
                       last_generated_at timestamptz,
                       item_count int DEFAULT 0,
                       settings jsonb,
                       created_at timestamptz,
                       UNIQUE (tenant_id, slug))

vendors               (id bigserial PK, tenant_id uuid,
                       name varchar(128),
                       psirt_feed_url text, watchlist bool DEFAULT false,
                       enabled bool DEFAULT true,
                       settings jsonb,
                       UNIQUE (tenant_id, name))

cves                  (cve_id varchar(32) PK,
                       description text,
                       cvss_v3_score numeric(3,1), cvss_v3_vector varchar(64),
                       severity enum('none','low','medium','high','critical'),
                       published_at timestamptz, modified_at timestamptz,
                       vendor_id bigint FK vendors,
                       affected_products jsonb, "references" jsonb,
                       exploits_known bool DEFAULT false,      -- CISA KEV flag
                       raw_record jsonb,                       -- full record for future
                       fetched_at timestamptz)
                      -- GIN (raw_record jsonb_path_ops)
                      -- INDEX (severity, published_at DESC), (vendor_id), (exploits_known)

cve_actions           (id bigserial PK, cve_id varchar(32) FK,
                       tenant_id uuid,
                       action enum('dismissed','watching','mitigated','accepted_risk'),
                       actor varchar(128), comment text,
                       ts timestamptz NOT NULL DEFAULT now())
```

#### 4.3.6 Operations (7 tables)

```sql
notification_channels (id bigserial PK, tenant_id uuid,
                       kind enum('email','slack','webhook','smtp'),
                       config jsonb,                           -- SMTP host/port/user/pass-enc, slack webhook, ...
                       enabled bool DEFAULT true,
                       created_at timestamptz)

notifications_sent    (id bigserial PK, channel_id bigint FK,
                       event_type varchar(64),
                       recipient text, status enum('sent','failed','queued'),
                       sent_at timestamptz, error text)

customers             (id bigserial PK, tenant_id uuid,
                       name varchar(255),
                       ip_ranges cidr[], vendor_hint varchar(128),
                       enabled bool DEFAULT true,
                       metadata jsonb DEFAULT '{}')

enrichment_cache      (id bigserial PK,
                       ioc_value text,
                       provider enum('vt','greynoise','shodan','abuseipdb'),
                       result jsonb,
                       fetched_at timestamptz, expires_at timestamptz,
                       UNIQUE (ioc_value, provider))

api_quotas            (provider varchar(32) PK,
                       used_today int DEFAULT 0, daily_limit int,
                       reset_at timestamptz,
                       monthly_used int DEFAULT 0)

fp_reports            (id bigserial PK,
                       ioc_value text, reported_by varchar(128),
                       ip_address inet, reason text,
                       status enum('open','reviewed','accepted','rejected') DEFAULT 'open',
                       created_at timestamptz, reviewed_at timestamptz)

system_settings       (key varchar(64) PK,
                       value jsonb,
                       updated_at timestamptz, updated_by varchar(128))
```

### 4.4 Performance & security indices

- `iocs.value_normalized` — `text_pattern_ops` index for prefix search; GIN trigram (`pg_trgm`) for substring
- `audit_log.ts` — BRIN index (efficient for append-only)
- `cves.raw_record` — GIN (`jsonb_path_ops`) for flexible JSON queries
- `login_attempts (ip_address, created_at DESC)` — rate limit lookups
- Required extensions: `CREATE EXTENSION pgcrypto;`, `CREATE EXTENSION pg_trgm;`, `CREATE EXTENSION citext;` (optional, case-insensitive usernames)

### 4.5 Row-Level Security (off initially, ready to enable)

```sql
-- Single migration to flip multi-tenant on:
ALTER TABLE iocs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON iocs
  USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- repeat for every domain table
```

Application sets the current tenant per connection: `SET LOCAL app.current_tenant = '...'`.

---

## 5. Authentication Architecture

### 5.1 Login flow

```text
┌──────────────┐
│  Login form  │  username + password
└──────┬───────┘
       ▼
┌───────────────────────────────────────────────────┐
│  AuthService::attempt(username, password, ip, ua) │
│  1) login_attempts INSERT — rate limit check       │
│     ip last 5min > 10 fail → 429                   │
│     user last 1h > 5 fail → lockout for 15m        │
│  2) users SELECT WHERE username = ?                │
│  3) password_verify(Argon2id)                      │
│     fail → failed_login_count++                    │
│            >=5 → locked_until = now() + 15min      │
│  4) password_changed_at + policy check             │
│     if >90 days → force-change flag                │
│  5) RiskScorer::evaluate(user, ip, ua)             │
│     new IP/country/UA → score 0-100                │
└──────┬─────────────────────────────────────────────┘
       ▼
┌───────────────────────────────────────────────────┐
│  MFA required?                                     │
│  - users.mfa_required = true             OR        │
│  - users.role = 'admin'                   OR        │
│  - risk_score > 60                                 │
└──┬─────────────────────┬───────────────────────────┘
   │ no                  │ yes
   ▼                     ▼
┌─────────┐    ┌──────────────────────┐
│ Session │    │ 2FA choice:           │
│ created │    │ - Passkey (if any)    │
│         │    │ - TOTP                │
└─────────┘    │ - Recovery code       │
               └──────────┬───────────┘
                          ▼
                   On success → Session
```

### 5.2 Session management

- PHP session handler is **DB-backed** (`user_sessions` table) — ready for horizontal scaling
- Session fingerprint = `sha256(user_agent || accept_language)` — change forces re-auth
- Inactivity timeout: 30 min; absolute timeout: 8 hours
- Logout → set `revoked_at = now()`
- "Sign out all sessions" feature — admins can use it on any user

### 5.3 Password policy (configurable, defaults)

- Minimum 12 characters, at least one each: uppercase, lowercase, digit, special
- `password_history`: last 5 entries — reuse blocked
- Force change after 90 days (configurable)
- Optional: HaveIBeenPwned k-anonymity check via API

### 5.4 WebAuthn / Passkey flow

Standard FIDO2 protocol via `web-auth/webauthn-lib`:
- **Registration:** `WebAuthnService::createRegistrationOptions()` → browser navigator.credentials.create() → `verifyRegistration()` → INSERT into `user_passkeys`
- **Login:** `createAssertionOptions()` → browser navigator.credentials.get() → `verifyAssertion()` → session created
- Resident keys allowed; passwordless login when passkey is the sole credential

### 5.5 Risk scoring (rule-based, no ML)

| Signal | Score |
|---|---|
| New IP (never seen in `login_attempts` for this user) | +30 |
| Different country (MaxMind GeoLite2 free) | +40 |
| Different user-agent family | +20 |
| Atypical hour (outside ±3h of user's last 30-login average) | +10 |

Total > 60 → step-up authentication (2FA required even if normally optional).

---

## 6. Audit Log + Hash Chain

The existing `audit.log` file uses `sha256(prev_hash || canonical_entry)` per line. This pattern is preserved and moved into PostgreSQL.

### 6.1 Append-only enforcement

```sql
REVOKE UPDATE, DELETE ON audit_log FROM blockharbor_app;
-- Only postgres superuser can DROP/TRUNCATE — outside the app's permission scope.
```

The `BEFORE INSERT` trigger (§4.3.2) computes `prev_hash` and `entry_hash` automatically. The application cannot supply either field; the chain is set by the database.

### 6.2 Chain verification CLI

```bash
php bin/verify-audit-chain --since "2026-01-01"
```

Walks all rows in order, recomputes `sha256(prev_hash || canonical_json)`, compares against stored `entry_hash`. A single mismatch triggers a tamper alert (exit code != 0; suitable for cron monitoring).

### 6.3 Migration of existing `audit.log`

The import script parses each existing line (format: `hash|json`), reconstructs the chain in PostgreSQL by setting `id = previous_max + offset` with the chain trigger DISABLED for the import session, then verifies: the last DB row's `entry_hash` must equal the last log line's hash.

After import, the trigger is re-enabled. New entries continue from the imported tail.

### 6.4 Universal logging hook (graphify finding)

Graphify analysis identified `audit_log_event()` as the highest-betweenness node — it currently connects 6 communities (Cron, Auth&Audit, GreyNoise, REST API, Feed Health, Notification). In the new architecture, **`Audit\AuditLogger`** is the universal injection target. Every domain service constructor receives it:

```php
public function __construct(
    private IocRepository $iocs,
    private AuditLogger $audit,
) {}
```

This preserves the existing logging discipline while making it explicit and testable.

---

## 7. Migration Strategy: Parallel Build + Cutover

**Approved approach:** new system built in a separate directory (`/var/www/blockharbor/`); old system at `/var/www/blacklist/cyberwebeyeos/` is untouched until cutover.

### 7.1 The 9-step flow

```text
1. Repo + skeleton          → blockharbor/ directory, composer init, PSR-4, .env.example,
                              git init, MIT LICENSE, README skeleton, CI workflow
2. Schema migration         → Phinx migration files for all ~30 tables
                              `phinx migrate -e dev` → empty schema verified
3. JSON inventory analysis  → `bin/analyze-json-stores` — per-file row count, sample,
                              predicted target table, identified anomalies
4. Import scripts           → `bin/import-from-json --source=users.json [--dry-run]`
                              one per legacy source; each idempotent + dry-run capable
5. Import dry-run           → `bin/import-from-json --all --dry-run`
                              Per-file row counts to be written, error list, no DB writes
6. New UI build             → Auth screens → IOC management → Feed management
                              → Dashboard → Audit viewer → Settings
                              PHPUnit tests per domain
7. Comparison test          → `bin/diff-old-vs-new` — byte-by-byte:
                              old `cyberwebeyeosblacklist.txt` vs new generated output
                              old audit.log tail hash vs new audit_log tail entry_hash
                              firewall feed URL — old content vs new content must match
8. Staging port             → Apache vhost: new system on :8443 (old stays on :443)
                              Smoke tests + UAT + browser verification
9. Cutover                  → apachectl configtest && systemctl reload apache2
                              New system takes :443; old preserved as blockharbor-old/ for 7 days
                              Rollback: single vhost change + reload
```

### 7.2 Dry-run report example

```text
$ bin/import-from-json --all --dry-run

[users.json]          1 user → users (1 INSERT, 0 skip)
[audit.log]           847 entries → audit_log (chain reconstruction OK, 0 corrupt)
[blacklist.txt]       12 IPs → iocs (list=blacklist, source=manual)
[firehol_level1]      8,432 CIDRs → iocs (list=blacklist, source=firehol)
[spamhaus_drop]       1,247 → iocs (list=blacklist, source=spamhaus_drop)
[cve_state.json]      14,829 CVEs → cves (raw_record preserved)
[lists.json]          5 lists → custom_lists
[sources_config.json] 18 sources → feed_sources
[customer_assets.json] 0 customers (empty)
[notifications.json]  1 channel → notification_channels
[vendor_watchlist.json] 4 vendors → vendors
[vendor_psirt.json]   12 entries → vendors (merged)
[enrichment_cache/]   2,340 cached results → enrichment_cache
[greynoise_quota.json] 1 row → api_quotas
[fp_state.json]       2 reports → fp_reports
[sighting_state.json] 1 entry → ioc_sightings
[blacklist_meta.json] 0 (empty)
...

TOTAL: 47,328 rows to insert.
DRY-RUN OK. Re-run without --dry-run to commit.
```

### 7.3 Rollback procedure

```bash
# bin/rollback-cutover
sed -i 's|blockharbor/public|blacklist/cyberwebeyeos|' /etc/apache2/sites-enabled/cwe.conf
apachectl configtest && systemctl reload apache2
echo "Rollback complete — old system back in service"
```

The old system directory is preserved untouched for 7 days post-cutover. Original DB is unmodified (PostgreSQL was empty; we only added new schema).

---

## 8. Frontend Architecture

### 8.1 Technology mix

- **Server-side PHP rendering** via Plates templates — no SPA, no Node runtime in production
- **Tailwind CSS v3** for styling — JIT build, purged for production
- **Alpine.js v3** for UI interactions (tabs, dropdowns, modals, toasts)
- **HTMX** selectively, only for: table refresh, pagination, search, inline status updates
- Standard form submissions use Post-Redirect-Get pattern (no HTMX overhead)

### 8.2 Component rules

| Behavior | Tool |
|---|---|
| Tab switching, dropdown, modal, toast | Alpine.js |
| Table refresh, search, pagination, inline status | HTMX |
| Form submit | POST + 303 redirect (no HTMX) |
| CSRF | Every form: `<?= csrf_field() ?>` helper, session-bound token |

### 8.3 Security headers

- `Content-Security-Policy`: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'`
  - `'unsafe-inline'` needed by Alpine.js — minimum scope
- `Strict-Transport-Security`: `max-age=31536000; includeSubDomains; preload`
- `X-Content-Type-Options`: `nosniff`
- `X-Frame-Options`: `DENY`
- `Referrer-Policy`: `strict-origin-when-cross-origin`
- `Permissions-Policy`: minimum opt-ins

### 8.4 Build pipeline

- `npm run build` → `public/assets/app.[hash].css` (Tailwind purged) + `public/assets/app.[hash].js` (Alpine + HTMX bundled)
- `npm run dev` → Tailwind watch + livereload (only in dev container)
- Production: file hashes for cache busting; `public/assets/manifest.json` maps logical → physical names

---

## 9. Operational Concerns

| Concern | Decision |
|---|---|
| **Secrets** | `.env` (`vlucas/phpdotenv`); `.env.example` checked in; actual `.env` in `.gitignore`, mode **0600**, owned by `www-data`. DB password, API keys, TOTP master key — all in env. |
| **DB connection** | `pgsql:host=...;dbname=...;sslmode=require` — TLS even on localhost (configure `pg_hba.conf`). |
| **Backup** | `pg_dump --format=custom` daily at 03:00 cron, output to `/var/backups/blockharbor/`, **30-day** retention, GPG-encrypted, `pg_restore` runbook in `docs/deployment.md`. |
| **Logging** | Monolog → `/var/log/blockharbor/app.log` (daily rotate, 30 days); errors → separate stream + optional Sentry hook; PG `log_min_duration_statement = 100ms`. |
| **Monitoring** | Phase 1: cron alert on `feed_health` table (email/slack via existing channels). Post-launch: optional Prometheus PHP exporter. |
| **Container** | `docker-compose.yml`: `postgres:14-alpine` + `php:8.1-fpm-alpine` + `nginx:alpine`. Dev: `make up`. |
| **CI/CD** | GitHub Actions: `composer install` → `phpunit` → `phpstan analyse -l 8` → `psalm` → `composer audit` → `npm run build` → artifact. Branch protection: main merge requires all green. |
| **Tests** | `tests/Unit/` (PHPUnit), `tests/Integration/` (ephemeral PG container, DBUnit pattern). Target: critical paths ≥80% coverage. |
| **TLS** | Let's Encrypt; HSTS 1 year; TLS 1.2+ only. |
| **Rate limiting** | Login: 10 fails per IP per 5 min → 429. API: per-key `rate_limit_per_min` (default 60). Uses `login_attempts` table — no Redis needed. |
| **Retention** | `audit_log`: 1 year (then archive). `login_attempts`: 90 days. `notifications_sent`: 30 days. Cron cleanup job. |
| **Encryption at rest** | TOTP secrets, recovery codes, API keys, SMTP passwords → `pgp_sym_encrypt` (master key in `.env`). Full-disk encryption assumed at the OS level. |
| **Locale** | UI Turkish (preserves existing UX); code, comments, README, docs in English; error messages bilingual via i18n helper (`__('msg.invalid_credentials')`). |

---

## 10. GitHub-ready Project Files

```text
LICENSE                  MIT
README.md                EN: hero, screenshots, quick start (`docker compose up`)
CONTRIBUTING.md          branch model, Conventional Commits, dev setup
SECURITY.md              responsible disclosure email, supported versions
CODE_OF_CONDUCT.md       Contributor Covenant 2.1
docs/
├── architecture.md      condensed version of this spec
├── security.md          threat model, hash chain, encryption strategy
├── deployment.md        docker, bare-metal, k8s
├── migration-runbook.md step-by-step JSON → DB
├── api.md               REST reference + OpenAPI 3 spec
└── adr/                 Architecture Decision Records
.github/
├── workflows/{ci.yml, codeql.yml}
├── ISSUE_TEMPLATE/{bug.md, feature.md}
└── PULL_REQUEST_TEMPLATE.md
```

### 10.1 Demo mode

`docker compose up` + `make seed` brings up a clean instance with:
- 1 admin user (credentials documented in README)
- ~1000 sample IOCs (anonymized public feed samples)
- 1 sample feed source (e.g., FireHOL Level 1 cached)
- 1 sample CVE entry
- Audit log seeded with the initial events

The intent: a contributor or evaluator can be at a working UI in under 2 minutes.

---

## 11. Out of Scope (explicit YAGNI)

The following are explicitly NOT part of this design and should not be implemented in the first version:

- **Mobile app or React Native client.** Server-side rendering is sufficient; HTMX gives SPA feel.
- **Real-time push (WebSockets).** Cron + page refresh covers it; complexity not justified.
- **ML-based risk scoring.** Rule-based scorer is deterministic, auditable, sufficient.
- **Multi-region replication.** Single PG instance + pg_dump backup; multi-region is a future ADR.
- **SAML/OIDC SSO.** Local auth + WebAuthn covers small teams; SSO is a v2 feature.
- **Tenant onboarding UI.** Multi-tenant infrastructure ready, but UI for adding tenants is post-v1.
- **Custom report builder.** Existing dashboard + audit timeline are sufficient.
- **Workflow engine for IOC approvals.** Simple approve/reject covers current need.

These can be added later via documented ADRs without rework, because the foundation supports them.

---

## 12. Open Items for Implementation Planning

The following are decisions deferred to the implementation phase (writing-plans) rather than design:

1. **Wave parallelization order** of the 30 Phinx migrations — likely identity first, then audit, then IOC, then feeds, then ops
2. **Exact import sequencing** — order of `bin/import-from-json` invocations to satisfy FK dependencies
3. **Cutover scheduling** — calendar slot for the maintenance window (off-hours)
4. **Apache vhost configuration** — exact `cwe.conf` content (vs Nginx alternative)
5. **Tailwind theme tokens** — exact color palette pulled from existing UI for visual continuity
6. **OpenAPI 3 spec authoring** — to be generated alongside controllers in Api/ domain

These will be addressed in the writing-plans output.

---

## Appendix A: Graphify Evidence

A knowledge graph of the existing codebase was generated as input to this design:

- **407 nodes, 623 edges, 36 communities**
- Token cost: 421,655 input tokens (~$1.30)
- Output: `/var/www/blacklist/cyberwebeyeos/graphify-out/{graph.html,graph.json,GRAPH_REPORT.md}`

Key findings used in this design:

| Graph finding | Used in spec |
|---|---|
| `audit_log_event()` connects 6 communities (highest betweenness centrality) | §6.4 — `AuditLogger` as universal injection target |
| `audit_log.php` has 14 edges (most connected) | §4.3.2 — audit is a first-class domain |
| `blacklist_admin_auth.php` has 12 edges | §5 — auth is the second hub; centralized in `src/Auth/` |
| `pending_ips.json` bridges Auth&Audit and Admin Entry Points | §4.3.3 — pending workflow modeled as `iocs.list='pending'` not a separate table |
| 5 sprint-design rationale docs cluster together (C6) | Confirmed the design rules (R26 RBAC, R28 10-field IoC schema, etc.) are well-bounded for migration |
| `cyberwebeyeosblacklistadmin.php` (5682 lines) clusters with 10+ display helpers | §3 — admin UI split into per-domain controllers in `src/{Auth,Blacklist,Feeds,Cve,Vendors,Lists,Notifications,Admin}/Controllers/` |
| `audit_log_event()` has 9 INFERRED edges (model-reasoned, unverified) | Flagged for verification during implementation; informs which integration tests to write (audit hooks in every subsystem) |

---

## Appendix B: Existing Code → New Module Mapping

| Existing file | New location |
|---|---|
| `users.php` (CRUD) | `src/Auth/UserRepository.php` + `src/Auth/Controllers/UserController.php` |
| `login.php`, `logout.php` | `src/Auth/Controllers/LoginController.php` |
| `blacklist_admin_auth.php` | `src/Auth/AuthService.php` + middleware |
| `auth_config.php` | `.env` + `config/auth.php` |
| `audit_log.php` | `src/Audit/AuditLogger.php` + `AuditRepository.php` |
| `verify_audit.php` | `bin/verify-audit-chain` |
| `api.php` (REST v1) | `src/Api/Controllers/*` + `ApiAuthMiddleware` |
| `add-ip.php`, `delete.php`, `edit.php`, `bulk_action.php` | `src/Blacklist/Controllers/IocController.php` |
| `approve_ip.php`, `move_to_pending.php`, `pending_ips_helper.php` | `src/Blacklist/PendingWorkflow.php` |
| `enrichment.php`, `greynoise.php`, `shodan_exposure.php` | `src/Blacklist/EnrichmentService.php` + per-provider classes |
| `ioc_helpers.php`, `ioc_history.php`, `ioc_pivot.php`, `ioc_provenance.php` | `src/Blacklist/IocService.php`, `IocRepository.php`, history/provenance methods |
| `sources_manager.php` | `src/Feeds/SourceRepository.php` + Controllers |
| `csaf_fetcher.php`, `taxii.php`, `threatfox.php`, `psirt_rss_fetcher.php` | `src/Feeds/Fetchers/*` |
| `feed_health.php` | `src/Feeds/FeedHealthService.php` |
| `cve_fetch.php`, `cve_action.php`, `cve_dismiss.php` | `src/Cve/*` |
| `lists.php` | `src/Lists/CustomListRepository.php` + Controllers |
| `lib_firewall_feed.php`, `cyberwebeyeosblacklist.php` | `src/Lists/ListBuilder.php` |
| `vendor_watchlist_save.php` | `src/Vendors/VendorRepository.php` + Controllers |
| `notify.php`, `smtp_client.php` | `src/Notifications/*` |
| `fp_report.php` | `src/Blacklist/FalsePositiveService.php` |
| `sighting.php` | `src/Blacklist/SightingService.php` |
| `dashboard_stats.php` | `src/Admin/DashboardService.php` |
| `cron_expire_check.php`, `warninglist_sync.php`, `bigtech_whitelist_sync.php` | `bin/cron-expire`, `bin/sync-warninglists`, `bin/sync-bigtech-whitelist` (scheduled by system cron) |
| `cyberwebeyeosblacklistadmin.php` (5682 lines) | Split across Controllers + Plates views, no file > 500 lines |
| `migrate_blacklist_schema.php`, `migrate_lists_sprint7.php` | Subsumed by Phinx; the legacy migrators are no longer needed after import |
| `whitelist.php`, `whitelist-readonly.php` | `src/Blacklist/Controllers/WhitelistController.php` (same domain, `list='whitelist'`) |

---

## Approval

This design was developed via brainstorming dialog on 2026-06-07. The full chain of decisions:

1. **Scope:** All 16 JSON stores → PostgreSQL (full migration)
2. **Auth level:** Advanced — Argon2id + lockout + policy + TOTP 2FA + WebAuthn/Passkey + risk scoring
3. **Tenancy:** Single-tenant with `tenant_id` columns for future multi-tenant
4. **Code structure:** Modern PHP — Composer + PSR-4 + src/public separation + lightly domain-modular `src/`
5. **Migration:** Parallel build at `/var/www/blockharbor/` + cutover + dry-run + rollback script
6. **Frontend:** Server-side PHP + Plates + Tailwind + Alpine.js + HTMX (selective)
7. **License:** MIT
8. **UI/Docs:** Turkish UI + English code/docs

**User approval:** "onaylıyorum" (2026-06-07).

Next step: invoke `superpowers:writing-plans` skill to produce implementation plan.
