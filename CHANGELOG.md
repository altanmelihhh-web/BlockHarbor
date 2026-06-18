# Changelog

All notable changes to BlockHarbor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-06-18

P2 backend infrastructure (audit hardening + TOTP groundwork). MFA UI is
intentionally not yet routed; the backend ships dormant until `v0.1.2`
delivers the `/2fa` flow.

### Added
- `bin/verify-audit-chain` CLI (text / `--json` / `--quiet` modes) for cron-
  monitored tamper detection. Already registered weekly by `bin/install.sh`.
- `BlockHarbor\Audit\AuditLogger` — universal hook injected into auth
  services
- `BlockHarbor\Audit\ChainVerifier` — PG-delegated recompute of the SHA-256
  chain; returns first mismatch (id + reason)
- `BlockHarbor\Core\Crypto` — pgcrypto `pgp_sym_encrypt` wrapper for at-rest
  encryption of TOTP secrets, recovery codes, future API keys
- `BlockHarbor\Auth\TotpService` — RFC 6238 (spomky-labs/otphp), with QR
  provisioning URI + 10-code recovery generator
- `BlockHarbor\Auth\UserTotpRepository` — enroll / verify / consume recovery
  codes (bcrypt-hashed at rest) / mark-verified
- `BlockHarbor\Auth\{MfaState, MfaResolver}` — decides which factor is
  enrolled (TOTP / Passkey / Either / None); policy gate distinct from
  enrollment state
- `AuthResult::RequiresMfa` outcome; `AuthService` gates Success behind
  factor check. `LoginController` redirects to `/2fa` on RequiresMfa
- Migrations: `user_totp` (with secret + recovery codes encrypted, partial
  index on verified rows)
- New Composer deps: `spomky-labs/otphp ^11.2`, `bacon/bacon-qr-code ^3.0`,
  `web-auth/webauthn-lib ^4.7`, `geoip2/geoip2 ^3.0` (with 15 transitive)

### Container
- `ghcr.io/altanmelihhh-web/blockharbor:v0.1.1` — published via GitHub
  Actions `docker.yml` on tag push (PHP 8.1-FPM Alpine + composer + npm
  build baked in)

### Status of MFA flow
- Backend complete: services, repositories, migration, AuthService gate
- UI NOT yet wired: `/2fa` GET/POST + `/2fa/setup` controllers land in
  v0.1.2. Until then, no user can self-enroll TOTP via UI, so the
  RequiresMfa outcome cannot fire in practice for fresh installs

## [0.1.0-setup] — 2026-06-09 → [0.1.0-p1] — 2026-06-11

(See git tags for full set-up + P1 deliverables.)

## [Unreleased — pre-v0.1.0]

### Added
- Comprehensive interactive installer (`bin/install.sh`) with pre-flight checks,
  dry-run mode, install transcript, and per-step state JSON
- Apache vhost template (`docker/apache/blockharbor.conf.template`) as the
  canonical first-class deployment artifact
- Server hardening config (`etc/apache2/conf-available/blockharbor-hardening.conf`)
- fail2ban filter + jail templates (`etc/fail2ban/`)
- logrotate config (`etc/logrotate.d/blockharbor`)
- Comprehensive `.env.example` with all P1-P7 configuration keys (DB, SMTP,
  enrichment API keys, notification channels, retention, backup paths)
- Database role separation: `blockharbor_app` (DML runtime) + `blockharbor_migrator` (DDL)
- Cron job registry covering P1-P7 services (installer registers active jobs)
- GitHub repo polish: SECURITY.md, CODE_OF_CONDUCT.md, ROADMAP.md, CHANGELOG.md,
  `.editorconfig`, `.gitattributes`, dependabot, issue/PR templates

### Documentation
- P1 design spec (`docs/superpowers/specs/2026-06-07-blockharbor-db-migration-design.md`)
- P1 implementation plan (`docs/superpowers/plans/2026-06-07-blockharbor-p1-foundation-auth-core.md`)
- P1 execution notes for host-mode deployment

## [0.1.0-p1] — TBD (after P1 Task 22 sign-off)

### Added
- Foundation: Composer + PSR-4 + Docker Compose stack
- 6 PostgreSQL migrations: tenants, users, password_history, user_sessions,
  login_attempts, audit_log (with hash chain trigger)
- Argon2id password hashing
- DB-backed sessions (`SessionHandlerInterface`)
- Per-IP and per-user rate limiting with 15-min account lockout
- Login / logout / dashboard pages (Plates templates, Tailwind, Alpine.js)
- Default admin seeder
- PHPUnit, PHPStan level 8, Psalm clean
- GitHub Actions CI

[Unreleased]: https://github.com/altanmelihhh-web/BlockHarbor/compare/p1-foundation-auth-core...HEAD
[0.1.0-p1]: https://github.com/altanmelihhh-web/BlockHarbor/releases/tag/p1-foundation-auth-core
