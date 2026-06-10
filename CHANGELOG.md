# Changelog

All notable changes to BlockHarbor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
