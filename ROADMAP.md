# BlockHarbor Roadmap

This is a public-facing summary of the 7-phase implementation plan. Detailed
phase specs and plans live in `docs/superpowers/`.

## Phase 1 — Foundation + Auth Core (active)

Working PostgreSQL-backed auth panel — sufficient for login + dashboard.

- Composer + PSR-4 + Docker Compose stack
- 6 Phinx migrations (tenants, users, password_history, user_sessions,
  login_attempts, audit_log with hash chain trigger)
- Argon2id passwords, per-IP + per-user lockout, DB-backed sessions
- Login / logout / dashboard via Plates + Tailwind + Alpine.js
- GitHub Actions CI (PHPUnit + PHPStan L8 + Psalm + npm build)

## Phase 2 — Audit + 2FA + Passkeys

Universal audit hook + step-up authentication.

- `AuditLogger` integrated into every domain service constructor
- `bin/verify-audit-chain` CLI for periodic tamper detection
- TOTP 2FA (RFC 6238), WebAuthn / FIDO2 passkeys
- Rule-based RiskScorer (new IP, country, UA → step-up auth)
- New tables: `user_totp`, `user_passkeys`, `user_ip_allowlist`, `risk_events`

## Phase 3 — IOC Domain + Pending Workflow

Threat intelligence indicator management.

- `iocs` table unifying blacklist + whitelist + pending + manual lists
- `ioc_history`, `ioc_sightings`, `ioc_provenance` (chain of evidence)
- CRUD UI (HTMX-powered tables with pagination + search)
- `IocValidator` (IPv4/CIDR/domain/URL/MD5/SHA1/SHA256)
- `EnrichmentService` skeleton (VT, GreyNoise, Shodan, AbuseIPDB drivers)
- Bulk actions + approve/reject workflow

## Phase 4 — Feeds + CVE + Vendors

External feed integration + vulnerability intelligence.

- `feed_sources` CRUD + Fetchers: CSAF, RSS, TAXII, plain text
- `feed_runs` history + `feed_health` monitoring
- `cves` table normalized from NVD; CISA KEV sync
- `cve_actions` (dismissed / watching / mitigated / accepted)
- `vendors` + PSIRT feed integration
- Cron-scheduled fetchers (every 15min, daily KEV, daily warninglist sync)

## Phase 5 — Custom Lists + Notifications + Customers + REST API

Firewall feed generation + alerting + programmatic access.

- `custom_lists` with `ListBuilder` (firewall feed URL generation)
- `notification_channels` (SMTP, Slack, webhook) + dispatcher
- `customers` (multi-tenant prep) + `customer_assets`
- REST API v1 + `ApiAuthMiddleware` + per-key rate limiting
- OpenAPI 3 spec at `docs/api.md`
- API key management UI

## Phase 6 — JSON → DB Import + Cutover

Migrate the existing system without downtime.

- `bin/analyze-json-stores` — per-file row count, sample, predicted target
- `bin/import-from-json --source=<file> [--dry-run]` — per-source idempotent
- `bin/import-from-json --all --dry-run` — full preview
- `bin/diff-old-vs-new` — byte-level output comparison
- Staging vhost on port 8443; production cutover with 7-day rollback window

## Phase 7 — GitHub Readiness + Polish

Public open-source launch quality.

- Comprehensive docs: architecture, security, deployment, runbook, API
- Architecture Decision Records (ADRs)
- Demo seed (~1000 sample IOCs, 1 sample feed) for `docker compose up` demo
- Screenshots + GIF tour
- Apache + Docker deployment paths documented equally
- PHP 8.3-FPM upgrade option (side-by-side with existing 8.1)
- `bin/doctor.sh`, `bin/uninstall.sh`, `bin/update.sh`, `bin/backup.sh`,
  `bin/restore.sh`, `bin/verify-install.sh`

## Beyond P7 (ideas)

These are out of scope for v0.1 but documented for transparency:

- Kubernetes Helm chart
- Ansible playbook
- Multi-region replication
- WebAuthn-only login (passwordless default)
- SAML / OIDC SSO
- Mobile companion app
- AI/ML-based anomaly scoring (currently rule-based)

See `docs/superpowers/specs/` for in-depth design decisions per phase.
