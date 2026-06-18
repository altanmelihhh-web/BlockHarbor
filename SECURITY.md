# Security Policy

## Supported Versions

| Version    | Status                              |
|------------|-------------------------------------|
| `0.1.x`    | ✅ Supported (current — `v0.1.1`)   |
| `< 0.1.0`  | ❌ Pre-release; not supported       |

BlockHarbor is pre-1.0. The MFA UI lands in `v0.1.2`; until then `v0.1.1` provides password authentication, hash-chained audit, and the TOTP backend. Production deployments are reasonable for the password-auth + audit scope; expect that **major versions may introduce breaking schema changes**, with documented migration paths.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

**Channels (in order of preference):**

1. **GitHub Security Advisory** — [Open a draft advisory](https://github.com/altanmelihhh-web/BlockHarbor/security/advisories/new) (private to maintainers; preferred — credit and CVE tracking are automatic).
2. **Email** — `altanmelihhh@gmail.com` with subject `[BlockHarbor SECURITY]`. Encrypt with PGP if the issue is critical (key forthcoming; ask for the fingerprint).

**Response timeline:**

| Stage                | Target          |
|----------------------|-----------------|
| Acknowledgement      | within 72 hours |
| Initial assessment   | within 7 days   |
| Patch for critical   | within 30 days  |
| Coordinated disclosure | case-by-case |

## Scope

**In scope:**

- Authentication / session / RBAC bypass (Argon2id verify, lockout, session fingerprint)
- SQL injection, XSS, CSRF on any form or controller in `src/`
- Audit-log tampering or hash-chain breaking attacks (the `verify-audit-chain` CLI must catch any in-band mutation)
- Privilege escalation between roles (`viewer` → `operator` → `admin`)
- Denial of service via the REST API (when it lands in `v0.2.x`)
- Container escape from the published Docker image
- Insecure defaults in `bin/install.sh` or shipped configs (`etc/`)

**Out of scope:**

- Vulnerabilities in upstream dependencies — please report to their vendors. We'll happily mirror via Dependabot or our own changelog once a fix is available.
- Social engineering, physical access, dev-machine supply-chain attacks.
- Self-XSS (requires victim to paste attacker-controlled JS into devtools).
- Issues that require an already-compromised PostgreSQL superuser.
- Missing security headers that don't expose real risk (e.g. `Expect-CT`).

## Hardening Defaults (already shipped)

The repo ships secure defaults — these passed an initial review at `v0.1.1`:

- **Passwords:** Argon2id (OWASP 2021+ recommendation), 64 MiB / 3 iterations / 1 thread
- **Sessions:** DB-backed via `SessionHandlerInterface`; cookies `Secure + HttpOnly + SameSite=Strict`
- **Rate limit + lockout:** per-IP (10 fail / 5 min → 429) + per-account (5 fail / 1 h → 15 min lockout)
- **Audit log:** hash-chained `sha256(prev || canonical_jsonb)`, PG trigger-enforced; tampering surfaced by `bin/verify-audit-chain`
- **TLS:** vhost template restricts to TLS 1.2+; HSTS `max-age=31536000`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`
- **At-rest encryption:** TOTP secrets + recovery codes via `pgcrypto` `pgp_sym_encrypt`
- **fail2ban filter+jail:** `etc/fail2ban/` templates (opt-in via installer)
- **DB roles:** `blockharbor_app` (DML runtime) separated from `blockharbor_migrator` (DDL only used by Phinx)

See [`docs/deployment-apache.md`](docs/deployment-apache.md) for the recommended production hardening checklist (logrotate, mod_security baseline, AppArmor profile).

## Credit

We're happy to credit reporters in the release notes unless they request anonymity. CVE coordination via GitHub Security Advisories.
