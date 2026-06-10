# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ (active development — P1)   |
| < 0.1   | ❌                              |

This project is in early development (P1). Production deployment is not yet
recommended without a security review.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Email: `altanmelihhh@gmail.com` with subject `[BlockHarbor SECURITY]`

You can expect:
- Acknowledgement within **72 hours**
- Initial assessment within **7 days**
- Coordinated disclosure timeline negotiated case-by-case

If the issue is critical (RCE, auth bypass, audit-chain tamper) we aim to
ship a patched release within **30 days** of the report.

## Scope

In scope for BlockHarbor:
- Authentication / session / RBAC bypass
- SQL injection, XSS, CSRF
- Audit-log tampering or chain-breaking attacks
- Privilege escalation between roles
- Denial of service via the public API

Out of scope:
- Vulnerabilities in upstream dependencies (please report to their vendors;
  we'll happily mirror the report)
- Social engineering, physical access, supply-chain on dev machines
- Self-XSS (requires the victim to paste attacker-controlled code)

## Hardening Recommendations

The repo ships defaults that pass a basic audit:
- Argon2id passwords (OWASP 2021+ recommendation)
- DB-backed sessions with strict cookies
- Per-IP and per-account rate limiting / lockout
- Hash-chained append-only audit log enforced at DB level
- TLS 1.2+ only, HSTS preload, X-Frame-Options DENY
- fail2ban filter shipped (opt-in via installer)

See `docs/deployment-apache.md` and `docs/observability.md` for additional
hardening (logrotate, mod_security baseline, AppArmor profile).
