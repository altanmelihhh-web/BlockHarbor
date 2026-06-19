# BlockHarbor

<img width="1415" height="608" alt="BlockHarbor login screen" src="https://github.com/user-attachments/assets/3ed8b6f6-e331-4744-8777-af8c4b0a05e3" />

Threat intelligence management panel — PostgreSQL-backed, Argon2id auth, hash-chained audit log, MIT licensed.

> **Latest release:** [`v0.1.1`](https://github.com/altanmelihhh-web/BlockHarbor/releases) — audit chain verifier + TOTP backend. MFA UI lands in `v0.1.2`. [CHANGELOG](CHANGELOG.md) · [ROADMAP](ROADMAP.md)

---

## Install

Pick **one** of two paths. Both end with you logged into the dashboard at `https://<host>:8443/login` as `admin` / `changeme-p1-seed`.

### Option A — Docker (2 commands, recommended for trying it out)

```bash
git clone https://github.com/altanmelihhh-web/BlockHarbor.git && cd BlockHarbor
bash bin/docker-up.sh
```

`bin/docker-up.sh` generates `.env` with random secrets, detects port conflicts and prompts for an alternate (default `HTTP_PORT=8090`), then builds the image (~5 min first time), starts the stack, runs migrations and the default admin seed. Open the printed URL: <http://localhost:8090/login>.

For unattended / CI: `bash bin/docker-up.sh --auto-port` skips prompts and picks the next free port.

The Compose stack is HTTP-only; production deploys terminate TLS at an upstream reverse proxy (apache / nginx / ALB). Manual step-by-step is in [`docker/README.md`](docker/README.md).

### Option B — Native (Ubuntu/Debian + Apache, recommended for production)

```bash
git clone https://github.com/altanmelihhh-web/BlockHarbor.git && cd BlockHarbor
sudo bash bin/install.sh
```

The interactive installer asks for hostname/port, DB credentials, optional SMTP + API keys, then handles everything:

- apt install missing packages (apache2, php8.1, postgresql-14, composer, node)
- Create DB + 2 roles (`blockharbor_app` runtime, `blockharbor_migrator` DDL)
- Generate `.env` with random `APP_KEY` + DB password (mode 0600)
- `composer install`, `npm install && npm run build`
- Apache vhost on chosen port with TLS + HSTS + CSP headers
- Optional hardening: fail2ban filter, logrotate, mod_security headers
- Cron registry: session cleanup, audit verify, backups
- Migrations + default admin

Idempotent — re-run safely. `--unattended` for non-interactive. `--dry-run` to preview.

---

## Operations

```bash
sudo bash bin/doctor.sh          # 12-check health report
sudo bash bin/backup.sh          # pg_dump → /var/backups/blockharbor/
sudo bash bin/restore.sh         # interactive backup picker
sudo bash bin/update.sh          # git pull + migrate + reload
sudo bash bin/uninstall.sh       # full removal (--keep-data optional)
./bin/verify-audit-chain         # tamper detection (cron-scheduled weekly)
```

---

## Architecture

PostgreSQL 14 + PHP 8.1 + Apache (or nginx via Docker) + Plates templates + Tailwind + Alpine. Domain-driven `src/`:

```
src/Auth/      — Argon2id login, lockout, MFA (TOTP backend in v0.1.1)
src/Audit/     — universal hash-chained audit logger + tamper detection
src/Core/      — bootstrap, PDO factory, router, sessions, CSRF, pgcrypto wrapper
src/Admin/     — dashboard + (future) admin panels
```

Detailed design in [`docs/superpowers/specs/`](docs/superpowers/specs/) and [`docs/superpowers/plans/`](docs/superpowers/plans/). Apache deployment guide: [`docs/deployment-apache.md`](docs/deployment-apache.md).

---

## Roadmap

| Release | Focus | Status |
|---|---|---|
| v0.1.0-p1 | Password auth + dashboard | ✅ shipped |
| **v0.1.1** | **Audit hardening + TOTP backend** | **✅ current** |
| v0.1.2 | MFA UI (`/2fa` + `/2fa/setup` + WebAuthn) | next |
| v0.2.x | IOC domain (threat indicator CRUD) | planned |
| v0.3.x | Feed fetchers (CSAF, USOM, KEV) | planned |

Full plan in [ROADMAP.md](ROADMAP.md).

---

## Contributing & Security

- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, commit style
- [SECURITY.md](SECURITY.md) — responsible disclosure
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

MIT — see [LICENSE](LICENSE).
