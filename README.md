# BlockHarbor

<img width="1415" height="608" alt="image" src="https://github.com/user-attachments/assets/3ed8b6f6-e331-4744-8777-af8c4b0a05e3" />


Threat intelligence management panel — PostgreSQL-backed, Argon2id auth, hash-chained audit log, MIT licensed.

> **Status:** P1 (Foundation + Auth Core) in development. See implementation plans in `docs/superpowers/plans/`.

## 🚀 One-command install (Ubuntu/Debian)

```bash
git clone https://github.com/altanmelihhh-web/BlockHarbor.git
cd BlockHarbor
sudo bash bin/install.sh
```

That's it. The interactive installer asks for hostname, port, DB credentials,
SMTP, and optional API keys (VirusTotal, GreyNoise, Shodan, AbuseIPDB, MaxMind,
ipgeolocation, Slack webhook). It then:

- ✅ Installs missing system packages (apache2, php8.1, postgresql-14, composer, node)
- ✅ Creates DB (`blockharbor`) + 2 roles (`blockharbor_app` runtime, `blockharbor_migrator` DDL)
- ✅ Generates `.env` with secure random `APP_KEY` + DB password (mode 0600, owner www-data)
- ✅ Runs `composer install` + `npm install` + `npm run build`
- ✅ Configures Apache vhost on chosen port (default 8443) with TLS, HSTS, CSP
- ✅ Applies security hardening (mod_security headers, fail2ban filter+jail, logrotate)
- ✅ Registers cron jobs (session/login cleanup, audit verify, feed fetch, CVE sync, backups)
- ✅ Runs migrations + seeds default admin user
- ✅ Prints access URL + admin credentials at the end

Re-run safely — every step is idempotent.

### Other install modes

```bash
sudo bash bin/install.sh --unattended                # use defaults; non-interactive
sudo bash bin/install.sh --dry-run --unattended      # preview without writing
sudo bash bin/install.sh --config /path/to/values.env # source variables from file
sudo bash bin/install.sh --skip-packages             # skip apt; assume installed
sudo bash bin/install.sh --skip-crons                # skip cron registration
```

### Day-2 operations

```bash
sudo bash bin/doctor.sh         # 12-check health report
sudo bash bin/backup.sh         # pg_dump → /var/backups/blockharbor/
sudo bash bin/restore.sh <file> # interactive picker or named file
sudo bash bin/update.sh         # git pull + composer + npm + migrate + reload
sudo bash bin/verify-install.sh # smoke test endpoints + security headers
sudo bash bin/uninstall.sh      # full removal (or --keep-data)
```

## Alternative install paths

### Docker Compose (for evaluators / GitHub portability)

```bash
docker compose up -d
docker compose exec php composer install
docker compose exec php vendor/bin/phinx migrate
docker compose exec php vendor/bin/phinx seed:run
# Browse: https://localhost:8443/login
```

### Manual (for advanced users — see [docs/deployment-apache.md](docs/deployment-apache.md))

```bash
cp .env.example .env
# Edit .env: DB_PASSWORD, APP_KEY (openssl rand -hex 32), etc.
composer install
npm install && npm run build
vendor/bin/phinx migrate && vendor/bin/phinx seed:run
sudo a2ensite blockharbor && sudo systemctl reload apache2
```

## Architecture

See `docs/architecture.md` (added in P7) and the design spec at
`docs/superpowers/specs/2026-06-07-blockharbor-db-migration-design.md`.

## License

MIT — see `LICENSE`.
