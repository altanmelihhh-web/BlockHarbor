# Deploying BlockHarbor on Apache (recommended for self-hosted)

Apache + mod_php (or PHP-FPM) is the **first-class deployment path** for
BlockHarbor — it's what production deployments use. Docker Compose is the
parallel alternative for developer onboarding and GitHub portability.

## TL;DR

```bash
git clone https://github.com/altanmelihhh-web/BlockHarbor.git
cd BlockHarbor
sudo bash bin/install.sh           # interactive prompts (whiptail UI)
# Browser → https://<host>:8443/login (creds shown at install end)
```

## Requirements

- Ubuntu 22.04 LTS or Debian 12+
- Apache 2.4 with mod_php8.1 OR PHP 8.1+ FPM
- PostgreSQL 14+
- Composer 2
- Node 20+, npm
- 1 GB free disk, 1 GB RAM minimum (4 GB recommended for production)
- Root access (sudo) on the server

## What the installer does

1. **Pre-flight** — disk/RAM/network/PG/Apache checks
2. **System packages** — `apt install` anything missing
3. **PostgreSQL** — creates `blockharbor` DB + 2 roles (`blockharbor_app`
   runtime, `blockharbor_migrator` DDL) with least-privilege grants
4. **Install directory** — `/var/www/blockharbor/` (configurable)
5. **`.env`** — generates secure random `APP_KEY` + DB password; mode 600,
   owner `www-data`
6. **Composer + npm** — installs deps + builds Tailwind/Alpine assets
7. **Log + backup dirs** — `/var/log/blockharbor/`, `/var/backups/blockharbor/`
8. **Apache vhost** — port 8443 (configurable), TLS (self-signed default or
   Let's Encrypt), security headers (HSTS, X-Frame-Options, CSP)
9. **Migrations + seed** — Phinx schema + default admin user
10. **Cron jobs** — `/etc/cron.d/blockharbor` with placeholders for P1-P7 services

## Apache vhost template

Template at `docker/apache/blockharbor.conf.template`. The installer renders
it with substitutions and writes to `/etc/apache2/sites-available/blockharbor.conf`.

Key settings:
- Port 8443 (avoids conflict with port 443 if running other sites)
- TLS 1.2+ only, HIGH ciphers, HSTS preload
- `<DirectoryMatch>` denies web access to `.git`, `.env`, `vendor/`, `node_modules/`, `tests/`, `db/migrations/`
- `/health` + `/metrics` restricted to localhost + private RFC1918

## Server-wide hardening

Optional opt-in config at `etc/apache2/conf-available/blockharbor-hardening.conf`:
```bash
sudo cp etc/apache2/conf-available/blockharbor-hardening.conf /etc/apache2/conf-available/
sudo a2enconf blockharbor-hardening
sudo systemctl reload apache2
```

Disables: TRACE method, Apache version disclosure, default ServerSignature.

## fail2ban (recommended)

```bash
sudo cp etc/fail2ban/filter.d/blockharbor.conf /etc/fail2ban/filter.d/
sudo cp etc/fail2ban/jail.d/blockharbor.conf  /etc/fail2ban/jail.d/
sudo systemctl reload fail2ban
sudo fail2ban-client status blockharbor
```

5 failed logins from one IP within 10 minutes → 1-hour ban.

## logrotate

```bash
sudo cp etc/logrotate.d/blockharbor /etc/logrotate.d/
sudo logrotate -d /etc/logrotate.d/blockharbor   # dry-run
```

## TLS / Let's Encrypt

The installer's `--unattended` path uses Ubuntu's self-signed snakeoil cert.
For production with a public domain, choose Let's Encrypt during interactive
install OR run:

```bash
sudo certbot --apache -d blockharbor.your-domain.com
```

certbot will auto-edit the vhost. To prevent the next `bin/install.sh` from
overwriting the changes, set `APP_URL=https://blockharbor.your-domain.com` in
`.env` and re-run installer with `--skip-vhost` (planned for Bundle 2).

## Upgrading

```bash
cd /var/www/blockharbor
sudo bash bin/update.sh   # Bundle 2 — git pull + composer + npm build + migrate + reload
```

## Uninstalling

```bash
sudo bash bin/uninstall.sh           # full removal
sudo bash bin/uninstall.sh --keep-data   # remove vhost + source, keep DB + backups
```

## Troubleshooting

| Symptom | Check |
|---|---|
| 502 Bad Gateway | `journalctl -u apache2` and `tail -f /var/log/apache2/blockharbor-error.log` |
| 500 Internal Server Error | `tail -f /var/log/blockharbor/app.log` |
| Can't login | `bin/doctor.sh` (Bundle 2) — checks DB + migrations + .env |
| Cert warning | Expected with snakeoil cert; install Let's Encrypt cert |
| Cron not running | `sudo systemctl status cron && sudo grep blockharbor /var/log/syslog` |
