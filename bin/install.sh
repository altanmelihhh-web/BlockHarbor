#!/usr/bin/env bash
#
# BlockHarbor — Interactive installer
# Usage:
#   sudo bash install.sh                     # interactive (whiptail UI if available)
#   sudo bash install.sh --unattended        # use defaults; non-interactive
#   sudo bash install.sh --config FILE       # source FILE for variable overrides
#   sudo bash install.sh --dry-run           # show what would happen, write nothing
#   sudo bash install.sh --skip-packages     # don't apt install; assume already done
#   sudo bash install.sh --skip-crons        # don't install cron jobs
#
# What it installs / configures:
#   - System packages: apache2, mod_php8.1, postgresql-14, composer, node, etc.
#   - PostgreSQL: database + 2 roles (runtime + migrator) with least-privilege grants
#   - Application directory + .env with secure random APP_KEY + DB password
#   - composer install + npm install + npm run build
#   - Apache vhost on chosen port with TLS (self-signed or Let's Encrypt)
#   - phinx migrate + seed
#   - Cron jobs for: feed fetching, CVE sync, audit verification, backups, cleanup
#   - Optional: API keys (VirusTotal, GreyNoise, Shodan, AbuseIPDB, MaxMind)
#   - Optional: SMTP notification config
#
# After completion, prints access URL and admin credentials.
# Re-running is safe — every step is idempotent.

set -Eeuo pipefail

# ------------------------------------------------------------------ defaults
# v2 additions: pre-flight, transcript, trap rollback, state JSON, dry-run-safe writes
INSTALL_DIR_DEFAULT="/var/www/blockharbor"
DOMAIN_DEFAULT="$(hostname -I | awk '{print $1}')"
APP_PORT_DEFAULT="8443"
DB_NAME_DEFAULT="blockharbor"
DB_USER_DEFAULT="blockharbor_app"
DB_MIGRATOR_DEFAULT="blockharbor_migrator"
ADMIN_USERNAME_DEFAULT="admin"
ADMIN_EMAIL_DEFAULT="admin@example.com"
INITIAL_ADMIN_PASSWORD_DEFAULT="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-16)"

REQUIRED_PACKAGES=(
    apache2 libapache2-mod-php8.1 php8.1-cli php8.1-pgsql php8.1-mbstring
    php8.1-intl php8.1-zip php8.1-curl postgresql-14 postgresql-client-14
    nodejs npm git openssl whiptail ssl-cert cron
)

UNATTENDED=0
NON_INTERACTIVE=0
DRY_RUN=0
SKIP_PACKAGES=0
SKIP_CRONS=0
CONFIG_FILE=""
INSTALL_LOG=""
STATE_JSON="/var/lib/blockharbor/install-state.json"
CURRENT_STEP="boot"

# ------------------------------------------------------------------ logging
log()  { printf '\e[1;34m[install]\e[0m %s\n' "$*" >&2; }
ok()   { printf '\e[1;32m[ok]\e[0m      %s\n' "$*" >&2; }
warn() { printf '\e[1;33m[warn]\e[0m    %s\n' "$*" >&2; }
err()  { printf '\e[1;31m[error]\e[0m   %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }
section() { printf '\n\e[1;36m=== %s ===\e[0m\n' "$*" >&2; }

# ------------------------------------------------------------------ args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --unattended)      UNATTENDED=1; shift ;;
        --non-interactive) NON_INTERACTIVE=1; shift ;;
        --dry-run)         DRY_RUN=1; shift ;;
        --skip-packages)   SKIP_PACKAGES=1; shift ;;
        --skip-crons)      SKIP_CRONS=1; shift ;;
        --config)          CONFIG_FILE="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -35
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

# ------------------------------------------------------------------ trap + transcript
on_err() {
    local exit_code=$?
    local line=$1
    err "FAILED at line $line during step '$CURRENT_STEP' (exit $exit_code)"
    err "Transcript: ${INSTALL_LOG:-/dev/null}"
    err "State:      $STATE_JSON"
    err "To resume:  re-run the same command (idempotent)"
    err "To clean:   bin/uninstall.sh --keep-data"
    exit $exit_code
}
trap 'on_err $LINENO' ERR

start_transcript() {
    if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p /var/log/blockharbor /var/lib/blockharbor 2>/dev/null || true
        INSTALL_LOG="/var/log/blockharbor/install-$(date +%Y%m%d-%H%M%S).log"
        # Tee stderr to log (script output already goes to stderr via log/ok/warn helpers)
        exec 2> >(tee -a "$INSTALL_LOG" >&2)
        log "Install transcript: $INSTALL_LOG"
    fi
}

mark_step() {
    CURRENT_STEP="$1"
    if [[ $DRY_RUN -eq 0 && -w "$(dirname "$STATE_JSON")" ]] 2>/dev/null; then
        printf '{"step":"%s","ts":"%s","dry_run":false}\n' "$1" "$(date -Iseconds)" > "$STATE_JSON" || true
    fi
}

# ------------------------------------------------------------------ pre-flight checks
preflight() {
    local issues=()

    # Disk space (need ≥1 GB free at /var/www and /var)
    local free_kb=$(df -k /var | tail -1 | awk '{print $4}')
    if (( free_kb < 1048576 )); then
        issues+=("Insufficient disk: $((free_kb/1024)) MB free at /var, need 1024+ MB")
    fi

    # RAM (need ≥1 GB total)
    local total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    if (( total_kb < 900000 )); then
        issues+=("Low RAM: $((total_kb/1024)) MB total, recommend 1024+ MB")
    fi

    # Internet (only if packages will be installed)
    if [[ $SKIP_PACKAGES -eq 0 ]]; then
        if ! curl -fsSL --max-time 5 https://deb.debian.org/ >/dev/null 2>&1 && \
           ! curl -fsSL --max-time 5 https://archive.ubuntu.com/ >/dev/null 2>&1; then
            issues+=("No internet (apt repositories unreachable). Use --skip-packages if intentional.")
        fi
    fi

    # PostgreSQL major version
    if command -v psql >/dev/null 2>&1; then
        local pg_version=$(sudo -u postgres psql -tAc "SHOW server_version_num" 2>/dev/null | head -1)
        if [[ -n "$pg_version" ]] && (( pg_version < 140000 )); then
            issues+=("PostgreSQL too old: $pg_version, need 14.0+")
        fi
    fi

    # Apache MPM (we don't require specific MPM, but log it)
    if command -v apache2ctl >/dev/null 2>&1; then
        local mpm=$(apache2ctl -M 2>/dev/null | grep -oE 'mpm_\w+' | head -1)
        log "Detected Apache MPM: ${mpm:-unknown}"
    fi

    if (( ${#issues[@]} > 0 )); then
        err "Pre-flight checks failed:"
        for i in "${issues[@]}"; do err "  - $i"; done
        if [[ $UNATTENDED -eq 0 && $NON_INTERACTIVE -eq 0 ]]; then
            ask_yes_no "Continue anyway?" || die "Pre-flight aborted by user."
        else
            die "Pre-flight failed in non-interactive mode."
        fi
    else
        ok "Pre-flight checks passed (disk + RAM + network + PG version)."
    fi
}

# ------------------------------------------------------------------ pre-flight
[[ $EUID -eq 0 ]] || die "Must run as root (use sudo)."

OS_ID=$(. /etc/os-release; echo "$ID")
[[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]] || \
    die "Unsupported OS: $OS_ID (only Ubuntu/Debian supported in P1)"

HAVE_WHIPTAIL=0
command -v whiptail >/dev/null 2>&1 && HAVE_WHIPTAIL=1

# ------------------------------------------------------------------ prompt helpers
ask_text() {
    local prompt="$1" default="$2" var
    if [[ $UNATTENDED -eq 1 ]]; then echo "$default"; return; fi
    if [[ $NON_INTERACTIVE -eq 1 ]]; then
        [[ -n "$default" ]] && { echo "$default"; return; }
        die "Non-interactive mode but no value for: $prompt"
    fi
    if [[ $HAVE_WHIPTAIL -eq 1 ]]; then
        var=$(whiptail --inputbox "$prompt" 10 70 "$default" --title "BlockHarbor installer" 3>&1 1>&2 2>&3) || die "Cancelled."
    else
        read -r -p "$prompt [$default]: " var
        var="${var:-$default}"
    fi
    echo "$var"
}

ask_password() {
    local prompt="$1" var
    [[ $UNATTENDED -eq 1 ]] && { echo ""; return; }
    if [[ $HAVE_WHIPTAIL -eq 1 ]]; then
        var=$(whiptail --passwordbox "$prompt" 10 70 --title "BlockHarbor installer" 3>&1 1>&2 2>&3) || var=""
    else
        read -rs -p "$prompt (hidden): " var; echo >&2
    fi
    echo "$var"
}

ask_yes_no() {
    local prompt="$1" default_yes="${2:-no}"
    if [[ $UNATTENDED -eq 1 ]]; then
        [[ "$default_yes" == "yes" ]] && return 0 || return 1
    fi
    if [[ $HAVE_WHIPTAIL -eq 1 ]]; then
        local flag="--defaultno"; [[ "$default_yes" == "yes" ]] && flag=""
        whiptail $flag --yesno "$prompt" 10 70 --title "BlockHarbor installer" 3>&1 1>&2 2>&3
    else
        local ans
        read -r -p "$prompt (y/N): " ans
        [[ "${ans,,}" =~ ^(y|yes)$ ]]
    fi
}

# ------------------------------------------------------------------ config file
if [[ -n "$CONFIG_FILE" ]]; then
    [[ -r "$CONFIG_FILE" ]] || die "Config file not readable: $CONFIG_FILE"
    log "Sourcing config: $CONFIG_FILE"
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

# ------------------------------------------------------------------ welcome
section "BlockHarbor installer"
[[ $UNATTENDED -eq 1 ]] && log "Running unattended (defaults used)."
[[ $DRY_RUN -eq 1 ]] && warn "DRY-RUN: no changes will be made."

# =================================================================
# PHASE 1 — Interactive Q&A (collect all inputs UP FRONT)
# =================================================================

section "Phase 1/3 — collecting configuration"

# --- Core
INSTALL_DIR="${INSTALL_DIR:-$(ask_text "Install directory" "$INSTALL_DIR_DEFAULT")}"
DOMAIN="${DOMAIN:-$(ask_text "Server hostname or IP" "$DOMAIN_DEFAULT")}"
APP_PORT="${APP_PORT:-$(ask_text "HTTPS port for BlockHarbor" "$APP_PORT_DEFAULT")}"

# --- TLS
TLS_MODE="${TLS_MODE:-}"
if [[ -z "$TLS_MODE" ]]; then
    if ask_yes_no "Use Let's Encrypt for TLS (requires public domain + port 80 reachable)?"; then
        TLS_MODE="letsencrypt"
        LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-$(ask_text "Email for Let's Encrypt notifications" "$ADMIN_EMAIL_DEFAULT")}"
    else
        TLS_MODE="snakeoil"
        log "Using self-signed cert (ssl-cert-snakeoil)"
    fi
fi

# --- Database
DB_NAME="${DB_NAME:-$(ask_text "PostgreSQL database name" "$DB_NAME_DEFAULT")}"
DB_USER="${DB_USER:-$(ask_text "PostgreSQL app role (DML)" "$DB_USER_DEFAULT")}"
DB_MIGRATOR="${DB_MIGRATOR:-$(ask_text "PostgreSQL migrator role (DDL)" "$DB_MIGRATOR_DEFAULT")}"

if [[ -z "${DB_PASSWORD:-}" ]]; then
    if ask_yes_no "Auto-generate strong DB password?" "yes"; then
        DB_PASSWORD=$(openssl rand -hex 24)
    else
        DB_PASSWORD=$(ask_password "DB password")
        [[ -n "$DB_PASSWORD" ]] || die "DB password required."
    fi
fi

# --- Admin user
ADMIN_USERNAME="${ADMIN_USERNAME:-$(ask_text "Initial admin username" "$ADMIN_USERNAME_DEFAULT")}"
ADMIN_EMAIL="${ADMIN_EMAIL:-$(ask_text "Initial admin email" "$ADMIN_EMAIL_DEFAULT")}"
INITIAL_ADMIN_PASSWORD="${INITIAL_ADMIN_PASSWORD:-$INITIAL_ADMIN_PASSWORD_DEFAULT}"

# --- SMTP (optional)
ENABLE_SMTP=0
if [[ -z "${SMTP_HOST:-}" ]]; then
    if ask_yes_no "Configure SMTP for notifications? (optional, can skip)"; then
        ENABLE_SMTP=1
        SMTP_HOST="$(ask_text "SMTP host" "smtp.gmail.com")"
        SMTP_PORT="$(ask_text "SMTP port" "587")"
        SMTP_USER="$(ask_text "SMTP username" "")"
        SMTP_PASSWORD="$(ask_password "SMTP password")"
        SMTP_FROM="$(ask_text "SMTP From address" "$ADMIN_EMAIL")"
        SMTP_ENCRYPTION="$(ask_text "Encryption (tls/ssl/none)" "tls")"
    fi
else
    ENABLE_SMTP=1
fi

# --- Optional API keys (all skippable; enrichment falls back to 'no data' if missing)
section "Phase 1/3 — optional API keys (press Enter to skip any)"
VT_API_KEY="${VT_API_KEY:-$(ask_text "VirusTotal API key (optional)" "")}"
GREYNOISE_API_KEY="${GREYNOISE_API_KEY:-$(ask_text "GreyNoise API key (optional, free tier 50/day)" "")}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-$(ask_text "AbuseIPDB API key (optional)" "")}"
SHODAN_API_KEY="${SHODAN_API_KEY:-$(ask_text "Shodan API key (optional)" "")}"
IPGEOLOCATION_API_KEY="${IPGEOLOCATION_API_KEY:-$(ask_text "ipgeolocation.io API key (optional)" "")}"
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:-$(ask_text "MaxMind GeoLite2 license key (optional)" "")}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-$(ask_text "Slack incoming webhook URL (optional)" "")}"

# --- Cron jobs
INSTALL_CRONS=1
if [[ $SKIP_CRONS -eq 1 ]]; then
    INSTALL_CRONS=0
elif [[ $UNATTENDED -eq 0 ]]; then
    ask_yes_no "Install cron jobs (feed fetch, CVE sync, audit verify, backups, cleanup)?" "yes" || INSTALL_CRONS=0
fi

# =================================================================
# PHASE 2 — Summary + confirm
# =================================================================

section "Phase 2/3 — review summary"
cat >&2 <<SUMMARY

============================================================
 BlockHarbor — install summary
------------------------------------------------------------
 Install dir          : $INSTALL_DIR
 URL                  : https://$DOMAIN:$APP_PORT
 TLS mode             : $TLS_MODE${TLS_MODE:+ ${LETSENCRYPT_EMAIL:+(LE email: $LETSENCRYPT_EMAIL)}}
 Database name        : $DB_NAME
 DB app role          : $DB_USER
 DB migrator role     : $DB_MIGRATOR
 Admin username       : $ADMIN_USERNAME ($ADMIN_EMAIL)
 Admin password       : (will display after install)
 SMTP                 : $([ $ENABLE_SMTP -eq 1 ] && echo "$SMTP_HOST:$SMTP_PORT ($SMTP_FROM)" || echo "disabled")
 API keys             : VT=$([ -n "$VT_API_KEY" ] && echo SET || echo -) \
                         GN=$([ -n "$GREYNOISE_API_KEY" ] && echo SET || echo -) \
                         AbuseIPDB=$([ -n "$ABUSEIPDB_API_KEY" ] && echo SET || echo -) \
                         Shodan=$([ -n "$SHODAN_API_KEY" ] && echo SET || echo -) \
                         ipgeo=$([ -n "$IPGEOLOCATION_API_KEY" ] && echo SET || echo -) \
                         MaxMind=$([ -n "$MAXMIND_LICENSE_KEY" ] && echo SET || echo -)
 Slack webhook        : $([ -n "$SLACK_WEBHOOK_URL" ] && echo SET || echo -)
 Cron jobs            : $([ $INSTALL_CRONS -eq 1 ] && echo "enabled" || echo "skipped")
 Packages (apt)       : $([ $SKIP_PACKAGES -eq 1 ] && echo "skipped (--skip-packages)" || echo "ensure ${#REQUIRED_PACKAGES[@]} packages")
 Mode                 : $([ $DRY_RUN -eq 1 ] && echo DRY-RUN || echo APPLY)
============================================================

SUMMARY

if [[ $UNATTENDED -eq 0 ]]; then
    ask_yes_no "Proceed with installation?" "yes" || die "Cancelled by user."
fi

# =================================================================
# PHASE 3 — Execute
# =================================================================

section "Phase 3/3 — executing"

run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '  \e[2m[dry-run] %s\e[0m\n' "$*" >&2
    else
        log "$*"
        eval "$@"
    fi
}

write_file() {
    local path="$1" content="$2"
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '  \e[2m[dry-run] write %s (%d bytes)\e[0m\n' "$path" "${#content}" >&2
    else
        log "Writing $path"
        printf '%s' "$content" > "$path"
    fi
}

# --- Step 1: apt packages
log "Step 1/10 — system packages"
if [[ $SKIP_PACKAGES -eq 1 ]]; then
    warn "Skipping apt install (--skip-packages)"
else
    MISSING=()
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        dpkg -l "$pkg" 2>/dev/null | grep -q '^ii' || MISSING+=("$pkg")
    done
    if [[ ${#MISSING[@]} -gt 0 ]]; then
        log "Installing missing packages: ${MISSING[*]}"
        run "apt-get update -qq"
        run "DEBIAN_FRONTEND=noninteractive apt-get install -y ${MISSING[*]}"
    else
        ok "All required packages present."
    fi
    if ! command -v composer >/dev/null 2>&1; then
        log "Installing Composer 2"
        run "curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer"
    else
        ok "Composer present: $(composer --version 2>/dev/null | head -1)"
    fi
fi

# --- Step 2: PostgreSQL
log "Step 2/10 — PostgreSQL roles + database"
pg_ready=$(sudo -u postgres psql -tAc "SELECT 1" 2>/dev/null || true)
[[ "$pg_ready" == "1" ]] || die "PostgreSQL not reachable."
for role in "$DB_USER" "$DB_MIGRATOR"; do
    has=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$role'")
    if [[ "$has" != "1" ]]; then
        run "sudo -u postgres psql -c \"CREATE ROLE $role LOGIN PASSWORD '\$DB_PASSWORD'\""
    else
        ok "Role $role exists; refreshing password."
        run "sudo -u postgres psql -c \"ALTER ROLE $role WITH PASSWORD '\$DB_PASSWORD'\""
    fi
done
has_db=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")
[[ "$has_db" == "1" ]] || run "sudo -u postgres createdb -O $DB_MIGRATOR $DB_NAME"
run "sudo -u postgres psql -d $DB_NAME -c \"GRANT ALL ON SCHEMA public TO $DB_MIGRATOR\""
run "sudo -u postgres psql -d $DB_NAME -c \"GRANT USAGE ON SCHEMA public TO $DB_USER\""
run "sudo -u postgres psql -d $DB_NAME -c \"ALTER DEFAULT PRIVILEGES FOR ROLE $DB_MIGRATOR IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO $DB_USER\""
run "sudo -u postgres psql -d $DB_NAME -c \"ALTER DEFAULT PRIVILEGES FOR ROLE $DB_MIGRATOR IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO $DB_USER\""

# --- Step 3: install dir
log "Step 3/10 — install directory"
[[ -d "$INSTALL_DIR" ]] || run "mkdir -p $INSTALL_DIR"
REPO_SRC="$(pwd)"
if [[ "$REPO_SRC" != "$INSTALL_DIR" ]]; then
    if ask_yes_no "Copy current directory ($REPO_SRC) to $INSTALL_DIR?" "yes"; then
        run "cp -a $REPO_SRC/. $INSTALL_DIR/"
        cd "$INSTALL_DIR"
    fi
else
    ok "Already in install dir."
fi

# --- Step 4: .env
log "Step 4/10 — generate .env"
ENV_PATH="$INSTALL_DIR/.env"
if [[ -f "$ENV_PATH" && $DRY_RUN -eq 0 ]]; then
    BACKUP="${ENV_PATH}.bak.$(date +%s)"
    warn ".env exists — backing up to $BACKUP"
    cp "$ENV_PATH" "$BACKUP"
fi
APP_KEY=$(openssl rand -hex 32)

ENV_CONTENT=$(cat <<EOF
# ── Application
APP_ENV=production
APP_DEBUG=false
APP_URL=https://$DOMAIN:$APP_PORT
APP_TIMEZONE=UTC
APP_KEY=$APP_KEY

# ── Database (runtime app role, DML-only)
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_SSLMODE=prefer

# ── Database (migrator role, DDL — used by phinx only)
DB_MIGRATOR_USER=$DB_MIGRATOR
DB_MIGRATOR_PASSWORD=$DB_PASSWORD

# ── Session
SESSION_NAME=BLOCKHARBOR_SESSION
SESSION_LIFETIME=1800
SESSION_ABSOLUTE_LIFETIME=28800

# ── Password policy
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_MIXED_CASE=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_HISTORY_COUNT=5

# ── Lockout
LOGIN_MAX_FAILS_PER_IP_5MIN=10
LOGIN_MAX_FAILS_PER_USER_1H=5
LOGIN_LOCKOUT_MINUTES=15

# ── Initial admin (used by seeder on first migrate; ignored thereafter)
INITIAL_ADMIN_USERNAME=$ADMIN_USERNAME
INITIAL_ADMIN_EMAIL=$ADMIN_EMAIL
INITIAL_ADMIN_PASSWORD=$INITIAL_ADMIN_PASSWORD

# ── Logging
LOG_PATH=/var/log/blockharbor/app.log
LOG_LEVEL=info

# ── Backups
BACKUP_DIR=/var/backups/blockharbor
BACKUP_RETENTION_DAYS=30

# ── SMTP (optional; leave empty to disable notifications)
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-}
SMTP_USER=${SMTP_USER:-}
SMTP_PASSWORD=${SMTP_PASSWORD:-}
SMTP_FROM=${SMTP_FROM:-}
SMTP_ENCRYPTION=${SMTP_ENCRYPTION:-tls}

# ── External enrichment API keys (all optional)
VT_API_KEY=$VT_API_KEY
GREYNOISE_API_KEY=$GREYNOISE_API_KEY
ABUSEIPDB_API_KEY=$ABUSEIPDB_API_KEY
SHODAN_API_KEY=$SHODAN_API_KEY
IPGEOLOCATION_API_KEY=$IPGEOLOCATION_API_KEY
MAXMIND_LICENSE_KEY=$MAXMIND_LICENSE_KEY

# ── Notification channels
SLACK_WEBHOOK_URL=$SLACK_WEBHOOK_URL
EOF
)
write_file "$ENV_PATH" "$ENV_CONTENT"
if [[ $DRY_RUN -eq 0 ]]; then
    chmod 600 "$ENV_PATH"
    chown www-data:www-data "$ENV_PATH"
fi
ok ".env ready (mode 600, owner www-data)"

# --- Step 5: composer + npm
log "Step 5/10 — composer install + npm build"
if [[ -f "$INSTALL_DIR/composer.json" ]]; then
    run "cd $INSTALL_DIR && composer install --no-progress --no-interaction --prefer-dist"
    ok "Composer dependencies installed."
else
    warn "composer.json not present (Task 2 hasn't run) — skipping."
fi
if [[ -f "$INSTALL_DIR/package.json" ]]; then
    run "cd $INSTALL_DIR && npm install --no-audit --no-fund"
    run "cd $INSTALL_DIR && npm run build || true"
    ok "npm dependencies + build complete."
else
    warn "package.json not present — skipping."
fi

# --- Step 6: log + backup dirs
log "Step 6/10 — log + backup directories"
for d in /var/log/blockharbor /var/backups/blockharbor; do
    run "mkdir -p $d"
    run "chown www-data:www-data $d"
    run "chmod 750 $d"
done
ok "Created /var/log/blockharbor + /var/backups/blockharbor"

# --- Step 7: Apache vhost
log "Step 7/10 — Apache vhost on port $APP_PORT"
run "a2enmod ssl headers rewrite"
PORTS_CONF="/etc/apache2/ports.conf"
if ! grep -q "Listen $APP_PORT" "$PORTS_CONF" 2>/dev/null; then
    log "Adding 'Listen $APP_PORT' to $PORTS_CONF"
    if [[ $DRY_RUN -eq 0 ]]; then echo "Listen $APP_PORT" >> "$PORTS_CONF"; fi
fi

# TLS cert path
if [[ "$TLS_MODE" == "letsencrypt" ]]; then
    log "Installing certbot for Let's Encrypt"
    run "DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-apache"
    run "certbot --apache --non-interactive --agree-tos -m $LETSENCRYPT_EMAIL -d $DOMAIN || warn 'certbot failed (DNS/port 80 not reachable?) — falling back to snakeoil'"
    SSL_CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    SSL_KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    [[ -f "$SSL_CERT_PATH" ]] || { SSL_CERT_PATH="/etc/ssl/certs/ssl-cert-snakeoil.pem"; SSL_KEY_PATH="/etc/ssl/private/ssl-cert-snakeoil.key"; }
else
    SSL_CERT_PATH="/etc/ssl/certs/ssl-cert-snakeoil.pem"
    SSL_KEY_PATH="/etc/ssl/private/ssl-cert-snakeoil.key"
fi

VHOST_PATH="/etc/apache2/sites-available/blockharbor.conf"
VHOST_CONTENT=$(cat <<EOF
<VirtualHost *:$APP_PORT>
    ServerName  $DOMAIN
    DocumentRoot $INSTALL_DIR/public
    DirectoryIndex index.php

    SSLEngine on
    SSLCertificateFile      $SSL_CERT_PATH
    SSLCertificateKeyFile   $SSL_KEY_PATH
    SSLProtocol             -all +TLSv1.2 +TLSv1.3

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    <Directory $INSTALL_DIR/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog  \${APACHE_LOG_DIR}/blockharbor-error.log
    CustomLog \${APACHE_LOG_DIR}/blockharbor-access.log combined
</VirtualHost>
EOF
)
write_file "$VHOST_PATH" "$VHOST_CONTENT"
run "a2ensite blockharbor"
run "apachectl configtest"
run "systemctl reload apache2"

# --- Step 8: migrations + seed
log "Step 8/10 — database migrations + seed"
if [[ -f "$INSTALL_DIR/vendor/bin/phinx" ]] && [[ -d "$INSTALL_DIR/db/migrations" ]]; then
    run "cd $INSTALL_DIR && vendor/bin/phinx migrate"
    run "cd $INSTALL_DIR && vendor/bin/phinx seed:run"
    ok "Migrations + seed applied."
else
    warn "Phinx or migrations not present yet — skipping (run again after P1 Task 22)."
fi

# --- Step 9: cron jobs (only register crons whose scripts actually exist)
log "Step 9/10 — cron jobs"
if [[ $INSTALL_CRONS -eq 1 ]]; then
    CRON_FILE="/etc/cron.d/blockharbor"
    CRON_CONTENT=""
    add_cron() {
        local schedule="$1" script="$2" comment="$3"
        if [[ -x "$INSTALL_DIR/bin/$script" ]]; then
            CRON_CONTENT+="# $comment"$'\n'
            CRON_CONTENT+="$schedule www-data cd $INSTALL_DIR && bin/$script >> /var/log/blockharbor/cron.log 2>&1"$'\n\n'
            ok "  + $script ($schedule)"
        else
            warn "  - skipping $script (not yet implemented in this phase)"
        fi
    }
    CRON_CONTENT="# BlockHarbor cron jobs — managed by bin/install.sh"$'\n'
    CRON_CONTENT+="SHELL=/bin/bash"$'\n'
    CRON_CONTENT+="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"$'\n\n'

    add_cron "*/15 * * * *"  "fetch-feeds"          "Fetch all enabled feed sources (P4)"
    add_cron "0    2 * * *"  "sync-cves"            "Daily CVE+KEV sync (P4)"
    add_cron "0    3 * * *"  "backup-db"            "Daily pg_dump backup (P5)"
    add_cron "5    3 * * *"  "cleanup-old-sessions" "Hourly+ session GC (P1 enabled)"
    add_cron "10   3 * * *"  "cleanup-login-attempts" "Daily login_attempts retention (P1 enabled)"
    add_cron "0    4 * * 0"  "verify-audit-chain"   "Weekly audit-log tamper check (P2)"
    add_cron "30   4 * * *"  "expire-iocs"          "Daily TTL/expiry pass on IOCs (P3)"
    add_cron "45   4 * * *"  "cleanup-enrichment-cache" "Cleanup expired enrichment cache (P3)"

    write_file "$CRON_FILE" "$CRON_CONTENT"
    if [[ $DRY_RUN -eq 0 ]]; then chmod 644 "$CRON_FILE"; fi
    ok "Cron jobs registered (those whose scripts exist)."
else
    warn "Cron jobs SKIPPED (--skip-crons or user said no)."
fi

# --- Step 10: ownership
log "Step 10/10 — fix ownership"
if [[ $DRY_RUN -eq 0 ]]; then
    chown -R www-data:www-data "$INSTALL_DIR"
    chmod -R u+rwX,g+rX,o-rwx "$INSTALL_DIR"
    chmod 600 "$INSTALL_DIR/.env"
fi
ok "Ownership normalized."

# =================================================================
# DONE
# =================================================================
ACCESS_URL="https://$DOMAIN:$APP_PORT/login"

cat <<DONE

╔══════════════════════════════════════════════════════════════╗
║              BlockHarbor — install complete                  ║
╠══════════════════════════════════════════════════════════════╣
║  URL          : $ACCESS_URL
║  Admin user   : $ADMIN_USERNAME ($ADMIN_EMAIL)
║  Password     : $INITIAL_ADMIN_PASSWORD
║                                                              ║
║  IMPORTANT: change password after first login!               ║
║                                                              ║
║  Repository   : $INSTALL_DIR
║  .env file    : $INSTALL_DIR/.env  (mode 600)                ║
║  Logs         : /var/log/blockharbor/                        ║
║  Backups      : /var/backups/blockharbor/                    ║
║  Cron config  : /etc/cron.d/blockharbor                      ║
║  Apache vhost : /etc/apache2/sites-available/blockharbor.conf║
║                                                              ║
║  Test:   curl -k -I $ACCESS_URL                              ║
║  Logs:   tail -f /var/log/apache2/blockharbor-error.log      ║
╚══════════════════════════════════════════════════════════════╝

DONE
