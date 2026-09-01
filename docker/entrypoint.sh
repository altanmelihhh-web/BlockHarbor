#!/bin/sh
set -e

# Create runtime directories (may be missing on fresh volume)
mkdir -p \
    /var/www/html/domain_dyn \
    /var/www/html/lists_dyn \
    /var/www/html/cve_cache/greynoise \
    /var/www/html/cve_cache/shodan \
    /var/www/html/enrichment_cache \
    /var/www/html/usom \
    /var/www/html/warninglists \
    /var/log/cyberwebeyeos

# Seed runtime state from shipped templates on first boot.
# These files are gitignored (they hold credentials / operational data),
# so the image ships only the *.example templates.
for f in users.json notifications.json customer_assets.json whitelist.txt; do
    if [ ! -f "/var/www/html/$f" ] && [ -f "/var/www/html/$f.example" ]; then
        cp "/var/www/html/$f.example" "/var/www/html/$f"
    fi
done

# Touch writable runtime files so www-data can write them on first request
for f in blacklist.txt whitelist.txt domain_combined.txt cyberwebeyeosblacklist.txt \
          audit.log ip_blocklist.log conflict_log.txt; do
    [ -f "/var/www/html/$f" ] || touch "/var/www/html/$f"
done

# --------------------------------------------------------------- demo mode --
# Enabled by DEMO_MODE=true. Everything below is a no-op otherwise, so a normal
# deployment behaves exactly as before.
if [ "$(echo "${DEMO_MODE:-}" | tr '[:upper:]' '[:lower:]')" = "true" ]; then
    echo "[entrypoint] DEMO_MODE=true — read-only public demo"

    # Load demo_mode.php ahead of every request. This is the single choke point
    # that enforces the write lock, injects the banner and stubs outbound APIs;
    # it does not depend on any per-endpoint wiring.
    cat > /usr/local/etc/php/conf.d/zz-blockharbor-demo.ini <<'PHPINI'
auto_prepend_file = /var/www/html/demo_mode.php
expose_php = Off
display_errors = Off
PHPINI

    # Regenerate the synthetic dataset on every boot: the demo is stateless and
    # each visitor should get the same clean data.
    php /var/www/html/bin/seed-demo.php || echo "[entrypoint] seed-demo failed (continuing)"

    # No scheduled feed fetching in the demo.
    rm -f /etc/cron.d/cyberwebeyeos-tip 2>/dev/null || true
else
    rm -f /usr/local/etc/php/conf.d/zz-blockharbor-demo.ini 2>/dev/null || true
fi

# ------------------------------------------------------------ mount point --
# CWE_BASE_PATH decides where the app is served. Default keeps the historical
# /blacklist/cyberwebeyeos mount; "/" serves it from the domain root, which is
# what the public demo uses.
BASE_PATH="${CWE_BASE_PATH:-/blacklist/cyberwebeyeos}"
BASE_PATH="/$(echo "$BASE_PATH" | sed 's#^/*##; s#/*$##')"
VHOST=/etc/apache2/sites-available/000-default.conf

if [ "$BASE_PATH" = "/" ]; then
    echo "[entrypoint] serving BlockHarbor at /"
    sed -i 's|# BLOCKHARBOR_MOUNT|# served from DocumentRoot at /|' "$VHOST"
    sed -i 's|# BLOCKHARBOR_ROOT_REDIRECT|# no root redirect needed|' "$VHOST"
    CWE_BASE_PATH="/"
else
    echo "[entrypoint] serving BlockHarbor at $BASE_PATH"
    sed -i "s|# BLOCKHARBOR_MOUNT|Alias $BASE_PATH /var/www/html|" "$VHOST"
    sed -i "s|# BLOCKHARBOR_ROOT_REDIRECT|RedirectMatch 302 ^/?\$ $BASE_PATH/|" "$VHOST"
    CWE_BASE_PATH="$BASE_PATH"
fi
export CWE_BASE_PATH

# Make the resolved value visible to PHP through the vhost.
grep -q 'PassEnv CWE_BASE_PATH' "$VHOST" || \
    sed -i "s|PassEnv CWE_CONTACT_EMAIL|PassEnv CWE_CONTACT_EMAIL\n    PassEnv CWE_BASE_PATH|" "$VHOST"

# ------------------------------------------------------- listen port (PaaS) --
# Render, Fly and similar platforms inject $PORT and expect the process to bind
# to it. Default to 80 for plain docker-compose runs.
LISTEN_PORT="${PORT:-80}"
if [ "$LISTEN_PORT" != "80" ]; then
    echo "[entrypoint] binding Apache to port $LISTEN_PORT"
    sed -i "s/^Listen 80$/Listen $LISTEN_PORT/" /etc/apache2/ports.conf
    sed -i "s/<VirtualHost \*:80>/<VirtualHost *:$LISTEN_PORT>/" \
        /etc/apache2/sites-available/000-default.conf
fi

chown -R www-data:www-data /var/www/html /var/log/cyberwebeyeos

exec "$@"
