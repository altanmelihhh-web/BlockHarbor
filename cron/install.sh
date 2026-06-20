#!/usr/bin/env bash
# Install or update Cyberwebeyeos TIP cron entries
# Usage: sudo bash cron/install.sh
set -euo pipefail

SRC="$(dirname "$(readlink -f "$0")")/cyberwebeyeos-tip"
DST=/etc/cron.d/cyberwebeyeos-tip

if [ ! -f "$SRC" ]; then
    echo "ERROR: $SRC missing" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must be run as root (use sudo)" >&2
    exit 1
fi

# Backup existing
if [ -f "$DST" ]; then
    cp "$DST" "${DST}.bak-$(date +%Y%m%d-%H%M%S)"
    echo "Existing cron backed up."
fi

cp "$SRC" "$DST"
chown root:root "$DST"
chmod 644 "$DST"

# Pre-create log files with correct ownership
mkdir -p /var/log/cyberwebeyeos
for log in expire-check bigtech-sync cidr-aggregate warninglist-sync cve-fetch shodan-exposure csaf-fetch psirt-rss; do
    touch "/var/log/cyberwebeyeos/${log}.log"
done
chown -R www-data:adm /var/log/cyberwebeyeos

echo "✓ Cron installed at $DST"
echo "✓ Log dir ready at /var/log/cyberwebeyeos/"
echo "Cron auto-detects /etc/cron.d/ changes — no reload needed."
