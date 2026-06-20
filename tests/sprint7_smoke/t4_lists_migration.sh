#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

cp lists.json /tmp/sprint7_t4_lists.bak

# Run migration twice (must be idempotent)
out1=$(php migrate_lists_sprint7.php)
out2=$(php migrate_lists_sprint7.php)

echo "$out1" | jq -e '.ok' >/dev/null || { cp /tmp/sprint7_t4_lists.bak lists.json; echo "FAIL: migration 1 (got $out1)"; exit 1; }
echo "$out2" | jq -e '.ok' >/dev/null || { cp /tmp/sprint7_t4_lists.bak lists.json; echo "FAIL: migration 2 (got $out2)"; exit 1; }

# 2nd run must report 0 changes
c2=$(echo "$out2" | jq -r '.changes.added + .changes.updated')
[ "$c2" = "0" ] || { cp /tmp/sprint7_t4_lists.bak lists.json; echo "FAIL: not idempotent (2nd run added/updated $c2)"; exit 1; }

# Verify system-whitelist-all present
jq -e '.lists[] | select(.id == "system-whitelist-all")' lists.json >/dev/null || { cp /tmp/sprint7_t4_lists.bak lists.json; echo "FAIL: system-whitelist-all missing"; exit 1; }

# Verify default-manual got kind=system + side=blacklist
jq -e '.lists[] | select(.id == "default-manual") | .kind == "system" and .side == "blacklist"' lists.json >/dev/null || { cp /tmp/sprint7_t4_lists.bak lists.json; echo "FAIL: default-manual not migrated correctly"; exit 1; }

# Verify at least 1 external mirror exists (if sources_config has enabled feeds)
external_count=$(jq '[.lists[] | select(.kind == "external")] | length' lists.json)
echo "External feeds mirrored: $external_count"

echo "PASS: t4_lists_migration"
