#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# Backup state
cp blacklist.txt /tmp/sprint6_t8_bl_bak
cp -f blacklist_meta.json /tmp/sprint6_t8_meta_bak 2>/dev/null || echo "{}" > /tmp/sprint6_t8_meta_bak
cp -f pending_ips.json /tmp/sprint6_t8_pending_bak 2>/dev/null || true

# Seed: 2 entries — one expired (cve-bound), one fresh (manual)
php -r '
$bl = file_exists("blacklist.txt") ? file_get_contents("blacklist.txt") : "";
file_put_contents("blacklist.txt", $bl . "\n198.51.100.50|ip-src|cve:CVE-X test|2026-05-01|test||||AMBER|70|2026-05-10T00:00:00Z\n198.51.100.60|ip-src|manual test|2026-05-01|test||||AMBER|70|2099-01-01T00:00:00Z\n");
$m = file_exists("blacklist_meta.json") ? (json_decode(file_get_contents("blacklist_meta.json"), true) ?: []) : [];
$m["198.51.100.50"] = ["source"=>"cve:CVE-X","cve_ref"=>"CVE-X","expires_at"=>"2026-05-10T00:00:00Z","added_by"=>"test","first_seen"=>"2026-05-01T00:00:00Z","sighting_count"=>0,"confidence"=>70];
$m["198.51.100.60"] = ["source"=>"manual","expires_at"=>"2099-01-01T00:00:00Z","added_by"=>"test","first_seen"=>"2026-05-01T00:00:00Z","sighting_count"=>0,"confidence"=>70];
file_put_contents("blacklist_meta.json", json_encode($m, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
'

# Run cron
php cron_expire_check.php 2>&1 | tail -5

# Expired CVE-bound IP must NOT be in blacklist
if grep -q "^198\.51\.100\.50|" blacklist.txt; then
    echo "FAIL: expired CVE IP still in blacklist"
    cp /tmp/sprint6_t8_bl_bak blacklist.txt
    cp /tmp/sprint6_t8_meta_bak blacklist_meta.json
    exit 1
fi

# Expired CVE IP must be in pending
if [ -f pending_ips.json ]; then
    grep -q "198.51.100.50" pending_ips.json || { echo "FAIL: expired CVE IP not in pending"; cp /tmp/sprint6_t8_bl_bak blacklist.txt; cp /tmp/sprint6_t8_meta_bak blacklist_meta.json; exit 1; }
fi

# Manual entry must remain
grep -q "^198\.51\.100\.60|" blacklist.txt || { echo "FAIL: manual entry removed"; cp /tmp/sprint6_t8_bl_bak blacklist.txt; cp /tmp/sprint6_t8_meta_bak blacklist_meta.json; exit 1; }

# Restore
cp /tmp/sprint6_t8_bl_bak blacklist.txt
cp /tmp/sprint6_t8_meta_bak blacklist_meta.json
[ -f /tmp/sprint6_t8_pending_bak ] && cp /tmp/sprint6_t8_pending_bak pending_ips.json

echo "PASS: t8_ttl_expiry"
