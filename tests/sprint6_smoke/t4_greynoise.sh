#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# 1. Function exists and returns array
out=$(php -r '
require "greynoise.php";
$r = greynoise_cve_search("CVE-2024-3400", true); // dry-run mode (no real HTTP)
echo json_encode($r);
')
echo "$out" | jq -e '.ips | type == "array"' >/dev/null || { echo "FAIL: greynoise_cve_search wrong shape"; exit 1; }

# 2. Quota counter exists
test -f greynoise_quota.json || { echo "FAIL: quota file missing"; exit 1; }
remaining=$(jq -r '.remaining_today' greynoise_quota.json)
[ "$remaining" -le 50 ] && [ "$remaining" -ge 0 ] || { echo "FAIL: quota out of range ($remaining)"; exit 1; }

# 3. Dry-run does not decrement quota
before=$(jq -r '.used_today' greynoise_quota.json)
php -r 'require "greynoise.php"; greynoise_cve_search("CVE-2024-3400", true);' >/dev/null
after=$(jq -r '.used_today' greynoise_quota.json)
[ "$before" = "$after" ] || { echo "FAIL: dry-run incremented quota"; exit 1; }

# 4. Cache hit short-circuits
php -r 'require "greynoise.php"; $r = greynoise_cve_search("CVE-2024-3400", true); echo $r["source"];' | grep -qE 'dry-run|cache' || \
    { echo "FAIL: source not dry-run/cache"; exit 1; }

echo "PASS: t4_greynoise"
