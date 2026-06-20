#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); _spa_tmp=$(mktemp); trap 'rm -f $COOKIES $_spa_tmp' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# Seed a test entry in blacklist_meta.json (T6 schema)
php -r '
$f = "blacklist_meta.json";
$m = file_exists($f) ? (json_decode(file_get_contents($f), true) ?: []) : [];
$m["198.51.100.7"] = [
  "source" => "cve:CVE-2024-3400", "cve_ref" => "CVE-2024-3400",
  "first_seen" => gmdate("c"), "sighting_count" => 5, "confidence" => 70,
  "expires_at" => gmdate("c", time()+14*86400), "added_by" => "test"
];
file_put_contents($f, json_encode($m, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
'

# 1. Endpoint returns the meta
resp=$(curl -sk -b $COOKIES "$BASE/ioc_provenance.php?ip=198.51.100.7")
echo "$resp" | jq -e '.meta.cve_ref == "CVE-2024-3400"' >/dev/null || { echo "FAIL: provenance lookup (got: $resp)"; exit 1; }

# 2. Unknown IP returns ok=true with meta=null
resp2=$(curl -sk -b $COOKIES "$BASE/ioc_provenance.php?ip=10.99.99.99")
echo "$resp2" | jq -e '.ok and .meta == null' >/dev/null || { echo "FAIL: unknown IP shape"; exit 1; }

# 3. UI marker
curl -sk -b $COOKIES -o "$_spa_tmp" "$BASE/cyberwebeyeosblacklistadmin.php"
grep -q "SPRINT6-A3" "$_spa_tmp" || { echo "FAIL: SPRINT6-A3 marker missing"; exit 1; }

# Cleanup test entry
php -r '
$f = "blacklist_meta.json"; $m = json_decode(file_get_contents($f), true) ?: [];
unset($m["198.51.100.7"]); file_put_contents($f, json_encode($m, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
'
echo "PASS: t7_provenance"
