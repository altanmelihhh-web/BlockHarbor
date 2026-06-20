#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# 1. Function exists, returns expected shape
out=$(php -r '
require "threatfox.php";
$r = threatfox_cve_query("CVE-2024-3400", true);
echo json_encode($r);
')
echo "$out" | jq -e '.iocs | type == "array"' >/dev/null || { echo "FAIL: iocs shape"; exit 1; }
echo "$out" | jq -e '.source == "dry-run"' >/dev/null || { echo "FAIL: dry-run not flagged"; exit 1; }

# 2. Cache directory created
test -d cve_cache/threatfox || { echo "FAIL: cache dir missing"; exit 1; }

# 3. Invalid CVE rejected
out2=$(php -r 'require "threatfox.php"; echo json_encode(threatfox_cve_query("not-a-cve", true));')
echo "$out2" | jq -e '.source == "invalid_cve"' >/dev/null || { echo "FAIL: invalid CVE not caught"; exit 1; }

echo "PASS: t5_threatfox"
