#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# 1. customer_assets.json valid
test -f customer_assets.json || { echo "FAIL: customer_assets.json missing"; exit 1; }
jq -e '.customers | type == "array"' customer_assets.json >/dev/null || { echo "FAIL: customers not array"; exit 1; }

# 2. Function exists, dry-run returns expected shape
out=$(php -r '
require "shodan_exposure.php";
$r = shodan_exposure_check_ip("1.1.1.1", true);
echo json_encode($r);
')
echo "$out" | jq -e '.ok and has("vulns")' >/dev/null || { echo "FAIL: dry-run shape"; exit 1; }
echo "$out" | jq -e '.source == "dry-run"' >/dev/null || { echo "FAIL: dry-run flag"; exit 1; }

# 3. Cache dir created
test -d cve_cache/shodan || { echo "FAIL: cache dir missing"; exit 1; }

# 4. CLI scan returns summary
sum=$(php shodan_exposure.php --dry-run)
echo "$sum" | jq -e 'has("scanned") and has("matches")' >/dev/null || { echo "FAIL: CLI summary shape (got: $sum)"; exit 1; }

echo "PASS: t9_shodan"
