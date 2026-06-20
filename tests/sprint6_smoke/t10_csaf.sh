#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# 1. Config file exists with 5 publishers
test -f vendor_psirt.json || { echo "FAIL: vendor_psirt.json missing"; exit 1; }
count=$(jq '.csaf_publishers | length' vendor_psirt.json)
[ "$count" -ge 5 ] || { echo "FAIL: expected >=5 publishers, got $count"; exit 1; }

# 2. Function exists, dry-run works
out=$(php -r '
require "csaf_fetcher.php";
$r = csaf_fetcher_dry_run();
echo json_encode($r);
')
echo "$out" | jq -e '.ok and (.publishers | type == "array")' >/dev/null || { echo "FAIL: dry-run shape (got $out)"; exit 1; }

# 3. CLI dry-run prints summary
sum=$(php csaf_fetcher.php --dry-run)
echo "$sum" | jq -e 'has("ok")' >/dev/null || { echo "FAIL: CLI shape"; exit 1; }

# 4. Cache directory created
test -d cve_cache/csaf || { echo "FAIL: cve_cache/csaf dir missing"; exit 1; }

echo "PASS: t10_csaf"
