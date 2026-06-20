#!/usr/bin/env bash
# Smoke test for Task 1 (B4): feed_health extend
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# 1. State file must exist after running a sample heartbeat
php -r '
require "feed_health.php";
feed_health_heartbeat("test_source", [
    "url" => "https://example.com/feed",
    "http_status" => 200,
    "bytes_received" => 1234,
    "parser_ok" => true,
    "entries_extracted" => 5,
    "raw_body" => "{\"key1\":1,\"key2\":2}",
]);
' > /dev/null
test -f feed_health_state.json || { echo "FAIL: feed_health_state.json missing"; exit 1; }

# 2. Schema fingerprint must be MD5 of sorted top-level JSON keys
fp=$(jq -r '.test_source.schema_fingerprint' feed_health_state.json)
expected=$(echo -n "key1,key2" | md5sum | awk '{print $1}')
[ "$fp" = "$expected" ] || { echo "FAIL: schema fingerprint mismatch ($fp != $expected)"; exit 1; }

# 3. Drift detection: second call with different keys must flag SCHEMA_DRIFT
php -r '
require "feed_health.php";
$ok = feed_health_heartbeat("test_source", [
    "url" => "https://example.com/feed",
    "http_status" => 200,
    "bytes_received" => 999,
    "parser_ok" => true,
    "entries_extracted" => 0,
    "raw_body" => "{\"newkey\":1}",
]);
echo $ok ? "INGEST_OK\n" : "INGEST_BLOCKED\n";
'
status=$(jq -r '.test_source.status' feed_health_state.json)
[ "$status" = "SCHEMA_DRIFT" ] || { echo "FAIL: drift not detected (status=$status)"; exit 1; }

# 4. Cleanup
rm -f feed_health_state.json
echo "PASS: t1_feed_health"
