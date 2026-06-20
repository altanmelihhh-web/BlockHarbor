#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# Backup
cp cyberwebeyeosblacklist.txt /tmp/sprint7_t3_feed.bak
cp whitelist.txt /tmp/sprint7_t3_wl.bak
cp blacklist.txt /tmp/sprint7_t3_bl.bak

# Seed: add 198.51.100.99 to BOTH blacklist + whitelist (whitelist should win)
echo "198.51.100.99|test|2026-05-21|test||||AMBER|70|permanent" >> blacklist.txt
echo "198.51.100.99|2026-05-21|test|t3-whitelist-test|AMBER" >> whitelist.txt

# Run rebuild
out=$(php -r 'require "lib_firewall_feed.php"; echo json_encode(rebuild_firewall_feed());')
echo "$out" | jq -e '.ok and (.subtracted | type == "number")' >/dev/null || {
    cp /tmp/sprint7_t3_feed.bak cyberwebeyeosblacklist.txt
    cp /tmp/sprint7_t3_wl.bak whitelist.txt
    cp /tmp/sprint7_t3_bl.bak blacklist.txt
    echo "FAIL: shape (got $out)"; exit 1;
}

# Whitelist IP must NOT be in feed
grep -q "^198\.51\.100\.99$" cyberwebeyeosblacklist.txt && {
    cp /tmp/sprint7_t3_feed.bak cyberwebeyeosblacklist.txt
    cp /tmp/sprint7_t3_wl.bak whitelist.txt
    cp /tmp/sprint7_t3_bl.bak blacklist.txt
    echo "FAIL: whitelist IP leaked into feed"; exit 1;
}

# Restore
cp /tmp/sprint7_t3_feed.bak cyberwebeyeosblacklist.txt
cp /tmp/sprint7_t3_wl.bak whitelist.txt
cp /tmp/sprint7_t3_bl.bak blacklist.txt
echo "PASS: t3_firewall_feed"
