#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# 1. CVE extraction from sample RSS
out=$(php -r '
require "psirt_rss_fetcher.php";
$rss = "<?xml version=\"1.0\"?><rss><channel><item><title>FG-IR-26-118 SSL-VPN RCE CVE-2026-12345</title><description>Affects CVE-2026-99999 also</description><pubDate>Tue, 21 May 2026 11:00:00 GMT</pubDate></item></channel></rss>";
$r = psirt_rss_extract_cves($rss);
echo json_encode($r);
')
echo "$out" | jq -e '. | type=="array" and length>=2 and contains(["CVE-2026-12345"])' >/dev/null || \
    { echo "FAIL: CVE extraction (got $out)"; exit 1; }

# 2. Run dry returns publisher list
sum=$(php psirt_rss_fetcher.php --dry-run)
echo "$sum" | jq -e '.publishers | type=="array"' >/dev/null || { echo "FAIL: CLI shape"; exit 1; }

echo "PASS: t11_psirt_rss"
