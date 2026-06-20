#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

# Backup cve_state.json
cp cve_state.json /tmp/s61_cve_state.bak

# Seed two CVEs in cve_state.json via parallel writes
php -r '
$cve_state_file = "cve_state.json";
$s = file_exists($cve_state_file) ? json_decode(file_get_contents($cve_state_file), true) : [];
if (!isset($s["cves"])) $s["cves"] = [];
file_put_contents($cve_state_file, json_encode($s, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
'

# Run csaf_merge AND psirt_merge in parallel via background subshells
(php -r '
require "csaf_fetcher.php";
csaf_merge_into_cve_state([
    "cves" => ["CVE-2030-11111"], "vendor" => "test", "cvss" => 9.0, "published" => "2030-01-01"
], "racetest_csaf");
' >/dev/null 2>&1) &
(php -r '
require "psirt_rss_fetcher.php";
psirt_merge_cve("CVE-2030-22222", "racetest_psirt", "title", "http://x", "2030-01-01");
' >/dev/null 2>&1) &
wait

# Both CVEs must be present (no silent drop)
got1=$(jq -r '.cves["CVE-2030-11111"] | .cve_id' cve_state.json)
got2=$(jq -r '.cves["CVE-2030-22222"] | .cve_id' cve_state.json)
[ "$got1" = "CVE-2030-11111" ] || { echo "FAIL: CVE-2030-11111 missing"; cp /tmp/s61_cve_state.bak cve_state.json; exit 1; }
[ "$got2" = "CVE-2030-22222" ] || { echo "FAIL: CVE-2030-22222 missing"; cp /tmp/s61_cve_state.bak cve_state.json; exit 1; }

# Cleanup
php -r '
$s = json_decode(file_get_contents("cve_state.json"), true);
unset($s["cves"]["CVE-2030-11111"], $s["cves"]["CVE-2030-22222"]);
file_put_contents("cve_state.json", json_encode($s, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
'

echo "PASS: s61_1_race"
