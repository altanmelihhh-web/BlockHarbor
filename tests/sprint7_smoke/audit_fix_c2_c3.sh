#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
COOKIES=$(mktemp); trap 'rm -f $COOKIES' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# Backup
cp blacklist.txt /tmp/c23_bl.bak
cp cyberwebeyeosblacklist.txt /tmp/c23_feed.bak

# C2: Trigger sync — should now merge external feeds into firewall feed
BEFORE=$(wc -l < cyberwebeyeosblacklist.txt)
curl -sk -b $COOKIES -X POST "$BASE/cyberwebeyeosblacklistadmin.php" --data "sync_blacklist=1" -L -o /dev/null
AFTER=$(wc -l < cyberwebeyeosblacklist.txt)
echo "Firewall feed lines: $BEFORE → $AFTER"
[ $AFTER -gt 100 ] || { echo "FAIL C2: feed didn't grow (still $AFTER lines, expected >100 from USOM/Firehol)"; cp /tmp/c23_feed.bak cyberwebeyeosblacklist.txt; exit 1; }

# Restore feed (test artifact)
cp /tmp/c23_feed.bak cyberwebeyeosblacklist.txt

# C3: Form should accept target_list field
SPA_CHECK=$(curl -sk -b $COOKIES "$BASE/cyberwebeyeosblacklistadmin.php" | grep -c 'name="target_list"')
[ $SPA_CHECK -ge 1 ] || { echo "FAIL C3: target_list hidden field missing"; exit 1; }

# Cleanup
cp /tmp/c23_bl.bak blacklist.txt

echo "PASS: audit_fix_c2_c3"
