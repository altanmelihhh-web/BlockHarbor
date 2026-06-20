#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos

BASE="https://portal.cyberwebeyeos.com/blacklist/cyberwebeyeos"
BL_FILE="/var/www/html/blacklist.txt"
COOKIES=$(mktemp); trap 'rm -f $COOKIES' EXIT
curl -sk -c $COOKIES -d "username=${CWE_TEST_USER:-admin}&password=${CWE_TEST_PASS:-admin}" "$BASE/login.php" -o /dev/null

# Backup blacklist
cp "$BL_FILE" /tmp/c1_bl.bak

# Test 1: Domain submit (warninglist_override needed because example.com is in tranco_top)
resp=$(curl -sk -b $COOKIES -X POST "$BASE/cyberwebeyeosblacklistadmin.php" \
  --data-urlencode "ip_address=audit-fix-c1.example.com" \
  --data-urlencode "force_type=" \
  --data-urlencode "tlp=AMBER" \
  --data-urlencode "confidence=70" \
  --data-urlencode "valid_until_preset=+30 days" \
  --data-urlencode "warninglist_override=1" \
  -L -o /dev/null -w "%{http_code}")
echo "Domain submit HTTP: $resp"

# Verify it landed in blacklist.txt
grep -q "audit-fix-c1.example.com" "$BL_FILE" || {
    cp /tmp/c1_bl.bak "$BL_FILE"
    echo "FAIL: domain not in blacklist.txt"; exit 1;
}

# Test 2: SHA-256 hash submit
HASH="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
resp=$(curl -sk -b $COOKIES -X POST "$BASE/cyberwebeyeosblacklistadmin.php" \
  --data-urlencode "ip_address=$HASH" \
  --data-urlencode "force_type=" \
  --data-urlencode "tlp=WHITE" \
  --data-urlencode "confidence=85" \
  -L -o /dev/null -w "%{http_code}")
echo "Hash submit HTTP: $resp"

grep -q "$HASH" "$BL_FILE" || {
    cp /tmp/c1_bl.bak "$BL_FILE"
    echo "FAIL: hash not in blacklist.txt"; exit 1;
}

# Test 3: URL submit
resp=$(curl -sk -b $COOKIES -X POST "$BASE/cyberwebeyeosblacklistadmin.php" \
  --data-urlencode "ip_address=https://phish.audit-fix-c1.test/login" \
  --data-urlencode "force_type=" \
  --data-urlencode "tlp=RED" \
  --data-urlencode "confidence=90" \
  -L -o /dev/null -w "%{http_code}")
echo "URL submit HTTP: $resp"

grep -q "phish.audit-fix-c1.test" "$BL_FILE" || {
    cp /tmp/c1_bl.bak "$BL_FILE"
    echo "FAIL: URL not in blacklist.txt"; exit 1;
}

# Cleanup — restore
cp /tmp/c1_bl.bak "$BL_FILE"

echo "PASS: audit_fix_c1"
