#!/usr/bin/env bash
set -euo pipefail
cd /var/www/blacklist/cyberwebeyeos
TMPDIR=$(mktemp -d); trap 'rm -rf $TMPDIR' EXIT

# 1. Happy path: write to existing dir
out=$(php -r '
require "lib_safe_write.php";
$r = safe_write_atomic("'$TMPDIR'/hello.txt", "hello world");
echo json_encode($r);
')
echo "$out" | jq -e '.ok and .bytes == 11' >/dev/null || { echo "FAIL: happy path (got $out)"; exit 1; }
[ "$(cat $TMPDIR/hello.txt)" = "hello world" ] || { echo "FAIL: content mismatch"; exit 1; }

# 2. Auto-mkdir parent
out=$(php -r '
require "lib_safe_write.php";
$r = safe_write_atomic("'$TMPDIR'/nested/deep/file.txt", "x");
echo json_encode($r);
')
echo "$out" | jq -e '.ok' >/dev/null || { echo "FAIL: auto-mkdir (got $out)"; exit 1; }
test -f $TMPDIR/nested/deep/file.txt || { echo "FAIL: nested file missing"; exit 1; }

# 3. No .tmp leftover after success
ls $TMPDIR/*.tmp.* 2>/dev/null && { echo "FAIL: tmp file leaked"; exit 1; } || true

# 4. Empty content allowed
out=$(php -r '
require "lib_safe_write.php";
echo json_encode(safe_write_atomic("'$TMPDIR'/empty.txt", ""));
')
echo "$out" | jq -e '.ok and .bytes == 0' >/dev/null || { echo "FAIL: empty content (got $out)"; exit 1; }

echo "PASS: t1_safe_write"
