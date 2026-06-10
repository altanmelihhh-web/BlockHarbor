#!/usr/bin/env bash
#
# BlockHarbor — post-install smoke test
#
# Validates that the installed application responds correctly.
#
# Usage:
#   bash bin/verify-install.sh                # default: localhost
#   bash bin/verify-install.sh --url <url>    # explicit URL
#   bash bin/verify-install.sh --strict       # require all checks pass

set -uo pipefail

URL=""
STRICT=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)    URL="$2"; shift 2 ;;
        --strict) STRICT=1; shift ;;
        -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown: $1" >&2; exit 2 ;;
    esac
done

INSTALL_DIR="${INSTALL_DIR:-/var/www/blockharbor}"
[[ -r "$INSTALL_DIR/.env" ]] && { set -a; . "$INSTALL_DIR/.env"; set +a; }
URL="${URL:-${APP_URL:-https://localhost:8443}}"

PASS=0
FAIL=0

check() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        printf '  \e[1;32m✓\e[0m %-30s %s\n' "$name" "$actual"
        ((PASS++))
    else
        printf '  \e[1;31m✗\e[0m %-30s expected=%s got=%s\n' "$name" "$expected" "$actual"
        ((FAIL++))
    fi
}

echo "Smoking $URL ..."

# 1. /login returns 200 with HTML
STATUS=$(curl -kso /dev/null -w '%{http_code}' "$URL/login")
check "GET /login" "200" "$STATUS"

# 2. /login contains the form
BODY=$(curl -ks "$URL/login")
echo "$BODY" | grep -q 'name="username"' \
    && check "login form has username field" "yes" "yes" \
    || check "login form has username field" "yes" "no"
echo "$BODY" | grep -q 'name="_csrf"' \
    && check "login form has CSRF token" "yes" "yes" \
    || check "login form has CSRF token" "yes" "no"

# 3. /dashboard requires auth (302 redirect to /login)
STATUS=$(curl -kso /dev/null -w '%{http_code}' "$URL/dashboard")
check "GET /dashboard (no auth)" "303" "$STATUS"

# 4. /health (if Bundle 4 deployed) — accept 200 or 404 (controller might not exist yet)
STATUS=$(curl -kso /dev/null -w '%{http_code}' "$URL/health")
case "$STATUS" in
    200|404) printf '  \e[1;32m✓\e[0m %-30s %s (acceptable)\n' "GET /health" "$STATUS"; ((PASS++)) ;;
    *)       printf '  \e[1;31m✗\e[0m %-30s %s (expected 200 or 404)\n' "GET /health" "$STATUS"; ((FAIL++)) ;;
esac

# 5. Security headers present
HEADERS=$(curl -ksI "$URL/login")
echo "$HEADERS" | grep -qi 'strict-transport-security' \
    && check "HSTS header" "yes" "yes" \
    || check "HSTS header" "yes" "no"
echo "$HEADERS" | grep -qi 'x-content-type-options' \
    && check "X-Content-Type-Options" "yes" "yes" \
    || check "X-Content-Type-Options" "yes" "no"

echo
echo "Summary: $PASS passed, $FAIL failed."

if (( FAIL > 0 )); then
    [[ $STRICT -eq 1 ]] && exit 1 || exit 0
fi
exit 0
