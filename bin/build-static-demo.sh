#!/usr/bin/env bash
#
# Build a static snapshot of the demo for GitHub Pages.
#
# GitHub Pages cannot execute PHP, so this boots the real application in demo
# mode, exercises it over HTTP, and captures what it produces: the HTML pages
# plus every JSON response the dashboard asks for. A small shim is injected into
# the captured HTML that answers fetch() from the captured responses, so the
# interactive parts of the UI keep working without a backend.
#
# Usage:  bash bin/build-static-demo.sh [output-dir]
# Output: static-demo/ (default), ready to publish to Pages.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/static-demo}"
PORT="${STATIC_DEMO_PORT:-8899}"
BASE="http://127.0.0.1:$PORT"

command -v php >/dev/null || { echo "php is required" >&2; exit 1; }

echo "==> Seeding the demo dataset"
DEMO_MODE=true php "$ROOT/bin/seed-demo.php" >/dev/null

echo "==> Starting the application in demo mode on port $PORT"
# Portable across BSD and GNU mktemp: -t without X's is a BSD-only spelling.
ROUTER="$(mktemp "${TMPDIR:-/tmp}/bhrouter.XXXXXX").php"
cat > "$ROUTER" <<'PHP'
<?php
$root = getenv('BH_ROOT');
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($uri === '/' || $uri === '') $uri = '/index.php';
$file = $root . $uri;
if (!is_file($file)) { http_response_code(404); echo 'not found'; return true; }
if (substr($file, -4) !== '.php') return false;
$_SERVER['SCRIPT_NAME'] = $uri;
$_SERVER['SCRIPT_FILENAME'] = $file;
unset($_SERVER['PATH_INFO']);
require $root . '/demo_mode.php';
require $file;
return true;
PHP

BH_ROOT="$ROOT" DEMO_MODE=true CWE_BASE_PATH=/ CWE_USOM_BASE= \
    php -S "127.0.0.1:$PORT" -t "$ROOT" "$ROUTER" >/tmp/static-demo-server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; rm -f "$ROUTER"' EXIT

for _ in $(seq 1 40); do
    curl -fsS -o /dev/null "$BASE/login.php" 2>/dev/null && break
    sleep 0.25
done

COOKIES="$(mktemp)"
curl -fsS -c "$COOKIES" -o /dev/null -d "username=demo&password=demo" "$BASE/login.php"
grep -q CWE_BLACKLIST_SESSION "$COOKIES" || { echo "demo login failed" >&2; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT/_api"

# ---------------------------------------------------------------- HTML pages --
# Only read-only views. Everything that mutates state is refused by demo mode
# anyway, and has no meaning in a snapshot.
# audit_log.php is a library (it only defines helpers) and search.php is a JSON
# API — neither renders a page, so both are captured as API responses instead.
PAGES=(
    cyberwebeyeosblacklistadmin.php
    feed_health.php
    whitelist-readonly.php
    verify_audit.php
)
echo "==> Capturing pages"
for page in "${PAGES[@]}"; do
    out="$OUT/${page%.php}.html"
    curl -fsS -b "$COOKIES" "$BASE/$page" -o "$out"
    printf '    %-34s %8s bytes\n' "$page" "$(wc -c < "$out" | tr -d ' ')"
done
cp "$OUT/cyberwebeyeosblacklistadmin.html" "$OUT/index.html"

# ------------------------------------------------------------ API responses --
# Keyed by the exact URL the front-end requests, so the shim can look them up.
echo "==> Capturing API responses"
: > "$OUT/_api/index.txt"
capture() {
    local q="$1"
    local key
    key="$(printf '%s' "$q" | shasum | cut -c1-16)"
    if curl -fsS -b "$COOKIES" "$BASE/$q" -o "$OUT/_api/$key.json" 2>/dev/null; then
        printf '%s\t%s\n' "$q" "$key" >> "$OUT/_api/index.txt"
        printf '    %-52s -> %s\n' "$q" "$key"
    fi
}

capture "dashboard_stats.php"
capture "cve_action.php?action=list"
capture "cve_action.php?action=stats"
capture "feed_health.php?json"
capture "verify_audit.php?json=1"

# Enrichment, provenance, history and pivot for the seeded indicators, so
# clicking around the snapshot returns real captured output.
SAMPLE_IPS="$(grep -oE '^(192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]+' "$ROOT/blacklist.txt" | head -40)"
for ip in $SAMPLE_IPS; do
    capture "enrichment.php?value=$ip"
    capture "enrichment.php?action=vt&value=$ip"
    capture "ioc_provenance.php?ip=$ip"
    capture "ioc_history.php?value=$ip"
done

SAMPLE_CVES="$(php -r '$d=json_decode(file_get_contents($argv[1]),true); echo implode(" ", array_slice(array_keys($d),0,20));' "$ROOT/cve_state.json")"
for cve in $SAMPLE_CVES; do
    capture "ioc_pivot.php?action=lookup&cve=$cve"
done

for q in 192.0.2 198.51.100 203.0.113 malicious phishing scanning; do
    capture "search.php?q=$q&json=1"
done

# --------------------------------------------------------------- static feed --
cp "$ROOT/cyberwebeyeosblacklist.txt" "$OUT/cyberwebeyeosblacklist.txt" 2>/dev/null || true

# ---------------------------------------------------------------- fetch shim --
echo "==> Building the fetch shim"
php -r '
$dir = $argv[1];
$map = [];
foreach (file("$dir/_api/index.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
    [$q, $key] = explode("\t", $line);
    $body = @file_get_contents("$dir/_api/$key.json");
    if ($body !== false) { $map[$q] = json_decode($body, true); }
}
file_put_contents("$dir/demo-data.js",
    "window.__BH_STATIC__ = " . json_encode($map, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . ";\n");
' "$OUT"

cat > "$OUT/static-demo.js" <<'JSEOF'
/* Static snapshot shim.
 *
 * The pages in this directory were produced by the real application; there is
 * no backend here. Every fetch() the UI makes is answered from the responses
 * captured at build time, so navigation, enrichment lookups, provenance and
 * pivots all show genuine output. Anything that was not captured (an arbitrary
 * search term, a write) returns an explanatory payload rather than failing.
 */
(function () {
  var data = window.__BH_STATIC__ || {};
  var realFetch = window.fetch ? window.fetch.bind(window) : null;

  // Map a request to the key it was captured under. Captured keys are relative
  // to the directory the snapshot is served from ("dashboard_stats.php",
  // "enrichment.php?value=192.0.2.4"), and that directory is not the domain
  // root on GitHub Pages — it is /<repo>/. Resolving against the page URL and
  // then stripping the page's own directory is what makes the two line up.
  function normalise(url) {
    var abs;
    try { abs = new URL(url, window.location.href); }
    catch (e) { return String(url).replace(/^\.?\//, ''); }
    if (abs.origin !== window.location.origin) return abs.href;
    var baseDir = window.location.pathname.replace(/[^/]*$/, '');
    var path = abs.pathname;
    if (path.indexOf(baseDir) === 0) path = path.slice(baseDir.length);
    else path = path.replace(/^\//, '');
    return path + abs.search;
  }

  function respond(payload, status) {
    return Promise.resolve(new Response(JSON.stringify(payload), {
      status: status || 200,
      headers: { 'Content-Type': 'application/json' }
    }));
  }

  window.fetch = function (input, init) {
    var url = normalise(typeof input === 'string' ? input : (input && input.url) || '');
    var method = ((init && init.method) || 'GET').toUpperCase();

    if (method !== 'GET' && method !== 'HEAD') {
      return respond({
        ok: false, error: 'static_demo',
        detail: 'This is a static snapshot — write operations are not available. ' +
                'Run the application locally to exercise them.'
      }, 403);
    }
    if (Object.prototype.hasOwnProperty.call(data, url)) {
      return respond(data[url]);
    }
    var bare = url.split('?')[0];
    if (Object.prototype.hasOwnProperty.call(data, bare)) {
      return respond(data[bare]);
    }
    return respond({
      ok: false, error: 'not_captured',
      detail: 'This request was not captured in the static snapshot. ' +
              'The seeded indicators and CVEs on this page do have captured responses.'
    }, 404);
  };

  // Neutralise form posts — there is nothing to post to. A non-blocking toast
  // rather than alert(): a modal dialog freezes the page for anyone driving it
  // programmatically and is poor UX besides.
  function toast(msg) {
    var el = document.getElementById('bh-static-toast');
    if (!el) {
      el = document.createElement('div');
      el.id = 'bh-static-toast';
      el.style.cssText = 'position:fixed;left:50%;bottom:24px;transform:translateX(-50%);' +
        'z-index:2147483647;background:#1e293b;color:#fff;padding:11px 18px;border-radius:8px;' +
        'font:500 13px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;max-width:min(90vw,32rem);' +
        'box-shadow:0 4px 16px rgba(0,0,0,.3);opacity:0;transition:opacity .18s';
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.opacity = '1';
    clearTimeout(el._t);
    el._t = setTimeout(function () { el.style.opacity = '0'; }, 4000);
  }

  document.addEventListener('submit', function (e) {
    e.preventDefault();
    toast('Static snapshot — forms are disabled. Run the application locally to use them.');
  }, true);

  // Same for confirm(): it blocks too, and several handlers gate on it.
  window.confirm = function () { return false; };
  window.alert = function (m) { toast(String(m)); };
})();
JSEOF

# --------------------------------------------------------- rewrite the pages --
echo "==> Rewriting captured pages"
php -r '
$dir = $argv[1];
$banner = "<div id=\"bh-static-banner\" style=\"position:sticky;top:0;z-index:99999;"
        . "background:#f1f5f9;color:#475569;border-bottom:1px solid #e2e8f0;padding:5px 14px;"
        . "font:400 11.5px/1.4 system-ui,-apple-system,Segoe UI,sans-serif;text-align:center\">"
        . "Demo &middot; synthetic data, read-only &middot; "
        . "<a href=\"https://github.com/altanmelihhh-web/BlockHarbor\" "
        . "style=\"color:#475569;text-decoration:underline\">source</a></div>";
foreach (glob("$dir/*.html") as $f) {
    $h = file_get_contents($f);
    // point internal .php links at the captured .html files
    $h = preg_replace_callback("/(href|action)=\"([a-z0-9_\-]+)\.php(#[^\"]*)?\"/i", function ($m) use ($dir) {
        return file_exists("$dir/{$m[2]}.html")
            ? $m[1] . "=\"{$m[2]}.html" . ($m[3] ?? "") . "\""
            : $m[1] . "=\"#\"";
    }, $h);
    // replace the demo-mode banner with the static-snapshot banner
    $h = preg_replace("/<div id=\"bh-demo-banner\".*?<\/div>/s", $banner, $h, 1);
    if (strpos($h, "bh-static-banner") === false) {
        $h = preg_replace("/(<body\b[^>]*>)/i", "$1" . $banner, $h, 1);
    }
    // Load the shim before anything else runs. The ?v= stamp is the content hash
    // of the two files: without it a returning visitor keeps the browser-cached
    // copy from an earlier build, and a shim that no longer matches the captured
    // data fails every lookup.
    $stamp = substr(hash("sha256",
        (string)@file_get_contents("$dir/demo-data.js") . (string)@file_get_contents("$dir/static-demo.js")), 0, 10);
    $tags = "<script src=\"demo-data.js?v=$stamp\"></script><script src=\"static-demo.js?v=$stamp\"></script>";
    $h = preg_replace("/(<\/head>)/i", $tags . "$1", $h, 1);
    if (strpos($h, "static-demo.js") === false) {
        $h = preg_replace("/(<body\b[^>]*>)/i", "$1" . $tags, $h, 1);
    }
    // The capture ran against a local server, so any URL the page built from
    // HTTP_HOST carries that host and port. Replace it with a neutral example
    // so the snapshot does not advertise 127.0.0.1:<build port>.
    $h = str_replace(["https://127.0.0.1:" . getenv("STATIC_DEMO_PORT_USED"),
                      "http://127.0.0.1:" . getenv("STATIC_DEMO_PORT_USED")],
                     "https://blockharbor.example.com", $h);
    $h = preg_replace("#https?://127\\.0\\.0\\.1(:\\d+)?#", "https://blockharbor.example.com", $h);
    file_put_contents($f, $h);
}
' "$OUT"

touch "$OUT/.nojekyll"
echo "==> Done: $OUT"
du -sh "$OUT"
echo "    $(find "$OUT" -name '*.html' | wc -l | tr -d ' ') pages, $(ls "$OUT/_api" | grep -c json) captured responses"
