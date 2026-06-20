<?php
/**
 * Cyberwebeyeos — Warninglist Refresh (R41 T4.1)
 *
 * Statik listeler (rfc1918, iana_reserved, public_dns) repository'de checked-in.
 * Bu script sadece Tranco top-N domain listesini günceller.
 *
 * Tranco: https://tranco-list.eu/  — Alexa Top 1M'in yerini alan kararlı liste.
 * Top 10K çekilir (full 1M = 25MB+, taranması yavaş). Domain-only filtre.
 *
 * Modlar:
 *   CLI: php warninglist_sync.php [--top=10000] [--dry] [--quiet]
 *   Web: POST /warninglist_sync.php (RBAC admin)
 *
 * Cron örneği: 0 2 * * 1 /usr/bin/php /var/www/html/warninglist_sync.php --quiet
 */

require_once __DIR__ . '/ioc_helpers.php';

$IS_CLI = (php_sapi_name() === 'cli');
$OUT_FILE = __DIR__ . '/warninglists/tranco_top.txt';

$TOP = 10000; $DRY = false; $QUIET = false; $WEB_OWNER = '';
if ($IS_CLI) {
    foreach ($argv as $a) {
        if ($a === '--dry' || $a === '-n') $DRY = true;
        elseif ($a === '--quiet' || $a === '-q') $QUIET = true;
        elseif (preg_match('/^--top=(\d+)$/', $a, $m)) $TOP = max(100, min(100000, (int)$m[1]));
    }
} else {
    require_once __DIR__ . '/blacklist_admin_auth.php';
    require_once __DIR__ . '/audit_log.php';
    require_role(['admin']);
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        header('Content-Type: application/json');
        echo json_encode(['ok'=>false, 'error'=>'POST required']);
        exit;
    }
    header('Content-Type: application/json; charset=utf-8');
    $DRY = !empty($_POST['dry']);
    if (!empty($_POST['top'])) $TOP = max(100, min(100000, (int)$_POST['top']));
    $WEB_OWNER = cwe_current_user() ?: 'web';
}

/**
 * Tranco list — daily ID redirect'i çöz. Direct top-1m URL "tranco-list.eu/top/{listId}-1m.csv.zip" gibi.
 * En kolay: https://tranco-list.eu/top-1m.csv.zip (latest)
 * ZIP gerekiyor — pragmatik: text wget hatlı `top-1m.csv` mirror'larını kullan.
 *
 * Burada: Cloudflare Radar Top Domains CSV — auth gereksiz, daily JSON.
 * Fallback: Tranco latest ID'sini al, top-N csv'sini çek.
 */
function _fetch_top_domains(int $n): array {
    // Tranco daily list ID
    $idRaw = @file_get_contents('https://tranco-list.eu/api/lists/date/latest');
    if ($idRaw) {
        $j = json_decode($idRaw, true);
        $list_id = $j['list_id'] ?? null;
        if ($list_id) {
            // Tranco download endpoint: /download/{id}/{N}
            $url = "https://tranco-list.eu/download/{$list_id}/{$n}";
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_USERAGENT => 'cyberwebeyeos-tip/1.0',
            ]);
            $body = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($code === 200 && $body) {
                $domains = [];
                $lines = preg_split('/\r?\n/', $body);
                foreach ($lines as $line) {
                    if (count($domains) >= $n) break;
                    $line = trim($line);
                    if ($line === '') continue;
                    $parts = explode(',', $line, 2);
                    $rank = (int)$parts[0];
                    $dom = strtolower(trim($parts[1] ?? ''));
                    if ($rank === 0 || !preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/', $dom)) continue;
                    $domains[] = ['rank' => $rank, 'domain' => $dom];
                }
                return $domains;
            }
        }
    }
    return [];
}

if (!$QUIET) echo "[" . date('Y-m-d H:i:s') . "] Fetching Tranco top-{$TOP}...\n";
$domains = _fetch_top_domains($TOP);

if (empty($domains)) {
    $err = ['ok'=>false, 'error'=>'Tranco fetch başarısız'];
    if ($IS_CLI) { fwrite(STDERR, $err['error']."\n"); exit(2); }
    echo json_encode($err); exit;
}

$payload = [
    'ok' => true,
    'fetched' => count($domains),
    'top_requested' => $TOP,
    'sample' => array_slice(array_map(fn($d) => $d['domain'], $domains), 0, 5),
    'dry' => $DRY,
];

if ($DRY) {
    $payload['message'] = '[DRY] Yazma yapılmadı';
    if ($IS_CLI) { if (!$QUIET) print_r($payload); exit(0); }
    echo json_encode($payload); exit;
}

// Write
$lines = [
    '# Tranco Top-' . count($domains) . ' Popular Domains',
    '# Source: https://tranco-list.eu/  · Synced: ' . date('Y-m-d H:i:s'),
    '# Format: <domain>|rank:N',
];
foreach ($domains as $d) {
    $lines[] = $d['domain'] . '|rank:' . $d['rank'];
}
$tmp = $OUT_FILE . '.tmp';
file_put_contents($tmp, implode("\n", $lines) . "\n");
rename($tmp, $OUT_FILE);
@chmod($OUT_FILE, 0664);

$payload['message'] = "✅ Tranco top-" . count($domains) . " sync edildi → " . basename($OUT_FILE);

if (function_exists('audit_log_event')) {
    audit_log_event('warninglist_sync', ['count'=>count($domains), 'top'=>$TOP, 'file'=>basename($OUT_FILE), 'owner'=>$WEB_OWNER ?: 'cron']);
}

if ($IS_CLI) { if (!$QUIET) print_r($payload); exit(0); }
echo json_encode($payload, JSON_UNESCAPED_UNICODE);
