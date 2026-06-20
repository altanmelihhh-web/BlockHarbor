<?php
/**
 * Cyberwebeyeos — CIDR Aggregation (R33 T2.3)
 *
 * blacklist.txt'teki tek IP'leri (type=ip-src) /24 bloklara grupla. Aynı /24'te
 * eşik (default 50) sayıda veya daha fazla IP varsa, hepsini tek bir CIDR satırı
 * ile değiştir. comment 'aggregated from N IPs (192.0.2.{1,3,5,...})' formatında.
 *
 * Modlar:
 *   Web: POST /cidr_aggregate.php  (RBAC admin only, audit log)
 *        — query 'dry=1' veya 'threshold=N' opsiyonel
 *   CLI: php cidr_aggregate.php [--dry] [--threshold=50] [--quiet]
 *
 * Backup: blacklist.txt.bak-cidragg-<ts>
 *
 * Çıktı (web): JSON {ok, aggregated_count, total_collapsed_ips, sample, dry}
 */

require_once __DIR__ . '/ioc_helpers.php';

$IS_CLI = (php_sapi_name() === 'cli');
$BLACKLIST = __DIR__ . '/blacklist.txt';
$FEED = __DIR__ . '/cyberwebeyeosblacklist.txt';

// --- Auth + RBAC (web only) ---
$DRY = false; $THRESHOLD = 50; $QUIET = false; $WEB_OWNER = '';
if ($IS_CLI) {
    foreach ($argv as $a) {
        if ($a === '--dry' || $a === '-n') $DRY = true;
        elseif ($a === '--quiet' || $a === '-q') $QUIET = true;
        elseif (preg_match('/^--threshold=(\d+)$/', $a, $m)) $THRESHOLD = max(2, (int)$m[1]);
    }
} else {
    require_once __DIR__ . '/blacklist_admin_auth.php';
    require_once __DIR__ . '/audit_log.php';
    require_role(['admin']);
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        header('Content-Type: application/json');
        echo json_encode(['ok'=>false,'error'=>'POST required']);
        exit;
    }
    header('Content-Type: application/json; charset=utf-8');
    $DRY = !empty($_POST['dry']);
    if (!empty($_POST['threshold'])) $THRESHOLD = max(2, (int)$_POST['threshold']);
    $WEB_OWNER = cwe_current_user() ?: 'web';
}

if (!file_exists($BLACKLIST)) {
    if ($IS_CLI) { fwrite(STDERR, "blacklist.txt yok\n"); exit(1); }
    echo json_encode(['ok'=>false,'error'=>'blacklist.txt yok']); exit;
}

$raw_lines = file($BLACKLIST, FILE_IGNORE_NEW_LINES);
$entries = [];        // index → parsed entry
$comment_lines = [];  // index → original line (header/comment passthrough)

foreach ($raw_lines as $i => $line) {
    if ($line === '' || (isset($line[0]) && $line[0] === '#')) {
        $comment_lines[$i] = $line;
        continue;
    }
    $entries[$i] = cwe_parse_blacklist_entry($line);
}

// --- /24 grupla (sadece IPv4 single IP'ler) ---
$buckets = []; // '192.0.2' → [index, index, ...]
foreach ($entries as $i => $e) {
    if ($e['type'] !== 'ip-src') continue;
    $ip = $e['value'];
    // /32 varsa strip
    if (preg_match('#^(\d+\.\d+\.\d+\.\d+)(/32)?$#', $ip, $m)) {
        $octets = explode('.', $m[1]);
        $key = $octets[0] . '.' . $octets[1] . '.' . $octets[2];
        $last = $octets[3];
        $buckets[$key][] = ['index' => $i, 'last' => (int)$last, 'value' => $m[1]];
    }
}

$aggregations = [];
foreach ($buckets as $cidr_base => $members) {
    if (count($members) < $THRESHOLD) continue;
    // Eşik geçildi — bunları tek CIDR'a indirgeyeceğiz
    $aggregations[] = ['cidr' => $cidr_base . '.0/24', 'base' => $cidr_base, 'members' => $members];
}

$total_collapsed = 0;
foreach ($aggregations as $agg) $total_collapsed += count($agg['members']);

if (empty($aggregations)) {
    $payload = ['ok'=>true, 'aggregated_count'=>0, 'total_collapsed_ips'=>0, 'message'=>'Eşiği aşan /24 bloğu yok', 'threshold'=>$THRESHOLD, 'dry'=>$DRY];
    if ($IS_CLI) { if (!$QUIET) print_r($payload); exit(0); }
    echo json_encode($payload); exit;
}

// --- Yeni satır listesi oluştur ---
$now = date('Y-m-d H:i:s');
$removed_indices = [];
foreach ($aggregations as $agg) {
    foreach ($agg['members'] as $m) $removed_indices[$m['index']] = true;
}

$new_lines = [];
$inserted_aggs = []; // sample for response

// Mevcut satırları sırayla işle — kaldırılacaklar dışındaki tüm satırları koru
foreach ($raw_lines as $i => $line) {
    if (isset($removed_indices[$i])) continue;
    $new_lines[] = $line;
}

// Her aggregation için bir yeni CIDR satırı ekle
foreach ($aggregations as $agg) {
    $ips_sample = array_map(fn($m) => $m['value'], array_slice($agg['members'], 0, 5));
    $comment = sprintf("aggregated from %d IPs (örnek: %s%s)",
        count($agg['members']),
        implode(', ', $ips_sample),
        count($agg['members']) > 5 ? '...' : ''
    );
    $new_entry = [
        'value' => $agg['cidr'],
        'comment' => $comment,
        'date' => $now,
        'fqdn' => '',
        'jira' => '',
        'tlp' => 'WHITE',
        'type' => 'cidr',
        'added_by' => 'cidr-aggregate' . ($WEB_OWNER ? ':' . $WEB_OWNER : ':cron'),
        'confidence' => 50, // ihtiyatlı — bireysel IP'lerin avg'ı yerine 50 verdik
        'valid_until' => 'permanent',
    ];
    $new_lines[] = cwe_format_blacklist_entry($new_entry);
    $inserted_aggs[] = ['cidr' => $agg['cidr'], 'collapsed' => count($agg['members'])];
}

$payload = [
    'ok' => true,
    'aggregated_count' => count($aggregations),
    'total_collapsed_ips' => $total_collapsed,
    'inserted' => $inserted_aggs,
    'threshold' => $THRESHOLD,
    'dry' => $DRY,
];

if ($DRY) {
    $payload['message'] = '[DRY] Değişiklik uygulanmadı';
    if ($IS_CLI) { if (!$QUIET) print_r($payload); exit(0); }
    echo json_encode($payload, JSON_UNESCAPED_UNICODE); exit;
}

// Backup + write
$backup = $BLACKLIST . '.bak-cidragg-' . date('Ymd-His');
if (!copy($BLACKLIST, $backup)) {
    $err = ['ok'=>false, 'error'=>'Backup başarısız', 'backup'=>$backup];
    if ($IS_CLI) { fwrite(STDERR, $err['error']."\n"); exit(2); }
    echo json_encode($err); exit;
}

// Atomic write with flock
$fh = fopen($BLACKLIST, 'w');
if (!$fh || !flock($fh, LOCK_EX)) {
    if ($fh) fclose($fh);
    $err = ['ok'=>false, 'error'=>'Dosya kilitlenemedi'];
    if ($IS_CLI) { fwrite(STDERR, $err['error']."\n"); exit(2); }
    echo json_encode($err); exit;
}
fwrite($fh, implode("\n", $new_lines) . "\n");
fflush($fh); flock($fh, LOCK_UN); fclose($fh);

// Feed rebuild
$feed_vals = [];
foreach ($new_lines as $line) {
    if ($line === '' || (isset($line[0]) && $line[0] === '#')) continue;
    $e = cwe_parse_blacklist_entry($line);
    $feed_vals[] = $e['value'];
}
file_put_contents($FEED, implode("\n", $feed_vals) . "\n");

$payload['backup'] = basename($backup);
$payload['message'] = sprintf("✅ %d /24 bloğu aggregate edildi (%d IP → %d CIDR)",
    count($aggregations), $total_collapsed, count($aggregations));

if (function_exists('audit_log_event')) {
    audit_log_event('cidr_aggregate', [
        'aggregated_count' => count($aggregations),
        'total_collapsed_ips' => $total_collapsed,
        'threshold' => $THRESHOLD,
        'inserted' => $inserted_aggs,
        'backup' => basename($backup),
        'owner' => $WEB_OWNER ?: 'cron',
    ]);
}

if ($IS_CLI) { if (!$QUIET) print_r($payload); exit(0); }
echo json_encode($payload, JSON_UNESCAPED_UNICODE);
