<?php
/**
 * Cyberwebeyeos Global Search API
 * Tüm IoC kaynaklarında (blacklist + whitelist + pending + USOM + dinamik listeler) arama yapar.
 * Cevap JSON.
 */
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/ioc_helpers.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$q = trim($_GET['q'] ?? '');
$max = 20;

if ($q === '' || strlen($q) < 2) {
    echo json_encode(['ok' => true, 'q' => $q, 'results' => [], 'note' => 'En az 2 karakter']);
    exit;
}

$results = [];
$qLower = strtolower($q);

function _search_file($path, $source_label, $tab_hash, &$results, $q, $max) {
    if (count($results) >= $max) return;
    if (!file_exists($path)) return;
    $fh = @fopen($path, 'r');
    if (!$fh) return;
    $lineno = 0;
    while (($line = fgets($fh)) !== false) {
        $lineno++;
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        if (stripos($line, $q) !== false) {
            $results[] = [
                'value' => $line,
                'source' => $source_label,
                'tab' => $tab_hash,
                'line' => $lineno,
            ];
            if (count($results) >= $max) break;
        }
    }
    fclose($fh);
}

// 1) Manuel blacklist (R28 T1.2: ioc_helpers ile 10-field parse, tip+conf+expired metadata)
if (file_exists(__DIR__ . '/blacklist.txt') && count($results) < $max) {
    foreach (@file(__DIR__ . '/blacklist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $i => $line) {
        if ($line === '' || $line[0] === '#') continue;
        if (stripos($line, $q) !== false) {
            $e = cwe_parse_blacklist_entry($line);
            $extra = $e['comment'];
            if ($e['fqdn']) $extra .= ' · ' . $e['fqdn'];
            if (cwe_is_expired($e)) $extra .= ' · ⚠ EXPIRED';
            $results[] = [
                'value' => $e['value'],
                'extra' => trim($extra),
                'type' => $e['type'],
                'tlp' => $e['tlp'],
                'confidence' => $e['confidence'],
                'source' => 'Manuel',
                'tab' => 'blacklist',
                'line' => $i + 1,
            ];
            if (count($results) >= $max) break;
        }
    }
}

// 2) Whitelist
_search_file(__DIR__ . '/whitelist.txt', 'Whitelist', 'whitelist', $results, $q, $max);

// 3) Pending
if (file_exists(__DIR__ . '/pending_ips.json') && count($results) < $max) {
    $pj = @json_decode(@file_get_contents(__DIR__ . '/pending_ips.json'), true) ?: [];
    foreach (($pj['pending_ips'] ?? []) as $p) {
        if (stripos($p['ip'] ?? '', $q) !== false) {
            $results[] = ['value'=>$p['ip'], 'source'=>'Pending', 'tab'=>'pending', 'extra'=>$p['source'] ?? ''];
            if (count($results) >= $max) break;
        }
    }
}

// 4) Cyberwebeyeos combined feed
_search_file(__DIR__ . '/cyberwebeyeosblacklist.txt', 'Feed', 'blacklist', $results, $q, $max);

// 5) USOM feed dosyaları (büyük dosya: fgrep equivalent)
$usom_files = ['url-list.txt','domain-list.txt','ip-list.txt','url-only-list.txt','ip6-list.txt','ip6net-list.txt'];
foreach ($usom_files as $uf) {
    if (count($results) >= $max) break;
    $p = '/var/www/html/usom/' . $uf;
    if (!file_exists($p)) continue;
    // Büyük dosya için fgrep
    $cmd = 'fgrep -i ' . escapeshellarg($q) . ' ' . escapeshellarg($p) . ' 2>/dev/null | head -5';
    $out = @shell_exec($cmd);
    if ($out) {
        foreach (explode("\n", trim($out)) as $l) {
            $l = trim($l);
            if ($l === '' || $l[0] === '#') continue;
            $results[] = ['value'=>$l, 'source'=>'USOM ' . str_replace('.txt','',$uf), 'tab'=>'usom'];
            if (count($results) >= $max) break;
        }
    }
}

// 6) Dinamik listeler
$lists = @json_decode(@file_get_contents(__DIR__ . '/lists.json'), true) ?: ['lists'=>[]];
foreach (($lists['lists'] ?? []) as $L) {
    if (count($results) >= $max) break;
    if (empty($L['file']) || !file_exists($L['file'])) continue;
    _search_file($L['file'], 'Liste: ' . ($L['name'] ?? '-'), 'lists', $results, $q, $max);
}

echo json_encode(['ok' => true, 'q' => $q, 'count' => count($results), 'results' => $results], JSON_UNESCAPED_UNICODE);
