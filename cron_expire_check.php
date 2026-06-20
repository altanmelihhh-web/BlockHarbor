<?php
/**
 * Cyberwebeyeos — Expiration Check Cron (R28 T1.2)
 *
 * Süresi dolan IoC'leri tespit eder. İki mod:
 *   --report (default): listele, audit log'a kaydet, dosyaya dokunma
 *   --move:             süresi dolanları blacklist.txt'den çıkarıp pending'e ekle
 *
 * Cron örneği (root crontab):
 *   0 3 * * * /usr/bin/php /var/www/html/cron_expire_check.php --report
 *
 * Çıktı kod: 0 = expired yok, 1 = expired var, 2 = hata
 */

require_once __DIR__ . '/ioc_helpers.php';
require_once __DIR__ . '/audit_log.php';

$MOVE = in_array('--move', $argv, true);
$QUIET = in_array('--quiet', $argv, true) || in_array('-q', $argv, true);

$BLACKLIST = __DIR__ . '/blacklist.txt';
$FEED = __DIR__ . '/cyberwebeyeosblacklist.txt';
$PENDING = __DIR__ . '/pending_ips.json';

// SPRINT6-A4: CVE-bound IoC TTL expiry (defined early so R28 early exits don't skip it)
function expire_run_cve_bound(): array {
    $now = time();
    $bl_file      = __DIR__ . '/blacklist.txt';
    $meta_file    = __DIR__ . '/blacklist_meta.json';
    $pending_file = __DIR__ . '/pending_ips.json';

    if (!file_exists($bl_file)) return ['ok' => false, 'error' => 'blacklist.txt missing'];

    $bl_lines = file($bl_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($bl_lines === false) return ['ok' => false, 'error' => 'cannot read blacklist'];

    $meta = [];
    if (file_exists($meta_file)) {
        $j = json_decode(file_get_contents($meta_file), true);
        $meta = is_array($j) ? $j : [];
    }

    $pending = [];
    if (file_exists($pending_file)) {
        $j = json_decode(file_get_contents($pending_file), true);
        $pending = is_array($j) ? $j : [];
    }

    $kept  = [];
    $moved = 0;

    foreach ($bl_lines as $line) {
        if ($line === '' || ltrim($line)[0] === '#') { $kept[] = $line; continue; }
        $parts = explode('|', $line);
        $value = $parts[0] ?? '';
        if ($value === '') { $kept[] = $line; continue; }

        $meta_row    = $meta[$value] ?? null;
        $is_cve_bound = $meta_row && isset($meta_row['source']) && strpos($meta_row['source'], 'cve:') === 0;

        if (!$is_cve_bound) { $kept[] = $line; continue; }

        $exp_str = $meta_row['expires_at'] ?? ($parts[9] ?? '');
        $exp_ts  = $exp_str ? strtotime($exp_str) : 0;

        if ($exp_ts && $exp_ts < $now) {
            $pending[$value] = [
                'reason'        => 'auto_expire_cve',
                'cve_ref'       => $meta_row['cve_ref'] ?? '',
                'original_line' => $line,
                'expired_at'    => gmdate('c', $exp_ts),
                'moved_at'      => gmdate('c'),
            ];
            unset($meta[$value]);
            $moved++;
            if (function_exists('audit_log_event')) {
                audit_log_event('auto_expire_cve', ['ip' => $value, 'cve' => $meta_row['cve_ref'] ?? '']);
            }
        } else {
            $kept[] = $line;
        }
    }

    if ($moved > 0) {
        // Rewrite blacklist.txt with file-lock
        $fh = fopen($bl_file, 'c+');
        if ($fh && flock($fh, LOCK_EX)) {
            ftruncate($fh, 0); rewind($fh);
            fwrite($fh, implode("\n", $kept) . "\n");
            fflush($fh); flock($fh, LOCK_UN);
        }
        if ($fh) fclose($fh);

        // Save meta
        $fh = fopen($meta_file, 'c+');
        if ($fh && flock($fh, LOCK_EX)) {
            ftruncate($fh, 0); rewind($fh);
            fwrite($fh, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            fflush($fh); flock($fh, LOCK_UN);
        }
        if ($fh) fclose($fh);

        // Save pending
        $fh = fopen($pending_file, 'c+');
        if ($fh && flock($fh, LOCK_EX)) {
            ftruncate($fh, 0); rewind($fh);
            fwrite($fh, json_encode($pending, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            fflush($fh); flock($fh, LOCK_UN);
        }
        if ($fh) fclose($fh);
    }

    return ['ok' => true, 'moved' => $moved, 'kept' => count($kept)];
}

// Run CVE-bound expiry first — always executes regardless of R28 exit paths below
$cve_result = expire_run_cve_bound();
if (!$QUIET) {
    echo "[" . date('Y-m-d H:i:s') . "] CVE-bound expiry: moved=" . ($cve_result['moved'] ?? 0) . " kept=" . ($cve_result['kept'] ?? '-') . "\n";
}

if (!file_exists($BLACKLIST)) {
    fwrite(STDERR, "blacklist.txt yok: $BLACKLIST\n");
    exit(2);
}

$lines = file($BLACKLIST, FILE_IGNORE_NEW_LINES);
$expired = [];
$kept = [];

foreach ($lines as $line) {
    if ($line === '' || ltrim($line)[0] === '#') {
        $kept[] = $line;
        continue;
    }
    $e = cwe_parse_blacklist_entry($line);
    if (cwe_is_expired($e)) {
        $expired[] = $e;
    } else {
        $kept[] = $line;
    }
}

$count = count($expired);

if (!$QUIET) {
    echo "[" . date('Y-m-d H:i:s') . "] Expired IoC tarandı: " . count($lines) . " satır → " . $count . " expired\n";
}

if ($count === 0) {
    audit_log_event('expire_check', ['expired'=>0, 'mode'=>$MOVE ? 'move' : 'report']);
    exit(0);
}

if (!$QUIET) {
    foreach (array_slice($expired, 0, 10) as $e) {
        printf("  EXPIRED  %-40s  vu=%s  type=%s  conf=%d\n", $e['value'], $e['valid_until'], $e['type'], $e['confidence']);
    }
    if ($count > 10) echo "  … ve {$count} − 10 daha\n";
}

if ($MOVE) {
    // Backup + rewrite blacklist.txt without expired
    $backup = $BLACKLIST . '.bak-expire-' . date('Ymd-His');
    if (!copy($BLACKLIST, $backup)) {
        fwrite(STDERR, "Backup başarısız: $backup\n");
        exit(2);
    }
    file_put_contents($BLACKLIST, implode("\n", $kept) . "\n");

    // Feed'i de yeniden oluştur
    $feed_lines = [];
    foreach ($kept as $line) {
        if ($line === '' || ltrim($line)[0] === '#') continue;
        $e = cwe_parse_blacklist_entry($line);
        $feed_lines[] = $e['value'];
    }
    file_put_contents($FEED, implode("\n", $feed_lines) . "\n");

    // Pending'e ekle (basit append)
    $pending = json_decode(@file_get_contents($PENDING), true);
    if (!is_array($pending)) $pending = ['pending_ips' => []];
    if (!isset($pending['pending_ips'])) $pending['pending_ips'] = [];

    foreach ($expired as $e) {
        $pending['pending_ips'][] = [
            'ip'         => $e['value'],
            'source'     => 'expired:' . $e['type'],
            'created_at' => date('Y-m-d H:i:s'),
            'status'     => 'pending',
            'token'      => bin2hex(random_bytes(16)),
            'reason'     => 'Auto-expired (valid_until=' . $e['valid_until'] . ')',
            'expired_from' => [
                'tlp'         => $e['tlp'],
                'confidence'  => $e['confidence'],
                'comment'     => $e['comment'],
                'added_by'    => $e['added_by'],
            ],
        ];
    }
    file_put_contents($PENDING, json_encode($pending, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

    if (!$QUIET) echo "Move: {$count} entry blacklist'ten kaldırıldı, pending'e taşındı. Backup: {$backup}\n";
    audit_log_event('expire_check', ['expired'=>$count, 'mode'=>'move', 'backup'=>basename($backup)]);
} else {
    audit_log_event('expire_check', ['expired'=>$count, 'mode'=>'report',
        'sample' => array_map(fn($e) => $e['value'], array_slice($expired, 0, 5))
    ]);
}

exit(1); // expired var → 1
