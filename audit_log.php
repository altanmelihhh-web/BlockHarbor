<?php
/**
 * Cyberwebeyeos Audit Log
 *
 * Kim/ne/ne zaman/nereden — tüm değişiklik takibi.
 * JSON-lines format (her satır bir event), append-only.
 *
 * R47 (T5.2): Immutable Hash Chain
 *   Her satır format:  <line_hash>|<json>
 *   line_hash = sha256(prev_hash + "|" + json)
 *   Genesis prev_hash = "0" * 64 (64-char hex)
 *   Backward compat: prefix'siz eski satırlar verify aşamasında atlanır
 *                    (chain dosya başından başlar; mevcut log değişmez,
 *                     yeni satırlar prefix'li yazılır).
 */

define('AUDIT_LOG_FILE', __DIR__ . '/audit.log');
const AUDIT_GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Mevcut log dosyasının son hash'ini bul.
 * Prefix'siz satırlar geçilir (gerçek prefix bulunana kadar arar).
 * Hiç prefix yoksa genesis döner — dosyanın ucundan yeni chain başlatılır.
 */
function _audit_last_hash(): string {
    if (!file_exists(AUDIT_LOG_FILE)) return AUDIT_GENESIS_HASH;
    $sz = filesize(AUDIT_LOG_FILE);
    if ($sz === 0) return AUDIT_GENESIS_HASH;
    $fh = fopen(AUDIT_LOG_FILE, 'r');
    if (!$fh) return AUDIT_GENESIS_HASH;
    // Sondan yukarı sıçra (max 8KB)
    $chunk = 8192;
    fseek($fh, max(0, $sz - $chunk));
    $tail = stream_get_contents($fh);
    fclose($fh);
    $lines = preg_split('/\r?\n/', rtrim($tail, "\r\n"));
    for ($i = count($lines) - 1; $i >= 0; $i--) {
        $line = $lines[$i];
        if (preg_match('/^([a-f0-9]{64})\|/', $line, $m)) return $m[1];
    }
    return AUDIT_GENESIS_HASH;
}

/**
 * Audit event ekle
 * @param string $action  e.g. 'blacklist_add', 'whitelist_delete', 'user_create'
 * @param array  $details additional context
 */
function audit_log_event(string $action, array $details = []): void {
    $event = [
        'ts'      => date('Y-m-d H:i:s'),
        'user'    => $_SESSION['cwe_user'] ?? 'anon',
        'ip'      => $_SERVER['REMOTE_ADDR'] ?? '-',
        'action'  => $action,
        'details' => $details,
    ];
    $json = json_encode($event, JSON_UNESCAPED_UNICODE);

    // R47 (T5.2): hash chain — prev_hash + "|" + json
    $prev_hash = _audit_last_hash();
    $line_hash = hash('sha256', $prev_hash . '|' . $json);
    $line_out = $line_hash . '|' . $json;

    @file_put_contents(AUDIT_LOG_FILE, $line_out . "\n", FILE_APPEND | LOCK_EX);
    if (file_exists(AUDIT_LOG_FILE)) @chmod(AUDIT_LOG_FILE, 0664);

    // R37 (T3.2): Syslog forwarder
    static $syslog_loaded = null;
    if ($syslog_loaded === null) {
        $cfg = @json_decode(@file_get_contents(__DIR__ . '/notifications.json'), true) ?: [];
        $syslog_loaded = $cfg['syslog'] ?? ['enabled' => false];
        if (!empty($syslog_loaded['enabled'])) {
            $facility_map = [
                'local0'=>LOG_LOCAL0,'local1'=>LOG_LOCAL1,'local2'=>LOG_LOCAL2,'local3'=>LOG_LOCAL3,
                'local4'=>LOG_LOCAL4,'local5'=>LOG_LOCAL5,'local6'=>LOG_LOCAL6,'local7'=>LOG_LOCAL7,
                'user'=>LOG_USER, 'daemon'=>LOG_DAEMON,
            ];
            $facility = $facility_map[strtolower($syslog_loaded['facility'] ?? 'local0')] ?? LOG_LOCAL0;
            $ident = trim($syslog_loaded['ident'] ?? 'cyberwebeyeos-tip');
            @openlog($ident, LOG_PID | LOG_NDELAY, $facility);
        }
    }
    if (!empty($syslog_loaded['enabled'])) {
        @syslog(LOG_NOTICE, $json);
    }

    // Notification hook
    static $notify_loaded = false;
    if (!$notify_loaded) { @include_once __DIR__ . '/notify.php'; $notify_loaded = true; }
    if (function_exists('send_notification')) {
        @send_notification($action, $details);
    }
}

/**
 * Bir satırın prefix'ini soyup JSON kısmını döner. Prefix yoksa satırın kendisini.
 */
function _audit_strip_hash(string $line): string {
    if (preg_match('/^[a-f0-9]{64}\|(.*)$/', $line, $m)) return $m[1];
    return $line;
}

/**
 * Son N event'i oku (en yeni en üstte). Prefix var/yok transparent.
 */
function audit_log_recent(int $limit = 50, ?string $filter_action = null, ?string $filter_user = null): array {
    if (!file_exists(AUDIT_LOG_FILE)) return [];
    $lines = @file(AUDIT_LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $lines = array_reverse($lines);
    $events = [];
    foreach ($lines as $line) {
        $json = _audit_strip_hash($line);
        $e = json_decode($json, true);
        if (!is_array($e)) continue;
        if ($filter_action !== null && ($e['action'] ?? '') !== $filter_action) continue;
        if ($filter_user !== null && ($e['user'] ?? '') !== $filter_user) continue;
        $events[] = $e;
        if (count($events) >= $limit) break;
    }
    return $events;
}

/**
 * Audit özet (son 24h)
 */
function audit_log_summary(): array {
    if (!file_exists(AUDIT_LOG_FILE)) return [];
    $cutoff = time() - 86400;
    $by_action = [];
    $by_user = [];
    $total = 0;
    foreach (@file(AUDIT_LOG_FILE, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        $json = _audit_strip_hash($line);
        $e = json_decode($json, true);
        if (!is_array($e)) continue;
        $ts = strtotime($e['ts'] ?? '');
        if ($ts < $cutoff) continue;
        $total++;
        $by_action[$e['action'] ?? '-'] = ($by_action[$e['action'] ?? '-'] ?? 0) + 1;
        $by_user[$e['user'] ?? '-'] = ($by_user[$e['user'] ?? '-'] ?? 0) + 1;
    }
    arsort($by_action); arsort($by_user);
    return ['total_24h' => $total, 'by_action' => $by_action, 'by_user' => $by_user];
}

/**
 * R47 (T5.2): Chain'i baştan sona doğrula.
 * Returns ['ok'=>bool, 'verified'=>N, 'legacy_skipped'=>N, 'first_break'=>['line'=>N,'expected'=>...,'actual'=>...]]
 */
function audit_log_verify_chain(): array {
    if (!file_exists(AUDIT_LOG_FILE)) return ['ok' => true, 'verified' => 0, 'legacy_skipped' => 0];
    $lines = @file(AUDIT_LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $verified = 0;
    $legacy = 0;
    $prev_hash = AUDIT_GENESIS_HASH;
    $chain_started = false;
    foreach ($lines as $i => $line) {
        if (!preg_match('/^([a-f0-9]{64})\|(.*)$/', $line, $m)) {
            // Pre-chain legacy line
            if ($chain_started) {
                // Chain başladıktan sonra prefix'siz satır → KORUPSİYON
                return [
                    'ok' => false,
                    'verified' => $verified,
                    'legacy_skipped' => $legacy,
                    'first_break' => ['line' => $i + 1, 'reason' => 'unprefixed line after chain start'],
                ];
            }
            $legacy++;
            continue;
        }
        [, $line_hash, $json] = $m;
        $expected = hash('sha256', $prev_hash . '|' . $json);
        if (!hash_equals($expected, $line_hash)) {
            return [
                'ok' => false,
                'verified' => $verified,
                'legacy_skipped' => $legacy,
                'first_break' => [
                    'line' => $i + 1,
                    'expected' => $expected,
                    'actual' => $line_hash,
                    'json_preview' => mb_substr($json, 0, 120),
                ],
            ];
        }
        $prev_hash = $line_hash;
        $verified++;
        $chain_started = true;
    }
    return ['ok' => true, 'verified' => $verified, 'legacy_skipped' => $legacy, 'last_hash' => $prev_hash];
}
