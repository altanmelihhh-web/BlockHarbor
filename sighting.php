<?php
/**
 * Cyberwebeyeos — Sighting Ingest Endpoint (R42 T4.2)
 *
 * SIEM (Wazuh/Splunk/Sentinel) bir IoC'yi gerçekten görünce buraya POST eder.
 * UYARI: HER firewall event'ini POST etme — sadece bizim blacklist'imize MATCH eden
 * event'leri gönder. Ham event = TIP DB şişer + faydasız.
 *
 * Auth: X-API-Key (api.php ile aynı key system, herhangi rol).
 *
 * Request:
 *   POST /sighting.php
 *   Content-Type: application/json
 *   X-API-Key: <key>
 *   Body:
 *     Single:   {"value":"1.2.3.4","source":"wazuh","observed_at":"2026-05-21T13:00:00Z","count":1}
 *     Batch:    {"sightings":[{"value":"...","source":"...","count":N}, ...]}
 *
 * Response:
 *   {ok:true, processed:N, results:[{value,total_count,first_seen,last_seen,known_in_blacklist:bool}]}
 *
 * State: sighting_state.json keyed by value
 *   {"sightings":{"1.2.3.4":{count:47,first_seen:"...",last_seen:"...",sources:{wazuh:45,splunk:2}}}}
 *
 * Rate limit: flock + simple counter (50 req / 10s per key). Tek-server, basit.
 */

require_once __DIR__ . '/audit_log.php';
require_once __DIR__ . '/ioc_helpers.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$STATE_FILE = __DIR__ . '/sighting_state.json';
$RATE_FILE = __DIR__ . '/sighting_rate.json';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok'=>false,'error'=>'POST required']); exit;
}

// --- Auth (X-API-Key reuse) ---
$cfg = @include __DIR__ . '/auth_config.php';
$valid_keys = is_array($cfg['api_keys'] ?? null) ? $cfg['api_keys'] : [];
$provided = $_SERVER['HTTP_X_API_KEY'] ?? '';

$matched = null;
foreach ($valid_keys as $k) {
    if (is_string($k) && hash_equals($k, $provided)) { $matched = ['key'=>$k,'role'=>'admin','owner'=>'legacy']; break; }
    if (is_array($k) && hash_equals((string)($k['key'] ?? ''), $provided)) { $matched = $k; break; }
}
if (!$matched) {
    http_response_code(401);
    echo json_encode(['ok'=>false,'error'=>'Invalid or missing X-API-Key']); exit;
}

// --- Rate limit: 100 req / 10s per key (basit window) ---
$key_id = substr(md5($matched['key']), 0, 12);
$window = 10; $max_per_window = 100;
$rfh = @fopen($RATE_FILE, 'c+');
if ($rfh && flock($rfh, LOCK_EX)) {
    $raw = stream_get_contents($rfh);
    $rates = json_decode($raw, true) ?: [];
    $now_ts = time();
    $rates = array_filter($rates, fn($r) => ($now_ts - ($r['ts'] ?? 0)) < $window);
    $hits = array_filter($rates, fn($r) => ($r['k'] ?? '') === $key_id);
    if (count($hits) >= $max_per_window) {
        flock($rfh, LOCK_UN); fclose($rfh);
        http_response_code(429);
        echo json_encode(['ok'=>false,'error'=>'Rate limit exceeded','window_sec'=>$window,'max'=>$max_per_window]); exit;
    }
    $rates[] = ['k'=>$key_id, 'ts'=>$now_ts];
    ftruncate($rfh, 0); rewind($rfh);
    fwrite($rfh, json_encode(array_values($rates)));
    fflush($rfh); flock($rfh, LOCK_UN);
}
if ($rfh) fclose($rfh);

// --- Parse body ---
$raw_body = file_get_contents('php://input');
$body = json_decode($raw_body, true);
if (!is_array($body)) {
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>'Invalid JSON body']); exit;
}

$batch = isset($body['sightings']) && is_array($body['sightings'])
    ? $body['sightings']
    : [$body];

if (count($batch) > 500) {
    http_response_code(413);
    echo json_encode(['ok'=>false,'error'=>'Batch too large (max 500 per request)']); exit;
}

// --- Load blacklist values for "known" check ---
static $bl_values = null;
$bl_values = [];
if (file_exists(__DIR__ . '/blacklist.txt')) {
    foreach (file(__DIR__ . '/blacklist.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if ($line === '' || $line[0] === '#') continue;
        $e = cwe_parse_blacklist_entry($line);
        $bl_values[$e['value']] = true;
        // strip /32 alias
        if (str_ends_with($e['value'], '/32')) {
            $bl_values[substr($e['value'], 0, -3)] = true;
        }
    }
}

// --- Update state (flock) ---
$fh = fopen($STATE_FILE, 'c+');
if (!$fh || !flock($fh, LOCK_EX)) {
    if ($fh) fclose($fh);
    http_response_code(503);
    echo json_encode(['ok'=>false,'error'=>'State file lock failed']); exit;
}
$raw = stream_get_contents($fh);
$state = json_decode($raw, true);
if (!is_array($state) || !isset($state['sightings'])) $state = ['sightings' => []];

$now_iso = date('Y-m-d H:i:s');
$results = [];
$processed = 0;

foreach ($batch as $s) {
    $value = trim((string)($s['value'] ?? ''));
    if ($value === '') continue;
    $source = preg_replace('/[^a-z0-9_.-]/i', '', strtolower(trim((string)($s['source'] ?? 'unknown'))));
    if ($source === '') $source = 'unknown';
    $count = max(1, min(10000, (int)($s['count'] ?? 1)));
    $observed_at = trim((string)($s['observed_at'] ?? $now_iso));

    if (!isset($state['sightings'][$value])) {
        $state['sightings'][$value] = [
            'count' => 0,
            'first_seen' => $observed_at,
            'last_seen' => $observed_at,
            'sources' => [],
        ];
    }
    $state['sightings'][$value]['count'] += $count;
    $state['sightings'][$value]['last_seen'] = $observed_at;
    $state['sightings'][$value]['sources'][$source] =
        ($state['sightings'][$value]['sources'][$source] ?? 0) + $count;

    $results[] = [
        'value' => $value,
        'total_count' => $state['sightings'][$value]['count'],
        'first_seen' => $state['sightings'][$value]['first_seen'],
        'last_seen' => $state['sightings'][$value]['last_seen'],
        'known_in_blacklist' => isset($bl_values[$value]),
    ];
    $processed++;
}

ftruncate($fh, 0); rewind($fh);
fwrite($fh, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
fflush($fh); flock($fh, LOCK_UN); fclose($fh);

audit_log_event('sighting_ingest', [
    'count' => $processed,
    'source_key' => substr($key_id, 0, 6),
    'sample' => array_slice(array_map(fn($r) => $r['value'], $results), 0, 3),
]);

echo json_encode(['ok'=>true,'processed'=>$processed,'results'=>$results,'rate_limit'=>[
    'window_sec' => $window, 'max_per_window' => $max_per_window
]], JSON_UNESCAPED_UNICODE);
