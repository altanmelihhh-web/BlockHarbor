<?php
/**
 * Cyberwebeyeos Threat Intelligence REST API v1
 * Auth: X-API-Key header (auth_config.php → api_keys array)
 *
 * Endpoints:
 *   GET  ?action=iocs&type=<all|manual|whitelist|usom|pending>&limit=N
 *   GET  ?action=search&q=<text>&limit=N
 *   GET  ?action=stats          → KPI counts
 *   GET  ?action=export&format=<plain|json|csv>
 *   POST ?action=add            → JSON body: {entries:[...], list:'manual', comment:''}
 *   GET  ?action=audit&limit=N  → audit log
 */

define('API_BASE', __DIR__);
require_once API_BASE . '/audit_log.php';
require_once API_BASE . '/ioc_helpers.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-API-Version: 1.0');

// ---- Auth: X-API-Key (R26 T1.1 — rol bazlı) ----
$cfg = @include API_BASE . '/auth_config.php';
$valid_keys = is_array($cfg['api_keys'] ?? null) ? $cfg['api_keys'] : [];

$provided_key = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['api_key'] ?? '');

/**
 * api_keys array'inden eşleşen kayıt bul. Geriye uyumluluk:
 *   - ['cwe_xxx', 'cwe_yyy'] (string array) → her key 'admin' rolü kabul
 *   - [['key'=>..,'role'=>..,'owner'=>..], ...] (object array) → kayıttaki rol
 * Eşleşme yoksa null.
 */
function _api_match_key(array $keys, string $given): ?array {
    if ($given === '') return null;
    foreach ($keys as $k) {
        if (is_string($k) && hash_equals($k, $given)) {
            return ['key' => $k, 'role' => 'admin', 'owner' => 'legacy-string'];
        }
        if (is_array($k) && isset($k['key']) && hash_equals((string)$k['key'], $given)) {
            $role = in_array($k['role'] ?? '', ['admin','operator','viewer'], true) ? $k['role'] : 'viewer';
            return ['key' => $k['key'], 'role' => $role, 'owner' => $k['owner'] ?? '-'];
        }
    }
    return null;
}

$matched = _api_match_key($valid_keys, (string)$provided_key);
if (!$matched) {
    http_response_code(401);
    echo json_encode(['ok'=>false, 'error'=>'Invalid or missing X-API-Key', 'docs'=>'auth_config.php → api_keys (object array with key/role/owner)']);
    exit;
}

$action = $_GET['action'] ?? 'stats';
$api_role = $matched['role'];
$api_owner = $matched['owner'];
$_SESSION = [
    'cwe_user' => 'api:' . substr(md5($matched['key']), 0, 6) . ':' . $api_owner,
    'cwe_role' => $api_role,
]; // audit için

/**
 * API endpoint için rol kontrolü. Yetersizse 403 + audit.
 */
function _api_require_role(array $allowed): void {
    global $api_role, $action;
    if (in_array($api_role, $allowed, true)) return;
    if (function_exists('audit_log_event')) {
        audit_log_event('api_rbac_denied', [
            'role'     => $api_role,
            'required' => $allowed,
            'action'   => $action,
        ]);
    }
    http_response_code(403);
    echo json_encode(['ok'=>false, 'error'=>'Insufficient role', 'your_role'=>$api_role, 'required'=>$allowed]);
    exit;
}

function _api_read_pipe_file($path, $type_label) {
    if (!file_exists($path)) return [];
    $out = [];
    // R28 (T1.2): ioc_helpers ile 10-field parse
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $e = cwe_parse_blacklist_entry($line);
        $e['source'] = $type_label;
        $e['expired'] = cwe_is_expired($e);
        $out[] = $e;
    }
    return $out;
}
function _api_read_wl_file($path) {
    if (!file_exists($path)) return [];
    $out = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $p = explode('|', $line);
        $out[] = [
            'value' => trim($p[0]),
            'date' => trim($p[1] ?? ''),
            'user' => trim($p[2] ?? ''),
            'comment' => trim($p[3] ?? ''),
            'tlp' => strtoupper(trim($p[4] ?? 'WHITE')),
            'source' => 'whitelist',
        ];
    }
    return $out;
}

switch ($action) {
    case 'stats':
        _api_require_role(['admin','operator','viewer']);
        $manual = _api_read_pipe_file(API_BASE . '/blacklist.txt', 'manual');
        $wl     = _api_read_wl_file(API_BASE . '/whitelist.txt');
        $usom_state = @json_decode(@file_get_contents('/var/www/html/usom/usom-state.json'), true) ?? [];
        $pending = @json_decode(@file_get_contents(API_BASE . '/pending_ips.json'), true)['pending_ips'] ?? [];
        echo json_encode(['ok'=>true, 'stats'=>[
            'manual_count' => count($manual),
            'whitelist_count' => count($wl),
            'pending_count' => count($pending),
            'usom_count' => (int)($usom_state['file_entries'] ?? 0),
            'usom_last_sync' => $usom_state['last_sync'] ?? null,
        ]]);
        break;

    case 'iocs':
        _api_require_role(['admin','operator','viewer']);
        $type = $_GET['type'] ?? 'all';
        $limit = max(1, min(1000, (int)($_GET['limit'] ?? 100)));
        $results = [];
        if ($type === 'all' || $type === 'manual')    $results = array_merge($results, _api_read_pipe_file(API_BASE . '/blacklist.txt', 'manual'));
        if ($type === 'all' || $type === 'whitelist') $results = array_merge($results, _api_read_wl_file(API_BASE . '/whitelist.txt'));
        if ($type === 'all' || $type === 'pending') {
            $pending = @json_decode(@file_get_contents(API_BASE . '/pending_ips.json'), true)['pending_ips'] ?? [];
            foreach ($pending as $p) $results[] = ['value'=>$p['ip'], 'date'=>$p['created_at'] ?? '', 'source'=>'pending', 'comment'=>$p['source'] ?? ''];
        }
        echo json_encode(['ok'=>true, 'count'=>count($results), 'results'=>array_slice($results, 0, $limit)]);
        break;

    case 'search':
        _api_require_role(['admin','operator','viewer']);
        $q = trim($_GET['q'] ?? '');
        if (strlen($q) < 2) { echo json_encode(['ok'=>false, 'error'=>'q minimum 2 char']); break; }
        $limit = max(1, min(100, (int)($_GET['limit'] ?? 20)));
        $sources = array_merge(
            _api_read_pipe_file(API_BASE . '/blacklist.txt', 'manual'),
            _api_read_wl_file(API_BASE . '/whitelist.txt')
        );
        $matches = array_filter($sources, fn($x) => stripos($x['value'] ?? '', $q) !== false || stripos($x['comment'] ?? '', $q) !== false);
        echo json_encode(['ok'=>true, 'q'=>$q, 'count'=>count($matches), 'results'=>array_slice(array_values($matches), 0, $limit)]);
        break;

    case 'export':
        _api_require_role(['admin','operator','viewer']);
        $fmt = $_GET['format'] ?? 'plain';
        $feed = API_BASE . '/cyberwebeyeosblacklist.txt';
        if (!file_exists($feed)) { echo json_encode(['ok'=>false, 'error'=>'feed file not found']); break; }
        if ($fmt === 'plain') {
            header('Content-Type: text/plain; charset=utf-8');
            readfile($feed);
            exit;
        } elseif ($fmt === 'json') {
            $lines = array_filter(array_map('trim', file($feed)), fn($l) => $l !== '' && $l[0] !== '#');
            echo json_encode(['ok'=>true, 'count'=>count($lines), 'entries'=>array_values($lines)]);
        } elseif ($fmt === 'csv') {
            header('Content-Type: text/csv; charset=utf-8');
            header('Content-Disposition: attachment; filename="cyberwebeyeos-blacklist.csv"');
            echo "value,source\n";
            foreach (file($feed) as $l) {
                $l = trim($l);
                if ($l === '' || $l[0] === '#') continue;
                echo '"' . str_replace('"', '""', $l) . '",cyberwebeyeos' . "\n";
            }
            exit;
        }
        break;

    case 'add':
        _api_require_role(['admin','operator']);
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['ok'=>false, 'error'=>'POST required']); break; }
        $body = json_decode(file_get_contents('php://input'), true) ?: [];
        $entries = $body['entries'] ?? [];
        if (!is_array($entries) || empty($entries)) { echo json_encode(['ok'=>false, 'error'=>'entries array required']); break; }
        $comment = trim($body['comment'] ?? 'api-ingest');
        $tlp = strtoupper($body['tlp'] ?? 'WHITE');
        if (!in_array($tlp, ['RED','AMBER','GREEN','WHITE'], true)) $tlp = 'WHITE';
        $added = [];
        $blacklist = API_BASE . '/blacklist.txt';
        $feed = API_BASE . '/cyberwebeyeosblacklist.txt';
        // R28 (T1.2): API body opsiyonel olarak confidence/valid_until alabilir
        $body_conf = isset($body['confidence']) ? max(0, min(100, (int)$body['confidence'])) : 70;
        $body_vu = trim((string)($body['valid_until'] ?? ''));
        if ($body_vu === '' || $body_vu === 'permanent') {
            $body_vu_resolved = $body_vu === 'permanent' ? 'permanent' : cwe_default_valid_until(90);
        } else {
            $ts = strtotime($body_vu);
            $body_vu_resolved = $ts ? date('Y-m-d H:i:s', $ts) : cwe_default_valid_until(90);
        }
        // R41 (T4.1): API warninglist guard — override flag body'de gelir
        $api_wl_override = !empty($body['warninglist_override']);
        $api_wl_blocked = [];
        foreach ($entries as $val) {
            $val = trim($val);
            if ($val === '') continue;
            // Warninglist check
            $wl_match = cwe_warninglist_match($val);
            if ($wl_match && !$api_wl_override) {
                $api_wl_blocked[] = ['value'=>$val, 'list'=>$wl_match['list'], 'label'=>$wl_match['label']];
                audit_log_event('warninglist_block', ['entry'=>$val, 'match'=>$wl_match, 'source'=>'api']);
                continue;
            } elseif ($wl_match && $api_wl_override) {
                audit_log_event('warninglist_override', ['entry'=>$val, 'match'=>$wl_match, 'source'=>'api']);
            }
            $now = date('Y-m-d H:i:s');
            $entry_arr = [
                'value' => $val, 'comment' => $comment, 'date' => $now,
                'fqdn' => '', 'jira' => '', 'tlp' => $tlp,
                'type' => cwe_detect_type($val),
                'added_by' => 'api:' . ($api_owner ?? 'unknown'),
                'confidence' => $body_conf, 'valid_until' => $body_vu_resolved,
            ];
            file_put_contents($blacklist, cwe_format_blacklist_entry($entry_arr) . "\n", FILE_APPEND);
            file_put_contents($feed, $val . "\n", FILE_APPEND);
            $added[] = $val;
        }
        audit_log_event('api_ingest', ['count'=>count($added), 'tlp'=>$tlp, 'confidence'=>$body_conf, 'valid_until'=>$body_vu_resolved, 'comment'=>$comment, 'blocked'=>count($api_wl_blocked)]);
        echo json_encode([
            'ok' => true,
            'added' => count($added),
            'entries' => $added,
            'warninglist_blocked' => $api_wl_blocked, // R41: array of {value, list, label}
            'metadata' => ['tlp'=>$tlp,'confidence'=>$body_conf,'valid_until'=>$body_vu_resolved],
            'hint' => count($api_wl_blocked) > 0 ? 'Engelleneni eklemek için body.warninglist_override=true ekle' : null,
        ]);
        break;

    case 'audit':
        _api_require_role(['admin']);
        $limit = max(1, min(500, (int)($_GET['limit'] ?? 50)));
        echo json_encode(['ok'=>true, 'events'=>audit_log_recent($limit)]);
        break;

    default:
        http_response_code(400);
        echo json_encode(['ok'=>false, 'error'=>'unknown action', 'available'=>['stats','iocs','search','export','add','audit']]);
}
