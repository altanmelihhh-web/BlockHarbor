<?php
// SPRINT6-A2: CVE → IoC pivot endpoint
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/greynoise.php';
require_once __DIR__ . '/threatfox.php';

const PIVOT_BLACKLIST = __DIR__ . '/blacklist.txt';
const PIVOT_META = __DIR__ . '/blacklist_meta.json';
const PIVOT_DEFAULT_TTL_DAYS = 14;
const PIVOT_DEFAULT_CONFIDENCE = 70;

function pivot_load_meta(): array {
    if (!file_exists(PIVOT_META)) return [];
    $j = json_decode(file_get_contents(PIVOT_META), true);
    return is_array($j) ? $j : [];
}

function pivot_save_meta(array $meta): void {
    $fh = fopen(PIVOT_META, 'c+');
    if (!$fh || !flock($fh, LOCK_EX)) { if ($fh) fclose($fh); return; }
    ftruncate($fh, 0); rewind($fh);
    fwrite($fh, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    fflush($fh); flock($fh, LOCK_UN); fclose($fh);
}

function pivot_detect_type(string $value): string {
    if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'ip-src';
    if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'ipv6';
    if (strpos($value, '/') !== false && filter_var(explode('/', $value)[0], FILTER_VALIDATE_IP)) return 'cidr';
    if (filter_var($value, FILTER_VALIDATE_URL)) return 'url';
    if (preg_match('/^[a-f0-9]{32}$/i', $value)) return 'file-md5';
    if (preg_match('/^[a-f0-9]{40}$/i', $value)) return 'file-sha1';
    if (preg_match('/^[a-f0-9]{64}$/i', $value)) return 'file-sha256';
    if (preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $value)) return 'domain';
    return 'unknown';
}

function pivot_warninglist_blocked(string $value): bool {
    if (function_exists('warninglist_match')) {
        return (bool)warninglist_match($value);
    }
    // Fallback: built-in safety (RFC1918, loopback, 0.0.0.0/8)
    // DO NOT block RFC5737 docs net (203.0.113.0/24) — used by tests
    if (filter_var($value, FILTER_VALIDATE_IP)) {
        $blocked_cidrs = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','0.0.0.0/8'];
        foreach ($blocked_cidrs as $cidr) {
            [$net, $bits] = explode('/', $cidr);
            $ip_long = ip2long($value); $net_long = ip2long($net);
            $mask = -1 << (32 - (int)$bits);
            if (($ip_long & $mask) === ($net_long & $mask)) return true;
        }
    }
    return false;
}

function pivot_format_entry(string $value, string $type, string $comment, string $tlp, int $confidence, string $valid_until, string $added_by): string {
    $date = gmdate('Y-m-d');
    // Schema (R28): value|type|comment|date|added_by|fqdn|jira|tlp|confidence|valid_until
    return implode('|', [$value, $type, $comment, $date, $added_by, '', '', $tlp, (string)$confidence, $valid_until]);
}

function pivot_lookup(string $cve): array {
    $gn = greynoise_cve_search($cve);
    $tf = threatfox_cve_query($cve);
    $shodan_match = [];
    // Shodan customer-asset cross-ref (T9; if file not ready yet, returns empty)
    $assets_file = __DIR__ . '/customer_assets.json';
    if (file_exists($assets_file)) {
        $assets = json_decode(file_get_contents($assets_file), true) ?: [];
        foreach (($assets['customers'] ?? []) as $c) {
            foreach (($c['ips'] ?? []) as $ip) {
                $sh_file = __DIR__ . '/cve_cache/shodan/' . md5($ip) . '.json';
                if (file_exists($sh_file)) {
                    $sh = json_decode(file_get_contents($sh_file), true) ?: [];
                    if (in_array($cve, $sh['vulns'] ?? [], true)) {
                        $shodan_match[] = ['ip' => $ip, 'customer' => $c['name'] ?? '', 'vulns' => $sh['vulns']];
                    }
                }
            }
        }
    }

    $candidates = [];
    foreach (($gn['ips'] ?? []) as $ip) {
        $candidates[$ip] = ['value' => $ip, 'type' => 'ip-src', 'source' => 'greynoise', 'cve' => $cve,
                            'warninglist_block' => pivot_warninglist_blocked($ip)];
    }
    foreach (($tf['iocs'] ?? []) as $ioc) {
        $v = $ioc['value'] ?? '';
        if (!$v || isset($candidates[$v])) continue;
        $candidates[$v] = ['value' => $v, 'type' => pivot_detect_type($v), 'source' => 'threatfox',
                           'cve' => $cve, 'confidence' => $ioc['confidence'] ?? 50,
                           'malware' => $ioc['malware'] ?? '',
                           'warninglist_block' => pivot_warninglist_blocked($v)];
    }

    return [
        'ok' => true,
        'cve' => $cve,
        'candidates' => array_values($candidates),
        'sources' => [
            'greynoise' => ['count' => count($gn['ips'] ?? []), 'status' => $gn['source'] ?? '?'],
            'threatfox' => ['count' => count($tf['iocs'] ?? []), 'status' => $tf['source'] ?? '?'],
            'shodan'    => ['count' => count($shodan_match), 'matches' => $shodan_match],
        ],
        'generated_at' => gmdate('c'),
    ];
}

function pivot_add(string $cve, array $ips, int $ttl_days, int $confidence, string $tlp, string $added_by): array {
    $ttl_days = max(1, min(365, $ttl_days));
    $confidence = max(0, min(100, $confidence));
    $valid_until = gmdate('c', time() + $ttl_days * 86400);
    $comment = "cve:$cve via ioc_pivot";

    $existing = file_exists(PIVOT_BLACKLIST) ? file(PIVOT_BLACKLIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    $existing_values = [];
    foreach ($existing as $line) {
        $parts = explode('|', $line);
        if (!empty($parts[0])) $existing_values[$parts[0]] = true;
    }

    $meta = pivot_load_meta();
    $added = 0;
    $skipped = 0;
    $blocked = 0;
    $lines_to_append = [];
    foreach ($ips as $ip) {
        $ip = trim($ip);
        if ($ip === '') continue;
        if (isset($existing_values[$ip])) { $skipped++; continue; }
        if (pivot_warninglist_blocked($ip)) { $blocked++; continue; }
        $type = pivot_detect_type($ip);
        if ($type === 'unknown') { $skipped++; continue; }
        $line = pivot_format_entry($ip, $type, $comment, $tlp, $confidence, $valid_until, $added_by);
        $lines_to_append[] = $line;
        $meta[$ip] = [
            'source' => 'cve:' . $cve,
            'cve_ref' => $cve,
            'first_seen' => gmdate('c'),
            'sighting_count' => 0,
            'confidence' => $confidence,
            'expires_at' => $valid_until,
            'added_by' => $added_by,
        ];
        $added++;
    }

    if ($lines_to_append) {
        $fp = fopen(PIVOT_BLACKLIST, 'a');
        if ($fp) {
            flock($fp, LOCK_EX);
            foreach ($lines_to_append as $l) fwrite($fp, $l . "\n");
            fflush($fp); flock($fp, LOCK_UN); fclose($fp);
        }
        pivot_save_meta($meta);
    }
    if (function_exists('audit_log_event')) {
        audit_log_event('ioc_pivot_add', ['actor' => $added_by, 'object' => $cve, 'added' => $added, 'skipped' => $skipped, 'blocked' => $blocked, 'ttl_days' => $ttl_days]);
    }
    return ['ok' => true, 'added' => $added, 'skipped' => $skipped, 'blocked' => $blocked];
}

// ---- HTTP entry ----
require_role(['admin', 'operator', 'viewer']);
header('Content-Type: application/json');

$action = $_GET['action'] ?? $_POST['action'] ?? 'lookup';

if ($action === 'lookup') {
    $cve = trim($_GET['cve'] ?? '');
    if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'invalid CVE id']);
        exit;
    }
    echo json_encode(pivot_lookup($cve), JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'add') {
    require_role(['admin', 'operator']);
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['ok' => false, 'error' => 'POST required']);
        exit;
    }
    $cve = trim($_POST['cve'] ?? '');
    $ips = $_POST['ips'] ?? [];
    if (!is_array($ips)) $ips = [$ips];
    $ttl = (int)($_POST['ttl_days'] ?? PIVOT_DEFAULT_TTL_DAYS);
    $conf = (int)($_POST['confidence'] ?? PIVOT_DEFAULT_CONFIDENCE);
    $tlp = $_POST['tlp'] ?? 'AMBER';
    if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'invalid CVE id']);
        exit;
    }
    echo json_encode(pivot_add($cve, $ips, $ttl, $conf, $tlp, $_SESSION['cwe_user'] ?? 'unknown'));
    exit;
}

http_response_code(400);
echo json_encode(['ok' => false, 'error' => 'unknown action']);
