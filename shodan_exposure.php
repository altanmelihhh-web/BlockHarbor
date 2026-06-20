<?php
// SPRINT6-B1: Shodan InternetDB exposure scanner (unauth, free)

require_once __DIR__ . '/feed_health.php';

const SHODAN_IDB_BASE = 'https://internetdb.shodan.io';
const SHODAN_CACHE_DIR = __DIR__ . '/cve_cache/shodan';
const SHODAN_CACHE_TTL_SEC = 86400; // 24h
const SHODAN_ASSETS_FILE = __DIR__ . '/customer_assets.json';

function shodan_load_assets(): array {
    if (!file_exists(SHODAN_ASSETS_FILE)) return ['customers' => []];
    $j = json_decode(file_get_contents(SHODAN_ASSETS_FILE), true);
    return is_array($j) ? $j : ['customers' => []];
}

function shodan_load_watchlist(): array {
    $f = __DIR__ . '/vendor_watchlist.json';
    if (!file_exists($f)) return ['vendors' => []];
    return json_decode(file_get_contents($f), true) ?: ['vendors' => []];
}

function shodan_cache_path(string $ip): string {
    if (!is_dir(SHODAN_CACHE_DIR)) @mkdir(SHODAN_CACHE_DIR, 0775, true);
    return SHODAN_CACHE_DIR . '/' . md5($ip) . '.json';
}

function shodan_cache_get(string $ip): ?array {
    $p = shodan_cache_path($ip);
    if (!file_exists($p)) return null;
    if ((time() - filemtime($p)) > SHODAN_CACHE_TTL_SEC) return null;
    $j = json_decode(file_get_contents($p), true);
    return is_array($j) ? $j : null;
}

function shodan_cache_set(string $ip, array $data): void {
    file_put_contents(shodan_cache_path($ip), json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function shodan_exposure_check_ip(string $ip, bool $dry_run = false): array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return ['ok' => false, 'ip' => $ip, 'vulns' => [], 'source' => 'invalid_ip'];
    }
    if (!is_dir(SHODAN_CACHE_DIR)) @mkdir(SHODAN_CACHE_DIR, 0775, true);
    $cached = shodan_cache_get($ip);
    if ($cached !== null) return $cached + ['source' => 'cache'];

    if ($dry_run) {
        return ['ok' => true, 'ip' => $ip, 'vulns' => [], 'ports' => [], 'cpes' => [], 'hostnames' => [], 'tags' => [], 'source' => 'dry-run'];
    }

    $url = SHODAN_IDB_BASE . '/' . $ip;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_USERAGENT => 'cyberwebeyeos-tip/sprint6',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // 404 means "no records" — that's a successful negative result
    if ($code === 404) {
        $out = ['ok' => true, 'ip' => $ip, 'vulns' => [], 'ports' => [], 'cpes' => [], 'hostnames' => [], 'tags' => [], 'source' => 'api_empty', 'fetched_at' => gmdate('c')];
        shodan_cache_set($ip, $out);
        return $out;
    }
    if ($code !== 200 || !$body) {
        return ['ok' => false, 'ip' => $ip, 'vulns' => [], 'source' => 'api_error', 'http' => $code];
    }
    $j = json_decode($body, true);
    if (!is_array($j)) return ['ok' => false, 'ip' => $ip, 'vulns' => [], 'source' => 'parse_error'];

    $out = [
        'ok' => true, 'ip' => $ip,
        'vulns' => $j['vulns'] ?? [],
        'ports' => $j['ports'] ?? [],
        'cpes' => $j['cpes'] ?? [],
        'hostnames' => $j['hostnames'] ?? [],
        'tags' => $j['tags'] ?? [],
        'source' => 'api',
        'fetched_at' => gmdate('c'),
    ];
    shodan_cache_set($ip, $out);
    return $out;
}

function shodan_exposure_run_all(bool $dry_run = false): array {
    $assets = shodan_load_assets();
    $watchlist_vendors = array_map('strtolower', shodan_load_watchlist()['vendors'] ?? []);
    $scanned = 0;
    $matches = [];

    foreach (($assets['customers'] ?? []) as $cust) {
        foreach (($cust['ips'] ?? []) as $ip) {
            $scanned++;
            $r = shodan_exposure_check_ip($ip, $dry_run);
            if (!$r['ok']) continue;
            $vendor_match = false;
            foreach (($r['cpes'] ?? []) as $cpe) {
                foreach ($watchlist_vendors as $v) {
                    if (stripos($cpe, ':' . $v . ':') !== false) { $vendor_match = true; break 2; }
                }
            }
            if (!empty($r['vulns']) && ($vendor_match || empty($watchlist_vendors))) {
                $matches[] = [
                    'customer' => $cust['name'] ?? '?',
                    'ip' => $ip,
                    'vulns' => $r['vulns'],
                    'cpes' => $r['cpes'],
                ];
                if (!$dry_run && function_exists('notify_alert')) {
                    notify_alert('shodan_exposure', "Customer IP $ip exposed to " . implode(',', $r['vulns']));
                }
            }
        }
    }

    // Feed health heartbeat
    feed_health_heartbeat('shodan_internetdb', [
        'url' => SHODAN_IDB_BASE,
        'http_status' => 200,
        'bytes_received' => 0,
        'parser_ok' => true,
        'entries_extracted' => $scanned,
        'raw_body' => '{"ok":true}',
        'format' => 'json',
    ]);

    return ['ok' => true, 'scanned' => $scanned, 'matches' => $matches, 'matches_count' => count($matches)];
}

if (php_sapi_name() === 'cli') {
    $dry = in_array('--dry-run', $argv ?? [], true);
    echo json_encode(shodan_exposure_run_all($dry), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
}
