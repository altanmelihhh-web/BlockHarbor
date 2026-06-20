<?php
// SPRINT6-B2: GreyNoise community API wrapper + quota counter

const GREYNOISE_QUOTA_FILE = __DIR__ . '/greynoise_quota.json';
const GREYNOISE_DAILY_LIMIT = 50;
const GREYNOISE_CACHE_DIR = __DIR__ . '/cve_cache/greynoise';
const GREYNOISE_CACHE_TTL_SEC = 86400; // 24h
const GREYNOISE_API_BASE = 'https://api.greynoise.io/v3/community';

function greynoise_load_key(): string {
    $cfg = __DIR__ . '/auth_config.php';
    if (!file_exists($cfg)) return '';
    @include $cfg;
    return (string)($greynoise_api_key ?? '');
}

function greynoise_quota_state(): array {
    if (!is_dir(GREYNOISE_CACHE_DIR)) @mkdir(GREYNOISE_CACHE_DIR, 0775, true);
    $today = gmdate('Y-m-d');
    if (!file_exists(GREYNOISE_QUOTA_FILE)) {
        $s = ['date' => $today, 'used_today' => 0, 'remaining_today' => GREYNOISE_DAILY_LIMIT];
        file_put_contents(GREYNOISE_QUOTA_FILE, json_encode($s, JSON_PRETTY_PRINT));
        return $s;
    }
    $s = json_decode(file_get_contents(GREYNOISE_QUOTA_FILE), true) ?: [];
    if (($s['date'] ?? '') !== $today) {
        $s = ['date' => $today, 'used_today' => 0, 'remaining_today' => GREYNOISE_DAILY_LIMIT];
        file_put_contents(GREYNOISE_QUOTA_FILE, json_encode($s, JSON_PRETTY_PRINT));
    }
    return $s;
}

function greynoise_quota_consume(): bool {
    $fh = fopen(GREYNOISE_QUOTA_FILE, 'c+');
    if (!$fh || !flock($fh, LOCK_EX)) { if ($fh) fclose($fh); return false; }
    $raw = stream_get_contents($fh);
    $s = $raw ? (json_decode($raw, true) ?: []) : [];
    $today = gmdate('Y-m-d');
    if (($s['date'] ?? '') !== $today) {
        $s = ['date' => $today, 'used_today' => 0, 'remaining_today' => GREYNOISE_DAILY_LIMIT];
    }
    if (($s['remaining_today'] ?? 0) <= 0) {
        flock($fh, LOCK_UN); fclose($fh);
        if (function_exists('audit_log_event')) {
            audit_log_event('greynoise_quota_exhausted', array_merge(['object' => 'greynoise'], $s));
        }
        return false;
    }
    $s['used_today']++;
    $s['remaining_today']--;
    ftruncate($fh, 0); rewind($fh);
    fwrite($fh, json_encode($s, JSON_PRETTY_PRINT));
    fflush($fh); flock($fh, LOCK_UN); fclose($fh);
    if ($s['remaining_today'] === 10 && function_exists('audit_log_event')) {
        audit_log_event('greynoise_quota_warn_80pct', array_merge(['object' => 'greynoise'], $s));
    }
    return true;
}

function greynoise_cache_path(string $cve): string {
    if (!is_dir(GREYNOISE_CACHE_DIR)) @mkdir(GREYNOISE_CACHE_DIR, 0775, true);
    return GREYNOISE_CACHE_DIR . '/' . preg_replace('/[^A-Za-z0-9_-]/', '_', $cve) . '.json';
}

function greynoise_cache_get(string $cve): ?array {
    $p = greynoise_cache_path($cve);
    if (!file_exists($p)) return null;
    if ((time() - filemtime($p)) > GREYNOISE_CACHE_TTL_SEC) return null;
    $j = json_decode(file_get_contents($p), true);
    return is_array($j) ? $j : null;
}

function greynoise_cache_set(string $cve, array $data): void {
    file_put_contents(greynoise_cache_path($cve), json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

/**
 * Returns ['ips' => [...], 'source' => 'cache'|'api'|'dry-run'|'quota_exhausted'|'no_key'|'invalid_cve', 'count' => N]
 */
function greynoise_cve_search(string $cve, bool $dry_run = false): array {
    if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) {
        return ['ips' => [], 'source' => 'invalid_cve', 'count' => 0];
    }
    // Ensure quota state exists (creates file if needed) — required by smoke test
    greynoise_quota_state();
    $cached = greynoise_cache_get($cve);
    if ($cached !== null) return $cached + ['source' => 'cache'];

    if ($dry_run) {
        return ['ips' => [], 'source' => 'dry-run', 'count' => 0, 'cve' => $cve];
    }

    $key = greynoise_load_key();
    if ($key === '') {
        return ['ips' => [], 'source' => 'no_key', 'count' => 0, 'error' => 'GreyNoise API key not configured'];
    }
    if (!greynoise_quota_consume()) {
        return ['ips' => [], 'source' => 'quota_exhausted', 'count' => 0];
    }

    $url = GREYNOISE_API_BASE . '/cve/' . urlencode($cve);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_HTTPHEADER => ['key: ' . $key, 'Accept: application/json'],
        CURLOPT_USERAGENT => 'cyberwebeyeos-tip/sprint6',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code !== 200 || !$body) {
        $out = ['ips' => [], 'source' => 'api_error', 'count' => 0, 'http' => $code, 'cve' => $cve];
        greynoise_cache_set($cve, $out);
        return $out;
    }
    $j = json_decode($body, true);
    $ips = [];
    if (is_array($j) && isset($j['ips']) && is_array($j['ips'])) {
        foreach ($j['ips'] as $entry) {
            $ip = is_array($entry) ? ($entry['ip'] ?? null) : $entry;
            if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) $ips[] = $ip;
        }
    }
    $out = ['ips' => array_values(array_unique($ips)), 'source' => 'api', 'count' => count($ips), 'cve' => $cve, 'fetched_at' => gmdate('c')];
    greynoise_cache_set($cve, $out);
    return $out;
}
