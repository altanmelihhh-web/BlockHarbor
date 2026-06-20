<?php
// SPRINT6-B3: ThreatFox (abuse.ch) CVE tag query — no auth, no rate limit

const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/';
const THREATFOX_CACHE_DIR = __DIR__ . '/cve_cache/threatfox';
const THREATFOX_CACHE_TTL_SEC = 21600; // 6h

function threatfox_cache_path(string $cve): string {
    if (!is_dir(THREATFOX_CACHE_DIR)) @mkdir(THREATFOX_CACHE_DIR, 0775, true);
    return THREATFOX_CACHE_DIR . '/' . preg_replace('/[^A-Za-z0-9_-]/', '_', $cve) . '.json';
}

function threatfox_cache_get(string $cve): ?array {
    $p = threatfox_cache_path($cve);
    if (!file_exists($p)) return null;
    if ((time() - filemtime($p)) > THREATFOX_CACHE_TTL_SEC) return null;
    $j = json_decode(file_get_contents($p), true);
    return is_array($j) ? $j : null;
}

function threatfox_cache_set(string $cve, array $data): void {
    file_put_contents(threatfox_cache_path($cve), json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function threatfox_cve_query(string $cve, bool $dry_run = false): array {
    if (!is_dir(THREATFOX_CACHE_DIR)) @mkdir(THREATFOX_CACHE_DIR, 0775, true);
    if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) {
        return ['iocs' => [], 'source' => 'invalid_cve', 'count' => 0];
    }

    $cached = threatfox_cache_get($cve);
    if ($cached !== null) return $cached + ['source' => 'cache'];

    if ($dry_run) {
        return ['iocs' => [], 'source' => 'dry-run', 'count' => 0, 'cve' => $cve];
    }

    $payload = json_encode(['query' => 'taginfo', 'tag' => $cve, 'limit' => 100]);
    $ch = curl_init(THREATFOX_API);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_USERAGENT => 'cyberwebeyeos-tip/sprint6',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code !== 200 || !$body) {
        $out = ['iocs' => [], 'source' => 'api_error', 'count' => 0, 'http' => $code, 'cve' => $cve];
        threatfox_cache_set($cve, $out);
        return $out;
    }
    $j = json_decode($body, true);
    $iocs = [];
    if (is_array($j) && ($j['query_status'] ?? '') === 'ok' && is_array($j['data'] ?? null)) {
        foreach ($j['data'] as $row) {
            if (!is_array($row)) continue;
            $iocs[] = [
                'value' => $row['ioc'] ?? '',
                'type' => $row['ioc_type'] ?? '',
                'first_seen' => $row['first_seen'] ?? '',
                'confidence' => (int)($row['confidence_level'] ?? 50),
                'malware' => $row['malware_printable'] ?? '',
            ];
        }
    }
    $out = ['iocs' => $iocs, 'source' => 'api', 'count' => count($iocs), 'cve' => $cve, 'fetched_at' => gmdate('c')];
    threatfox_cache_set($cve, $out);
    return $out;
}
