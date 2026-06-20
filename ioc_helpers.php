<?php
/**
 * Cyberwebeyeos IoC Helpers — R28 (T1.2) IoC Taxonomy + Confidence + Expiration
 *
 * Blacklist schema artık 10 field. Pragmatik append-strategy: mevcut 6-field
 * schema'sının sonuna 4 yeni field eklenir; eski parser'lar position-stable.
 *
 *  pos 0: value         — IP / CIDR / domain / URL / hash
 *  pos 1: comment       — açıklama
 *  pos 2: date          — Y-m-d H:i:s (ekleme zamanı)
 *  pos 3: fqdn          — opsiyonel bağlı domain
 *  pos 4: jira          — ticket
 *  pos 5: tlp           — RED|AMBER|GREEN|WHITE
 *  pos 6: type          — ip-src|ip-dst|cidr|ipv6|domain|hostname|url|file-md5|file-sha1|file-sha256|email-src
 *  pos 7: added_by      — kullanıcı adı veya api:<owner>
 *  pos 8: confidence    — 0-100 integer
 *  pos 9: valid_until   — Y-m-d H:i:s veya 'permanent'
 *
 * Eski entry'ler (5 veya 6 field): eksikler default ile doldurulur:
 *   tlp='WHITE', type=auto-detect, added_by='legacy', confidence=50, valid_until='permanent'
 */

const CWE_IOC_TYPES = [
    'ip-src', 'ip-dst', 'cidr', 'ipv6',
    'domain', 'hostname', 'url',
    'file-md5', 'file-sha1', 'file-sha256',
    'email-src',
];

const CWE_TLP_VALUES = ['RED','AMBER','GREEN','WHITE'];

/**
 * Tip otomatik tespit (R2'deki UI helper'ın server-side versiyonu).
 * Boş veya yorum satırı → 'unknown'.
 */
function cwe_detect_type(string $value): string {
    $v = trim($value);
    if ($v === '' || $v[0] === '#') return 'unknown';

    // URL: scheme:// önek
    if (preg_match('#^https?://#i', $v)) return 'url';

    // Hash (hex string, exact lengths)
    if (preg_match('/^[0-9a-f]{64}$/i', $v)) return 'file-sha256';
    if (preg_match('/^[0-9a-f]{40}$/i', $v)) return 'file-sha1';
    if (preg_match('/^[0-9a-f]{32}$/i', $v)) return 'file-md5';

    // Email
    if (filter_var($v, FILTER_VALIDATE_EMAIL)) return 'email-src';

    // CIDR (IPv4)
    if (strpos($v, '/') !== false) {
        list($ip, $prefix) = explode('/', $v, 2);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && is_numeric($prefix)) {
            return ((int)$prefix === 32) ? 'ip-src' : 'cidr';
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'ipv6';
    }

    // IPv4
    if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'ip-src';

    // IPv6
    if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'ipv6';

    // Domain / hostname
    if (preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i', $v)) {
        // Tek-label (örn. 'localhost') → hostname; çok-label → domain
        return (substr_count($v, '.') >= 1) ? 'domain' : 'hostname';
    }
    if (preg_match('/^[a-z0-9][a-z0-9-]*$/i', $v)) return 'hostname';

    return 'unknown';
}

/**
 * Pipe-separated satırı 10-field assoc array'e parse et.
 * Eksik field'lar default ile doldurulur (backward compat).
 */
function cwe_parse_blacklist_entry(string $line): array {
    $parts = explode('|', rtrim($line, "\r\n"));
    $value = trim($parts[0] ?? '');
    $tlp = strtoupper(trim($parts[5] ?? 'WHITE'));
    if (!in_array($tlp, CWE_TLP_VALUES, true)) $tlp = 'WHITE';
    $type = strtolower(trim($parts[6] ?? ''));
    if (!in_array($type, CWE_IOC_TYPES, true)) $type = cwe_detect_type($value);
    $conf = isset($parts[8]) && $parts[8] !== '' ? (int)$parts[8] : 50;
    $conf = max(0, min(100, $conf));
    $valid_until = trim($parts[9] ?? 'permanent');
    if ($valid_until === '') $valid_until = 'permanent';

    return [
        'value'       => $value,
        'comment'     => trim($parts[1] ?? ''),
        'date'        => trim($parts[2] ?? ''),
        'fqdn'        => trim($parts[3] ?? ''),
        'jira'        => trim($parts[4] ?? ''),
        'tlp'         => $tlp,
        'type'        => $type,
        'added_by'    => trim($parts[7] ?? '') !== '' ? trim($parts[7]) : 'legacy',
        'confidence'  => $conf,
        'valid_until' => $valid_until,
    ];
}

/**
 * Assoc array → pipe-separated satır (newline dahil değil).
 */
function cwe_format_blacklist_entry(array $e): string {
    $tlp = in_array(strtoupper($e['tlp'] ?? 'WHITE'), CWE_TLP_VALUES, true) ? strtoupper($e['tlp']) : 'WHITE';
    $type = in_array(strtolower($e['type'] ?? ''), CWE_IOC_TYPES, true) ? strtolower($e['type']) : cwe_detect_type($e['value'] ?? '');
    $conf = max(0, min(100, (int)($e['confidence'] ?? 50)));
    $valid_until = trim((string)($e['valid_until'] ?? 'permanent'));
    if ($valid_until === '') $valid_until = 'permanent';

    return implode('|', [
        (string)($e['value']    ?? ''),
        str_replace('|', ' ', (string)($e['comment']  ?? '')),
        (string)($e['date']     ?? date('Y-m-d H:i:s')),
        (string)($e['fqdn']     ?? ''),
        (string)($e['jira']     ?? ''),
        $tlp,
        $type,
        str_replace('|', ' ', (string)($e['added_by'] ?? 'unknown')),
        (string)$conf,
        $valid_until,
    ]);
}

/**
 * Default valid_until (now + 90 days).
 */
function cwe_default_valid_until(int $days = 90): string {
    return date('Y-m-d H:i:s', time() + ($days * 86400));
}

/**
 * Bir entry expired mi? 'permanent' veya gelecek tarih → false.
 */
function cwe_is_expired(array $entry): bool {
    $vu = $entry['valid_until'] ?? 'permanent';
    if ($vu === 'permanent' || $vu === '') return false;
    $ts = strtotime($vu);
    if ($ts === false) return false;
    return $ts < time();
}

/**
 * Type → renk + ikon mapping (UI için).
 */
function cwe_type_meta(string $type): array {
    $map = [
        'ip-src'      => ['color' => '#10b981', 'label' => 'IPv4'],
        'ip-dst'      => ['color' => '#059669', 'label' => 'IPv4-dst'],
        'cidr'        => ['color' => '#0ea5e9', 'label' => 'CIDR'],
        'ipv6'        => ['color' => '#8b5cf6', 'label' => 'IPv6'],
        'domain'      => ['color' => '#6366f1', 'label' => 'Domain'],
        'hostname'    => ['color' => '#6366f1', 'label' => 'Host'],
        'url'         => ['color' => '#f59e0b', 'label' => 'URL'],
        'file-md5'    => ['color' => '#ec4899', 'label' => 'MD5'],
        'file-sha1'   => ['color' => '#ec4899', 'label' => 'SHA1'],
        'file-sha256' => ['color' => '#ec4899', 'label' => 'SHA256'],
        'email-src'   => ['color' => '#a855f7', 'label' => 'Email'],
    ];
    return $map[$type] ?? ['color' => '#94a3b8', 'label' => ucfirst($type ?: 'unknown')];
}

/**
 * Confidence için renk (yüksek=yeşil, düşük=kırmızı).
 */
function cwe_confidence_color(int $c): string {
    if ($c >= 80) return '#10b981';
    if ($c >= 60) return '#0ea5e9';
    if ($c >= 40) return '#f59e0b';
    return '#ef4444';
}

/**
 * R41 (T4.1): IoC'nin warninglist'lerden birinde olup olmadığını kontrol et.
 *
 * Lists: warninglists/*.txt — pipe-separated <value>|<label>, # comment.
 * Type-aware:
 *   - CIDR/IP listeleri: ip2long mask check (rfc1918, iana_reserved, public_dns)
 *   - Domain listeleri: exact + suffix match (popular_domains, tranco_top)
 *
 * Returns: null yoksa match; aksi halde ['list','value','label','rule']
 */
function cwe_warninglist_match(string $value, ?string $type = null): ?array {
    static $cache = null;
    if ($cache === null) {
        $cache = ['ip' => [], 'cidr' => [], 'domain' => []];
        $dir = __DIR__ . '/warninglists';
        if (!is_dir($dir)) return null;
        foreach (glob($dir . '/*.txt') as $path) {
            $list_name = basename($path, '.txt');
            foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') continue;
                $p = explode('|', $line, 2);
                $val = trim($p[0]); $label = trim($p[1] ?? '');
                if ($val === '') continue;

                // CIDR
                if (preg_match('#^(\d+\.\d+\.\d+\.\d+)/(\d+)$#', $val, $m)) {
                    $cache['cidr'][] = [
                        'net_long' => ip2long($m[1]) & (-1 << (32 - (int)$m[2])),
                        'mask_bits' => (int)$m[2],
                        'value' => $val, 'label' => $label, 'list' => $list_name,
                    ];
                }
                // Single IP
                elseif (filter_var($val, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $cache['ip'][$val] = ['value' => $val, 'label' => $label, 'list' => $list_name];
                }
                // Domain
                elseif (preg_match('/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i', $val)) {
                    $cache['domain'][strtolower($val)] = ['value' => $val, 'label' => $label, 'list' => $list_name];
                }
            }
        }
    }
    if (empty($cache['ip']) && empty($cache['cidr']) && empty($cache['domain'])) return null;

    $type = $type ?? cwe_detect_type($value);

    // IPv4 / CIDR check
    if (in_array($type, ['ip-src','ip-dst','cidr'], true)) {
        $ip = $value; if (strpos($ip, '/') !== false) $ip = explode('/', $ip)[0];
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // Exact IP match
            if (isset($cache['ip'][$ip])) {
                $h = $cache['ip'][$ip];
                return ['list' => $h['list'], 'value' => $h['value'], 'label' => $h['label'], 'rule' => 'exact-ip'];
            }
            // CIDR containment
            $ip_long = ip2long($ip);
            foreach ($cache['cidr'] as $c) {
                $mask = $c['mask_bits'] === 0 ? 0 : (-1 << (32 - $c['mask_bits']));
                if (($ip_long & $mask) === $c['net_long']) {
                    return ['list' => $c['list'], 'value' => $c['value'], 'label' => $c['label'], 'rule' => 'cidr-contains'];
                }
            }
        }
    }

    // Domain / URL check
    if (in_array($type, ['domain','hostname','url'], true)) {
        $host = $value;
        if (preg_match('#^https?://([^/\s:]+)#i', $host, $m)) $host = $m[1];
        $host = strtolower(trim($host, '. '));
        // Exact match
        if (isset($cache['domain'][$host])) {
            $h = $cache['domain'][$host];
            return ['list' => $h['list'], 'value' => $h['value'], 'label' => $h['label'], 'rule' => 'exact-domain'];
        }
        // Suffix match (subdomain'ler de düşer)
        foreach ($cache['domain'] as $d => $h) {
            if (str_ends_with($host, '.' . $d) || $host === $d) {
                return ['list' => $h['list'], 'value' => $h['value'], 'label' => $h['label'], 'rule' => 'suffix-domain'];
            }
        }
    }

    return null;
}

/**
 * R34 (T2.4): IP veya CIDR'ın big tech (Google/CF/MS/AWS) aralığıyla
 * çakışıp çakışmadığını kontrol et.
 *
 * Returns: null yoksa overlap; aksi halde ['cidr','provider','service'] dict.
 *
 * Pragmatik IPv4-only; IPv6 satırları atlanır.
 * In-memory cache: ilk çağrıda dosyayı yükler, sonraki çağrılarda reuse.
 */
function cwe_bigtech_match(string $ip_or_cidr): ?array {
    static $bigtech = null;
    if ($bigtech === null) {
        $bigtech = [];
        $path = __DIR__ . '/bigtech_cidr.txt';
        if (file_exists($path)) {
            foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                if ($line === '' || $line[0] === '#') continue;
                $p = explode('|', $line);
                $cidr = $p[0] ?? '';
                if (strpos($cidr, ':') !== false) continue; // IPv6 skip
                if (preg_match('#^(\d+\.\d+\.\d+\.\d+)/(\d+)$#', $cidr, $m)) {
                    $bigtech[] = [
                        'net_long' => ip2long($m[1]) & (-1 << (32 - (int)$m[2])),
                        'mask_bits' => (int)$m[2],
                        'cidr' => $cidr,
                        'provider' => $p[1] ?? '?',
                        'service' => $p[2] ?? '',
                    ];
                }
            }
        }
    }
    if (empty($bigtech)) return null;

    // Input → ip_long ve check_bits
    $check_ip = $ip_or_cidr;
    if (strpos($check_ip, '/') !== false) $check_ip = explode('/', $check_ip)[0];
    if (!filter_var($check_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return null;
    $check_long = ip2long($check_ip);

    foreach ($bigtech as $b) {
        $mask = $b['mask_bits'] === 0 ? 0 : (-1 << (32 - $b['mask_bits']));
        if (($check_long & $mask) === $b['net_long']) {
            return ['cidr'=>$b['cidr'], 'provider'=>$b['provider'], 'service'=>$b['service']];
        }
    }
    return null;
}
