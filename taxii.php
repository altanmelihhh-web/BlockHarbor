<?php
/**
 * Cyberwebeyeos — TAXII 2.1 Envelope (R40 T3.5)
 *
 * Tam TAXII sunucusu değil; minimal envelope endpoint'leri:
 *   GET /taxii2/                         → discovery (server info, default api_root)
 *   GET /taxii2/api1/                    → api root info
 *   GET /taxii2/api1/collections/        → collection listesi (1 koleksiyon)
 *   GET /taxii2/api1/collections/cyberwebeyeos-blacklist/         → collection details
 *   GET /taxii2/api1/collections/cyberwebeyeos-blacklist/objects/ → STIX 2.1 envelope (Indicator object'ler)
 *
 * Auth: X-API-Key (api.php ile aynı key system, role admin/operator/viewer hepsi okuyabilir).
 *
 * Routing: .htaccess RewriteRule /taxii2/* → taxii.php?path=*
 */

require_once __DIR__ . '/ioc_helpers.php';

header('Content-Type: application/taxii+json;version=2.1; charset=utf-8');
header('Cache-Control: max-age=60');

$path = trim($_GET['path'] ?? '', '/');
$base = '/blacklist/cyberwebeyeos/taxii2/';
$BASE_URL = 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . $base;

// --- Auth (X-API-Key, api.php uyumu) ---
$cfg = @include __DIR__ . '/auth_config.php';
$valid_keys = is_array($cfg['api_keys'] ?? null) ? $cfg['api_keys'] : [];
$provided = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['api_key'] ?? '');

$matched = null;
foreach ($valid_keys as $k) {
    if (is_string($k) && hash_equals($k, $provided)) { $matched = ['role'=>'admin']; break; }
    if (is_array($k) && hash_equals((string)($k['key'] ?? ''), $provided)) { $matched = $k; break; }
}
if (!$matched) {
    http_response_code(401);
    echo json_encode(['title'=>'Unauthorized', 'http_status'=>'401',
        'description'=>'X-API-Key header zorunlu. auth_config.php → api_keys']);
    exit;
}

// --- Routing ---
$COLLECTION_ID = 'cyberwebeyeos-blacklist';

if ($path === '' || $path === 'taxii') {
    // Discovery
    echo json_encode([
        'title' => 'Cyberwebeyeos Threat Intelligence Platform',
        'description' => 'TAXII 2.1 envelope for cyberwebeyeos blacklist IoCs (subset; not a full TAXII server)',
        'contact' => getenv('CWE_CONTACT_EMAIL') ?: 'admin@example.com',
        'default' => $BASE_URL . 'api1/',
        'api_roots' => [$BASE_URL . 'api1/'],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

if ($path === 'api1' || $path === 'api1/') {
    // API root info
    echo json_encode([
        'title' => 'Cyberwebeyeos TAXII API Root',
        'description' => 'STIX 2.1 indicators backed by cyberwebeyeos blacklist',
        'versions' => ['application/taxii+json;version=2.1'],
        'max_content_length' => 10485760,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

if ($path === 'api1/collections' || $path === 'api1/collections/') {
    echo json_encode([
        'collections' => [
            [
                'id' => $COLLECTION_ID,
                'title' => 'Cyberwebeyeos Blacklist',
                'description' => 'Curated IoC feed (IP/CIDR/Domain/URL/Hash) — 10-field schema',
                'can_read' => true,
                'can_write' => false,
                'media_types' => ['application/taxii+json;version=2.1'],
            ],
        ],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

if ($path === "api1/collections/{$COLLECTION_ID}" || $path === "api1/collections/{$COLLECTION_ID}/") {
    echo json_encode([
        'id' => $COLLECTION_ID,
        'title' => 'Cyberwebeyeos Blacklist',
        'description' => 'Curated IoC feed (IP/CIDR/Domain/URL/Hash)',
        'can_read' => true,
        'can_write' => false,
        'media_types' => ['application/taxii+json;version=2.1'],
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

if ($path === "api1/collections/{$COLLECTION_ID}/objects" || $path === "api1/collections/{$COLLECTION_ID}/objects/") {
    // STIX 2.1 envelope — Indicator objects'e map et
    $limit = max(1, min(2000, (int)($_GET['limit'] ?? 500)));

    // TLP marking-definition referansı (STIX 2.1 standartı)
    $tlp_marking = [
        'WHITE' => 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
        'GREEN' => 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
        'AMBER' => 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
        'RED'   => 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    ];

    // Type → STIX pattern mapping
    $stix_pattern = function(string $type, string $value): ?string {
        $val = addslashes($value);
        return match (true) {
            in_array($type, ['ip-src','ip-dst'], true) => "[ipv4-addr:value = '$val']",
            $type === 'cidr'                          => "[ipv4-addr:value ISSUBSET '$val']",
            $type === 'ipv6'                          => "[ipv6-addr:value = '$val']",
            in_array($type, ['domain','hostname'], true) => "[domain-name:value = '$val']",
            $type === 'url'                            => "[url:value = '$val']",
            $type === 'file-md5'                       => "[file:hashes.'MD5' = '$val']",
            $type === 'file-sha1'                      => "[file:hashes.'SHA-1' = '$val']",
            $type === 'file-sha256'                    => "[file:hashes.'SHA-256' = '$val']",
            $type === 'email-src'                      => "[email-addr:value = '$val']",
            default                                    => null,
        };
    };

    $objects = [];
    $bl_file = __DIR__ . '/blacklist.txt';
    if (file_exists($bl_file)) {
        $count = 0;
        foreach (file($bl_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if ($line === '' || $line[0] === '#') continue;
            $e = cwe_parse_blacklist_entry($line);
            if (cwe_is_expired($e)) continue;
            $pattern = $stix_pattern($e['type'], $e['value']);
            if (!$pattern) continue;

            // Deterministik UUID5 (namespace=DNS, name=value) → tekrar üretilebilir
            $uuid_input = 'cyberwebeyeos:' . $e['value'];
            $hash = sha1($uuid_input, false);
            $uuid5 = sprintf('%s-%s-5%s-%s-%s',
                substr($hash, 0, 8), substr($hash, 8, 4),
                substr($hash, 13, 3),
                dechex(0x8000 | (hexdec(substr($hash, 16, 4)) & 0x3fff)),
                substr($hash, 20, 12)
            );

            $created = $e['date'] ?: date('c');
            // ISO 8601 + Z
            $created_iso = date('Y-m-d\TH:i:s\Z', strtotime($created) ?: time());
            $valid_from_iso = $created_iso;
            $valid_until_iso = null;
            if ($e['valid_until'] !== 'permanent' && $e['valid_until'] !== '') {
                $vu_ts = strtotime($e['valid_until']);
                if ($vu_ts !== false) $valid_until_iso = date('Y-m-d\TH:i:s\Z', $vu_ts);
            }

            $obj = [
                'type' => 'indicator',
                'spec_version' => '2.1',
                'id' => 'indicator--' . $uuid5,
                'created' => $created_iso,
                'modified' => $created_iso,
                'name' => "{$e['type']} indicator: {$e['value']}",
                'description' => $e['comment'] ?: '(no comment)',
                'pattern' => $pattern,
                'pattern_type' => 'stix',
                'valid_from' => $valid_from_iso,
                'indicator_types' => ['malicious-activity'],
                'confidence' => (int)$e['confidence'],
                'labels' => ['malicious-activity'],
                'object_marking_refs' => [$tlp_marking[$e['tlp']] ?? $tlp_marking['WHITE']],
                'x_cwe_source' => $e['added_by'],
                'x_cwe_fqdn' => $e['fqdn'] ?: null,
                'x_cwe_jira' => $e['jira'] ?: null,
            ];
            if ($valid_until_iso) $obj['valid_until'] = $valid_until_iso;

            $objects[] = $obj;
            $count++;
            if ($count >= $limit) break;
        }
    }

    echo json_encode([
        'more' => false,
        'objects' => $objects,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// Unknown path
http_response_code(404);
echo json_encode([
    'title' => 'Not Found',
    'http_status' => '404',
    'description' => 'TAXII path bilinmiyor: ' . $path,
    'known_paths' => [
        $BASE_URL,
        $BASE_URL . 'api1/',
        $BASE_URL . 'api1/collections/',
        $BASE_URL . "api1/collections/{$COLLECTION_ID}/",
        $BASE_URL . "api1/collections/{$COLLECTION_ID}/objects/",
    ],
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
