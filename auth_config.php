<?php
/**
 * Cyberwebeyeos Blacklist — Auth Config (env-driven)
 *
 * Ortam değişkenleri (.env veya Docker env):
 *   CWE_ADMIN_USERNAME       — admin kullanıcı adı (default: admin)
 *   CWE_ADMIN_PASSWORD_HASH  — bcrypt hash (boşsa: admin/admin, ilk girişte değiştir)
 *   CWE_API_KEYS             — JSON: [{"key":"...","role":"admin","owner":"..."}]
 *   CWE_VT_API_KEY           — VirusTotal v3 API key
 *   CWE_GREYNOISE_API_KEY    — GreyNoise community API key
 *   CWE_IPGEOLOCATION_API_KEY — ipgeolocation.io API key
 *
 * Hash üretmek: php -r "echo password_hash('PAROLA', PASSWORD_BCRYPT) . \"\\n\";"
 */

$_raw_api_keys = getenv('CWE_API_KEYS');
$_api_keys = [];
if ($_raw_api_keys) {
    $decoded = json_decode($_raw_api_keys, true);
    if (is_array($decoded)) $_api_keys = $decoded;
}
if (empty($_api_keys)) {
    // Default dev key — production'da CWE_API_KEYS env ile override et
    $_api_keys = [
        [
            'key'   => 'cwe_dev_replace_before_production',
            'role'  => 'admin',
            'owner' => 'dev/test — production öncesi CWE_API_KEYS env değişkeni ile rotate et',
        ],
    ];
}

$_password_hash = getenv('CWE_ADMIN_PASSWORD_HASH') ?: password_hash('admin', PASSWORD_BCRYPT);

return [
    'username'         => getenv('CWE_ADMIN_USERNAME') ?: 'admin',
    'password_hash'    => $_password_hash,
    'session_name'     => 'CWE_BLACKLIST_SESSION',
    'session_lifetime' => 3600,

    // REST API access keys (X-API-Key header). Rol bazlı: admin/operator/viewer.
    'api_keys' => $_api_keys,

    // VirusTotal v3 API key (4 req/min free tier).
    'vt_api_key' => getenv('CWE_VT_API_KEY') ?: '',
];

// SPRINT6-B2: GreyNoise community API key (free tier, 50/day)
$greynoise_api_key = getenv('CWE_GREYNOISE_API_KEY') ?: '';

// R87b: ipgeolocation.io API key
$ipgeolocation_api_key = getenv('CWE_IPGEOLOCATION_API_KEY') ?: '';
