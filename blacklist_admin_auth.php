<?php
/**
 * Cyberwebeyeos Blacklist — Standalone Authentication + RBAC
 *
 * Bu dosya her admin sayfasının başında include edilir. Portal'dan tamamen
 * bağımsız: kendi $_SESSION'ı ile çalışır, kendi login form'unu kullanır.
 *
 * R26 (T1.1 RBAC): require_role() fonksiyonu eklendi. Roller:
 *   admin    — tüm yetkiler (user/list/source/data CRUD)
 *   operator — IoC ekle/sil/onayla, whitelist, bulk
 *   viewer   — sadece okuma (search, export, GET endpoints)
 */

$__cwe_cfg = require __DIR__ . '/auth_config.php';

// Session konfigürasyonu — portal session ile çakışmasın diye kendi isim
session_name($__cwe_cfg['session_name']);

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => $__cwe_cfg['session_lifetime'],
        'path'     => '/blacklist/cyberwebeyeos/',
        'domain'   => '',
        'secure'   => !empty($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

// Login kontrolü
$__authed = isset($_SESSION['cwe_auth']) && $_SESSION['cwe_auth'] === true
         && isset($_SESSION['cwe_user']) && !empty($_SESSION['cwe_user'])
         && isset($_SESSION['cwe_login_time']) && (time() - $_SESSION['cwe_login_time']) < $__cwe_cfg['session_lifetime'];

if (!$__authed) {
    // Login değil → login sayfasına yönlendir
    $login_url = '/blacklist/cyberwebeyeos/login.php?next=' . urlencode($_SERVER['REQUEST_URI'] ?? '/blacklist/cyberwebeyeos/');
    header('Location: ' . $login_url);
    exit;
}

// Default role fallback (eski oturumlar için)
if (empty($_SESSION['cwe_role'])) {
    $_SESSION['cwe_role'] = ($_SESSION['cwe_user'] === ($__cwe_cfg['username'] ?? 'cyberwebeyeos')) ? 'admin' : 'viewer';
}

// Aktivite zaman damgasını tazele (her admin sayfası ziyaretinde)
$_SESSION['cwe_login_time'] = time();

/**
 * Mevcut kullanıcının rolü (admin/operator/viewer). Boşsa viewer.
 */
function cwe_current_role(): string {
    return isset($_SESSION['cwe_role']) ? (string)$_SESSION['cwe_role'] : 'viewer';
}

function cwe_current_user(): string {
    return isset($_SESSION['cwe_user']) ? (string)$_SESSION['cwe_user'] : '';
}

/**
 * Mevcut kullanıcının verilen rollerden birine sahip olmasını zorunlu kılar.
 * Aksi halde 403 döndürür ve audit log'a kaydeder. Script'i sonlandırır.
 *
 * @param array $allowed örn. ['admin','operator']
 */
function require_role(array $allowed): void {
    $role = cwe_current_role();
    if (in_array($role, $allowed, true)) {
        return; // OK
    }

    // Audit log
    if (function_exists('audit_log_event')) {
        audit_log_event('rbac_denied', [
            'user'     => cwe_current_user(),
            'role'     => $role,
            'required' => $allowed,
            'uri'      => $_SERVER['REQUEST_URI'] ?? '',
            'method'   => $_SERVER['REQUEST_METHOD'] ?? '',
        ]);
    }

    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    $req = htmlspecialchars(implode(', ', $allowed));
    $cur = htmlspecialchars($role);
    echo <<<HTML
<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"><title>403 — Yetkisiz</title>
<style>body{font-family:-apple-system,sans-serif;max-width:520px;margin:80px auto;padding:24px;color:#0f172a}
h1{color:#dc2626;margin-bottom:12px}p{line-height:1.6;color:#475569}
.box{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;margin:16px 0}
.role{display:inline-block;padding:2px 8px;background:#1e293b;color:#fff;border-radius:4px;font-size:.85em}
a{color:#16a085;text-decoration:none}a:hover{text-decoration:underline}</style></head>
<body><h1>🚫 403 — Yetkisiz Erişim</h1>
<div class="box"><p>Bu işlem için yeterli yetkiniz yok.</p>
<p>Mevcut rol: <span class="role">{$cur}</span> · Gerekli rol(ler): <span class="role">{$req}</span></p></div>
<p><a href="/blacklist/cyberwebeyeos/cyberwebeyeosblacklistadmin.php">← Admin paneline dön</a></p>
</body></html>
HTML;
    exit;
}
