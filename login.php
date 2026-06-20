<?php
/**
 * Cyberwebeyeos Blacklist — Login Sayfası
 *
 * R26 (T1.1 RBAC): users.json'daki kullanıcılar artık login olabilir.
 * Sıralama:
 *   1. users.json'da username eşleşmesi ara (password_hash + active + role)
 *   2. Bulamazsa auth_config.php'deki default user'a düş (geriye uyumluluk)
 * Login sonrası $_SESSION['cwe_role'] set edilir.
 */

require_once __DIR__ . '/audit_log.php';

$cfg = require __DIR__ . '/auth_config.php';

session_name($cfg['session_name']);
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => $cfg['session_lifetime'],
        'path'     => '/blacklist/cyberwebeyeos/',
        'secure'   => !empty($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}

$error = '';
$next = isset($_GET['next']) ? $_GET['next'] : '/blacklist/cyberwebeyeos/cyberwebeyeosblacklistadmin.php';
// next URL guard — sadece kendi path'imize redirect
if (strpos($next, '/blacklist/cyberwebeyeos/') !== 0) {
    $next = '/blacklist/cyberwebeyeos/cyberwebeyeosblacklistadmin.php';
}

/**
 * users.json'dan kullanıcı bul. Bulamazsa null.
 * Return: ['username','role','password_hash','active','id'] veya null
 */
function _cwe_find_user(string $username): ?array {
    $path = __DIR__ . '/users.json';
    if (!file_exists($path)) return null;
    $data = json_decode(@file_get_contents($path), true);
    if (!is_array($data) || !isset($data['users']) || !is_array($data['users'])) return null;
    foreach ($data['users'] as $u) {
        if (($u['username'] ?? '') === $username) return $u;
    }
    return null;
}

/**
 * users.json'da last_login alanını güncelle (best-effort).
 */
function _cwe_touch_last_login(string $username): void {
    $path = __DIR__ . '/users.json';
    if (!file_exists($path)) return;
    $data = json_decode(@file_get_contents($path), true);
    if (!is_array($data) || empty($data['users'])) return;
    $changed = false;
    foreach ($data['users'] as &$u) {
        if (($u['username'] ?? '') === $username) {
            $u['last_login'] = date('Y-m-d H:i:s');
            $changed = true;
            break;
        }
    }
    if ($changed) {
        @file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = trim($_POST['username'] ?? '');
    $pass = $_POST['password'] ?? '';

    $authed_user = null;
    $authed_role = null;

    // 1) users.json kontrolü (password_hash olan kayıtlar için)
    $u = _cwe_find_user($user);
    if ($u && !empty($u['password_hash']) && !empty($u['active'])) {
        if (password_verify($pass, $u['password_hash'])) {
            $authed_user = $u['username'];
            $authed_role = in_array($u['role'] ?? '', ['admin','operator','viewer'], true) ? $u['role'] : 'viewer';
        }
    }

    // 2) Default user fallback (auth_config.php — geriye uyumluluk)
    if (!$authed_user && $user === ($cfg['username'] ?? '') && password_verify($pass, $cfg['password_hash'] ?? '')) {
        $authed_user = $cfg['username'];
        // Default user'ın users.json'daki rolünü al, yoksa admin
        if ($u && in_array($u['role'] ?? '', ['admin','operator','viewer'], true)) {
            $authed_role = $u['role'];
        } else {
            $authed_role = 'admin';
        }
    }

    if ($authed_user) {
        // Eğer users.json'daki user pasifse engelle
        if ($u && isset($u['active']) && $u['active'] === false) {
            $error = 'Hesabınız devre dışı bırakılmış. Yöneticiyle iletişime geçin.';
            audit_log_event('login_blocked_inactive', ['user' => $user]);
            usleep(500000);
        } else {
            session_regenerate_id(true);
            $_SESSION['cwe_auth']       = true;
            $_SESSION['cwe_user']       = $authed_user;
            $_SESSION['cwe_role']       = $authed_role;
            $_SESSION['cwe_login_time'] = time();
            _cwe_touch_last_login($authed_user);
            audit_log_event('login_success', ['user' => $authed_user, 'role' => $authed_role]);
            header('Location: ' . $next);
            exit;
        }
    } else {
        $error = 'Kullanıcı adı veya parola hatalı.';
        audit_log_event('login_failed', ['user' => $user, 'ip' => $_SERVER['REMOTE_ADDR'] ?? '-']);
        // Brute-force basit önlem
        usleep(500000);
    }
}

// Zaten login ise direkt admin'e git
if (isset($_SESSION['cwe_auth']) && $_SESSION['cwe_auth'] === true) {
    header('Location: ' . $next);
    exit;
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cyberwebeyeos Blacklist — Giriş</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);
       min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  .card{background:#fff;border-radius:14px;padding:40px 36px;width:100%;max-width:400px;
        box-shadow:0 20px 60px rgba(0,0,0,.4)}
  .brand{text-align:center;margin-bottom:28px}
  .brand-icon{width:64px;height:64px;background:#16a085;border-radius:50%;
              display:inline-flex;align-items:center;justify-content:center;color:#fff;
              font-size:28px;margin-bottom:14px}
  .brand h1{font-size:1.25rem;color:#0f172a;font-weight:700;letter-spacing:-.01em}
  .brand p{font-size:.85rem;color:#64748b;margin-top:4px}
  .field{margin-bottom:16px}
  .field label{display:block;font-size:.78rem;color:#475569;font-weight:600;
               margin-bottom:6px;text-transform:uppercase;letter-spacing:.04em}
  .field input{width:100%;padding:11px 14px;border:1.5px solid #e2e8f0;border-radius:8px;
               font-size:.95rem;font-family:inherit;transition:border-color .15s}
  .field input:focus{outline:none;border-color:#16a085}
  .btn{width:100%;padding:13px;background:#0f172a;color:#fff;border:none;border-radius:8px;
       font-size:.95rem;font-weight:600;cursor:pointer;letter-spacing:.02em;transition:background .15s}
  .btn:hover{background:#1e293b}
  .err{background:#fee2e2;color:#991b1b;padding:10px 14px;border-radius:8px;
       font-size:.85rem;margin-bottom:16px;border:1px solid #fecaca}
  .role-hint{font-size:.72rem;color:#94a3b8;text-align:center;margin-top:14px;line-height:1.5}
  .role-hint b{color:#475569}
  footer{text-align:center;font-size:.75rem;color:#94a3b8;margin-top:24px}
</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <div class="brand-icon">🛡</div>
    <h1>Cyberwebeyeos Blacklist</h1>
    <p>Yönetim Paneli</p>
  </div>

  <?php if ($error): ?>
    <div class="err"><?= htmlspecialchars($error) ?></div>
  <?php endif; ?>

  <form method="post" autocomplete="on">
    <input type="hidden" name="next" value="<?= htmlspecialchars($next) ?>">
    <div class="field">
      <label for="username">Kullanıcı Adı</label>
      <input id="username" name="username" type="text" required autofocus autocomplete="username">
    </div>
    <div class="field">
      <label for="password">Parola</label>
      <input id="password" name="password" type="password" required autocomplete="current-password">
    </div>
    <button class="btn" type="submit">Giriş Yap</button>
  </form>

  <div class="role-hint">
    Roller: <b>admin</b> · <b>operator</b> · <b>viewer</b><br>
    Yetkisiz işlem denemesi audit log'a kayıt olur.
  </div>

  <footer>© <?= date('Y') ?> Cyberwebeyeos</footer>
</div>
</body>
</html>
