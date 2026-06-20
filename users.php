<?php
// Cyberwebeyeos Users CRUD handler
require_once __DIR__ . '/blacklist_admin_auth.php';
require_once __DIR__ . '/audit_log.php';

// R26 (T1.1 RBAC): user CRUD sadece admin
// Exception: user_change_password — kullanıcı kendi parolasını değiştirebilir (operator/viewer dahil)
if (!empty($_POST['user_change_password'])) {
    require_role(['admin','operator','viewer']);
    // Ek güvenlik: değiştirilen user_id mevcut kullanıcı olmalı (admin değilse)
    if (cwe_current_role() !== 'admin') {
        $__data = json_decode(@file_get_contents(__DIR__ . '/users.json'), true);
        $__target = null;
        foreach (($__data['users'] ?? []) as $__u) {
            if (($__u['id'] ?? '') === ($_POST['user_change_password'] ?? '')) { $__target = $__u; break; }
        }
        if (!$__target || ($__target['username'] ?? '') !== cwe_current_user()) {
            audit_log_event('rbac_denied', ['reason'=>'cross-user-password-change', 'target_id'=>$_POST['user_change_password']]);
            http_response_code(403);
            die('Sadece kendi parolanızı değiştirebilirsiniz.');
        }
    }
} else {
    require_role(['admin']);
}

define('USERS_JSON', __DIR__ . '/users.json');

function load_users() {
    if (!file_exists(USERS_JSON)) return ['users' => []];
    $d = json_decode(@file_get_contents(USERS_JSON), true);
    return is_array($d) && isset($d['users']) ? $d : ['users' => []];
}
function save_users(array $data) {
    file_put_contents(USERS_JSON, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    @chmod(USERS_JSON, 0660);
}

$msg = '';
$redir = !empty($_POST['return_to']) ? $_POST['return_to'] : 'cyberwebeyeosblacklistadmin.php#users';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = load_users();

    if (!empty($_POST['user_add'])) {
        $username = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $pass     = $_POST['password'] ?? '';
        $role     = in_array($_POST['role'] ?? '', ['admin','operator','viewer'], true) ? $_POST['role'] : 'viewer';

        if ($username === '' || $pass === '') {
            $msg = '❌ Kullanıcı adı ve parola zorunlu';
        } elseif (strlen($pass) < 8) {
            $msg = '❌ Parola en az 8 karakter olmalı';
        } else {
            foreach ($data['users'] as $u) {
                if (($u['username'] ?? '') === $username) { $msg = '❌ Bu kullanıcı adı zaten var'; break; }
            }
            if (!$msg) {
                $data['users'][] = [
                    'id'            => 'u_' . uniqid(),
                    'username'      => $username,
                    'role'          => $role,
                    'email'         => $email,
                    'password_hash' => password_hash($pass, PASSWORD_BCRYPT),
                    'created_at'    => date('Y-m-d H:i:s'),
                    'last_login'    => null,
                    'active'        => true,
                ];
                save_users($data);
                audit_log_event('user_create', ['username'=>$username, 'role'=>$role]);
                $msg = '✅ Kullanıcı eklendi: ' . htmlspecialchars($username) . ' (' . htmlspecialchars($role) . ')';
            }
        }
    } elseif (!empty($_POST['user_delete'])) {
        $id = $_POST['user_delete'];
        $new = [];
        $removed = null;
        foreach ($data['users'] as $u) {
            if (($u['id'] ?? '') === $id) {
                if (($u['id'] ?? '') === 'u_default' || ($u['username'] ?? '') === 'cyberwebeyeos') {
                    $msg = '❌ Default kullanıcı silinemez'; $new[] = $u; continue;
                }
                $removed = $u;
            } else {
                $new[] = $u;
            }
        }
        if ($removed) {
            $data['users'] = array_values($new);
            save_users($data);
            audit_log_event('user_delete', ['username'=>$removed['username'] ?? '-', 'id'=>$id]);
            $msg = '✅ Kullanıcı silindi: ' . htmlspecialchars($removed['username']);
        } elseif (!$msg) {
            $msg = '❌ Kullanıcı bulunamadı';
        }
    } elseif (!empty($_POST['user_change_password'])) {
        $id      = $_POST['user_change_password'];
        $oldpw   = $_POST['old_password'] ?? '';
        $newpw   = $_POST['new_password'] ?? '';
        $newpw2  = $_POST['new_password2'] ?? '';
        if (strlen($newpw) < 8) {
            $msg = '❌ Yeni parola en az 8 karakter olmalı';
        } elseif ($newpw !== $newpw2) {
            $msg = '❌ Yeni parolalar eşleşmiyor';
        } else {
            $found = false;
            // Default user için auth_config.php'deki hash'i de güncelle
            foreach ($data['users'] as &$u) {
                if (($u['id'] ?? '') === $id) {
                    $found = true;
                    if (!password_verify($oldpw, $u['password_hash'] ?? '')) {
                        // Default kullanıcı için auth_config'deki hash'i kontrol et
                        $cfg = @include __DIR__ . '/auth_config.php';
                        if (!password_verify($oldpw, $cfg['password_hash'] ?? '')) {
                            $msg = '❌ Mevcut parola yanlış'; break;
                        }
                    }
                    $newhash = password_hash($newpw, PASSWORD_BCRYPT);
                    $u['password_hash'] = $newhash;
                    save_users($data);
                    // Default user → auth_config.php'yi de güncelle
                    if (($u['username'] ?? '') === ($cfg['username'] ?? 'cyberwebeyeos')) {
                        $cfg_content = @file_get_contents(__DIR__ . '/auth_config.php');
                        $cfg_content = preg_replace("/'password_hash'\s*=>\s*'[^']*'/", "'password_hash' => '" . str_replace("'", "\\'", $newhash) . "'", $cfg_content);
                        @file_put_contents(__DIR__ . '/auth_config.php', $cfg_content);
                    }
                    audit_log_event('user_password_change', ['username'=>$u['username']]);
                    $msg = '✅ Parola değiştirildi: ' . htmlspecialchars($u['username']);
                    break;
                }
            }
            if (!$found) $msg = '❌ Kullanıcı bulunamadı';
        }
    } elseif (!empty($_POST['user_toggle'])) {
        $id = $_POST['user_toggle'];
        foreach ($data['users'] as &$u) {
            if (($u['id'] ?? '') === $id) {
                $u['active'] = empty($u['active']);
                save_users($data);
                $msg = '✅ Durum değişti: ' . htmlspecialchars($u['username']) . ' → ' . ($u['active'] ? 'Aktif' : 'Pasif');
                break;
            }
        }
    }

    $_SESSION['message'] = $msg;
    header('Location: ' . $redir);
    exit;
}

header('Location: cyberwebeyeosblacklistadmin.php#users');
exit;
