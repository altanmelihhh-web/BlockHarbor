<?php
$cfg = require __DIR__ . '/auth_config.php';
session_name($cfg['session_name']);
session_start();
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}
session_destroy();
header('Location: /blacklist/cyberwebeyeos/login.php');
exit;
