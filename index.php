<?php
require_once __DIR__ . '/app_paths.php';
// /blacklist/cyberwebeyeos/ landing — auth durumuna göre yönlendir
require __DIR__ . '/blacklist_admin_auth.php';
header('Location: ' . cwe_url('cyberwebeyeosblacklistadmin.php'));
exit;
