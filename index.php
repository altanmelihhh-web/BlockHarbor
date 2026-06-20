<?php
// /blacklist/cyberwebeyeos/ landing — auth durumuna göre yönlendir
require __DIR__ . '/blacklist_admin_auth.php';
header('Location: /blacklist/cyberwebeyeos/cyberwebeyeosblacklistadmin.php');
exit;
