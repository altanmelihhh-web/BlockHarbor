<?php
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($uri === '/' || $uri === '') $uri = '/index.php';
$file = __DIR__ . $uri;
if (!is_file($file)) { http_response_code(404); echo 'nf'; return true; }
if (substr($file,-4) !== '.php') return false;
$_SERVER['SCRIPT_NAME']=$uri; $_SERVER['SCRIPT_FILENAME']=$file; unset($_SERVER['PATH_INFO']);
require __DIR__.'/demo_mode.php'; require $file; return true;
