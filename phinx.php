<?php declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

$dotenv = \Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

$env = $_ENV + getenv();

// Phinx uses the migrator role (DDL grants). Falls back to app role if
// DB_MIGRATOR_* not set (for environments that haven't separated the two).
$user = $env['DB_MIGRATOR_USER'] ?? $env['DB_USER'] ?? 'blockharbor_app';
$pass = $env['DB_MIGRATOR_PASSWORD'] ?? $env['DB_PASSWORD'] ?? '';

return [
    'paths' => [
        'migrations' => __DIR__ . '/db/migrations',
        'seeds'      => __DIR__ . '/db/seeds',
    ],
    'environments' => [
        'default_migration_table' => 'phinxlog',
        'default_environment'     => $env['APP_ENV'] ?? 'production',
        'production' => [
            'adapter' => 'pgsql',
            'host'    => $env['DB_HOST'] ?? '127.0.0.1',
            'name'    => $env['DB_NAME'] ?? 'blockharbor',
            'user'    => $user,
            'pass'    => $pass,
            'port'    => (int)($env['DB_PORT'] ?? 5432),
            'charset' => 'utf8',
        ],
        'testing' => [
            'adapter' => 'pgsql',
            'host'    => $env['DB_HOST'] ?? '127.0.0.1',
            'name'    => ($env['DB_NAME'] ?? 'blockharbor') . '_test',
            'user'    => $user,
            'pass'    => $pass,
            'port'    => (int)($env['DB_PORT'] ?? 5432),
            'charset' => 'utf8',
        ],
    ],
    'version_order' => 'creation',
];
