<?php declare(strict_types=1);

namespace BlockHarbor\Tests;

use BlockHarbor\Core\Config;
use BlockHarbor\Core\Database;
use PHPUnit\Framework\TestCase;

/**
 * Base class for tests that need a live DB connection. Truncates the
 * identity-domain tables in setUp() so each test starts clean.
 *
 * Subsequent phases (P2 audit, P3 IOC, ...) extend the TRUNCATE list as
 * new domain tables land.
 */
abstract class DatabaseTestCase extends TestCase
{
    protected Database $db;
    protected Config $config;

    protected function setUp(): void
    {
        $env = $this->parseEnv(__DIR__ . '/../.env');

        // Use the MIGRATOR role for tests — it has DDL (TRUNCATE) grants;
        // app role only has DML and would fail TRUNCATE on referenced tables.
        $this->config = new Config([
            'DB_HOST'     => $env['DB_HOST'] ?? '127.0.0.1',
            'DB_PORT'     => $env['DB_PORT'] ?? '5432',
            'DB_NAME'     => $env['DB_NAME'] ?? 'blockharbor',
            'DB_USER'     => $env['DB_MIGRATOR_USER'] ?? $env['DB_USER'] ?? 'blockharbor_migrator',
            'DB_PASSWORD' => $env['DB_MIGRATOR_PASSWORD'] ?? $env['DB_PASSWORD'] ?? '',
            'DB_SSLMODE'  => 'disable',
        ]);
        $this->db = new Database($this->config);
        $this->resetTables();
    }

    protected function resetTables(): void
    {
        $pdo = $this->db->pdo();
        $pdo->exec(
            'TRUNCATE audit_log, login_attempts, user_sessions, password_history, users '
            . 'RESTART IDENTITY CASCADE'
        );
    }

    /** @return array<string,string> */
    private function parseEnv(string $path): array
    {
        $out = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if (str_starts_with(ltrim($line), '#')) {
                continue;
            }
            if (preg_match('/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$/', $line, $m)) {
                $out[$m[1]] = $m[2];
            }
        }
        return $out;
    }
}
