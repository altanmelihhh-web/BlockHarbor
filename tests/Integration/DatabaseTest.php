<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration;

use BlockHarbor\Core\Config;
use BlockHarbor\Core\Database;
use PDO;
use PHPUnit\Framework\TestCase;

final class DatabaseTest extends TestCase
{
    private Config $config;

    protected function setUp(): void
    {
        // Read DB creds from .env via inline parse (Config::fromEnvFile mutates
        // global $_ENV; using direct array avoids cross-test contamination).
        $env = $this->parseEnv(__DIR__ . '/../../.env');

        $this->config = new Config([
            'DB_HOST'     => $env['DB_HOST'] ?? '127.0.0.1',
            'DB_PORT'     => $env['DB_PORT'] ?? '5432',
            'DB_NAME'     => $env['DB_NAME'] ?? 'blockharbor',
            'DB_USER'     => $env['DB_USER'] ?? 'blockharbor_app',
            'DB_PASSWORD' => $env['DB_PASSWORD'] ?? '',
            'DB_SSLMODE'  => 'disable',
        ]);
    }

    public function test_pdo_uses_exception_error_mode(): void
    {
        $db = new Database($this->config);
        $pdo = $db->pdo();
        self::assertSame(PDO::ERRMODE_EXCEPTION, $pdo->getAttribute(PDO::ATTR_ERRMODE));
    }

    public function test_pdo_returns_assoc_by_default(): void
    {
        $db = new Database($this->config);
        $pdo = $db->pdo();
        self::assertSame(PDO::FETCH_ASSOC, $pdo->getAttribute(PDO::ATTR_DEFAULT_FETCH_MODE));
    }

    public function test_pdo_is_singleton_per_instance(): void
    {
        $db = new Database($this->config);
        self::assertSame($db->pdo(), $db->pdo());
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
