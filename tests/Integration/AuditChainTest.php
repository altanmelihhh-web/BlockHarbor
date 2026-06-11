<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration;

use PDO;
use PHPUnit\Framework\TestCase;

final class AuditChainTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        // Read DB creds from .env directly (no Config dependency yet to keep
        // this test isolated from later P1 wiring).
        $envPath = __DIR__ . '/../../.env';
        $env = $this->parseEnv($envPath);

        $host = $env['DB_HOST'] ?? '127.0.0.1';
        $user = $env['DB_MIGRATOR_USER'] ?? $env['DB_USER'] ?? 'blockharbor_migrator';
        $pass = $env['DB_MIGRATOR_PASSWORD'] ?? $env['DB_PASSWORD'] ?? '';
        $name = $env['DB_NAME'] ?? 'blockharbor';

        $this->pdo = new PDO(
            "pgsql:host=$host;port=5432;dbname=$name",
            $user,
            $pass,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );

        $this->pdo->exec('DELETE FROM audit_log');
    }

    public function test_first_entry_has_null_byte_prev_hash(): void
    {
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('test.first')");

        $row = $this->pdo->query(
            'SELECT prev_hash, entry_hash FROM audit_log ORDER BY id'
        )->fetch(PDO::FETCH_ASSOC);

        self::assertSame("\x00", $row['prev_hash']);
        self::assertSame(32, strlen($row['entry_hash']));  // sha256 = 32 bytes
    }

    public function test_chain_links_to_previous_entry(): void
    {
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('first')");
        $first = $this->pdo->query(
            'SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1'
        )->fetchColumn();

        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('second')");
        $secondPrev = $this->pdo->query(
            'SELECT prev_hash FROM audit_log ORDER BY id DESC LIMIT 1'
        )->fetchColumn();

        self::assertSame($first, $secondPrev);
    }

    public function test_third_entry_continues_chain(): void
    {
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('a')");
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('b')");
        $this->pdo->exec("INSERT INTO audit_log (action) VALUES ('c')");

        $rows = $this->pdo->query(
            'SELECT prev_hash, entry_hash FROM audit_log ORDER BY id'
        )->fetchAll(PDO::FETCH_ASSOC);

        self::assertCount(3, $rows);
        self::assertSame($rows[0]['entry_hash'], $rows[1]['prev_hash']);
        self::assertSame($rows[1]['entry_hash'], $rows[2]['prev_hash']);
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
