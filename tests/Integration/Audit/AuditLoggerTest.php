<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Audit;

use BlockHarbor\Audit\AuditLogger;
use BlockHarbor\Tests\DatabaseTestCase;
use PDO;

final class AuditLoggerTest extends DatabaseTestCase
{
    public function test_log_inserts_row_with_chained_hash(): void
    {
        $logger = new AuditLogger($this->db->pdo());
        $logger->log('user.create', ['username' => 'alice'], actor: 'admin', ip: '10.0.0.1');

        $row = $this->db->pdo()->query(
            "SELECT action, actor_username, ip_address::text AS ip,
                    details, encode(prev_hash,'hex') AS ph, encode(entry_hash,'hex') AS eh
             FROM audit_log ORDER BY id DESC LIMIT 1"
        )->fetch(PDO::FETCH_ASSOC);

        self::assertSame('user.create', $row['action']);
        self::assertSame('admin', $row['actor_username']);
        self::assertSame('10.0.0.1', $row['ip']);
        self::assertSame(['username' => 'alice'], json_decode($row['details'], true));
        self::assertSame('00', $row['ph']);              // first row → \x00
        self::assertSame(64, strlen($row['eh']));         // sha256 hex
    }

    public function test_log_omits_optional_fields(): void
    {
        $logger = new AuditLogger($this->db->pdo());
        $logger->log('system.boot');

        $row = $this->db->pdo()->query(
            "SELECT action, actor_username, ip_address::text AS ip FROM audit_log ORDER BY id DESC LIMIT 1"
        )->fetch(PDO::FETCH_ASSOC);

        self::assertSame('system.boot', $row['action']);
        self::assertNull($row['actor_username']);
        self::assertNull($row['ip']);
    }
}
