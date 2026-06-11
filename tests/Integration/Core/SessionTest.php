<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Core;

use BlockHarbor\Core\Session;
use BlockHarbor\Tests\DatabaseTestCase;

final class SessionTest extends DatabaseTestCase
{
    public function test_writes_payload_to_user_sessions_row(): void
    {
        $pdo = $this->db->pdo();
        $pdo->exec("INSERT INTO users (username, password_hash, role) VALUES ('alice','x','admin')");
        $userId = (int)$pdo->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();

        $sid = '11111111-1111-1111-1111-111111111111';
        $pdo->exec("INSERT INTO user_sessions (id, user_id, expires_at)
                    VALUES ('$sid', $userId, now() + interval '1 hour')");

        $handler = new Session($pdo, lifetime: 3600);
        self::assertTrue($handler->write($sid, 'user_id|i:42;'));

        $payload = $pdo->query("SELECT payload FROM user_sessions WHERE id='$sid'")->fetchColumn();
        self::assertSame('user_id|i:42;', $payload);
        self::assertSame('user_id|i:42;', $handler->read($sid));
    }

    public function test_read_returns_empty_for_expired_or_revoked(): void
    {
        $pdo = $this->db->pdo();
        $pdo->exec("INSERT INTO users (username, password_hash, role) VALUES ('alice','x','admin')");
        $userId = (int)$pdo->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();

        $expired = '22222222-2222-2222-2222-222222222222';
        $revoked = '33333333-3333-3333-3333-333333333333';
        $pdo->exec("INSERT INTO user_sessions (id, user_id, payload, expires_at)
                    VALUES ('$expired', $userId, 'data', now() - interval '1 hour')");
        $pdo->exec("INSERT INTO user_sessions (id, user_id, payload, expires_at, revoked_at)
                    VALUES ('$revoked', $userId, 'data', now() + interval '1 hour', now())");

        $handler = new Session($pdo, lifetime: 3600);
        self::assertSame('', $handler->read($expired));
        self::assertSame('', $handler->read($revoked));
    }

    public function test_destroy_revokes_session(): void
    {
        $pdo = $this->db->pdo();
        $pdo->exec("INSERT INTO users (username, password_hash, role) VALUES ('alice','x','admin')");
        $userId = (int)$pdo->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();
        $id = '44444444-4444-4444-4444-444444444444';
        $pdo->exec("INSERT INTO user_sessions (id, user_id, expires_at)
                    VALUES ('$id', $userId, now() + interval '1 hour')");

        $handler = new Session($pdo, lifetime: 3600);
        self::assertTrue($handler->destroy($id));

        $revoked = $pdo->query("SELECT revoked_at FROM user_sessions WHERE id='$id'")->fetchColumn();
        self::assertNotNull($revoked);
    }
}
