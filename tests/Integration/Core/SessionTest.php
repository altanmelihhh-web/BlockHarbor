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

    public function test_write_inserts_anonymous_row_when_missing(): void
    {
        // Regression: prior implementation only UPDATEd, so anonymous PHP
        // sessions (CSRF token before login) were silently lost between
        // requests. write() must INSERT with user_id NULL.
        $pdo = $this->db->pdo();
        $handler = new Session($pdo, lifetime: 3600);
        $sid = '55555555-5555-5555-5555-555555555555';

        self::assertTrue($handler->write($sid, '_csrf|s:8:"abc12345";'));

        $row = $pdo->query("SELECT user_id, payload FROM user_sessions WHERE id='$sid'")->fetch();
        self::assertNotFalse($row);
        self::assertNull($row['user_id']);
        self::assertSame('_csrf|s:8:"abc12345";', $row['payload']);
        self::assertSame('_csrf|s:8:"abc12345";', $handler->read($sid));
    }

    public function test_bindToUser_promotes_existing_anonymous_row(): void
    {
        $pdo = $this->db->pdo();
        $pdo->exec("INSERT INTO users (username, password_hash, role) VALUES ('alice','x','admin')");
        $userId = (int)$pdo->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();

        $handler = new Session($pdo, lifetime: 3600);
        $sid = '66666666-6666-6666-6666-666666666666';

        // Anonymous session (e.g. set during GET /login)
        $handler->write($sid, '_csrf|s:8:"pretok12";');
        self::assertNull($pdo->query("SELECT user_id FROM user_sessions WHERE id='$sid'")->fetchColumn());

        // Login succeeds → bind to user
        $handler->bindToUser($sid, $userId, '1.2.3.4', 'TestUA/1.0');

        $row = $pdo->query("SELECT user_id, host(ip_address) AS ip, user_agent FROM user_sessions WHERE id='$sid'")->fetch();
        self::assertSame((string)$userId, (string)$row['user_id']);
        self::assertSame('1.2.3.4', $row['ip']);
        self::assertSame('TestUA/1.0', $row['user_agent']);
    }

    public function test_bindToUser_inserts_when_row_missing(): void
    {
        // session_regenerate_id mints a brand-new PHP session id; bindToUser
        // may run before the SessionHandler::write() for that id has fired.
        $pdo = $this->db->pdo();
        $pdo->exec("INSERT INTO users (username, password_hash, role) VALUES ('alice','x','admin')");
        $userId = (int)$pdo->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();

        $handler = new Session($pdo, lifetime: 3600);
        $sid = '77777777-7777-7777-7777-777777777777';

        $handler->bindToUser($sid, $userId, '5.6.7.8', null);

        $row = $pdo->query("SELECT user_id, host(ip_address) AS ip FROM user_sessions WHERE id='$sid'")->fetch();
        self::assertNotFalse($row);
        self::assertSame((string)$userId, (string)$row['user_id']);
        self::assertSame('5.6.7.8', $row['ip']);
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
