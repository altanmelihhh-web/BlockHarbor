<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Auth;

use BlockHarbor\Auth\LoginAttemptRepository;
use BlockHarbor\Tests\DatabaseTestCase;

final class LoginAttemptRepositoryTest extends DatabaseTestCase
{
    private LoginAttemptRepository $repo;

    protected function setUp(): void
    {
        parent::setUp();
        $this->repo = new LoginAttemptRepository($this->db->pdo());
    }

    public function test_record_and_count_failures_per_ip(): void
    {
        for ($i = 0; $i < 3; $i++) {
            $this->repo->record(
                username:      'alice',
                ip:            '10.0.0.1',
                success:       false,
                failureReason: 'bad_password',
            );
        }
        $this->repo->record(username: 'alice', ip: '10.0.0.1', success: true);

        self::assertSame(3, $this->repo->countFailuresByIp('10.0.0.1', 300));
        self::assertSame(0, $this->repo->countFailuresByIp('10.0.0.2', 300));
    }

    public function test_count_failures_per_user(): void
    {
        $this->repo->record('alice', '10.0.0.1', false, 'bad_password');
        $this->repo->record('alice', '10.0.0.2', false, 'bad_password');
        $this->repo->record('bob',   '10.0.0.3', false, 'bad_password');

        self::assertSame(2, $this->repo->countFailuresByUsername('alice', 3600));
        self::assertSame(1, $this->repo->countFailuresByUsername('bob',   3600));
    }

    public function test_window_excludes_old_attempts(): void
    {
        $this->db->pdo()->exec(
            "INSERT INTO login_attempts (username, ip_address, success, failure_reason, created_at)
             VALUES ('alice', '10.0.0.1', false, 'bad_password', now() - interval '1 hour')"
        );
        self::assertSame(0, $this->repo->countFailuresByIp('10.0.0.1', 300));   // 5-min window
        self::assertSame(1, $this->repo->countFailuresByIp('10.0.0.1', 7200));  // 2-hour window
    }
}
