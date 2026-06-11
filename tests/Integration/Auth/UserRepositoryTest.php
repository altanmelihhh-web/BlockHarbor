<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Auth;

use BlockHarbor\Auth\UserRepository;
use BlockHarbor\Tests\DatabaseTestCase;
use DateTimeImmutable;

final class UserRepositoryTest extends DatabaseTestCase
{
    private UserRepository $repo;

    protected function setUp(): void
    {
        parent::setUp();
        $this->repo = new UserRepository($this->db->pdo());
    }

    public function test_create_and_find_by_username(): void
    {
        $id = $this->repo->create(
            username:     'alice',
            email:        'alice@example.com',
            passwordHash: '$argon2id$v=19$m=65536,t=3,p=1$abc$def',
            role:         'admin',
        );
        self::assertGreaterThan(0, $id);

        $u = $this->repo->findByUsername('alice');
        self::assertNotNull($u);
        self::assertSame('alice', $u->username);
        self::assertSame('alice@example.com', $u->email);
        self::assertSame('admin', $u->role);
        self::assertTrue($u->active);
    }

    public function test_find_by_username_returns_null_when_missing(): void
    {
        self::assertNull($this->repo->findByUsername('ghost'));
    }

    public function test_record_successful_login_resets_failed_count(): void
    {
        $id = $this->repo->create('alice', null, 'hash', 'viewer');
        $this->repo->incrementFailedLoginCount($id);
        $this->repo->incrementFailedLoginCount($id);

        $this->repo->recordSuccessfulLogin($id);

        $u = $this->repo->findById($id);
        self::assertSame(0, $u->failedLoginCount);
        self::assertNotNull($u->lastLoginAt);
        self::assertNull($u->lockedUntil);
    }

    public function test_lock_until_sets_locked_until(): void
    {
        $id = $this->repo->create('alice', null, 'hash', 'viewer');
        $this->repo->lockUntil($id, new DateTimeImmutable('+15 minutes'));

        $u = $this->repo->findById($id);
        self::assertTrue($u->isLocked());
    }
}
