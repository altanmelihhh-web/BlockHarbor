<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Auth;

use BlockHarbor\Auth\UserTotpRepository;
use BlockHarbor\Core\Crypto;
use BlockHarbor\Tests\DatabaseTestCase;

final class UserTotpRepositoryTest extends DatabaseTestCase
{
    private UserTotpRepository $repo;
    private int $userId;

    protected function setUp(): void
    {
        parent::setUp();
        $crypto = new Crypto($this->db->pdo(), 'test-master-key');
        $this->repo = new UserTotpRepository($this->db->pdo(), $crypto);

        $this->db->pdo()->exec(
            "INSERT INTO users (username, role) VALUES ('alice', 'admin')"
        );
        $this->userId = (int)$this->db->pdo()
            ->query("SELECT id FROM users WHERE username='alice'")->fetchColumn();
    }

    public function test_enroll_and_decrypt_secret(): void
    {
        $this->repo->enroll($this->userId, 'NBSWY3DPO5XXE3DE', ['code-a', 'code-b']);

        self::assertSame('NBSWY3DPO5XXE3DE', $this->repo->getSecret($this->userId));
        self::assertCount(2, $this->repo->getRecoveryCodes($this->userId));
    }

    public function test_mark_verified(): void
    {
        $this->repo->enroll($this->userId, 'S', []);
        self::assertFalse($this->repo->isVerified($this->userId));

        $this->repo->markVerified($this->userId);
        self::assertTrue($this->repo->isVerified($this->userId));
    }

    public function test_consume_recovery_code_removes_it(): void
    {
        $this->repo->enroll($this->userId, 'S', ['code-a', 'code-b', 'code-c']);
        self::assertTrue($this->repo->consumeRecoveryCode($this->userId, 'code-b'));
        self::assertFalse($this->repo->consumeRecoveryCode($this->userId, 'code-b')); // already used
        self::assertCount(2, $this->repo->getRecoveryCodes($this->userId));
    }

    public function test_re_enroll_replaces_secret_and_clears_verified(): void
    {
        $this->repo->enroll($this->userId, 'FIRST', ['a']);
        $this->repo->markVerified($this->userId);

        $this->repo->enroll($this->userId, 'SECOND', ['b', 'c']);
        self::assertSame('SECOND', $this->repo->getSecret($this->userId));
        self::assertFalse($this->repo->isVerified($this->userId));
    }
}
