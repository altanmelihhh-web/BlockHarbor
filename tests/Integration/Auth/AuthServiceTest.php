<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Auth;

use BlockHarbor\Auth\AuthResult;
use BlockHarbor\Auth\AuthService;
use BlockHarbor\Auth\LoginAttemptRepository;
use BlockHarbor\Auth\PasswordHasher;
use BlockHarbor\Auth\UserRepository;
use BlockHarbor\Tests\DatabaseTestCase;

final class AuthServiceTest extends DatabaseTestCase
{
    private AuthService $service;
    private UserRepository $users;
    private PasswordHasher $hasher;

    protected function setUp(): void
    {
        parent::setUp();
        $pdo = $this->db->pdo();
        $this->users   = new UserRepository($pdo);
        $attempts      = new LoginAttemptRepository($pdo);
        $this->hasher  = new PasswordHasher();
        $this->service = new AuthService(
            $this->users, $attempts, $this->hasher,
            maxFailsPerIpIn5Min: 10,
            maxFailsPerUserIn1h: 5,
            lockoutMinutes:      15,
        );
    }

    public function test_successful_login_returns_success(): void
    {
        $this->users->create('alice', null, $this->hasher->hash('p@ssw0rd!XX'), 'admin');
        $r = $this->service->attempt('alice', 'p@ssw0rd!XX', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::Success, $r->result);
        self::assertNotNull($r->user);
    }

    public function test_wrong_password_returns_bad_credentials(): void
    {
        $this->users->create('alice', null, $this->hasher->hash('correct'), 'admin');
        $r = $this->service->attempt('alice', 'wrong', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::BadCredentials, $r->result);
        self::assertNull($r->user);
    }

    public function test_unknown_user_returns_bad_credentials_without_disclosing(): void
    {
        $r = $this->service->attempt('nobody', 'anything', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::BadCredentials, $r->result);
    }

    public function test_five_failures_locks_account(): void
    {
        $this->users->create('alice', null, $this->hasher->hash('correct'), 'admin');
        for ($i = 0; $i < 5; $i++) {
            $this->service->attempt('alice', 'wrong', '10.0.0.1', 'ua/1');
        }
        // 6th attempt — even with the right password — must be rejected
        $r = $this->service->attempt('alice', 'correct', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::Locked, $r->result);
    }

    public function test_too_many_per_ip_returns_rate_limited(): void
    {
        for ($i = 0; $i < 11; $i++) {
            $this->service->attempt("nobody$i", 'x', '10.0.0.1', 'ua/1');
        }
        $r = $this->service->attempt('alice', 'whatever', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::RateLimited, $r->result);
    }

    public function test_inactive_user_returns_inactive(): void
    {
        $id = $this->users->create('alice', null, $this->hasher->hash('correct'), 'admin');
        $this->db->pdo()->exec("UPDATE users SET active = false WHERE id = $id");
        $r = $this->service->attempt('alice', 'correct', '10.0.0.1', 'ua/1');
        self::assertSame(AuthResult::Inactive, $r->result);
    }
}
