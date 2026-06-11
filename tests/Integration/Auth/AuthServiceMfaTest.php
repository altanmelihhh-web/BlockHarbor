<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Auth;

use BlockHarbor\Auth\AuthResult;
use BlockHarbor\Auth\AuthService;
use BlockHarbor\Auth\LoginAttemptRepository;
use BlockHarbor\Auth\MfaResolver;
use BlockHarbor\Auth\PasswordHasher;
use BlockHarbor\Auth\UserRepository;
use BlockHarbor\Auth\UserTotpRepository;
use BlockHarbor\Core\Crypto;
use BlockHarbor\Tests\DatabaseTestCase;

final class AuthServiceMfaTest extends DatabaseTestCase
{
    public function test_no_mfa_enrolled_returns_success(): void
    {
        $pdo     = $this->db->pdo();
        $users   = new UserRepository($pdo);
        $hasher  = new PasswordHasher();
        $service = new AuthService(
            $users,
            new LoginAttemptRepository($pdo),
            $hasher,
            maxFailsPerIpIn5Min: 10,
            maxFailsPerUserIn1h: 5,
            lockoutMinutes: 15,
            mfa: new MfaResolver($pdo),
        );

        $users->create('alice', null, $hasher->hash('p@ssw0rd!XX'), 'viewer');
        $r = $service->attempt('alice', 'p@ssw0rd!XX', '10.0.0.1', 'ua/1');

        self::assertSame(AuthResult::Success, $r->result);
    }

    public function test_verified_totp_makes_password_login_require_mfa(): void
    {
        $pdo     = $this->db->pdo();
        $users   = new UserRepository($pdo);
        $hasher  = new PasswordHasher();
        $crypto  = new Crypto($pdo, 'k');
        $totp    = new UserTotpRepository($pdo, $crypto);
        $service = new AuthService(
            $users,
            new LoginAttemptRepository($pdo),
            $hasher,
            maxFailsPerIpIn5Min: 10,
            maxFailsPerUserIn1h: 5,
            lockoutMinutes: 15,
            mfa: new MfaResolver($pdo),
        );

        $id = $users->create('alice', null, $hasher->hash('correct'), 'admin');
        $totp->enroll($id, 'SECRET', ['r1', 'r2']);
        $totp->markVerified($id);

        $r = $service->attempt('alice', 'correct', '10.0.0.1', 'ua/1');

        self::assertSame(AuthResult::RequiresMfa, $r->result);
        self::assertNotNull($r->user);  // user still returned for pending_user_id
    }

    public function test_unverified_totp_does_not_require_mfa(): void
    {
        $pdo     = $this->db->pdo();
        $users   = new UserRepository($pdo);
        $hasher  = new PasswordHasher();
        $crypto  = new Crypto($pdo, 'k');
        $totp    = new UserTotpRepository($pdo, $crypto);
        $service = new AuthService(
            $users,
            new LoginAttemptRepository($pdo),
            $hasher,
            maxFailsPerIpIn5Min: 10,
            maxFailsPerUserIn1h: 5,
            lockoutMinutes: 15,
            mfa: new MfaResolver($pdo),
        );

        $id = $users->create('alice', null, $hasher->hash('correct'), 'admin');
        $totp->enroll($id, 'SECRET', ['r1']);
        // NOT calling markVerified — enrollment in progress

        $r = $service->attempt('alice', 'correct', '10.0.0.1', 'ua/1');

        self::assertSame(AuthResult::Success, $r->result);
    }
}
