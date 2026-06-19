<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Integration\Auth;

use BlockHarbor\Auth\AuthResult;
use BlockHarbor\Auth\AuthService;
use BlockHarbor\Auth\LoginAttemptRepository;
use BlockHarbor\Auth\PasswordHasher;
use BlockHarbor\Auth\UserRepository;
use BlockHarbor\Tests\DatabaseTestCase;

final class AuthServicePasswordChangeTest extends DatabaseTestCase
{
    private function service(UserRepository $users, PasswordHasher $hasher): AuthService
    {
        return new AuthService(
            $users,
            new LoginAttemptRepository($this->db->pdo()),
            $hasher,
            maxFailsPerIpIn5Min: 10,
            maxFailsPerUserIn1h: 5,
            lockoutMinutes: 15,
        );
    }

    public function test_must_change_password_flag_returns_password_change_required(): void
    {
        $pdo    = $this->db->pdo();
        $users  = new UserRepository($pdo);
        $hasher = new PasswordHasher();

        $id = $users->create('admin', null, $hasher->hash('admin'), 'admin');
        $pdo->exec("UPDATE users SET must_change_password = true WHERE id = $id");

        $r = $this->service($users, $hasher)->attempt('admin', 'admin', '10.0.0.1', 'ua/1');

        self::assertSame(AuthResult::PasswordChangeRequired, $r->result);
        self::assertNotNull($r->user); // user still returned for pending_password_change_user_id
    }

    public function test_clearing_the_flag_unblocks_login(): void
    {
        $pdo    = $this->db->pdo();
        $users  = new UserRepository($pdo);
        $hasher = new PasswordHasher();

        $id = $users->create('admin', null, $hasher->hash('admin'), 'admin');
        $pdo->exec("UPDATE users SET must_change_password = true WHERE id = $id");

        // updatePassword clears must_change_password
        $users->updatePassword($id, $hasher->hash('Sup3r-strong-new!'));

        $r = $this->service($users, $hasher)->attempt('admin', 'Sup3r-strong-new!', '10.0.0.1', 'ua/1');

        self::assertSame(AuthResult::Success, $r->result);
    }
}
