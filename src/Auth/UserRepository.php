<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

use DateTimeImmutable;
use PDO;

final class UserRepository
{
    public function __construct(private readonly PDO $pdo) {}

    public function create(string $username, ?string $email, string $passwordHash, string $role): int
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (username, email, password_hash, role, password_changed_at)
             VALUES (:u, :e, :h, :r, now()) RETURNING id'
        );
        $stmt->execute([':u' => $username, ':e' => $email, ':h' => $passwordHash, ':r' => $role]);
        return (int)$stmt->fetchColumn();
    }

    public function findById(int $id): ?User
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $id]);
        $row = $stmt->fetch();
        return $row ? User::fromRow($row) : null;
    }

    public function findByUsername(string $username): ?User
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        $row = $stmt->fetch();
        return $row ? User::fromRow($row) : null;
    }

    public function incrementFailedLoginCount(int $userId): int
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users SET failed_login_count = failed_login_count + 1
             WHERE id = :id RETURNING failed_login_count'
        );
        $stmt->execute([':id' => $userId]);
        return (int)$stmt->fetchColumn();
    }

    public function recordSuccessfulLogin(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users
             SET last_login_at      = now(),
                 failed_login_count = 0,
                 locked_until       = NULL
             WHERE id = :id'
        );
        $stmt->execute([':id' => $userId]);
    }

    public function lockUntil(int $userId, DateTimeImmutable $until): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET locked_until = :u WHERE id = :id');
        $stmt->execute([':u' => $until->format('Y-m-d H:i:sP'), ':id' => $userId]);
    }

    public function updatePassword(int $userId, string $passwordHash): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users SET password_hash = :h, password_changed_at = now() WHERE id = :id'
        );
        $stmt->execute([':h' => $passwordHash, ':id' => $userId]);

        // Append to password_history (trigger keeps last 5)
        $h = $this->pdo->prepare(
            'INSERT INTO password_history (user_id, password_hash) VALUES (:id, :h)'
        );
        $h->execute([':id' => $userId, ':h' => $passwordHash]);
    }
}
