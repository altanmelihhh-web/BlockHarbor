<?php declare(strict_types=1);

namespace BlockHarbor\Core;

use PDO;
use SessionHandlerInterface;

final class Session implements SessionHandlerInterface
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly int $lifetime = 1800,
    ) {}

    public function open(string $path, string $name): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read(string $id): string
    {
        $stmt = $this->pdo->prepare(
            'SELECT payload FROM user_sessions
             WHERE id = :id
               AND revoked_at IS NULL
               AND expires_at > now()'
        );
        $stmt->execute([':id' => $id]);
        $payload = $stmt->fetchColumn();
        return $payload === false ? '' : (string)$payload;
    }

    public function write(string $id, string $data): bool
    {
        $stmt = $this->pdo->prepare(
            'UPDATE user_sessions
             SET payload          = :p,
                 last_activity_at = now(),
                 expires_at       = now() + make_interval(secs => :l)
             WHERE id = :id'
        );
        $stmt->execute([':p' => $data, ':l' => $this->lifetime, ':id' => $id]);
        return $stmt->rowCount() > 0;
    }

    public function destroy(string $id): bool
    {
        $stmt = $this->pdo->prepare('UPDATE user_sessions SET revoked_at = now() WHERE id = :id');
        $stmt->execute([':id' => $id]);
        return true;
    }

    public function gc(int $max_lifetime): int|false
    {
        $stmt = $this->pdo->prepare(
            'UPDATE user_sessions
             SET revoked_at = now()
             WHERE revoked_at IS NULL AND expires_at < now()'
        );
        $stmt->execute();
        return $stmt->rowCount();
    }

    /**
     * Create a new session row tied to the given user and return its UUID.
     * The caller uses this UUID as the PHP session id (so PHP's native
     * cookie + session_set_save_handler flow writes through us).
     */
    public function start(int $userId, string $ip, ?string $userAgent): string
    {
        $id = \Ramsey\Uuid\Uuid::uuid7()->toString();
        $stmt = $this->pdo->prepare(
            'INSERT INTO user_sessions (id, user_id, ip_address, user_agent, expires_at)
             VALUES (:id, :uid, :ip, :ua, now() + make_interval(secs => :l))'
        );
        $stmt->execute([
            ':id'  => $id,
            ':uid' => $userId,
            ':ip'  => $ip,
            ':ua'  => $userAgent,
            ':l'   => $this->lifetime,
        ]);
        return $id;
    }
}
