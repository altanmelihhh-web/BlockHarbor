<?php declare(strict_types=1);

namespace BlockHarbor\Core;

use PDO;
use SessionHandlerInterface;

/**
 * DB-backed PHP session handler.
 *
 * The PHP session lifecycle is:
 *   request 1 (anonymous): session_start() → generates ID X → write(X, payload)
 *     → row inserted with user_id = NULL (CSRF token + flash live here)
 *   request 2 (login POST): read(X) → existing payload → CSRF verifies
 *     → AuthService success → session_regenerate_id(true) → destroy(X), new ID Y
 *     → LoginController calls bindToUser(Y, userId) → row Y exists with user_id
 *     → request ends → write(Y, payload) refreshes payload
 *   request 3+: read(Y) returns payload with user_id baked into $_SESSION
 */
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
        // UPSERT: anonymous sessions (user_id NULL) AND post-login regenerated
        // session ids both need a row. user_id is bound separately by
        // bindToUser() after AuthService promotes the request.
        $stmt = $this->pdo->prepare(
            'INSERT INTO user_sessions (id, payload, expires_at, last_activity_at)
             VALUES (:id, :p, now() + make_interval(secs => :l), now())
             ON CONFLICT (id) DO UPDATE SET
                 payload          = EXCLUDED.payload,
                 last_activity_at = now(),
                 expires_at       = EXCLUDED.expires_at'
        );
        $stmt->execute([':id' => $id, ':p' => $data, ':l' => $this->lifetime]);
        return true;
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
     * Promote the current PHP session row from anonymous (user_id NULL) to
     * authenticated. Call AFTER session_regenerate_id(true) in LoginController.
     *
     * Uses UPSERT so it works whether the SessionHandlerInterface::write()
     * call has already fired for the post-regenerate id or not.
     */
    public function bindToUser(string $id, int $userId, string $ip, ?string $userAgent): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO user_sessions (id, user_id, ip_address, user_agent, expires_at, last_activity_at)
             VALUES (:id, :uid, :ip, :ua, now() + make_interval(secs => :l), now())
             ON CONFLICT (id) DO UPDATE SET
                 user_id          = EXCLUDED.user_id,
                 ip_address       = EXCLUDED.ip_address,
                 user_agent       = EXCLUDED.user_agent,
                 last_activity_at = now(),
                 expires_at       = EXCLUDED.expires_at'
        );
        $stmt->execute([
            ':id'  => $id,
            ':uid' => $userId,
            ':ip'  => $ip,
            ':ua'  => $userAgent,
            ':l'   => $this->lifetime,
        ]);
    }
}
