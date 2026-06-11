<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateUserSessions extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TABLE user_sessions (
                id                uuid PRIMARY KEY,
                user_id           bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                ip_address        inet,
                user_agent        text,
                fingerprint       bytea,
                payload           text NOT NULL DEFAULT '',
                created_at        timestamptz NOT NULL DEFAULT now(),
                expires_at        timestamptz NOT NULL,
                last_activity_at  timestamptz NOT NULL DEFAULT now(),
                revoked_at        timestamptz
            );
            CREATE INDEX user_sessions_user_idx     ON user_sessions (user_id)    WHERE revoked_at IS NULL;
            CREATE INDEX user_sessions_expires_idx  ON user_sessions (expires_at) WHERE revoked_at IS NULL;
        SQL);
    }
}
