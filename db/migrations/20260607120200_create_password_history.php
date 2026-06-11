<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreatePasswordHistory extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<'SQL'
            CREATE TABLE password_history (
                id            bigserial PRIMARY KEY,
                user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                password_hash text NOT NULL,
                created_at    timestamptz NOT NULL DEFAULT now()
            );
            CREATE INDEX password_history_user_idx ON password_history (user_id, created_at DESC);

            -- Prune trigger: keep last 5 per user
            CREATE OR REPLACE FUNCTION prune_password_history() RETURNS trigger AS $$
            BEGIN
                DELETE FROM password_history
                WHERE id IN (
                    SELECT id FROM password_history
                    WHERE user_id = NEW.user_id
                    ORDER BY created_at DESC
                    OFFSET 5
                );
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER password_history_prune
                AFTER INSERT ON password_history
                FOR EACH ROW EXECUTE FUNCTION prune_password_history();
        SQL);
    }
}
