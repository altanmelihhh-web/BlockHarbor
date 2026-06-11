<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateUserTotp extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TABLE user_totp (
                id                       bigserial PRIMARY KEY,
                user_id                  bigint NOT NULL UNIQUE
                                            REFERENCES users(id) ON DELETE CASCADE,
                secret_encrypted         text NOT NULL,
                recovery_codes_encrypted text NOT NULL,
                recovery_codes_used      integer NOT NULL DEFAULT 0,
                verified_at              timestamptz,
                created_at               timestamptz NOT NULL DEFAULT now()
            );
            CREATE INDEX user_totp_verified_idx ON user_totp (user_id) WHERE verified_at IS NOT NULL;
        SQL);
    }
}
