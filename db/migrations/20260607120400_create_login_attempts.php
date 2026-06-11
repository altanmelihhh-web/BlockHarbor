<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateLoginAttempts extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TABLE login_attempts (
                id              bigserial PRIMARY KEY,
                username        varchar(64),
                ip_address      inet NOT NULL,
                success         boolean NOT NULL,
                failure_reason  varchar(64),
                geo_country     char(2),
                user_agent      text,
                created_at      timestamptz NOT NULL DEFAULT now()
            );
            CREATE INDEX login_attempts_ip_time   ON login_attempts (ip_address, created_at DESC);
            CREATE INDEX login_attempts_user_time ON login_attempts (username,   created_at DESC) WHERE username IS NOT NULL;
        SQL);
    }
}
