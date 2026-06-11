<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateUsers extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<SQL
            CREATE TYPE user_role AS ENUM ('admin', 'operator', 'viewer');

            CREATE TABLE users (
                id                     bigserial PRIMARY KEY,
                tenant_id              uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'
                                            REFERENCES tenants(id) ON DELETE RESTRICT,
                username               varchar(64) NOT NULL,
                email                  varchar(254),
                password_hash          text,
                role                   user_role NOT NULL DEFAULT 'viewer',
                active                 boolean NOT NULL DEFAULT true,
                failed_login_count     integer NOT NULL DEFAULT 0,
                locked_until           timestamptz,
                last_login_at          timestamptz,
                password_changed_at    timestamptz,
                mfa_required           boolean NOT NULL DEFAULT false,
                metadata               jsonb NOT NULL DEFAULT '{}'::jsonb,
                created_at             timestamptz NOT NULL DEFAULT now(),
                CONSTRAINT users_username_unique UNIQUE (tenant_id, username)
            );

            CREATE INDEX users_active_idx     ON users (active) WHERE active = true;
            CREATE INDEX users_metadata_gin   ON users USING gin (metadata jsonb_path_ops);
        SQL);
    }
}
