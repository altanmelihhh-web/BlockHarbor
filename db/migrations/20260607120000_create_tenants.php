<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateTenants extends AbstractMigration
{
    public function change(): void
    {
        // Note: pgcrypto + pg_trgm extensions are created out-of-band by the
        // installer (CREATE EXTENSION requires superuser; the migrator role
        // intentionally does not have that).

        $this->execute(<<<SQL
            CREATE TABLE tenants (
                id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                name        varchar(255) NOT NULL,
                active      boolean NOT NULL DEFAULT true,
                created_at  timestamptz NOT NULL DEFAULT now()
            )
        SQL);

        // Default tenant — UUID matches the application default used as
        // the single-tenant placeholder across all domain tables.
        $this->execute(<<<SQL
            INSERT INTO tenants (id, name) VALUES
                ('00000000-0000-0000-0000-000000000000', 'default')
        SQL);
    }
}
