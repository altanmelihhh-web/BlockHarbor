<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Seed/installer ships a well-known default admin (admin/admin). Force the
 * operator to replace it on first login by flagging the seeded row with
 * must_change_password = true. AuthService routes Success → PasswordChangeRequired
 * when this flag is set; the dashboard is unreachable until the password meets
 * PasswordPolicy and the flag clears.
 */
final class AddMustChangePassword extends AbstractMigration
{
    public function up(): void
    {
        $this->execute(
            'ALTER TABLE users ADD COLUMN must_change_password boolean NOT NULL DEFAULT false'
        );
    }

    public function down(): void
    {
        $this->execute('ALTER TABLE users DROP COLUMN must_change_password');
    }
}
