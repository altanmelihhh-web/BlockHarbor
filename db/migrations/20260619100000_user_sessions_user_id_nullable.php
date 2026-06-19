<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Anonymous PHP sessions (pre-login: holds CSRF token, flash messages) must
 * persist between requests, but they have no user yet. Drop the NOT NULL so
 * Session::write() can UPSERT a row before the user is known; the row is
 * promoted by Session::bindToUser() after authentication succeeds.
 */
final class UserSessionsUserIdNullable extends AbstractMigration
{
    public function up(): void
    {
        $this->execute('ALTER TABLE user_sessions ALTER COLUMN user_id DROP NOT NULL');
    }

    public function down(): void
    {
        // Re-tightening requires either purging anonymous rows first or back-
        // filling them, so down() is intentionally a no-op to avoid surprise
        // data loss on rollback.
    }
}
