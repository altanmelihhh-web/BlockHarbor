<?php declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

final class DefaultUserSeeder extends AbstractSeed
{
    public function getDependencies(): array
    {
        return ['DefaultTenantSeeder'];
    }

    public function run(): void
    {
        // Read initial admin from env (installer writes these into .env).
        // Fall back to safe seeded values for fresh dev installs.
        $username = (string)(getenv('INITIAL_ADMIN_USERNAME') ?: 'admin');
        $email    = (string)(getenv('INITIAL_ADMIN_EMAIL')    ?: 'admin@example.com');
        $plain    = (string)(getenv('INITIAL_ADMIN_PASSWORD') ?: 'changeme-p1-seed');

        $existing = $this->fetchRow("SELECT id FROM users WHERE username = '$username'");
        if ($existing) {
            $this->getOutput()->writeln("  ↳ user '$username' already exists; skipping");
            return;
        }

        $hash = password_hash($plain, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost'   => 3,
            'threads'     => 1,
        ]);

        $this->insert('users', [[
            'username'            => $username,
            'email'               => $email,
            'password_hash'       => $hash,
            'role'                => 'admin',
            'active'              => true,
            'mfa_required'        => false,
            'password_changed_at' => date('Y-m-d H:i:sP'),
        ]]);

        $this->getOutput()->writeln("  ↳ admin user '$username' seeded");
    }
}
