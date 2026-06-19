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
        // Fall back to vendor-style 'admin' default + must_change_password=true
        // so the first login is forced through /change-password before anything
        // else is reachable.
        $username = (string)(getenv('INITIAL_ADMIN_USERNAME') ?: 'admin');
        $email    = (string)(getenv('INITIAL_ADMIN_EMAIL')    ?: 'admin@example.com');
        $envPass  = (string)(getenv('INITIAL_ADMIN_PASSWORD') ?: '');
        $isDefault = $envPass === '';
        $plain    = $isDefault ? 'admin' : $envPass;

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
            'username'             => $username,
            'email'                => $email,
            'password_hash'        => $hash,
            'role'                 => 'admin',
            'active'               => true,
            'mfa_required'         => false,
            'must_change_password' => $isDefault,
            'password_changed_at'  => date('Y-m-d H:i:sP'),
        ]]);

        $msg = $isDefault
            ? "  ↳ admin user '$username' seeded with default password 'admin' (forced change on first login)"
            : "  ↳ admin user '$username' seeded with INITIAL_ADMIN_PASSWORD";
        $this->getOutput()->writeln($msg);
    }
}
