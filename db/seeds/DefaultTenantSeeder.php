<?php declare(strict_types=1);

use Phinx\Seed\AbstractSeed;

final class DefaultTenantSeeder extends AbstractSeed
{
    public function run(): void
    {
        // Default tenant row is created by the CreateTenants migration.
        // This seed is a placeholder for the dependency chain — keep so
        // DefaultUserSeeder can depend on tenants existence even on a
        // fresh DB where migrations + seeds are run separately.
    }
}
