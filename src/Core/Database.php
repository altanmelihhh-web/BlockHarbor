<?php declare(strict_types=1);

namespace BlockHarbor\Core;

use PDO;

final class Database
{
    private ?PDO $pdo = null;

    public function __construct(private readonly Config $config) {}

    public function pdo(): PDO
    {
        if ($this->pdo === null) {
            $dsn = sprintf(
                'pgsql:host=%s;port=%d;dbname=%s;sslmode=%s',
                $this->config->string('DB_HOST'),
                $this->config->int('DB_PORT', 5432),
                $this->config->string('DB_NAME'),
                $this->config->string('DB_SSLMODE', 'prefer'),
            );

            $this->pdo = new PDO(
                $dsn,
                $this->config->string('DB_USER'),
                $this->config->string('DB_PASSWORD'),
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ],
            );
        }

        return $this->pdo;
    }
}
