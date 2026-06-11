<?php declare(strict_types=1);

namespace BlockHarbor\Auth\Middleware;

final class RequireAuth
{
    /** @return int user_id of authenticated user, or aborts with redirect */
    public static function check(): int
    {
        if (!isset($_SESSION['user_id'])) {
            header('Location: /login', true, 303);
            exit;
        }
        return (int)$_SESSION['user_id'];
    }
}
