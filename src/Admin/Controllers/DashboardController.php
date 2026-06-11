<?php declare(strict_types=1);

namespace BlockHarbor\Admin\Controllers;

use BlockHarbor\Auth\Middleware\RequireAuth;
use BlockHarbor\Auth\UserRepository;
use BlockHarbor\Core\Csrf;
use League\Plates\Engine;

final class DashboardController
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly Engine $views,
    ) {}

    public function index(): void
    {
        $userId = RequireAuth::check();
        $user   = $this->users->findById($userId);
        if ($user === null) {
            session_destroy();
            header('Location: /login', true, 303);
            return;
        }

        $csrf = (new Csrf())->token();

        echo $this->views->render('dashboard/index', [
            'username'  => $user->username,
            'role'      => $user->role,
            'lastLogin' => $user->lastLoginAt?->format('Y-m-d H:i') ?? 'ilk giriş',
            'csrf'      => $csrf,
        ]);
    }
}
