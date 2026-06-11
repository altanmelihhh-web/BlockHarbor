<?php declare(strict_types=1);

namespace BlockHarbor\Auth\Controllers;

use BlockHarbor\Core\Csrf;
use BlockHarbor\Core\Session;

final class LogoutController
{
    public function __construct(
        private readonly Session $session,
        private readonly Csrf $csrf,
    ) {}

    public function submit(): void
    {
        if (!$this->csrf->verify($_POST['_csrf'] ?? null)) {
            http_response_code(419);
            return;
        }

        if (session_id() !== '') {
            $this->session->destroy(session_id());
        }
        $_SESSION = [];
        session_destroy();

        header('Location: /login', true, 303);
    }
}
