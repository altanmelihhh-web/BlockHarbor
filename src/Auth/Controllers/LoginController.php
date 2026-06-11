<?php declare(strict_types=1);

namespace BlockHarbor\Auth\Controllers;

use BlockHarbor\Auth\AuthResult;
use BlockHarbor\Auth\AuthService;
use BlockHarbor\Core\Csrf;
use BlockHarbor\Core\Session;
use League\Plates\Engine;

final class LoginController
{
    public function __construct(
        private readonly AuthService $auth,
        private readonly Session $session,
        private readonly Csrf $csrf,
        private readonly Engine $views,
    ) {}

    public function show(): void
    {
        if (isset($_SESSION['user_id'])) {
            $this->redirect('/dashboard');
            return;
        }
        echo $this->views->render('auth/login', [
            'csrf'  => $this->csrf->token(),
            'error' => $_SESSION['_flash_error'] ?? null,
        ]);
        unset($_SESSION['_flash_error']);
    }

    public function submit(): void
    {
        if (!$this->csrf->verify($_POST['_csrf'] ?? null)) {
            http_response_code(419);
            echo 'CSRF token invalid';
            return;
        }

        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $ip       = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $ua       = $_SERVER['HTTP_USER_AGENT'] ?? null;

        $outcome = $this->auth->attempt($username, $password, $ip, $ua);

        if ($outcome->result === AuthResult::Success && $outcome->user !== null) {
            $this->session->start($outcome->user->id, $ip, $ua);
            session_regenerate_id(true);
            $_SESSION['user_id']  = $outcome->user->id;
            $_SESSION['username'] = $outcome->user->username;
            $_SESSION['role']     = $outcome->user->role;
            $this->csrf->rotate();
            $this->redirect('/dashboard');
            return;
        }

        $_SESSION['_flash_error'] = match ($outcome->result) {
            AuthResult::BadCredentials => 'Kullanıcı adı veya parola hatalı.',
            AuthResult::Locked         => 'Hesap geçici olarak kilitli (çok fazla başarısız deneme).',
            AuthResult::RateLimited    => 'Çok fazla istek. Lütfen birkaç dakika sonra tekrar deneyin.',
            AuthResult::Inactive       => 'Bu hesap pasif. Yöneticinize başvurun.',
            default                    => 'Giriş başarısız.',
        };
        $this->redirect('/login');
    }

    private function redirect(string $path): void
    {
        header("Location: $path", true, 303);
    }
}
