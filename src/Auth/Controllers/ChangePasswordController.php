<?php declare(strict_types=1);

namespace BlockHarbor\Auth\Controllers;

use BlockHarbor\Auth\PasswordHasher;
use BlockHarbor\Auth\PasswordPolicy;
use BlockHarbor\Auth\UserRepository;
use BlockHarbor\Core\Csrf;
use BlockHarbor\Core\Session;
use League\Plates\Engine;

/**
 * Forced password change flow. Reached when AuthService returns
 * PasswordChangeRequired — the user has verified the current password but
 * must replace a flagged credential (default admin seed, operator reset)
 * before the dashboard becomes reachable.
 *
 * Session contract:
 *   pending_password_change_user_id → set by LoginController on success
 *   Cleared by submit() after a successful change; the new password
 *   binds the session via Session::bindToUser.
 */
final class ChangePasswordController
{
    public function __construct(
        private readonly UserRepository $users,
        private readonly PasswordHasher $hasher,
        private readonly PasswordPolicy $policy,
        private readonly Session $session,
        private readonly Csrf $csrf,
        private readonly Engine $views,
    ) {}

    public function show(): void
    {
        if (!isset($_SESSION['pending_password_change_user_id'])) {
            header('Location: /login', true, 303);
            return;
        }
        echo $this->views->render('auth/change-password', [
            'csrf'   => $this->csrf->token(),
            'errors' => $_SESSION['_flash_errors'] ?? [],
        ]);
        unset($_SESSION['_flash_errors']);
    }

    public function submit(): void
    {
        if (!$this->csrf->verify($_POST['_csrf'] ?? null)) {
            http_response_code(419);
            echo 'CSRF token invalid';
            return;
        }

        $pendingId = $_SESSION['pending_password_change_user_id'] ?? null;
        if (!is_int($pendingId)) {
            header('Location: /login', true, 303);
            return;
        }

        $new     = (string)($_POST['new_password']     ?? '');
        $confirm = (string)($_POST['confirm_password'] ?? '');

        $errors = $this->policy->validate($new);
        if ($new !== $confirm) {
            $errors[] = 'mismatch';
        }

        if ($errors !== []) {
            $_SESSION['_flash_errors'] = $errors;
            header('Location: /change-password', true, 303);
            return;
        }

        $this->users->updatePassword($pendingId, $this->hasher->hash($new));
        unset($_SESSION['pending_password_change_user_id']);

        $user = $this->users->findById($pendingId);
        if ($user === null) {
            header('Location: /login', true, 303);
            return;
        }

        // Promote session — same flow as a normal successful login.
        session_regenerate_id(true);
        $sid = session_id();
        if ($sid === false || $sid === '') {
            http_response_code(500);
            return;
        }
        $this->session->bindToUser(
            $sid,
            $user->id,
            $_SERVER['REMOTE_ADDR']     ?? '0.0.0.0',
            $_SERVER['HTTP_USER_AGENT'] ?? null,
        );
        $_SESSION['user_id']  = $user->id;
        $_SESSION['username'] = $user->username;
        $_SESSION['role']     = $user->role;
        $this->csrf->rotate();

        header('Location: /dashboard', true, 303);
    }
}
