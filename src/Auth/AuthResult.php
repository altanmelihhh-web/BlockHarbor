<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

enum AuthResult: string
{
    case Success        = 'success';
    case BadCredentials = 'bad_credentials';
    case Locked         = 'locked';
    case RateLimited    = 'rate_limited';
    case Inactive       = 'inactive';

    /**
     * Password OK but MFA challenge pending. The caller (LoginController)
     * stashes pending_user_id in \$_SESSION and redirects to /2fa.
     */
    case RequiresMfa = 'requires_mfa';

    /**
     * Password OK but the account is flagged must_change_password (default
     * admin seed, or operator-initiated reset). LoginController stashes
     * pending_password_change_user_id and redirects to /change-password.
     */
    case PasswordChangeRequired = 'password_change_required';
}
