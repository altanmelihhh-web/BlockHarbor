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
}
