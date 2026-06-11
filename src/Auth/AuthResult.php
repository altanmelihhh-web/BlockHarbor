<?php declare(strict_types=1);

namespace BlockHarbor\Auth;

enum AuthResult: string
{
    case Success        = 'success';
    case BadCredentials = 'bad_credentials';
    case Locked         = 'locked';
    case RateLimited    = 'rate_limited';
    case Inactive       = 'inactive';
}
