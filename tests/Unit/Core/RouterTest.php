<?php declare(strict_types=1);

namespace BlockHarbor\Tests\Unit\Core;

use BlockHarbor\Core\Router;
use PHPUnit\Framework\TestCase;

final class RouterTest extends TestCase
{
    public function test_match_returns_handler_for_registered_route(): void
    {
        $r = new Router();
        $r->get('/login', ['HomeController', 'show']);

        self::assertSame(['HomeController', 'show'], $r->match('GET', '/login'));
    }

    public function test_returns_null_for_unknown_route(): void
    {
        $r = new Router();
        self::assertNull($r->match('GET', '/no'));
    }

    public function test_method_distinguishes_handlers(): void
    {
        $r = new Router();
        $r->get ('/login', ['Login', 'show']);
        $r->post('/login', ['Login', 'submit']);

        self::assertSame(['Login', 'show'],   $r->match('GET',  '/login'));
        self::assertSame(['Login', 'submit'], $r->match('POST', '/login'));
    }

    public function test_query_string_is_stripped(): void
    {
        $r = new Router();
        $r->get('/dash', ['D', 'i']);
        self::assertSame(['D', 'i'], $r->match('GET', '/dash?x=1'));
    }
}
