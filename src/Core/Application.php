<?php declare(strict_types=1);

namespace BlockHarbor\Core;

use BlockHarbor\Admin\Controllers\DashboardController;
use BlockHarbor\Auth\AuthService;
use BlockHarbor\Auth\Controllers\LoginController;
use BlockHarbor\Auth\Controllers\LogoutController;
use BlockHarbor\Auth\LoginAttemptRepository;
use BlockHarbor\Auth\MfaResolver;
use BlockHarbor\Auth\PasswordHasher;
use BlockHarbor\Auth\UserRepository;
use League\Plates\Engine;

final class Application
{
    public function __construct(
        private readonly Config $config,
        private readonly Database $database,
        private readonly Router $router,
        private readonly Engine $views,
    ) {}

    public static function boot(string $root): self
    {
        $config   = Config::fromEnvFile($root . '/.env');
        $database = new Database($config);

        // DB-backed PHP session handler
        $sessionHandler = new Session($database->pdo(), $config->int('SESSION_LIFETIME', 1800));
        session_set_save_handler($sessionHandler, true);
        session_name($config->string('SESSION_NAME', 'BLOCKHARBOR_SESSION'));
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();

        $views  = new Engine($root . '/resources/views', 'php');
        $router = new Router();

        $app = new self($config, $database, $router, $views);
        $app->registerRoutes();

        return $app;
    }

    private function registerRoutes(): void
    {
        $this->router->get ('/login',     [LoginController::class,    'show']);
        $this->router->post('/login',     [LoginController::class,    'submit']);
        $this->router->post('/logout',    [LogoutController::class,   'submit']);
        $this->router->get ('/',          [DashboardController::class,'index']);
        $this->router->get ('/dashboard', [DashboardController::class,'index']);
    }

    public function run(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri    = $_SERVER['REQUEST_URI'] ?? '/';

        $handler = $this->router->match($method, $uri);

        if ($handler === null) {
            http_response_code(404);
            echo $this->views->render('errors/404');
            return;
        }

        [$class, $method2] = $handler;
        $controller = $this->resolve($class);
        $controller->{$method2}();
    }

    private function resolve(string $class): object
    {
        $pdo  = $this->database->pdo();
        $csrf = new Csrf();

        return match ($class) {
            LoginController::class => new LoginController(
                new AuthService(
                    new UserRepository($pdo),
                    new LoginAttemptRepository($pdo),
                    new PasswordHasher(),
                    maxFailsPerIpIn5Min: $this->config->int('LOGIN_MAX_FAILS_PER_IP_5MIN', 10),
                    maxFailsPerUserIn1h: $this->config->int('LOGIN_MAX_FAILS_PER_USER_1H', 5),
                    lockoutMinutes:      $this->config->int('LOGIN_LOCKOUT_MINUTES', 15),
                    mfa:                 new MfaResolver($pdo),
                ),
                new Session($pdo, $this->config->int('SESSION_LIFETIME', 1800)),
                $csrf,
                $this->views,
            ),
            LogoutController::class => new LogoutController(new Session($pdo), $csrf),
            DashboardController::class => new DashboardController(
                new UserRepository($pdo), $this->views,
            ),
            default => throw new \RuntimeException("Cannot resolve $class"),
        };
    }
}
