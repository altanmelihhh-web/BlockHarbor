<?php declare(strict_types=1);

namespace BlockHarbor\Core;

final class Router
{
    /** @var array<string, array<string, array{0:string,1:string}>> */
    private array $routes = [];

    /** @param array{0:string,1:string} $handler */
    public function get(string $path, array $handler): void
    {
        $this->add('GET', $path, $handler);
    }

    /** @param array{0:string,1:string} $handler */
    public function post(string $path, array $handler): void
    {
        $this->add('POST', $path, $handler);
    }

    /** @return array{0:string,1:string}|null */
    public function match(string $method, string $uri): ?array
    {
        $path = strtok($uri, '?');
        if ($path === false) {
            return null;
        }
        return $this->routes[$method][$path] ?? null;
    }

    /** @param array{0:string,1:string} $handler */
    private function add(string $method, string $path, array $handler): void
    {
        $this->routes[$method][$path] = $handler;
    }
}
