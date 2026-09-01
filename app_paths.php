<?php
/**
 * BlockHarbor — application base path.
 *
 * The application was originally mounted at /blacklist/cyberwebeyeos/ and that
 * remains the default so existing deployments keep working unchanged. Set
 * CWE_BASE_PATH to mount it elsewhere — "/" serves it from the domain root,
 * which is what the public demo uses.
 *
 *   CWE_BASE_PATH=/                     ->  https://host/login.php
 *   CWE_BASE_PATH=/blacklist/cyberwebeyeos  ->  https://host/blacklist/cyberwebeyeos/login.php
 */

if (!function_exists('cwe_base_path')) {

    /** Base path without a trailing slash; empty string when mounted at root. */
    function cwe_base_path(): string
    {
        static $base = null;
        if ($base !== null) {
            return $base;
        }
        $raw = (string)getenv('CWE_BASE_PATH');
        if ($raw === '') {
            $raw = '/blacklist/cyberwebeyeos';
        }
        $raw = '/' . trim($raw, '/');          // normalise: exactly one leading slash
        $base = ($raw === '/') ? '' : $raw;    // root mount -> '' so concatenation stays clean
        return $base;
    }

    /** Cookie / directory form of the base path — always ends with a slash. */
    function cwe_base_slash(): string
    {
        return cwe_base_path() . '/';
    }

    /** Absolute in-app URL for a file, e.g. cwe_url('login.php'). */
    function cwe_url(string $relative = ''): string
    {
        return cwe_base_slash() . ltrim($relative, '/');
    }
}
