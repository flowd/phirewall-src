<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks\Support;

use Flowd\Phirewall\Support\CompiledDataCache;

/**
 * What a "per request" case needs to stand for a request under PHP-FPM: the
 * process forgets everything between two requests, except what OPcache keeps.
 */
final class PhpFpm
{
    private function __construct()
    {
    }

    /**
     * Fail the case instead of counting something else: with OPcache off, a
     * compiled artifact is compiled again on every include.
     */
    public static function requireOpcache(): void
    {
        $status = function_exists('opcache_get_status') ? opcache_get_status(false) : false;
        if (!is_array($status) || ($status['opcache_enabled'] ?? false) !== true) {
            throw new \RuntimeException(
                'OPcache is not active. The per-request benchmarks need it; tally.php enables it, '
                . 'but the extension has to be loaded (it is built in since PHP 8.5).',
            );
        }
    }

    /**
     * Forget what the previous request left in the process. Call it inside
     * Meter::exclude(), it is not part of the request.
     */
    public static function startRequest(): void
    {
        CompiledDataCache::clearProcessCache();
    }
}
