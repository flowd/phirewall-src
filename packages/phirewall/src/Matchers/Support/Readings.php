<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers\Support;

use Flowd\Phirewall\Http\RequestView;

/**
 * One test on every reading of a value: that of the PSR-7 request and that of
 * the server parameters, as {@see RequestView} lists them.
 *
 * The application behind the firewall may read either, so:
 *
 * - **restrictive** (blocklists, fail2ban/allow2ban filters, throttle scopes,
 *   tracks): one matching reading is a match.
 * - **permissive** (safelists): every reading has to match, so a request is
 *   not let through for the one reading the application does not use.
 *
 * @internal Shared infrastructure for phirewall internals. Not part of the public API.
 */
final class Readings
{
    /**
     * @template TReading
     *
     * @param list<TReading> $readings
     * @param callable(TReading): bool $test
     */
    public static function match(array $readings, callable $test, bool $permissive): bool
    {
        foreach ($readings as $reading) {
            if ($test($reading) !== $permissive) {
                return !$permissive;
            }
        }

        return $permissive && $readings !== [];
    }

    /**
     * The first reading that is not empty, null when all are.
     *
     * @param list<string> $readings
     */
    public static function first(array $readings): ?string
    {
        foreach ($readings as $reading) {
            if ($reading !== '') {
                return $reading;
            }
        }

        return null;
    }
}
