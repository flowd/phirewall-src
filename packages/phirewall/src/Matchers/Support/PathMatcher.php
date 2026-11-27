<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers\Support;

use Flowd\Phirewall\Http\NormalizedPath;
use Flowd\Phirewall\Http\PathNormalizer;

/**
 * Path comparisons on the paths of a request, shared by every built-in path rule.
 * A request has one path, or two when its server parameters name another than
 * its PSR-7 URI ({@see \Flowd\Phirewall\Http\RequestView::normalizedPaths()}).
 *
 * Literal rule values (exact paths, prefixes) are normalised once at compile
 * time with {@see compileLiteral()}, so `'/my%20file'` and `'/my file'` match
 * the same requests. Regex patterns cannot be normalised; they run against
 * the normalised path (and, in restrictive mode, the raw path too).
 *
 * Two modes (see {@see PathNormalizer} for the reasoning):
 *
 * - **restrictive** (blocklists, fail2ban/allow2ban filters, throttle scopes,
 *   tracks): match when the normalised path matches the normalised rule value
 *   OR the raw path matches the rule value as written. Over-matching only
 *   blocks or counts more, and rules written against the raw form keep working.
 *   One matching path of the request is a match.
 * - **permissive** (safelists): match only an unambiguous path, on its
 *   normalised form, so an attacker cannot steer an ambiguous path into a
 *   safelisted one. Every path of the request has to match.
 *
 * @internal Shared infrastructure for phirewall internals. Not part of the public API.
 */
final class PathMatcher
{
    /**
     * A literal rule value in both forms: as written and normalised.
     */
    public static function compileLiteral(string $value): NormalizedPath
    {
        return new NormalizedPath($value, $value === '' ? '' : PathNormalizer::normalize($value), false);
    }

    /**
     * @param list<NormalizedPath> $requestPaths
     */
    public static function equals(array $requestPaths, NormalizedPath $normalizedPath, bool $permissive): bool
    {
        return Readings::match(
            $requestPaths,
            $permissive
                ? static fn(NormalizedPath $requestPath): bool => !$requestPath->ambiguous && $requestPath->normalized === $normalizedPath->normalized
                : static fn(NormalizedPath $requestPath): bool => $requestPath->normalized === $normalizedPath->normalized || $requestPath->raw === $normalizedPath->raw,
            $permissive,
        );
    }

    /**
     * An empty prefix never matches (it would otherwise match every request).
     *
     * @param list<NormalizedPath> $requestPaths
     */
    public static function startsWith(array $requestPaths, NormalizedPath $normalizedPath, bool $permissive): bool
    {
        if ($normalizedPath->raw === '') {
            return false;
        }

        return Readings::match(
            $requestPaths,
            $permissive
                ? static fn(NormalizedPath $requestPath): bool => !$requestPath->ambiguous && str_starts_with($requestPath->normalized, $normalizedPath->normalized)
                : static fn(NormalizedPath $requestPath): bool => str_starts_with($requestPath->normalized, $normalizedPath->normalized)
                    || str_starts_with($requestPath->raw, $normalizedPath->raw),
            $permissive,
        );
    }

    /**
     * @param list<NormalizedPath> $requestPaths
     * @param callable(string): bool $matches Regex test on one subject, carrying the caller's failure policy.
     */
    public static function matchesRegex(array $requestPaths, callable $matches, bool $permissive): bool
    {
        return Readings::match(
            $requestPaths,
            $permissive
                ? static fn(NormalizedPath $normalizedPath): bool => !$normalizedPath->ambiguous && $matches($normalizedPath->normalized)
                : static fn(NormalizedPath $normalizedPath): bool => $matches($normalizedPath->normalized)
                    || ($normalizedPath->raw !== $normalizedPath->normalized && $matches($normalizedPath->raw)),
            $permissive,
        );
    }
}
