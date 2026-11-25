<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * normalizePath and normalizePathWin.
 *
 * @internal
 */
final class Paths
{
    /**
     * Removes empty and "." segments and resolves ".." against the segment
     * before it. Above the root ".." is dropped; in a relative path it
     * stays when nothing is left to go up from. A trailing slash is kept.
     */
    public static function normalise(string $value): string
    {
        if ($value === '') {
            return '';
        }

        $rooted = $value[0] === '/';
        $segments = [];
        foreach (explode('/', $value) as $segment) {
            if ($segment === '') {
                continue;
            }

            if ($segment === '.') {
                continue;
            }

            if ($segment !== '..') {
                $segments[] = $segment;
                continue;
            }

            if ($segments !== [] && end($segments) !== '..') {
                array_pop($segments);
            } elseif (!$rooted) {
                $segments[] = '..';
            }
        }

        $path = ($rooted ? '/' : '') . implode('/', $segments);
        if ($path === '') {
            return '';
        }

        return str_ends_with($value, '/') && $path !== '/' ? $path . '/' : $path;
    }

    /**
     * Like {@see normalise()} with the backslash as a separator too, and
     * the same file as Windows opens: without a stream name ("file:stream")
     * in the last segment, and without dots and spaces at the end of a
     * segment.
     */
    public static function normaliseWindows(string $value): string
    {
        if ($value === '') {
            return '';
        }

        $path = self::normalise(str_replace('\\', '/', $value));

        return self::withoutTrailingDotsAndSpaces(self::withoutStreamName($path));
    }

    private static function withoutStreamName(string $path): string
    {
        $drive = '';
        if (preg_match('/^[a-zA-Z]:/', $path) === 1) {
            $drive = substr($path, 0, 2);
            $path = substr($path, 2);
        }

        $trailingSlash = '';
        if (str_ends_with($path, '/')) {
            $trailingSlash = '/';
            $path = substr($path, 0, -1);
        }

        $lastSlash = strrpos($path, '/');
        $lastSegmentStart = $lastSlash === false ? 0 : $lastSlash + 1;
        $colon = strpos($path, ':', $lastSegmentStart);
        if ($colon !== false) {
            $path = substr($path, 0, $colon);
        }

        return $drive . $path . $trailingSlash;
    }

    private static function withoutTrailingDotsAndSpaces(string $path): string
    {
        if (preg_match('~[. ](?:/|$)~', $path) !== 1) {
            return $path;
        }

        $changed = false;
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            // "." and ".." are segments of their own, not a name with dots at its end.
            if ($segment === '' || trim($segment, '.') === '') {
                $segments[] = $segment;
                continue;
            }

            $trimmed = rtrim($segment, '. ');
            if ($trimmed !== $segment) {
                $changed = true;
                // A segment of dots and spaces only is no segment to Windows.
                if ($trimmed === '') {
                    continue;
                }
            }

            $segments[] = $trimmed;
        }

        return $changed ? implode('/', $segments) : $path;
    }
}
