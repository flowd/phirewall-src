<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * cmdLine: what a shell on Windows or Unix makes of a command line, so that
 * `c^md /c`, `"cmd"` and `CMD  ,/c` all read `cmd/c`.
 *
 * @internal
 */
final class CommandLine
{
    private const TOUCHED = '~["\'\\\\^ ,;\t\r\n/(A-Z]~';

    /**
     * Deletes backslashes, quotes and carets; turns commas, semicolons and
     * every run of whitespace into one space; deletes the space before a
     * slash or an opening parenthesis; lowercases.
     */
    public static function normalise(string $value): string
    {
        if (preg_match(self::TOUCHED, $value) !== 1) {
            return $value;
        }

        $value = str_replace(['\\', '"', "'", '^'], '', $value);
        $value = preg_replace('/[ ,;\t\r\n]+/', ' ', $value) ?? $value;
        $value = str_replace([' /', ' ('], ['/', '('], $value);

        return strtolower($value);
    }
}
