<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * compressWhitespace and removeWhitespace.
 *
 * Both read the value as UTF-8, so that a no-break space is found and the
 * byte 0xA0 inside another character is left alone. A value that is not
 * UTF-8 is read byte by byte, as ModSecurity does.
 *
 * @internal
 */
final class Whitespace
{
    /**
     * Every run of whitespace, no-break spaces included, becomes one space.
     */
    public static function compress(string $value): string
    {
        return preg_replace('/[\t-\r \x{85}\x{A0}]+/u', ' ', $value)
            ?? preg_replace('/[\t-\r \xA0]+/', ' ', $value)
            ?? $value;
    }

    /**
     * Takes out everything Unicode counts as white space.
     */
    public static function remove(string $value): string
    {
        return preg_replace('/[\t-\r \x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]+/u', '', $value)
            ?? preg_replace('/[\t-\r \xA0]+/', '', $value)
            ?? $value;
    }
}
