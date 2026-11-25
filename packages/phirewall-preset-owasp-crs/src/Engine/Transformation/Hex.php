<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * hexDecode and sqlHexDecode.
 *
 * @internal
 */
final class Hex
{
    /**
     * The bytes of a string of hex digit pairs; nothing for a value that is not one.
     */
    public static function decode(string $value): string
    {
        if (strlen($value) % 2 !== 0 || strspn($value, '0123456789abcdefABCDEF') !== strlen($value)) {
            return '';
        }

        return (string) hex2bin($value);
    }

    /**
     * Every "0xHH..." of SQL becomes the bytes it stands for.
     */
    public static function decodeSql(string $value): string
    {
        if (stripos($value, '0x') === false) {
            return $value;
        }

        return preg_replace_callback(
            '/0[xX]((?:[0-9a-fA-F]{2})+)/',
            static fn(array $matches): string => (string) hex2bin($matches[1]),
            $value,
        ) ?? $value;
    }
}
