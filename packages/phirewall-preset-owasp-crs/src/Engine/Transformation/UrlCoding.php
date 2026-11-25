<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * urlDecode, urlDecodeUni, urlEncode and utf8toUnicode.
 *
 * @internal
 */
final class UrlCoding
{
    /**
     * "+" becomes a space and "%HH" the byte. A "%" that is not followed by
     * two hex digits stays.
     */
    public static function decode(string $value): string
    {
        if (strpbrk($value, '%+') === false) {
            return $value;
        }

        $value = str_replace('+', ' ', $value);
        if (!str_contains($value, '%')) {
            return $value;
        }

        return preg_replace_callback(
            '/%([0-9a-fA-F]{2})/',
            static fn(array $matches): string => chr((int) hexdec($matches[1])),
            $value,
        ) ?? $value;
    }

    /**
     * Like {@see decode()}, and "%uHHHH" (the encoding of IIS) becomes one
     * byte as well: the low byte of the number, or the ASCII character for
     * a full-width one (U+FF01 to U+FF5E).
     */
    public static function decodeUnicode(string $value): string
    {
        if (strpbrk($value, '%+') === false) {
            return $value;
        }

        $value = str_replace('+', ' ', $value);
        if (!str_contains($value, '%')) {
            return $value;
        }

        return preg_replace_callback(
            '/%(?:[uU]([0-9a-fA-F]{4})|([0-9a-fA-F]{2}))/',
            static function (array $matches): string {
                if (isset($matches[2])) {
                    return chr((int) hexdec($matches[2]));
                }

                $codePoint = (int) hexdec($matches[1]);
                $lowByte = $codePoint & 0xFF;
                if ($codePoint >> 8 === 0xFF && $lowByte > 0x00 && $lowByte < 0x5F) {
                    $lowByte += 0x20;
                }

                return chr($lowByte);
            },
            $value,
        ) ?? $value;
    }

    /**
     * A space becomes "+", every byte other than an ASCII letter, a digit
     * or "*" becomes "%hh".
     */
    public static function encode(string $value): string
    {
        return preg_replace_callback(
            '/[^A-Za-z0-9*]/',
            static fn(array $matches): string => $matches[0] === ' ' ? '+' : '%' . bin2hex($matches[0]),
            $value,
        ) ?? $value;
    }

    /**
     * Every character outside ASCII becomes "%uHHHH". A byte that is not
     * part of a well-formed UTF-8 sequence stays.
     */
    public static function utf8ToUnicode(string $value): string
    {
        if (preg_match('/[\x80-\xFF]/', $value) !== 1) {
            return $value;
        }

        return preg_replace_callback(
            '/' . Utf8::MULTIBYTE_SEQUENCE . '/',
            static fn(array $matches): string => sprintf('%%u%04x', Utf8::codePoint($matches[0])),
            $value,
        ) ?? $value;
    }
}
