<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * UTF-8 helpers of the transformations.
 *
 * @internal
 */
final class Utf8
{
    /** One well-formed multi-byte sequence, as a pattern that reads bytes. */
    public const MULTIBYTE_SEQUENCE = '[\xC2-\xDF][\x80-\xBF]'
        . '|\xE0[\xA0-\xBF][\x80-\xBF]'
        . '|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}'
        . '|\xED[\x80-\x9F][\x80-\xBF]'
        . '|\xF0[\x90-\xBF][\x80-\xBF]{2}'
        . '|[\xF1-\xF3][\x80-\xBF]{3}'
        . '|\xF4[\x80-\x8F][\x80-\xBF]{2}';

    private const REPLACEMENT_CHARACTER = "\xEF\xBF\xBD";

    /** @var array<string, string> */
    private static array $bytesAsCharacters = [];

    public static function isWellFormed(string $value): bool
    {
        return preg_match('//u', $value) === 1;
    }

    /**
     * The code point as UTF-8; U+FFFD for a surrogate or a number outside Unicode.
     */
    public static function encode(int $codePoint): string
    {
        if ($codePoint < 0 || $codePoint > 0x10FFFF || ($codePoint >= 0xD800 && $codePoint <= 0xDFFF)) {
            return self::REPLACEMENT_CHARACTER;
        }

        if ($codePoint < 0x80) {
            return chr($codePoint);
        }

        if ($codePoint < 0x800) {
            return chr(0xC0 | ($codePoint >> 6)) . chr(0x80 | ($codePoint & 0x3F));
        }

        if ($codePoint < 0x10000) {
            return chr(0xE0 | ($codePoint >> 12))
                . chr(0x80 | (($codePoint >> 6) & 0x3F))
                . chr(0x80 | ($codePoint & 0x3F));
        }

        return chr(0xF0 | ($codePoint >> 18))
            . chr(0x80 | (($codePoint >> 12) & 0x3F))
            . chr(0x80 | (($codePoint >> 6) & 0x3F))
            . chr(0x80 | ($codePoint & 0x3F));
    }

    /**
     * The code point of one well-formed multi-byte sequence.
     */
    public static function codePoint(string $sequence): int
    {
        return match (strlen($sequence)) {
            2 => ((ord($sequence[0]) & 0x1F) << 6) | (ord($sequence[1]) & 0x3F),
            3 => ((ord($sequence[0]) & 0x0F) << 12) | ((ord($sequence[1]) & 0x3F) << 6) | (ord($sequence[2]) & 0x3F),
            default => ((ord($sequence[0]) & 0x07) << 18)
                | ((ord($sequence[1]) & 0x3F) << 12)
                | ((ord($sequence[2]) & 0x3F) << 6)
                | (ord($sequence[3]) & 0x3F),
        };
    }

    /**
     * The value as well-formed UTF-8: every byte that is not part of a
     * well-formed sequence becomes the character with the number of that
     * byte, so 0xFC becomes U+00FC.
     *
     * The decoding transformations produce bytes, and the operators read
     * UTF-8. Read this way a pattern such as "\xfc" still finds the byte
     * it was written for, and a decoded value never is unreadable to the
     * regex engine.
     */
    public static function fromBytes(string $value): string
    {
        // The well-formed sequences are the delimiters and stay; what lies between them is read byte by byte.
        $parts = preg_split('/((?:' . self::MULTIBYTE_SEQUENCE . ')+)/', $value, -1, PREG_SPLIT_DELIM_CAPTURE);
        if ($parts === false) {
            return strtr($value, self::bytesAsCharacters());
        }

        $bytesAsCharacters = self::bytesAsCharacters();
        for ($index = 0, $count = count($parts); $index < $count; $index += 2) {
            $parts[$index] = strtr($parts[$index], $bytesAsCharacters);
        }

        return implode('', $parts);
    }

    /**
     * Every byte from 0x80 on with the character of its number, as UTF-8.
     *
     * @return array<string, string>
     */
    private static function bytesAsCharacters(): array
    {
        if (self::$bytesAsCharacters === []) {
            for ($byte = 0x80; $byte <= 0xFF; ++$byte) {
                self::$bytesAsCharacters[chr($byte)] = self::encode($byte);
            }
        }

        return self::$bytesAsCharacters;
    }
}
