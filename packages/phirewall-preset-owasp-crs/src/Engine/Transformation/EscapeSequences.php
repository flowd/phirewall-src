<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * jsDecode, cssDecode and escapeSeqDecode: the backslash escapes of
 * JavaScript, of CSS and of ANSI C.
 *
 * @internal
 */
final class EscapeSequences
{
    private const NAMED = [
        'a' => "\x07",
        'b' => "\x08",
        'f' => "\f",
        'n' => "\n",
        'r' => "\r",
        't' => "\t",
        'v' => "\v",
    ];

    /**
     * "\uHHHH" and "\u{H...}" become one byte (the low byte of the number,
     * or the ASCII character for a full-width one), "\xHH" and "\OOO" the
     * byte, "\n" and its like the control character. Before any other
     * character the backslash is dropped.
     */
    public static function decodeJavaScript(string $value): string
    {
        if (!str_contains($value, '\\')) {
            return $value;
        }

        return preg_replace_callback(
            '/\\\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|([0-3][0-7]{2}|[0-7]{1,2})|(.))/s',
            static function (array $matches): string {
                if (isset($matches[5])) {
                    return self::NAMED[$matches[5]] ?? $matches[5];
                }

                if (isset($matches[4])) {
                    return chr((int) octdec($matches[4]));
                }

                if (isset($matches[3])) {
                    return chr((int) hexdec($matches[3]));
                }

                $codePoint = (int) hexdec(($matches[2] ?? '') !== '' ? $matches[2] : $matches[1]);
                $lowByte = $codePoint & 0xFF;
                if ($codePoint >= 0xFF01 && $codePoint <= 0xFF5E) {
                    $lowByte += 0x20;
                }

                return chr($lowByte);
            },
            $value,
        ) ?? $value;
    }

    /**
     * A backslash with one to six hex digits becomes the character of that
     * number (a full-width one its ASCII character, zero U+FFFD), and one
     * whitespace character after the digits is dropped. A backslash before
     * a line break disappears with it; before any other character, and at
     * the end, only the backslash does.
     */
    public static function decodeCss(string $value): string
    {
        if (!str_contains($value, '\\')) {
            return $value;
        }

        return preg_replace_callback(
            '/\\\\(?:([0-9a-fA-F]{1,6})[ \t\n\r\f\x0B]?|\n|(.))?/s',
            static function (array $matches): string {
                if (isset($matches[2])) {
                    return $matches[2];
                }

                if (!isset($matches[1])) {
                    return '';
                }

                $codePoint = (int) hexdec($matches[1]);
                if ($codePoint >= 0xFF01 && $codePoint <= 0xFF5E) {
                    $codePoint -= 0xFEE0;
                }

                return Utf8::encode($codePoint === 0 ? -1 : $codePoint);
            },
            $value,
        ) ?? $value;
    }

    /**
     * "\n" and its like become the control character, "\xHH" and "\OOO"
     * (the low byte of up to three octal digits) the byte. Before any other
     * character the backslash is dropped.
     */
    public static function decodeAnsiC(string $value): string
    {
        if (!str_contains($value, '\\')) {
            return $value;
        }

        return preg_replace_callback(
            '/\\\\(?:[xX]([0-9a-fA-F]{2})|([0-7]{1,3})|(.))/s',
            static function (array $matches): string {
                if (isset($matches[3])) {
                    return self::NAMED[$matches[3]] ?? $matches[3];
                }

                if (isset($matches[2])) {
                    return chr((int) octdec($matches[2]) & 0xFF);
                }

                return chr((int) hexdec($matches[1]));
            },
            $value,
        ) ?? $value;
    }
}
