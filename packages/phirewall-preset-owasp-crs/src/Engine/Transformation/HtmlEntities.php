<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * htmlEntityDecode: replaces character references the way a browser reads
 * them. A numeric reference needs no closing semicolon, and neither do the
 * names that HTML has always had (`&lt`, `&amp`, `&nbsp`, ...); every
 * other name of HTML 5 needs it.
 *
 * @internal
 */
final class HtmlEntities
{
    private const FLAGS = ENT_QUOTES | ENT_HTML5;

    /** Names that count without a semicolon in upper case as well. */
    private const UPPERCASE_LEGACY_NAMES = ['AMP', 'COPY', 'GT', 'LT', 'QUOT', 'REG'];

    /** Longest number of digits read; more is no character of Unicode anyway. */
    private const MAX_DIGITS = 8;

    /**
     * What a browser shows for the references 0x80 to 0x9F: the characters of Windows-1252.
     */
    private const WINDOWS_1252 = [
        0x80 => 0x20AC, 0x82 => 0x201A, 0x83 => 0x0192, 0x84 => 0x201E, 0x85 => 0x2026, 0x86 => 0x2020,
        0x87 => 0x2021, 0x88 => 0x02C6, 0x89 => 0x2030, 0x8A => 0x0160, 0x8B => 0x2039, 0x8C => 0x0152,
        0x8E => 0x017D, 0x91 => 0x2018, 0x92 => 0x2019, 0x93 => 0x201C, 0x94 => 0x201D, 0x95 => 0x2022,
        0x96 => 0x2013, 0x97 => 0x2014, 0x98 => 0x02DC, 0x99 => 0x2122, 0x9A => 0x0161, 0x9B => 0x203A,
        0x9C => 0x0153, 0x9E => 0x017E, 0x9F => 0x0178,
    ];

    /**
     * The names that count without a semicolon, with their character.
     *
     * @var array<string, string>|null
     */
    private static ?array $legacyNames = null;

    public static function decode(string $value): string
    {
        if (!str_contains($value, '&')) {
            return $value;
        }

        return preg_replace_callback(
            '/&(?:#(?:[xX]([0-9a-fA-F]+)|(\d+));?|([a-zA-Z0-9]+)(;?))/',
            static function (array $matches): string {
                if (isset($matches[3])) {
                    return self::named($matches[3], ($matches[4] ?? '') === ';') ?? $matches[0];
                }

                $decimal = $matches[2] ?? '';
                $digits = ltrim($decimal !== '' ? $decimal : ($matches[1] ?? ''), '0');
                if (strlen($digits) > self::MAX_DIGITS) {
                    return Utf8::encode(-1);
                }

                return self::numeric($decimal !== '' ? (int) $digits : (int) hexdec($digits));
            },
            $value,
        ) ?? $value;
    }

    private static function numeric(int $codePoint): string
    {
        if ($codePoint >= 0x80 && $codePoint <= 0x9F) {
            $codePoint = self::WINDOWS_1252[$codePoint] ?? $codePoint;
        }

        return Utf8::encode($codePoint === 0 ? -1 : $codePoint);
    }

    /**
     * The text for "&name" or "&name;", or null when it is no reference.
     * Without a semicolon, or with a name HTML does not have, the longest
     * legacy name the text starts with counts and the rest stays.
     */
    private static function named(string $name, bool $terminated): ?string
    {
        if ($terminated) {
            $reference = '&' . $name . ';';
            $decoded = html_entity_decode($reference, self::FLAGS, 'UTF-8');
            if ($decoded !== $reference) {
                return $decoded;
            }
        }

        $legacyNames = self::$legacyNames ??= self::legacyNames();
        for ($length = strlen($name); $length >= 2; --$length) {
            $character = $legacyNames[substr($name, 0, $length)] ?? null;
            if ($character !== null) {
                return $character . substr($name, $length) . ($terminated ? ';' : '');
            }
        }

        return null;
    }

    /**
     * The named references of ISO 8859-1 and the four of the markup itself:
     * the ones a browser replaces even without a semicolon.
     *
     * @return array<string, string>
     */
    private static function legacyNames(): array
    {
        $legacyNames = [];
        foreach (get_html_translation_table(HTML_ENTITIES, ENT_QUOTES | ENT_HTML401, 'ISO-8859-1') as $reference) {
            if (preg_match('/^&([a-zA-Z][a-zA-Z0-9]*);$/', $reference, $matches) === 1) {
                $legacyNames[$matches[1]] = html_entity_decode($reference, self::FLAGS, 'UTF-8');
            }
        }

        foreach (self::UPPERCASE_LEGACY_NAMES as $name) {
            $legacyNames[$name] = html_entity_decode('&' . $name . ';', self::FLAGS, 'UTF-8');
        }

        return $legacyNames;
    }
}
