<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * base64Decode and base64DecodeExt.
 *
 * @internal
 */
final class Base64
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    /**
     * Decodes up to the first character that is not Base64 (padding and a
     * space included) and returns what was decoded until there. Line breaks
     * are skipped.
     */
    public static function decode(string $value): string
    {
        $value = str_replace(["\r", "\n"], '', $value);

        return self::decodeAlphabetOnly(substr($value, 0, strspn($value, self::ALPHABET)));
    }

    /**
     * The forgiving decoder: skips every character that is not Base64,
     * reads the URL-safe alphabet as well and stops at the padding only.
     */
    public static function decodeForgiving(string $value): string
    {
        $value = substr($value, 0, strcspn($value, '='));
        $value = preg_replace('~[^A-Za-z0-9+/]~', '', strtr($value, '-_', '+/')) ?? '';

        return self::decodeAlphabetOnly($value);
    }

    /**
     * A single character left over at the end carries six bits only, not a byte, and is dropped.
     */
    private static function decodeAlphabetOnly(string $value): string
    {
        if (strlen($value) % 4 === 1) {
            $value = substr($value, 0, -1);
        }

        return (string) base64_decode($value, false);
    }
}
