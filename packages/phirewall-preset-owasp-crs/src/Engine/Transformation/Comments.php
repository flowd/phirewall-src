<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * removeComments, removeCommentsChar and replaceComments.
 *
 * @internal
 */
final class Comments
{
    /**
     * Every C comment becomes one space; one that is not closed runs to the end.
     */
    public static function replace(string $value): string
    {
        if (!str_contains($value, '/*')) {
            return $value;
        }

        return preg_replace('~/\*.*?(?:\*/|\z)~s', ' ', $value) ?? $value;
    }

    /**
     * Takes out what opens and closes a comment and leaves its text.
     */
    public static function removeMarkers(string $value): string
    {
        if (strpbrk($value, '/*-#') === false) {
            return $value;
        }

        return preg_replace('~/\*|\*/|<!--|-->|--|#~', '', $value) ?? $value;
    }

    /**
     * Takes out C and HTML comments; "--" and "#" outside of a comment end
     * the value. A comment that is not closed leaves one space.
     *
     * ModSecurity copies the byte after the end of a comment without looking
     * at it; this does the same, byte for byte.
     */
    public static function remove(string $value): string
    {
        if (strpbrk($value, '/<-#') === false) {
            return $value;
        }

        $length = strlen($value);
        // One byte of padding: the byte after a comment that ends the value.
        $input = $value . "\0";
        $output = '';
        $inComment = false;
        $index = 0;
        while ($index < $length) {
            if ($inComment) {
                if (substr_compare($input, '*/', $index, 2) === 0 && $index + 1 < $length) {
                    $inComment = false;
                    $output .= $input[$index + 2];
                    $index += 3;
                } elseif (substr_compare($input, '-->', $index, 3) === 0 && $index + 2 < $length) {
                    $inComment = false;
                    $output .= $input[$index + 3] ?? '';
                    $index += 4;
                } else {
                    ++$index;
                }

                continue;
            }

            if (substr_compare($input, '/*', $index, 2) === 0 && $index + 1 < $length) {
                $inComment = true;
                $index += 2;
            } elseif (substr_compare($input, '<!--', $index, 4) === 0 && $index + 3 < $length) {
                $inComment = true;
                $index += 4;
            } elseif ($input[$index] === '#' || (substr_compare($input, '--', $index, 2) === 0 && $index + 1 < $length)) {
                break;
            } else {
                $output .= $input[$index];
                ++$index;
            }
        }

        return $inComment ? $output . ' ' : $output;
    }
}
