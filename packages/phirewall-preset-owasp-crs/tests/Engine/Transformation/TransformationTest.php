<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine\Transformation;

use Flowd\PhirewallPresetOwaspCrs\Engine\Transformation\Transformation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TransformationTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function cases(): iterable
    {
        $cases = [
            'urlDecodeUni' => [
                'nothing to decode' => ['/index.php', '/index.php'],
                'a percent-encoded byte' => ['/%2eenv', '/.env'],
                'upper and lower hex digits' => ['%2F%2f', '//'],
                'a plus sign is a space' => ['a+b', 'a b'],
                'an encoded plus sign stays one' => ['a%2Bb', 'a+b'],
                'decodes once only' => ['%252e', '%2e'],
                'a percent sign without hex digits stays' => ['100%', '100%'],
                'one hex digit is not enough' => ['%2', '%2'],
                'no hex digits' => ['%zz', '%zz'],
                'a percent sign before an encoded byte' => ['%%41', '%A'],
                'the low byte of %u' => ['%u0041', 'A'],
                'an upper-case U' => ['%U0041', 'A'],
                'the high byte of %u is dropped' => ['%u1234', '4'],
                'full-width less-than' => ['%uff1cscript%uff1e', '<script>'],
                'full-width tilde' => ['%uff5e', '~'],
                'beyond the full-width letters' => ['%uff5f', "\x5F"],
                '%u with three hex digits stays' => ['%u004', '%u004'],
                '%u without hex digits stays' => ['%u00zz', '%u00zz'],
                'a byte above ASCII' => ['%FC', "\xFC"],
                'a NUL byte' => ['a%00b', "a\0b"],
            ],
            'urlDecode' => [
                'a percent-encoded byte' => ['%3Cb%3E', '<b>'],
                'a plus sign is a space' => ['a+b', 'a b'],
                '%u is left alone' => ['%u0041', '%u0041'],
                'a percent sign without hex digits stays' => ['50% off', '50% off'],
            ],
            'urlEncode' => [
                'letters, digits and the asterisk stay' => ['aZ09*', 'aZ09*'],
                'a space becomes a plus sign' => ['a b', 'a+b'],
                'everything else in lower-case hex' => ["<./\xFC", '%3c%2e%2f%fc'],
                'nothing' => ['', ''],
            ],
            'utf8toUnicode' => [
                'ASCII stays' => ['plain', 'plain'],
                'two bytes' => ['Müller', 'M%u00fcller'],
                'three bytes' => ['＜', '%uff1c'],
                'four bytes' => ['😀', '%u1f600'],
                'a byte that is not UTF-8 stays' => ["a\xFCb", "a\xFCb"],
            ],
            'htmlEntityDecode' => [
                'nothing to decode' => ['a < b', 'a < b'],
                'decimal' => ['&#60;script&#62;', '<script>'],
                'hex' => ['&#x3c;&#X3E;', '<>'],
                'decimal without a semicolon' => ['&#106avascript', 'javascript'],
                'hex without a semicolon' => ['&#x6Aquery', 'jquery'],
                'takes every hex digit that follows' => ['&#x6Aa', "\u{6AA}"],
                'leading zeros' => ['&#0000060;', '<'],
                'a named reference' => ['&lt;b&gt;', '<b>'],
                'a legacy name without a semicolon' => ['&ltb&gt', '<b>'],
                'a legacy name in upper case' => ['&LT;&AMP', '<&'],
                'a name of HTML 5' => ['java&Tab;script&colon;', "java\tscript:"],
                'a name of HTML 5 needs its semicolon' => ['&colon', '&colon'],
                'a legacy name at the start of an unknown one' => ['&notit;', '¬it;'],
                'an unknown name stays' => ['&nosuchname;', '&nosuchname;'],
                'an ampersand by itself stays' => ['fish & chips', 'fish & chips'],
                'no digits' => ['&#;&#x;', '&#;&#x;'],
                'above ASCII as UTF-8' => ['&#252;&uuml;', 'üü'],
                'the Windows-1252 range' => ['&#128;&#x92;', '€’'],
                'zero is the replacement character' => ['&#0;', "\u{FFFD}"],
                'a surrogate is the replacement character' => ['&#xD800;', "\u{FFFD}"],
                'beyond Unicode is the replacement character' => ['&#x110000;&#99999999999;', "\u{FFFD}\u{FFFD}"],
            ],
            'jsDecode' => [
                'nothing to decode' => ['alert(1)', 'alert(1)'],
                '\uHHHH is its low byte' => ['\u0061lert', 'alert'],
                'the high byte is dropped' => ['\u1234', '4'],
                'full-width less-than' => ['\uff1c', '<'],
                'a code point escape' => ['\u{61}\u{0061}', 'aa'],
                'a full-width code point escape' => ['\u{ff1c}', '<'],
                'a code point escape that is not closed' => ['\u{61', 'u{61'],
                '\xHH' => ['\x3cscript\x3E', '<script>'],
                'octal' => ['\141\0', "a\0"],
                'octal takes two digits when three are more than a byte' => ['\777', '?7'],
                'named escapes' => ['\a\b\f\n\r\t\v', "\x07\x08\x0C\n\r\t\x0B"],
                'the backslash before anything else is dropped' => ['\"\\\'\\\\\z', '"\'\\z'],
                '\u without four hex digits' => ['\u12', 'u12'],
                'a backslash at the end stays' => ['a\\', 'a\\'],
                'a byte above ASCII' => ['\xfc', "\xFC"],
            ],
            'cssDecode' => [
                'nothing to decode' => ['color: red', 'color: red'],
                'hex digits' => ['\6a\61va', 'java'],
                'up to six hex digits' => ['\00006a\0000611', 'ja1'],
                'one whitespace after the digits is dropped' => ['\6a avascript', 'javascript'],
                'only one' => ['\6a  b', 'j b'],
                'the character of the number, not its low byte' => ['\141', 'Ł'],
                'above ASCII as UTF-8' => ['\fc', 'ü'],
                'full-width less-than' => ['\ff1c', '<'],
                'zero is the replacement character' => ['\0', "\u{FFFD}"],
                'beyond Unicode is the replacement character' => ['\110000', "\u{FFFD}"],
                'a backslash before a line break disappears with it' => ["ja\\\nva", 'java'],
                'the backslash before anything else is dropped' => ['\j\(', 'j('],
                'a backslash at the end is dropped' => ['a\\', 'a'],
            ],
            'escapeSeqDecode' => [
                'nothing to decode' => ['abc', 'abc'],
                'named escapes' => ['\a\b\f\n\r\t\v', "\x07\x08\x0C\n\r\t\x0B"],
                'quotes, question mark and backslash' => ['\?\\\'\"\\\\', '?\'"\\'],
                '\xHH and \XHH' => ['\x41\X42', 'AB'],
                '\x without two hex digits' => ['\x4', 'x4'],
                'octal' => ['\101\60', 'A0'],
                'the low byte of three octal digits' => ['\777', "\xFF"],
                'the backslash before anything else is dropped' => ['\z', 'z'],
                'a backslash at the end stays' => ['a\\', 'a\\'],
            ],
            'base64Decode' => [
                'padded' => ['PHNjcmlwdD4=', '<script>'],
                'without padding' => ['PHNjcmlwdD4', '<script>'],
                'stops at the padding' => ['YQ==YQ==', 'a'],
                'stops at a character that is not Base64' => ['YWJj!ZGVm', 'abc'],
                'stops at a space' => ['YWJj ZGVm', 'abc'],
                'line breaks are skipped' => ["YWJj\r\nZGVm", 'abcdef'],
                'a single character left over is dropped' => ['YWJjZ', 'abc'],
                'nothing' => ['', ''],
            ],
            'base64DecodeExt' => [
                'skips what is not Base64' => ['YWJj!.ZGVm', 'abcdef'],
                'skips whitespace' => ["YW Jj\tZGVm", 'abcdef'],
                'the URL-safe alphabet' => ['Pz8-Pz8_', '??>???'],
                'stops at the padding' => ['YQ==YQ==', 'a'],
            ],
            'base64Encode' => [
                'encodes' => ['<script>', 'PHNjcmlwdD4='],
            ],
            'hexDecode' => [
                'pairs of hex digits' => ['3c623E', '<b>'],
                'an odd number of digits is nothing' => ['3c6', ''],
                'anything else is nothing' => ['3cxx', ''],
            ],
            'hexEncode' => [
                'lower-case hex' => ["<\xFF", '3cff'],
            ],
            'sqlHexDecode' => [
                'a hex literal' => ['select 0x414243', 'select ABC'],
                'an upper-case X' => ['0X61', 'a'],
                'pairs only' => ['0x41424', 'AB4'],
                'no hex literal' => ['0xzz 10x', '0xzz 10x'],
            ],
            'lowercase' => [
                'ASCII letters' => ['SeLeCT', 'select'],
                'other letters stay' => ['ÄB', 'Äb'],
            ],
            'uppercase' => [
                'ASCII letters' => ['SeLeCT', 'SELECT'],
            ],
            'removeNulls' => [
                'takes them out' => ["a\0b\0", 'ab'],
            ],
            'replaceNulls' => [
                'a space for each' => ["a\0b\0", 'a b '],
            ],
            'removeWhitespace' => [
                'ASCII white space' => [" a\tb\nc\r\x0B\x0Cd ", 'abcd'],
                'a no-break space' => ["a\u{A0}b", 'ab'],
                'other white space of Unicode' => ["a\u{2003}b\u{3000}c\u{2028}d", 'abcd'],
                'the byte 0xA0 inside a character stays' => ['à', 'à'],
                'a value that is not UTF-8 is read as bytes' => ["\xFC a\xA0b", "\xFCab"],
            ],
            'compressWhitespace' => [
                'a run becomes one space' => ["a \t\r\n b", 'a b'],
                'a single tab becomes a space' => ["a\tb", 'a b'],
                'a no-break space' => ["a\u{A0}\u{A0}b", 'a b'],
                'the byte 0xA0 inside a character stays' => ['à  à', 'à à'],
                'a value that is not UTF-8 is read as bytes' => ["\xFC\xA0\xA0b", "\xFC b"],
            ],
            'replaceComments' => [
                'no comment' => ['a / * b', 'a / * b'],
                'a comment becomes one space' => ['un/**/ion', 'un ion'],
                'with text' => ['a/* b */c', 'a c'],
                'not closed runs to the end' => ['a/* b', 'a '],
                'the slash of the opening does not close' => ['a/*/b', 'a '],
                'several' => ['a/*1*/b/*2*/c', 'a b c'],
                'across lines' => ["a/*\n*/b", 'a b'],
            ],
            'removeCommentsChar' => [
                'C comment markers' => ['un/**/ion', 'union'],
                'the text of a comment stays' => ['a/* b */c', 'a b c'],
                'HTML comment markers' => ['<!-- a -->', ' a '],
                'SQL comment markers' => ['1--2#3', '123'],
                'nothing to remove' => ['a - b', 'a - b'],
            ],
            'removeComments' => [
                'a C comment' => ['a/* b */c', 'ac'],
                'an HTML comment' => ['a<!-- b -->c', 'ac'],
                'not closed leaves a space' => ['a/* b', 'a '],
                'two dashes end the value' => ['a -- b', 'a '],
                'a hash ends the value' => ['a # b', 'a '],
                'a comment that ends the value leaves the padding byte' => ['a/* b */', "a\0"],
                'nothing to remove' => ['a - b', 'a - b'],
            ],
            'cmdLine' => [
                'carets, quotes and backslashes go' => ['c^m"d" \'/c\' \\x', 'cmd/c x'],
                'commas and semicolons are spaces' => ['a,b;c', 'a b c'],
                'a run of whitespace is one space' => ["a \t\r\n b", 'a b'],
                'no space before a slash or a parenthesis' => ['cmd  /c echo (1)', 'cmd/c echo(1)'],
                'lower case' => ['CMD.EXE', 'cmd.exe'],
                'nothing to do' => ['cmd.exe', 'cmd.exe'],
            ],
            'normalizePath' => [
                'nothing to do' => ['/a/b', '/a/b'],
                'a dot segment' => ['/a/./b', '/a/b'],
                'a double dot segment' => ['/a/b/../c', '/a/c'],
                'several slashes' => ['/a//b///c', '/a/b/c'],
                'not above the root' => ['/../../etc/passwd', '/etc/passwd'],
                'a relative path keeps what it cannot resolve' => ['../a/../../b', '../../b'],
                'a trailing slash is kept' => ['/a/b/../', '/a/'],
                'the root' => ['/a/..', '/'],
                'a relative path that resolves to nothing' => ['a/..', ''],
                'the current directory' => ['./', ''],
                'nothing' => ['', ''],
                'a backslash is no separator' => ['/a\\..\\b', '/a\\..\\b'],
            ],
            'normalisePath' => [
                'the British spelling' => ['/a/./b', '/a/b'],
            ],
            'normalizePathWin' => [
                'a backslash is a separator' => ['\\a\\..\\b', '/b'],
                'mixed separators' => ['/a\\b/../c', '/a/c'],
                'dots and spaces at the end of a segment' => ['/web.config. ./x .', '/web.config/x'],
                'a stream name' => ['/web.config::$DATA', '/web.config'],
                'a stream name before a trailing slash' => ['/a/file.txt:stream/', '/a/file.txt/'],
                'the colon of a drive stays' => ['c:\\boot.ini', 'c:/boot.ini'],
                'a segment of spaces is none' => ['/a/ /b', '/a/b'],
                'nothing' => ['', ''],
            ],
            'trim' => [
                'both ends' => [" \t\n\r\x0B\x0Ca b \n", 'a b'],
            ],
            'trimLeft' => [
                'the start' => ["\t a ", 'a '],
            ],
            'trimRight' => [
                'the end' => [" a \n", ' a'],
            ],
            'length' => [
                'in bytes' => ['aä', '3'],
                'nothing' => ['', '0'],
            ],
            'md5' => [
                'the raw digest' => ['abc', (string) hex2bin('900150983cd24fb0d6963f7d28e17f72')],
            ],
            'sha1' => [
                'the raw digest' => ['abc', (string) hex2bin('a9993e364706816aba3e25717850c26c9cd0d89d')],
            ],
        ];

        foreach ($cases as $name => $ofTransformation) {
            foreach ($ofTransformation as $label => [$input, $expected]) {
                yield $name . ': ' . $label => [$name, $input, $expected];
            }
        }
    }

    #[DataProvider('cases')]
    public function testTransforms(string $name, string $input, string $expected): void
    {
        $transformation = Transformation::tryFromName($name);

        $this->assertInstanceOf(Transformation::class, $transformation);
        $this->assertSame($expected, $transformation->apply($input));
    }

    public function testEveryTransformationHasACase(): void
    {
        $covered = [];
        foreach (self::cases() as [$name]) {
            $covered[Transformation::tryFromName($name)?->value] = true;
        }

        $this->assertSame([], array_values(array_filter(
            Transformation::cases(),
            static fn(Transformation $transformation): bool => !isset($covered[$transformation->value]),
        )));
    }

    /**
     * The pipeline skips every transformation for a value that holds none of
     * the bytes they touch. That is only right when such a value really
     * stays as it is.
     */
    public function testAValueWithoutATouchedByteStaysAsItIs(): void
    {
        mt_srand(20261125);

        foreach (Transformation::cases() as $transformation) {
            $touchedBytes = $transformation->touchedBytes();
            if ($touchedBytes === null) {
                continue;
            }

            $pattern = '/[' . $touchedBytes . ']/';
            $untouched = [];
            for ($byte = 0; $byte < 256; ++$byte) {
                if (preg_match($pattern, chr($byte)) === 0) {
                    $untouched[] = chr($byte);
                }
            }

            $this->assertNotSame([], $untouched, $transformation->value);

            for ($round = 0; $round < 2000; ++$round) {
                $value = '';
                for ($length = mt_rand(1, 12); $length > 0; --$length) {
                    $value .= $untouched[mt_rand(0, count($untouched) - 1)];
                }

                $this->assertSame($value, $transformation->apply($value), $transformation->value . ' changes ' . bin2hex($value));
            }
        }
    }

    public function testATransformationThatChangesEveryValueNamesNoBytes(): void
    {
        $this->assertNull(Transformation::Length->touchedBytes());
        $this->assertNull(Transformation::Base64Decode->touchedBytes());
        $this->assertSame('0', Transformation::Length->apply(''));
    }

    public function testNamesAreReadWithoutRegardToCase(): void
    {
        $this->assertSame(Transformation::UrlDecodeUni, Transformation::tryFromName('urlDecodeUni'));
        $this->assertSame(Transformation::UrlDecodeUni, Transformation::tryFromName('URLDECODEUNI'));
        $this->assertSame(Transformation::NormalisePathWin, Transformation::tryFromName('normalizePathWin'));
        $this->assertNotInstanceOf(Transformation::class, Transformation::tryFromName('none'));
        $this->assertNotInstanceOf(Transformation::class, Transformation::tryFromName('parityEven7bit'));
    }

    public function testNoneIsSupportedAlthoughItIsNoTransformation(): void
    {
        $this->assertTrue(Transformation::isSupported('none'));
        $this->assertTrue(Transformation::isSupported('None'));
        $this->assertTrue(Transformation::isSupported('lowercase'));
        $this->assertFalse(Transformation::isSupported('parityEven7bit'));
        $this->assertFalse(Transformation::isSupported(''));
    }
}
