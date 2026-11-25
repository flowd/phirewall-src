<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine\Transformation;

use Flowd\PhirewallPresetOwaspCrs\Engine\Transformation\Utf8;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Utf8Test extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function bytes(): iterable
    {
        yield 'ASCII stays' => ['plain', 'plain'];
        yield 'well-formed UTF-8 stays' => ['Grüße 你好 😀', 'Grüße 你好 😀'];
        yield 'a byte of ISO 8859-1' => ["M\xFCller", 'Müller'];
        yield 'a continuation byte by itself' => ["a\xA0b", "a\u{A0}b"];
        yield 'next to a well-formed character' => ["\xFCü\xFC", 'üüü'];
        yield 'a lead byte without its continuation' => ["\xC3(", 'Ã('];
        yield 'a sequence that is cut off' => ["\xE4\xBD", "\u{E4}\u{BD}"];
        yield 'an overlong encoding' => ["\xC0\xAF", "\u{C0}\u{AF}"];
        yield 'a surrogate' => ["\xED\xA0\x80", "\u{ED}\u{A0}\u{80}"];
        yield 'beyond Unicode' => ["\xF4\x90\x80\x80", "\u{F4}\u{90}\u{80}\u{80}"];
        yield 'every byte above ASCII' => ["\xFF\xFE\x80", "\u{FF}\u{FE}\u{80}"];
        yield 'nothing' => ['', ''];
    }

    #[DataProvider('bytes')]
    public function testReadsBytesThatAreNotUtf8AsTheCharacterOfTheirNumber(string $bytes, string $expected): void
    {
        $this->assertSame($expected, Utf8::fromBytes($bytes));
        $this->assertTrue(Utf8::isWellFormed(Utf8::fromBytes($bytes)));
    }

    public function testEncodesCodePoints(): void
    {
        $this->assertSame('A', Utf8::encode(0x41));
        $this->assertSame('ü', Utf8::encode(0xFC));
        $this->assertSame('你', Utf8::encode(0x4F60));
        $this->assertSame('😀', Utf8::encode(0x1F600));
        $this->assertSame("\u{FFFD}", Utf8::encode(0xD800));
        $this->assertSame("\u{FFFD}", Utf8::encode(0x110000));
        $this->assertSame("\u{FFFD}", Utf8::encode(-1));
    }

    public function testReadsTheCodePointOfASequence(): void
    {
        $this->assertSame(0xFC, Utf8::codePoint('ü'));
        $this->assertSame(0x4F60, Utf8::codePoint('你'));
        $this->assertSame(0x1F600, Utf8::codePoint('😀'));
    }
}
