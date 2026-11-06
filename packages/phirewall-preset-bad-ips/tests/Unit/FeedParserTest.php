<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\Unit;

use Flowd\PhirewallPresetBadIps\FeedParser;
use PHPUnit\Framework\TestCase;

final class FeedParserTest extends TestCase
{
    public function testParsesBareAndCountSuffixedLinesSkippingCommentsAndBlanks(): void
    {
        $feed = "# ipsum snapshot\n203.0.113.7\n\n10.0.0.1\t9\n198.51.100.23 3\n# trailing comment\n";

        $this->assertSame(['10.0.0.1', '198.51.100.23', '203.0.113.7'], FeedParser::parse($feed));
    }

    public function testDeduplicatesAndOrdersByAddress(): void
    {
        $feed = "203.0.113.7\n192.0.2.1\n203.0.113.7\n192.0.2.1\n";

        $this->assertSame(['192.0.2.1', '203.0.113.7'], FeedParser::parse($feed));
    }

    public function testDropsInvalidAndNonIpv4Tokens(): void
    {
        $feed = "not-an-ip\n999.999.999.999\n2001:db8::1\n192.0.2.10\n";

        $this->assertSame(['192.0.2.10'], FeedParser::parse($feed));
    }

    public function testEmptyFeedYieldsEmptyList(): void
    {
        $this->assertSame([], FeedParser::parse("# only comments\n\n"));
    }
}
