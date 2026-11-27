<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Matchers\Support;

use Flowd\Phirewall\Matchers\Support\Readings;
use PHPUnit\Framework\TestCase;

final class ReadingsTest extends TestCase
{
    public function testARestrictiveTestNeedsOneReadingToMatch(): void
    {
        $isAdmin = static fn(string $reading): bool => $reading === 'admin';

        $this->assertTrue(Readings::match(['admin'], $isAdmin, false));
        $this->assertTrue(Readings::match(['guest', 'admin'], $isAdmin, false));
        $this->assertFalse(Readings::match(['guest', 'user'], $isAdmin, false));
        $this->assertFalse(Readings::match([], $isAdmin, false));
    }

    public function testAPermissiveTestNeedsEveryReadingToMatch(): void
    {
        $isAdmin = static fn(string $reading): bool => $reading === 'admin';

        $this->assertTrue(Readings::match(['admin'], $isAdmin, true));
        $this->assertTrue(Readings::match(['admin', 'admin'], $isAdmin, true));
        $this->assertFalse(Readings::match(['admin', 'guest'], $isAdmin, true));
        $this->assertFalse(Readings::match(['guest', 'admin'], $isAdmin, true));
        $this->assertFalse(Readings::match([], $isAdmin, true));
    }

    public function testTheTestStopsAtTheReadingThatDecides(): void
    {
        $seen = [];
        $record = static function (string $reading) use (&$seen): bool {
            $seen[] = $reading;

            return $reading === 'b';
        };

        Readings::match(['a', 'b', 'c'], $record, false);
        $this->assertSame(['a', 'b'], $seen);

        $seen = [];
        Readings::match(['b', 'a', 'c'], $record, true);
        $this->assertSame(['b', 'a'], $seen);
    }

    public function testTheFirstReadingThatIsNotEmpty(): void
    {
        $this->assertSame('a', Readings::first(['a', 'b']));
        $this->assertSame('b', Readings::first(['', 'b']));
        $this->assertNull(Readings::first(['', '']));
        $this->assertNull(Readings::first([]));
    }
}
