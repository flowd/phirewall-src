<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use Flowd\Phirewall\Matchers\IpMatcher;
use Flowd\Phirewall\Matchers\Support\CidrMatcher;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\Phirewall\Support\IpLookupTable;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class IpLookupTableTest extends TestCase
{
    use TemporaryFiles;

    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    public function testSingleAddressesAndNetworks(): void
    {
        $ipLookupTable = IpLookupTable::fromEntries(['192.0.2.1', '198.51.100.0/24', '2001:db8::1', '2001:db8:1::/48']);

        $this->assertTrue($ipLookupTable->contains('192.0.2.1'));
        $this->assertFalse($ipLookupTable->contains('192.0.2.2'));
        $this->assertTrue($ipLookupTable->contains('198.51.100.0'));
        $this->assertTrue($ipLookupTable->contains('198.51.100.255'));
        $this->assertFalse($ipLookupTable->contains('198.51.101.0'));
        $this->assertTrue($ipLookupTable->contains('2001:db8::1'));
        $this->assertTrue($ipLookupTable->contains('2001:0DB8:0000::0001'));
        $this->assertFalse($ipLookupTable->contains('2001:db8::2'));
        $this->assertTrue($ipLookupTable->contains('2001:db8:1:ffff::1'));
        $this->assertFalse($ipLookupTable->contains('2001:db8:2::1'));
    }

    public function testAPrefixThatEndsInsideAByteComparesOnlyItsBits(): void
    {
        // 10.32.0.0/11 covers 10.32.0.0 - 10.63.255.255.
        $ipLookupTable = IpLookupTable::fromEntries(['10.32.0.0/11', '2001:db8:8000::/33']);

        $this->assertFalse($ipLookupTable->contains('10.31.255.255'));
        $this->assertTrue($ipLookupTable->contains('10.32.0.0'));
        $this->assertTrue($ipLookupTable->contains('10.63.255.255'));
        $this->assertFalse($ipLookupTable->contains('10.64.0.0'));
        $this->assertFalse($ipLookupTable->contains('2001:db8:7fff::1'));
        $this->assertTrue($ipLookupTable->contains('2001:db8:8000::1'));
        $this->assertTrue($ipLookupTable->contains('2001:db8:ffff::1'));
    }

    public function testTheHostPartOfANetworkEntryIsIgnored(): void
    {
        $ipLookupTable = IpLookupTable::fromEntries(['192.0.2.77/24', '10.77.1.1/12']);

        $this->assertTrue($ipLookupTable->contains('192.0.2.1'));
        $this->assertTrue($ipLookupTable->contains('10.64.0.1'));
        $this->assertTrue($ipLookupTable->contains('10.79.255.255'));
        $this->assertFalse($ipLookupTable->contains('10.80.0.0'));
    }

    public function testAPrefixOfZeroCoversItsAddressFamilyOnly(): void
    {
        $ipv4 = IpLookupTable::fromEntries(['0.0.0.0/0']);
        $this->assertTrue($ipv4->contains('203.0.113.9'));
        $this->assertTrue($ipv4->contains('::ffff:203.0.113.9'));
        $this->assertFalse($ipv4->contains('2001:db8::1'));

        $ipv6 = IpLookupTable::fromEntries(['::/0']);
        $this->assertTrue($ipv6->contains('2001:db8::1'));
        $this->assertFalse($ipv6->contains('203.0.113.9'));
        // An IPv4 client is compared in its IPv4 form, also when it arrives as IPv6.
        $this->assertFalse($ipv6->contains('::ffff:203.0.113.9'));
    }

    public function testAWholeAddressAsNetwork(): void
    {
        $ipLookupTable = IpLookupTable::fromEntries(['192.0.2.1/32', '2001:db8::1/128']);

        $this->assertTrue($ipLookupTable->contains('192.0.2.1'));
        $this->assertFalse($ipLookupTable->contains('192.0.2.0'));
        $this->assertTrue($ipLookupTable->contains('2001:db8::1'));
        $this->assertFalse($ipLookupTable->contains('2001:db8::'));
    }

    public function testIpv4WrittenAsIpv6IsIpv4OnBothSides(): void
    {
        $ipLookupTable = IpLookupTable::fromEntries(['::ffff:192.0.2.1', '198.51.100.7', '::ffff:10.0.0.0/104', '172.16.0.0/12']);

        $this->assertTrue($ipLookupTable->contains('192.0.2.1'));
        $this->assertTrue($ipLookupTable->contains('::ffff:192.0.2.1'));
        $this->assertTrue($ipLookupTable->contains('::ffff:198.51.100.7'));
        $this->assertTrue($ipLookupTable->contains('10.200.1.1'));
        $this->assertTrue($ipLookupTable->contains('::ffff:10.200.1.1'));
        $this->assertFalse($ipLookupTable->contains('11.0.0.1'));
        $this->assertTrue($ipLookupTable->contains('::ffff:172.31.255.255'));
        $this->assertFalse($ipLookupTable->contains('::ffff:172.32.0.0'));
    }

    public function testEntriesThatAreNoAddressOrNetworkAreLeftOut(): void
    {
        $ipLookupTable = IpLookupTable::fromEntries(['', 'not-an-ip', '192.0.2.1/33', '192.0.2.0/-1', '192.0.2.0/', '/24', '2001:db8::/129', '999.1.1.1', '203.0.113.7']);

        $this->assertSame(['exact' => [inet_pton('203.0.113.7') => true], 'networks' => []], $ipLookupTable->toArray());
        $this->assertTrue($ipLookupTable->contains('203.0.113.7'));
        $this->assertFalse($ipLookupTable->contains('192.0.2.1'));
    }

    public function testAStringThatIsNoAddressIsOnNoList(): void
    {
        $ipLookupTable = IpLookupTable::fromEntries(['0.0.0.0/0', '::/0']);

        $this->assertFalse($ipLookupTable->contains(''));
        $this->assertFalse($ipLookupTable->contains('unknown'));
        $this->assertFalse($ipLookupTable->contains('192.0.2.1:8080'));
        $this->assertFalse($ipLookupTable->contains('192.0.2.1/32'));
    }

    public function testAnEmptyTableContainsNothing(): void
    {
        $ipLookupTable = IpLookupTable::fromEntries([]);

        $this->assertSame(['exact' => [], 'networks' => []], $ipLookupTable->toArray());
        $this->assertFalse($ipLookupTable->contains('192.0.2.1'));
        $this->assertFalse($ipLookupTable->contains('::1'));
    }

    public function testNetworksAreGroupedByFamilyAndPrefixLength(): void
    {
        $ipLookupTable = IpLookupTable::fromEntries(['10.1.0.0/16', '10.2.0.0/16', '10.2.99.0/16', '192.0.2.128/25', '2001:db8::/32']);

        $this->assertSame([
            'exact' => [],
            'networks' => [
                4 => [16 => ["\x0a\x01" => true, "\x0a\x02" => true], 25 => ["\xc0\x00\x02\x80" => true]],
                16 => [32 => ["\x20\x01\x0d\xb8" => true]],
            ],
        ], $ipLookupTable->toArray());
    }

    /**
     * The array form has to survive being written as PHP code and read back,
     * which is what the compiled-data cache does with it. Binary keys are the
     * delicate part: bytes that look like a number, quotes, backslashes and
     * NUL bytes.
     */
    public function testTheArrayFormSurvivesTheCompiledDataCache(): void
    {
        $entries = ['49.50.51.52', '0.0.0.0', '39.92.39.92', '48.0.0.0/8', '49.50.0.0/16', '0.39.92.0/24', '::', '::/128', '3132:3334::/32', '127.0.0.1'];
        $ipLookupTable = IpLookupTable::fromEntries($entries);

        $compiledDataCache = new CompiledDataCache($this->temporaryPath());
        $compiledDataCache->load('table', [], static fn(): array => $ipLookupTable->toArray());
        CompiledDataCache::clearProcessCache();

        $restored = IpLookupTable::fromArray($compiledDataCache->load('table', [], static fn(): array => []));

        $this->assertInstanceOf(IpLookupTable::class, $restored);
        $this->assertSame($ipLookupTable->toArray(), $restored->toArray());
        foreach (['49.50.51.52', '49.50.51.53', '0.0.0.0', '0.0.0.1', '39.92.39.92', '48.255.0.1', '47.0.0.1', '49.50.200.1', '0.39.92.200', '0.39.93.0', '::', '::1', '3132:3334:ffff::1', '3132:3335::1', '127.0.0.1'] as $ip) {
            $this->assertSame($ipLookupTable->contains($ip), $restored->contains($ip), $ip);
        }
    }

    public function testDataThatIsNoTableIsRefused(): void
    {
        $this->assertNull(IpLookupTable::fromArray([]));
        $this->assertNull(IpLookupTable::fromArray(['exact' => []]));
        $this->assertNull(IpLookupTable::fromArray(['networks' => []]));
        $this->assertNull(IpLookupTable::fromArray(['exact' => 'x', 'networks' => []]));
        $this->assertNull(IpLookupTable::fromArray(['exact' => [], 'networks' => null]));
        // The form of the lookup tables before this class.
        $this->assertNull(IpLookupTable::fromArray(['cidrs' => [], 'exact' => []]));
    }

    public function testATableWithUnexpectedInnerDataMatchesWithoutFailing(): void
    {
        $ipLookupTable = IpLookupTable::fromArray([
            'exact' => [inet_pton('192.0.2.1') => true],
            'networks' => [
                4 => [
                    'x' => ['' => true],
                    // Would be "all but the last byte" if a negative length were used.
                    -8 => ["\xcb\x00\x71" => true],
                    8 => 'nothing',
                    24 => ["\xc6\x33\x64" => true],
                    // More bits than an IPv4 address has.
                    35 => ["\x0a\x00\x00" => true],
                ],
                16 => 'nothing',
            ],
        ]);
        $this->assertInstanceOf(IpLookupTable::class, $ipLookupTable);

        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });
        try {
            $this->assertTrue($ipLookupTable->contains('192.0.2.1'));
            $this->assertTrue($ipLookupTable->contains('198.51.100.9'));
            $this->assertFalse($ipLookupTable->contains('198.51.101.9'));
            $this->assertFalse($ipLookupTable->contains('203.0.113.1'));
            $this->assertFalse($ipLookupTable->contains('10.0.0.1'));
            $this->assertFalse($ipLookupTable->contains('2001:db8::1'));
        } finally {
            restore_error_handler();
        }
    }

    /**
     * The table has to decide exactly like comparing an address with every
     * entry in turn, which is how the list was matched before.
     *
     * @param list<string> $entries
     * @param list<string> $addresses
     */
    #[DataProvider('generatedLists')]
    public function testDecidesLikeComparingWithEveryEntry(array $entries, array $addresses): void
    {
        $ipLookupTable = IpLookupTable::fromEntries($entries);
        $restored = IpLookupTable::fromArray($ipLookupTable->toArray());
        $this->assertInstanceOf(IpLookupTable::class, $restored);
        $ipMatcher = new IpMatcher($entries);

        $matches = 0;
        foreach ($addresses as $address) {
            $expected = $this->entryByEntry($entries, $address);
            $matches += (int) $expected;

            $this->assertSame($expected, $ipLookupTable->contains($address), $address);
            $this->assertSame($expected, $restored->contains($address), $address);
            $this->assertSame(
                $expected,
                $ipMatcher->match(new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => $address]))->isMatch(),
                $address,
            );
        }

        // Both answers have to occur, or the comparison says nothing.
        $this->assertGreaterThan(0, $matches);
        $this->assertLessThan(count($addresses), $matches);
    }

    /**
     * @return iterable<string, array{list<string>, list<string>}>
     */
    public static function generatedLists(): iterable
    {
        foreach ([1, 2, 3, 4, 5, 6] as $seed) {
            mt_srand($seed);

            $entries = [];
            $addresses = [];
            for ($i = 0; $i < 150; ++$i) {
                $ipv4 = self::randomIpv4();
                $ipv6 = self::randomIpv6();
                $bits4 = mt_rand(0, 32);
                $bits6 = mt_rand(0, 128);

                $entries[] = match ($i % 10) {
                    0 => $ipv4,
                    1 => $ipv6,
                    2 => '::ffff:' . $ipv4,
                    3 => $ipv4 . '/' . max(8, $bits4),
                    4 => $ipv6 . '/' . max(16, $bits6),
                    // Inside and across the range of IPv4 written as IPv6.
                    5 => '::ffff:' . $ipv4 . '/' . mt_rand(90, 128),
                    // Prefix lengths as they should not, but can, be written.
                    6 => $ipv4 . '/' . [' 24', '24.9', '1e1', '+16', '024', '33', '-1', '', 'x', '24 '][mt_rand(0, 9)],
                    7 => ['', 'garbage', '1.2.3', '1.2.3.4.5', ':::', '1.2.3.4/24/8', '/', ' ' . $ipv4, $ipv4 . ' '][mt_rand(0, 8)],
                    8 => strtoupper($ipv6) . '/' . [32, 48, 56, 64, 127][mt_rand(0, 4)],
                    default => $ipv4 . '/' . [8, 12, 16, 20, 24, 28, 30, 31, 32][mt_rand(0, 8)],
                };

                // Around every generated address: itself, its neighbours, the edges of
                // its networks, and each of them the way a dual-stack server presents it.
                foreach ([$ipv4, self::offsetIpv4($ipv4, 1), self::offsetIpv4($ipv4, -1), self::edgeIpv4($ipv4, $bits4, false), self::edgeIpv4($ipv4, $bits4, true), self::offsetIpv4(self::edgeIpv4($ipv4, $bits4, true), 1)] as $address) {
                    $addresses[] = $address;
                    $addresses[] = '::ffff:' . $address;
                }

                $addresses[] = $ipv6;
                $addresses[] = self::flipLastBit($ipv6);
                $addresses[] = self::randomIpv4();
                $addresses[] = self::randomIpv6();
            }

            $addresses[] = 'not-an-address';
            $addresses[] = '';

            yield 'seed ' . $seed => [$entries, $addresses];
        }
    }

    /**
     * The way a list was matched before the lookup table: single addresses by
     * their canonical binary form, networks one after the other.
     *
     * @param list<string> $entries
     */
    private function entryByEntry(array $entries, string $address): bool
    {
        $binary = @inet_pton($address);
        if ($binary === false) {
            return false;
        }

        $binary = CidrMatcher::canonicalizeBinary($binary);
        foreach ($entries as $entry) {
            if (str_contains($entry, '/')) {
                $compiled = CidrMatcher::compile($entry);
                if ($compiled !== null && CidrMatcher::matches($binary, $compiled)) {
                    return true;
                }

                continue;
            }

            $entryBinary = @inet_pton($entry);
            if ($entryBinary !== false && CidrMatcher::canonicalizeBinary($entryBinary) === $binary) {
                return true;
            }
        }

        return false;
    }

    private static function randomIpv4(): string
    {
        // A small range, so that generated networks and addresses meet.
        return sprintf('%d.%d.%d.%d', mt_rand(10, 13), mt_rand(0, 3), mt_rand(0, 255), mt_rand(0, 255));
    }

    private static function randomIpv6(): string
    {
        return sprintf('2001:db8:%x:%x::%x', mt_rand(0, 3), mt_rand(0, 0xffff), mt_rand(0, 0xffff));
    }

    private static function offsetIpv4(string $ip, int $offset): string
    {
        return (string) long2ip(((int) ip2long($ip) + $offset) & 0xFFFFFFFF);
    }

    /**
     * First or last address of the network of that prefix length around an address.
     */
    private static function edgeIpv4(string $ip, int $bits, bool $last): string
    {
        $mask = $bits === 0 ? 0 : (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;
        $first = (int) ip2long($ip) & $mask;

        return (string) long2ip($last ? $first | (~$mask & 0xFFFFFFFF) : $first);
    }

    private static function flipLastBit(string $ipv6): string
    {
        $binary = (string) inet_pton($ipv6);
        $binary[15] = chr(ord($binary[15]) ^ 1);

        return (string) inet_ntop($binary);
    }
}
