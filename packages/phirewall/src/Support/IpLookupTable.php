<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Support;

use Flowd\Phirewall\Matchers\Support\CidrMatcher;

/**
 * A list of IP addresses and networks, prepared so that asking whether an
 * address is on it takes the same time for ten entries as for a hundred
 * thousand.
 *
 * Single addresses are kept by their binary form. Networks are kept by
 * address family, then prefix length, then the prefix itself, so a lookup
 * costs one array access for the address and one per prefix length in use,
 * not one comparison per network.
 *
 * Entries compare the way {@see CidrMatcher} compares them: an IPv4 address
 * written as IPv6 (`::ffff:a.b.c.d`) is the IPv4 address, in entries and in
 * the address asked for, and an entry that is neither an address nor a
 * network is left out.
 *
 * The array form ({@see toArray()} / {@see fromArray()}) is plain data for a
 * {@see CompiledDataCache}. Whoever stores it names its own artifact and has
 * to change that name when the form changes.
 */
final readonly class IpLookupTable
{
    /**
     * @param array<array-key, mixed> $exact Canonical binary address => true.
     * @param array<array-key, mixed> $networks Address length in bytes (4 or 16) => prefix length in bits => first bits of the network => true.
     */
    private function __construct(
        private array $exact,
        private array $networks,
    ) {
    }

    /**
     * @param iterable<string> $entries Addresses and networks, e.g. `192.0.2.1`, `198.51.100.0/24`, `2001:db8::/32`.
     */
    public static function fromEntries(iterable $entries): self
    {
        $exact = [];
        $networks = [];
        foreach ($entries as $entry) {
            // Most entries of a long list are single addresses: no need to take them apart.
            if (!str_contains($entry, '/')) {
                $binary = @inet_pton($entry);
                if ($binary !== false) {
                    $exact[CidrMatcher::canonicalizeBinary($binary)] = true;
                }

                continue;
            }

            $compiled = CidrMatcher::compile($entry);
            if ($compiled !== null) {
                $networks[strlen($compiled['network'])][$compiled['bits']][self::prefix($compiled['network'], $compiled['bits'])] = true;
            }
        }

        return new self($exact, $networks);
    }

    /**
     * The table out of its array form, or null when the data does not have
     * that form. Only the outer shape is looked at, so that a table of any
     * size is ready at once; {@see contains()} does not trust the rest either.
     *
     * A caller that gets null must build the table from its entries: an empty
     * table in place of an unreadable one would let every address through.
     *
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): ?self
    {
        $exact = $data['exact'] ?? null;
        $networks = $data['networks'] ?? null;
        if (!is_array($exact) || !is_array($networks)) {
            return null;
        }

        return new self($exact, $networks);
    }

    /**
     * @return array{exact: array<array-key, mixed>, networks: array<array-key, mixed>}
     */
    public function toArray(): array
    {
        return ['exact' => $this->exact, 'networks' => $this->networks];
    }

    /**
     * Whether the address is one of the single addresses or inside one of the
     * networks. A string that is not an IP address is on no list.
     */
    public function contains(string $ip): bool
    {
        $binary = @inet_pton($ip);
        if ($binary === false) {
            return false;
        }

        $binary = CidrMatcher::canonicalizeBinary($binary);
        if (isset($this->exact[$binary])) {
            return true;
        }

        $networks = $this->networks[strlen($binary)] ?? null;
        if (!is_array($networks)) {
            return false;
        }

        foreach ($networks as $bits => $prefixes) {
            if (is_int($bits) && $bits >= 0 && is_array($prefixes) && isset($prefixes[self::prefix($binary, $bits)])) {
                return true;
            }
        }

        return false;
    }

    /**
     * The first $bits bits of an address: whole bytes, and of the next byte
     * only the bits that belong to the prefix.
     */
    private static function prefix(string $binary, int $bits): string
    {
        $wholeBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;
        $prefix = substr($binary, 0, $wholeBytes);
        if ($remainingBits === 0 || !isset($binary[$wholeBytes])) {
            return $prefix;
        }

        return $prefix . chr(ord($binary[$wholeBytes]) & (0xFF00 >> $remainingBits) & 0xFF);
    }
}
