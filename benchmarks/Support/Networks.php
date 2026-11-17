<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks\Support;

/**
 * Address lists of a given size that are the same on every run.
 */
final class Networks
{
    private function __construct()
    {
    }

    /**
     * /24 networks from 10.0.0.0/8, which never contain Requests::CLIENT_IP.
     *
     * @return list<string>
     */
    public static function privateNetworks(int $count): array
    {
        $networks = [];
        for ($i = 0; $i < $count; ++$i) {
            $networks[] = sprintf('10.%d.%d.0/24', intdiv($i, 256), $i % 256);
        }

        return $networks;
    }

    /**
     * Single addresses spread over the IPv4 space, in the format of the bad-IP
     * snapshot. The shipped snapshot is refreshed regularly, so its size is not
     * a base for expected numbers.
     *
     * @return list<string>
     */
    public static function scatteredAddresses(int $count): array
    {
        $addresses = [];
        $state = 20261117;
        while (count($addresses) < $count) {
            // Linear congruential generator: the same sequence on every platform.
            $state = ($state * 1103515245 + 12345) % 2147483648;
            $number = ($state * 2) % 4294967296;
            // Not long2ip(): it may return false before PHP 8.4.
            $address = sprintf('%d.%d.%d.%d', $number >> 24, ($number >> 16) & 255, ($number >> 8) & 255, $number & 255);
            // Leave out what a request of the benchmarks could come from.
            if (str_starts_with($address, '203.0.113.')) {
                continue;
            }

            if (str_starts_with($address, '0.')) {
                continue;
            }

            $addresses[$address] = $address;
        }

        return array_values($addresses);
    }
}
