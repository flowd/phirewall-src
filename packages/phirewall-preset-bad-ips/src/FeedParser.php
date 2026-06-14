<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps;

/**
 * Normalizes a raw IP feed into a deduplicated, address-ordered list of IPv4 addresses.
 *
 * Accepts the formats stamparm/ipsum ships: bare `IP` per line (levels/N.txt) and
 * `IP<whitespace>count` (ipsum.txt). Blank lines and `#` comments are skipped, and
 * only syntactically valid IPv4 addresses are kept.
 */
final class FeedParser
{
    /**
     * @return list<string>
     */
    public static function parse(string $feedContent): array
    {
        $unique = [];
        foreach (preg_split('/\R/', $feedContent) ?: [] as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            if (str_starts_with($line, '#')) {
                continue;
            }

            $candidate = preg_split('/\s+/', $line)[0] ?? '';
            if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                $unique[$candidate] = true;
            }
        }

        $addresses = array_keys($unique);
        usort($addresses, static fn(string $a, string $b): int => strcmp((string) inet_pton($a), (string) inet_pton($b)));

        return $addresses;
    }
}
