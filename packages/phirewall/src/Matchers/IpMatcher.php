<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Matchers;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\Phirewall\Support\IpLookupTable;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Matches requests by client IP against a list of IPs and CIDR ranges.
 *
 * Supports both IPv4 and IPv6 addresses and CIDR notation.
 * Used internally by SafelistSection::ip() and BlocklistSection::ip().
 *
 * When constructed without an explicit resolver the client IP is read through
 * the evaluating Config's resolver at match time ({@see ClientIpResolverAware});
 * standalone use falls back to the raw REMOTE_ADDR peer address.
 *
 * The entries are compiled into an {@see IpLookupTable} on the first match,
 * not at construction: a match then costs one lookup for the address and one
 * per prefix length in use, however many networks the list has. With a
 * compiled-data cache on the evaluating Config ({@see CompiledDataCacheAware})
 * the table loads from a compiled artifact keyed by the content hash of the
 * entry list, so large lists skip the per-request compilation. What remains
 * per request is reading the entries once to check and hash them; a list
 * that lives in a file is cheaper through a matcher that watches the file,
 * like the bad-IP preset's. Unparseable entries are skipped, as before; only
 * non-string entries throw, still at construction.
 */
final class IpMatcher implements RequestMatcherInterface, ClientIpResolverAware, CompiledDataCacheAware
{
    /**
     * Format version of the compiled lookup table. The compiled-cache
     * identifier is keyed on the entry content alone (no source files), so
     * bump this whenever the array form of {@see IpLookupTable} or the way
     * it is built changes, to force existing artifacts to rebuild after an
     * upgrade.
     */
    private const COMPILED_SCHEMA_VERSION = 2;

    /** @var list<string>|null Entries awaiting compilation; null once compiled. */
    private ?array $pendingEntries;

    private ?IpLookupTable $ipLookupTable = null;

    private ?CompiledDataCache $compiledDataCache = null;

    /** @var (callable(ServerRequestInterface): ?string)|null */
    private $ipResolver;

    /**
     * @param list<string> $ipsOrCidrs List of IPs and/or CIDR ranges (e.g. '10.0.0.1', '192.168.0.0/16', '::1')
     * @param (callable(ServerRequestInterface): ?string)|null $ipResolver Explicit IP resolver. When omitted, the evaluating Config's resolver is used (falling back to REMOTE_ADDR).
     */
    public function __construct(array $ipsOrCidrs, ?callable $ipResolver = null)
    {
        $this->ipResolver = $ipResolver;
        foreach ($ipsOrCidrs as $i => $ipOrCidr) {
            if (!is_string($ipOrCidr)) {
                throw new \InvalidArgumentException(sprintf('IP/CIDR entry at index %d must be a string.', $i));
            }
        }

        $this->pendingEntries = array_values($ipsOrCidrs);
    }

    public function useCompiledDataCache(CompiledDataCache $compiledDataCache): void
    {
        $this->compiledDataCache = $compiledDataCache;
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        return $this->matchWithResolver($serverRequest, static function (ServerRequestInterface $serverRequest): ?string {
            $remoteAddr = $serverRequest->getServerParams()['REMOTE_ADDR'] ?? null;
            return is_string($remoteAddr) && $remoteAddr !== '' ? $remoteAddr : null;
        });
    }

    public function matchWithResolver(ServerRequestInterface $serverRequest, callable $defaultResolver): MatchResult
    {
        $ipLookupTable = $this->ipLookupTable ??= $this->compile();

        $resolver = $this->ipResolver ?? $defaultResolver;
        $ip = $resolver($serverRequest);
        if ($ip === null) {
            return MatchResult::noMatch();
        }

        // The table compares IPv4-mapped IPv6 (`::ffff:x.x.x.x`) as IPv4, so a
        // rule written in either notation matches a dual-stack peer presented
        // in either form.
        return $ipLookupTable->contains($ip)
            ? MatchResult::matched('ip_match', ['ip' => $ip])
            : MatchResult::noMatch();
    }

    /**
     * Compile the pending entries into the lookup table on first use, served
     * from the compiled-data cache when one was injected.
     */
    private function compile(): IpLookupTable
    {
        $entries = $this->pendingEntries ?? [];

        if ($this->compiledDataCache instanceof CompiledDataCache) {
            // Content-addressed identifier: a changed list gets a fresh
            // artifact, so no source files need watching.
            $identifier = 'ip-matcher-v' . self::COMPILED_SCHEMA_VERSION . '-' . sha1(implode("\n", $entries));
            $compiled = $this->compiledDataCache->load(
                $identifier,
                [],
                static fn(): array => IpLookupTable::fromEntries($entries)->toArray(),
            );

            // A stale, corrupt, or otherwise unexpected artifact shape must not
            // leave the table empty, silently matching nothing (fail-open for a
            // blocklist). Recompile from the entries we still hold instead.
            $ipLookupTable = IpLookupTable::fromArray($compiled) ?? IpLookupTable::fromEntries($entries);
        } else {
            $ipLookupTable = IpLookupTable::fromEntries($entries);
        }

        // Only now: were the entries let go before the table exists, a failure
        // on the way would leave a list that matches nothing.
        $this->pendingEntries = null;

        return $ipLookupTable;
    }
}
