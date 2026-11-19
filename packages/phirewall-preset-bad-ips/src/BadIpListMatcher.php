<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Matchers\ClientIpResolverAware;
use Flowd\Phirewall\Matchers\CompiledDataCacheAware;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\Phirewall\Support\IpLookupTable;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Matches the client IP against the bundled bad-IP snapshot, loading lazily.
 *
 * The snapshot is read on the first evaluated request, not at construction,
 * and turned into an {@see IpLookupTable}: a match is one lookup, however
 * long the list is. When the evaluating Config carries a
 * {@see CompiledDataCache} the table comes ready from one compiled artifact,
 * so a request neither reads the snapshot nor walks its addresses. The
 * artifact is rebuilt when the data file's modification time changes and is
 * only used for a file of the size it was made from. The client IP resolves
 * through the evaluating Config's resolver ({@see ClientIpResolverAware}),
 * falling back to REMOTE_ADDR.
 */
final class BadIpListMatcher implements RequestMatcherInterface, ClientIpResolverAware, CompiledDataCacheAware
{
    /**
     * Format version of the compiled artifact. Bump whenever its shape, the
     * array form of {@see IpLookupTable} or the way the snapshot is parsed
     * changes, so an upgrade rebuilds stale artifacts.
     */
    private const COMPILED_SCHEMA_VERSION = 2;

    private ?IpLookupTable $ipLookupTable = null;

    private ?CompiledDataCache $compiledDataCache = null;

    private function __construct(private readonly ?string $dataFile)
    {
    }

    public static function fromDataFile(?string $dataFile = null): self
    {
        return new self($dataFile);
    }

    public function useCompiledDataCache(CompiledDataCache $compiledDataCache): void
    {
        $this->compiledDataCache = $compiledDataCache;
        // Drop an already-loaded table so a cache injected after a first
        // match still takes effect on the next one, keeping injection
        // order-independent.
        $this->ipLookupTable = null;
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        return $this->matchWithResolver($serverRequest, static function (ServerRequestInterface $serverRequest): ?string {
            $remoteAddress = $serverRequest->getServerParams()['REMOTE_ADDR'] ?? null;

            return is_string($remoteAddress) && $remoteAddress !== '' ? $remoteAddress : null;
        });
    }

    public function matchWithResolver(ServerRequestInterface $serverRequest, callable $defaultResolver): MatchResult
    {
        // Loaded before the address is resolved: a missing snapshot is reported
        // on the first request, whoever sends it.
        $ipLookupTable = $this->ipLookupTable ??= $this->load();

        $ip = $defaultResolver($serverRequest);
        if (!is_string($ip)) {
            return MatchResult::noMatch();
        }

        return $ipLookupTable->contains($ip)
            ? MatchResult::matched('ip_match', ['ip' => $ip])
            : MatchResult::noMatch();
    }

    /**
     * @throws \RuntimeException When the data file is missing or unreadable.
     */
    private function load(): IpLookupTable
    {
        $dataFile = $this->dataFile ?? BadIpList::defaultDataFile();
        // PHP remembers time and size of the file it was asked about last. In a
        // long-running worker that can be this one, as it was before it changed.
        clearstatcache();
        $size = is_file($dataFile) ? filesize($dataFile) : false;
        if (!$this->compiledDataCache instanceof CompiledDataCache || $size === false) {
            return IpLookupTable::fromEntries(BadIpList::load($dataFile));
        }

        // The whole hash of the path: two snapshots must never share an artifact.
        $identifier = 'bad-ips-v' . self::COMPILED_SCHEMA_VERSION . '-' . hash('sha256', $dataFile);
        $builder = static function () use ($dataFile): array {
            $content = BadIpList::read($dataFile);

            return ['size' => strlen($content)] + IpLookupTable::fromEntries(BadIpList::parse($content))->toArray();
        };

        // An artifact of an unexpected shape, or one made from a file of another
        // size, would match nothing or the wrong addresses, which for a blocklist
        // means letting someone through. The cache would keep it as long as the
        // snapshot keeps its modification time, so it is made anew once; if that
        // does not help either, the snapshot is read without the cache.
        $ipLookupTable = null;
        try {
            $ipLookupTable = $this->tableOf($this->compiledDataCache->load($identifier, [$dataFile], $builder), $size);
            if (!$ipLookupTable instanceof IpLookupTable) {
                $this->compiledDataCache->forget($identifier);
                $ipLookupTable = $this->tableOf($this->compiledDataCache->load($identifier, [$dataFile], $builder), $size);
            }
        } catch (\Throwable) {
            // A cache that cannot be used must not leave the snapshot unused.
        }

        return $ipLookupTable ?? IpLookupTable::fromEntries(BadIpList::load($dataFile));
    }

    /**
     * @param array<mixed> $compiled
     */
    private function tableOf(array $compiled, int $size): ?IpLookupTable
    {
        return ($compiled['size'] ?? null) === $size ? IpLookupTable::fromArray($compiled) : null;
    }
}
