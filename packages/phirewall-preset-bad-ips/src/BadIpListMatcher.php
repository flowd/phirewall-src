<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Matchers\ClientIpResolverAware;
use Flowd\Phirewall\Matchers\CompiledDataCacheAware;
use Flowd\Phirewall\Matchers\IpMatcher;
use Flowd\Phirewall\Support\CompiledDataCache;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Matches the client IP against the bundled bad-IP snapshot, loading lazily.
 *
 * The snapshot is read on the first evaluated request, not at construction.
 * When the evaluating Config carries a {@see CompiledDataCache} the address
 * list loads from a compiled artifact invalidated by the data file's mtime,
 * and the inner {@see IpMatcher} serves its binary lookup tables from its own
 * content-addressed artifact - so a warm setup parses and compiles nothing
 * per request. The client IP resolves through the evaluating Config's
 * resolver ({@see ClientIpResolverAware}), falling back to REMOTE_ADDR.
 */
final class BadIpListMatcher implements RequestMatcherInterface, ClientIpResolverAware, CompiledDataCacheAware
{
    /**
     * Format version of the cached address list. Bump whenever the parsed
     * list shape changes, so an upgrade rebuilds stale artifacts. (The inner
     * IpMatcher versions its own compiled tables independently.)
     */
    private const COMPILED_SCHEMA_VERSION = 1;

    private ?IpMatcher $ipMatcher = null;

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
        // Drop an already-built inner matcher so a cache injected after a first
        // match still takes effect on the next one, keeping injection
        // order-independent.
        $this->ipMatcher = null;
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        return $this->ipMatcher()->match($serverRequest);
    }

    public function matchWithResolver(ServerRequestInterface $serverRequest, callable $defaultResolver): MatchResult
    {
        return $this->ipMatcher()->matchWithResolver($serverRequest, $defaultResolver);
    }

    private function ipMatcher(): IpMatcher
    {
        if ($this->ipMatcher instanceof IpMatcher) {
            return $this->ipMatcher;
        }

        $ipMatcher = new IpMatcher($this->loadAddresses());
        if ($this->compiledDataCache instanceof CompiledDataCache) {
            $ipMatcher->useCompiledDataCache($this->compiledDataCache);
        }

        return $this->ipMatcher = $ipMatcher;
    }

    /**
     * @return list<string>
     */
    private function loadAddresses(): array
    {
        $dataFile = $this->dataFile ?? BadIpList::defaultDataFile();

        if (!$this->compiledDataCache instanceof CompiledDataCache) {
            return BadIpList::load($dataFile);
        }

        $identifier = 'bad-ips-v' . self::COMPILED_SCHEMA_VERSION . '-' . substr(sha1($dataFile), 0, 12);
        $cached = $this->compiledDataCache->load(
            $identifier,
            [$dataFile],
            static fn(): array => BadIpList::load($dataFile),
        );

        $addresses = $this->asStringList($cached);
        if ($addresses === null) {
            // A stale or corrupt artifact of an unexpected shape: parse the
            // source directly rather than feeding untyped data to IpMatcher.
            return BadIpList::load($dataFile);
        }

        return $addresses;
    }

    /**
     * Narrow a loaded artifact to a list of address strings, or null when its
     * shape is unexpected.
     *
     * @param array<mixed> $value
     * @return list<string>|null
     */
    private function asStringList(array $value): ?array
    {
        if (!array_is_list($value)) {
            return null;
        }

        $addresses = [];
        foreach ($value as $item) {
            if (!is_string($item)) {
                return null;
            }

            $addresses[] = $item;
        }

        return $addresses;
    }
}
