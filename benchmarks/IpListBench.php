<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallBenchmarks\Support\Networks;
use Flowd\PhirewallBenchmarks\Support\Outcome;
use Flowd\PhirewallBenchmarks\Support\PhpFpm;
use Flowd\PhirewallBenchmarks\Support\Requests;
use Psr\Http\Message\ServerRequestInterface;
use Tally\Attribute\Before;
use Tally\Attribute\Expected;
use Tally\Attribute\Warmup;
use Tally\Meter;
use Tally\ScratchDirectory;

/**
 * An IP blocklist of 1,000 networks given in the configuration.
 */
#[Warmup(2)]
final class IpListBench
{
    private const NETWORKS = 1_000;

    private Firewall $firewall;

    private ServerRequestInterface $serverRequest;

    /** @var list<string> */
    private array $networks;

    public function __construct(private readonly Meter $meter, private readonly ScratchDirectory $scratchDirectory)
    {
    }

    #[Before]
    public function buildFirewall(): void
    {
        PhpFpm::requireOpcache();

        $this->networks = Networks::privateNetworks(self::NETWORKS);
        $this->serverRequest = Requests::pageView();
        $this->firewall = new Firewall($this->config(null));

        Outcome::mustPass($this->firewall->decide($this->serverRequest));
        Outcome::mustPass((new Firewall($this->config($this->compiledDataCache())))->decide($this->serverRequest));
    }

    #[Expected(instructions: '2.016M', cycles: '2.072M', memory: '1.008KiB')]
    public function benchUnlistedClientInAWorker(): void
    {
        $this->firewall->decide($this->serverRequest);
    }

    /** The list is parsed on every request. */
    #[Expected(instructions: '6.364M', cycles: '6.666M', memory: '422.2KiB')]
    public function benchPerRequestWithoutCache(): void
    {
        $this->meter->exclude(PhpFpm::startRequest(...));

        (new Firewall($this->config(null)))->decide($this->serverRequest);
    }

    /** The parsed list comes from the compiled-data cache. */
    #[Expected(instructions: '2.588M', cycles: '2.702M', memory: '19.59KiB')]
    public function benchPerRequestWithCache(): void
    {
        $this->meter->exclude(PhpFpm::startRequest(...));

        (new Firewall($this->config($this->compiledDataCache())))->decide($this->serverRequest);
    }

    private function config(?CompiledDataCache $compiledDataCache): Config
    {
        $config = (new Config(new InMemoryCache()))->setCompiledDataCache($compiledDataCache);
        $config->blocklists->ip('networks', $this->networks);

        return $config;
    }

    private function compiledDataCache(): CompiledDataCache
    {
        return new CompiledDataCache($this->scratchDirectory->path() . '/compiled');
    }
}
