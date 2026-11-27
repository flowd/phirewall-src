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

    /** @var list<ServerRequestInterface> */
    private array $pageViews;

    /** Which of the unseen requests the next call takes, see {@see Requests::unseen()}. */
    private int $call = 0;

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
        $this->pageViews = Requests::unseen(Requests::pageView(...));
        $this->firewall = new Firewall($this->config(null));

        Outcome::mustPass($this->firewall->decide(Requests::pageView()));
        Outcome::mustPass((new Firewall($this->config($this->compiledDataCache())))->decide(Requests::pageView()));
    }

    #[Expected(instructions: '29.13K', cycles: '41.24K', memory: '1.047KiB')]
    public function benchUnlistedClientInAWorker(): void
    {
        $this->firewall->decide($this->pageViews[$this->call++]);
    }

    /** The list is parsed on every request. */
    #[Expected(instructions: '6.025M', cycles: '6.431M', memory: '84.36KiB')]
    public function benchPerRequestWithoutCache(): void
    {
        $this->meter->exclude(PhpFpm::startRequest(...));

        (new Firewall($this->config(null)))->decide($this->pageViews[$this->call++]);
    }

    /** The parsed list comes from the compiled-data cache. */
    #[Expected(instructions: '641.3K', cycles: '718.7K', memory: '19.58KiB')]
    public function benchPerRequestWithCache(): void
    {
        $this->meter->exclude(PhpFpm::startRequest(...));

        (new Firewall($this->config($this->compiledDataCache())))->decide($this->pageViews[$this->call++]);
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
