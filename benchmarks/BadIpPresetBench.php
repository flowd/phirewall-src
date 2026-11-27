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
use Flowd\PhirewallPresetBadIps\Presets;
use Psr\Http\Message\ServerRequestInterface;
use Tally\Attribute\Before;
use Tally\Attribute\Expected;
use Tally\Attribute\Warmup;
use Tally\Meter;
use Tally\ScratchDirectory;

/**
 * The bad-IP preset with a list of 20,000 addresses, about the size of the
 * shipped snapshot. The list is generated: the snapshot is refreshed regularly
 * and would move the numbers with every refresh.
 */
#[Warmup(2)]
final class BadIpPresetBench
{
    private const ADDRESSES = 20_000;

    private Firewall $firewall;

    /** @var list<ServerRequestInterface> */
    private array $unlistedClients;

    /** @var list<ServerRequestInterface> */
    private array $listedClients;

    /** Which of the unseen requests the next call takes, see {@see Requests::unseen()}. */
    private int $call = 0;

    public function __construct(private readonly Meter $meter, private readonly ScratchDirectory $scratchDirectory)
    {
    }

    #[Before]
    public function writeListAndBuildFirewall(): void
    {
        PhpFpm::requireOpcache();

        $addresses = Networks::scatteredAddresses(self::ADDRESSES);
        // The native process of this case has written the file already: keep it, so
        // the compiled artifact made from it stays valid.
        if (!is_file($this->dataFile())) {
            file_put_contents($this->dataFile(), "# Generated for the benchmarks.\n" . implode("\n", $addresses) . "\n");
        }

        $listedAddress = $addresses[self::ADDRESSES - 1];
        $this->unlistedClients = Requests::unseen(Requests::pageView(...));
        $this->listedClients = Requests::unseen(static fn(): ServerRequestInterface => Requests::pageView($listedAddress));
        $this->firewall = new Firewall($this->config(null));

        Outcome::mustPass($this->firewall->decide(Requests::pageView()));
        Outcome::mustBlock($this->firewall->decide(Requests::pageView($listedAddress)));
        Outcome::mustPass((new Firewall($this->config($this->compiledDataCache())))->decide(Requests::pageView()));
    }

    #[Expected(instructions: '28.15K', cycles: '39.06K', memory: '1.008KiB')]
    public function benchUnlistedClientInAWorker(): void
    {
        $this->firewall->decide($this->unlistedClients[$this->call++]);
    }

    #[Expected(instructions: '25.27K', cycles: '36.60K', memory: '1.617KiB')]
    public function benchListedClientInAWorker(): void
    {
        $this->firewall->decide($this->listedClients[$this->call++]);
    }

    /** The list is read and parsed on every request. */
    #[Expected(instructions: '55.77M', cycles: '58.87M', memory: '3.798MiB')]
    public function benchPerRequestWithoutCache(): void
    {
        $this->meter->exclude(PhpFpm::startRequest(...));

        (new Firewall($this->config(null)))->decide($this->unlistedClients[$this->call++]);
    }

    /** The parsed list comes from the compiled-data cache. */
    #[Expected(instructions: '141.8K', cycles: '194.4K', memory: '6.398KiB')]
    public function benchPerRequestWithCache(): void
    {
        $this->meter->exclude(PhpFpm::startRequest(...));

        (new Firewall($this->config($this->compiledDataCache())))->decide($this->unlistedClients[$this->call++]);
    }

    private function config(?CompiledDataCache $compiledDataCache): Config
    {
        return (new Config(new InMemoryCache()))
            ->setCompiledDataCache($compiledDataCache)
            ->with(Presets::blocklist($this->dataFile()));
    }

    private function dataFile(): string
    {
        return $this->scratchDirectory->path() . '/bad-ips.data';
    }

    private function compiledDataCache(): CompiledDataCache
    {
        return new CompiledDataCache($this->scratchDirectory->path() . '/compiled');
    }
}
