<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallBenchmarks\Support\Outcome;
use Flowd\PhirewallBenchmarks\Support\PhpFpm;
use Flowd\PhirewallBenchmarks\Support\Requests;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Psr\Http\Message\ServerRequestInterface;
use Tally\Attribute\Before;
use Tally\Attribute\Expected;
use Tally\Attribute\Warmup;
use Tally\Meter;
use Tally\ScratchDirectory;

/**
 * The OWASP CRS preset at paranoia level 1 with the shipped rules. An update of
 * the rules changes what a request costs, so it usually needs new numbers here.
 */
#[Warmup(2)]
final class CrsPresetBench
{
    private Firewall $firewall;

    private ServerRequestInterface $pageView;

    private ServerRequestInterface $formPost;

    private ServerRequestInterface $sqlInjection;

    public function __construct(private readonly Meter $meter, private readonly ScratchDirectory $scratchDirectory)
    {
    }

    #[Before]
    public function buildFirewall(): void
    {
        PhpFpm::requireOpcache();

        $this->pageView = Requests::pageView();
        $this->formPost = Requests::formPost();
        $this->sqlInjection = Requests::sqlInjection();
        $this->firewall = new Firewall($this->config($this->compiledDataCache()));

        Outcome::mustPass($this->firewall->decide($this->pageView));
        Outcome::mustPass($this->firewall->decide($this->formPost));
        Outcome::mustBlock($this->firewall->decide($this->sqlInjection));
    }

    #[Expected(instructions: '7.275M', cycles: '8.240M', memory: '111.0KiB')]
    public function benchPageViewInAWorker(): void
    {
        $this->firewall->decide($this->pageView);
    }

    #[Expected(instructions: '12.22M', cycles: '13.46M', memory: '149.1KiB')]
    public function benchFormPostInAWorker(): void
    {
        $this->firewall->decide($this->formPost);
    }

    #[Expected(instructions: '5.242M', cycles: '6.186M', memory: '91.63KiB')]
    public function benchSqlInjectionInAWorker(): void
    {
        $this->firewall->decide($this->sqlInjection);
    }

    /** The rule files are parsed on every request. */
    #[Expected(instructions: '240.3M', cycles: '245.9M', memory: '1.058MiB')]
    public function benchPageViewPerRequestWithoutCache(): void
    {
        $this->meter->exclude(PhpFpm::startRequest(...));

        (new Firewall($this->config(null)))->decide($this->pageView);
    }

    /** The parsed rules come from the compiled-data cache. */
    #[Expected(instructions: '13.48M', cycles: '16.06M', memory: '534.2KiB')]
    public function benchPageViewPerRequestWithCache(): void
    {
        $this->meter->exclude(PhpFpm::startRequest(...));

        (new Firewall($this->config($this->compiledDataCache())))->decide($this->pageView);
    }

    private function config(?CompiledDataCache $compiledDataCache): Config
    {
        return (new Config(new InMemoryCache()))
            ->setCompiledDataCache($compiledDataCache)
            ->with(Presets::blocklist());
    }

    private function compiledDataCache(): CompiledDataCache
    {
        return new CompiledDataCache($this->scratchDirectory->path() . '/compiled');
    }
}
