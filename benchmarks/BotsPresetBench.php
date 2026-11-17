<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallBenchmarks\Support\FixedClock;
use Flowd\PhirewallBenchmarks\Support\Outcome;
use Flowd\PhirewallBenchmarks\Support\Requests;
use Flowd\PhirewallPresetBots\Presets;
use Psr\Http\Message\ServerRequestInterface;
use Tally\Attribute\Before;
use Tally\Attribute\Warmup;

/**
 * The bots preset: AI crawlers blocked, SEO crawlers throttled, seen by a browser.
 */
#[Warmup(2)]
final class BotsPresetBench
{
    private Firewall $firewall;

    private ServerRequestInterface $serverRequest;

    #[Before]
    public function buildFirewall(): void
    {
        $this->serverRequest = Requests::pageView();
        $this->firewall = new Firewall($this->config());

        Outcome::mustPass($this->firewall->decide($this->serverRequest));
    }

    public function benchBrowserInAWorker(): void
    {
        $this->firewall->decide($this->serverRequest);
    }

    public function benchBrowserPerRequest(): void
    {
        (new Firewall($this->config()))->decide($this->serverRequest);
    }

    private function config(): Config
    {
        $fixedClock = new FixedClock();

        return (new Config(new InMemoryCache($fixedClock), null, $fixedClock))->with(
            Presets::blockAiCrawlers(),
            Presets::throttleSeoCrawlers(),
        );
    }
}
