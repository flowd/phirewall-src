<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallBenchmarks\Support\FixedClock;
use Flowd\PhirewallBenchmarks\Support\Outcome;
use Flowd\PhirewallBenchmarks\Support\Requests;
use Psr\Http\Message\ServerRequestInterface;
use Tally\Attribute\Before;
use Tally\Attribute\Warmup;

/**
 * The core without presets: what the firewall itself costs around the rules.
 */
#[Warmup(2)]
final class DecisionBench
{
    private Firewall $emptyFirewall;

    private Firewall $smallFirewall;

    private ServerRequestInterface $serverRequest;

    #[Before]
    public function buildFirewalls(): void
    {
        $this->serverRequest = Requests::pageView();
        $this->emptyFirewall = new Firewall(new Config(new InMemoryCache()));
        $this->smallFirewall = new Firewall($this->smallRuleSet());

        Outcome::mustPass($this->emptyFirewall->decide($this->serverRequest));
        Outcome::mustPass($this->smallFirewall->decide($this->serverRequest));
    }

    public function benchNoRulesInAWorker(): void
    {
        $this->emptyFirewall->decide($this->serverRequest);
    }

    public function benchSmallRuleSetInAWorker(): void
    {
        $this->smallFirewall->decide($this->serverRequest);
    }

    public function benchSmallRuleSetPerRequest(): void
    {
        (new Firewall($this->smallRuleSet()))->decide($this->serverRequest);
    }

    /**
     * One rule of each common kind, none of which stops the page view.
     */
    private function smallRuleSet(): Config
    {
        $fixedClock = new FixedClock();
        $clientIp = static fn(ServerRequestInterface $serverRequest): string => Requests::CLIENT_IP;

        $config = new Config(new InMemoryCache($fixedClock), null, $fixedClock);
        $config->safelists->add('health-check', static fn(ServerRequestInterface $serverRequest): bool => $serverRequest->getUri()->getPath() === '/health');
        $config->blocklists->knownScanners();
        $config->blocklists->suspiciousHeaders();
        $config->blocklists->ip('banned-networks', ['198.51.100.0/24', '192.0.2.44']);

        $config->throttles->add('requests-per-client', 10_000, 60, $clientIp);
        $config->fail2ban->add(
            'login-failures',
            5,
            600,
            3600,
            static fn(ServerRequestInterface $serverRequest): bool => $serverRequest->getMethod() === 'POST' && $serverRequest->getUri()->getPath() === '/login',
            $clientIp,
        );

        return $config;
    }
}
