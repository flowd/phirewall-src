<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallBenchmarks\Support\Networks;
use Flowd\PhirewallBenchmarks\Support\Outcome;
use Flowd\PhirewallBenchmarks\Support\Requests;
use Psr\Http\Message\ServerRequestInterface;
use Tally\Attribute\Before;
use Tally\Attribute\Constant;
use Tally\Attribute\DataProvider;
use Tally\Attribute\Warmup;

/**
 * How the cost of one decision grows with the length of an IP blocklist. No
 * expected numbers here, only the complexity class: IpListBench has the numbers.
 */
#[Warmup(2)]
final class IpListGrowthBench
{
    private Firewall $firewall;

    /** @var list<ServerRequestInterface> */
    private array $pageViews;

    /** Which of the unseen requests the next call takes, see {@see Requests::unseen()}. */
    private int $call = 0;

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function lists(): iterable
    {
        foreach ([100, 1_000, 10_000] as $size) {
            yield 'networks-' . $size => [Networks::privateNetworks($size)];
        }
    }

    /**
     * @param list<string> $networks
     */
    #[Before]
    public function buildFirewall(array $networks): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->ip('networks', $networks);

        $this->firewall = new Firewall($config);
        $this->pageViews = Requests::unseen(Requests::pageView(...));

        Outcome::mustPass($this->firewall->decide(Requests::pageView()));
    }

    /**
     * The common case and the worst one for a list that is searched entry by
     * entry: the client is in none of the networks.
     *
     * @param list<string> $networks
     */
    #[DataProvider('lists')]
    #[Constant('networks')]
    public function benchUnlistedClientInAWorker(array $networks): void
    {
        $this->firewall->decide($this->pageViews[$this->call++]);
    }
}
