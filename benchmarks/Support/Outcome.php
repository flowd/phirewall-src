<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks\Support;

use Flowd\Phirewall\Http\FirewallResult;

/**
 * Checked in the #[Before] hooks: a benchmark whose request takes another way
 * through the firewall than its name says must fail, not deliver a number.
 */
final class Outcome
{
    private function __construct()
    {
    }

    public static function mustPass(FirewallResult $firewallResult): void
    {
        if (!$firewallResult->isPass()) {
            throw new \LogicException('The request of this benchmark is meant to pass, but the firewall stopped it.');
        }
    }

    public static function mustBlock(FirewallResult $firewallResult): void
    {
        if (!$firewallResult->isBlocked()) {
            throw new \LogicException('The request of this benchmark is meant to be blocked, but the firewall let it pass.');
        }
    }
}
