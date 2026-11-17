<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks\Support;

use Flowd\Phirewall\Store\ClockInterface;

/**
 * Time stands still, so a counter window never ends between the warm-up calls
 * and the counted call of a benchmark.
 */
final class FixedClock implements ClockInterface
{
    public function now(): float
    {
        return 1_800_000_000.0;
    }
}
