<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps;

/**
 * Provenance of an imported IP blocklist snapshot, recorded in the manifest.
 */
final readonly class FeedSource
{
    public function __construct(
        public string $name,
        public string $url,
        public string $level,
        public string $license,
    ) {
    }
}
