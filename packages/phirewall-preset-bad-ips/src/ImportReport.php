<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps;

/**
 * Summary of one import run, also serialized as manifest.json next to the data file.
 */
final readonly class ImportReport
{
    public function __construct(
        public FeedSource $source,
        public int $ipCount,
        public string $importedAt,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toManifestArray(): array
    {
        return [
            'feedName' => $this->source->name,
            'feedUrl' => $this->source->url,
            'feedLevel' => $this->source->level,
            'license' => $this->source->license,
            'ipCount' => $this->ipCount,
            'importedAt' => $this->importedAt,
        ];
    }
}
