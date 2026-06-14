<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps;

/**
 * Metadata about the bundled snapshot, read from manifest.json in the resource directory.
 */
final readonly class Manifest
{
    public function __construct(
        public string $feedName,
        public string $feedUrl,
        public string $feedLevel,
        public string $license,
        public int $ipCount,
        public string $importedAt,
    ) {
    }

    public static function read(?string $resourceDirectory = null): self
    {
        $resourceDirectory ??= BadIpList::defaultResourceDirectory();
        $path = rtrim($resourceDirectory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . Importer::MANIFEST_FILE;

        $content = @file_get_contents($path);
        if ($content === false) {
            throw new \RuntimeException('Bad-IP manifest not found: ' . $path);
        }

        try {
            $data = json_decode($content, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $jsonException) {
            throw new \RuntimeException('Bad-IP manifest is not valid JSON: ' . $path, 0, $jsonException);
        }

        if (!is_array($data)) {
            throw new \RuntimeException('Bad-IP manifest must decode to an object: ' . $path);
        }

        return self::fromArray($data);
    }

    /**
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        foreach (['feedName', 'feedUrl', 'feedLevel', 'license', 'importedAt'] as $required) {
            if (!isset($data[$required]) || !is_string($data[$required])) {
                throw new \RuntimeException(sprintf('Bad-IP manifest is missing string field "%s".', $required));
            }
        }

        if (!isset($data['ipCount']) || !is_int($data['ipCount'])) {
            throw new \RuntimeException('Bad-IP manifest is missing integer field "ipCount".');
        }

        /** @var array{feedName: string, feedUrl: string, feedLevel: string, license: string, ipCount: int, importedAt: string} $data */
        return new self(
            $data['feedName'],
            $data['feedUrl'],
            $data['feedLevel'],
            $data['license'],
            $data['ipCount'],
            $data['importedAt'],
        );
    }
}
