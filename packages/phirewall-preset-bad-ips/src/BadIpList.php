<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps;

/**
 * Reads the bundled `bad-ips.data` snapshot into a list of IP addresses.
 */
final class BadIpList
{
    /**
     * @return list<string>
     */
    public static function load(?string $dataFile = null): array
    {
        $dataFile ??= self::defaultDataFile();

        $content = @file_get_contents($dataFile);
        if ($content === false) {
            throw new \RuntimeException('Bad-IP data file not found: ' . $dataFile);
        }

        $addresses = [];
        foreach (preg_split('/\R/', $content) ?: [] as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            if (str_starts_with($line, '#')) {
                continue;
            }

            $addresses[] = $line;
        }

        return $addresses;
    }

    public static function defaultDataFile(): string
    {
        return self::defaultResourceDirectory() . DIRECTORY_SEPARATOR . Importer::DATA_FILE;
    }

    public static function defaultResourceDirectory(): string
    {
        return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'resources';
    }
}
