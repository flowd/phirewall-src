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
        return self::parse(self::read($dataFile ?? self::defaultDataFile()));
    }

    /**
     * The content of a snapshot file.
     *
     * @internal
     *
     * @throws \RuntimeException When the file is missing or unreadable.
     */
    public static function read(string $dataFile): string
    {
        // Asked first, so that a missing file is the exception below and not a warning.
        $content = is_file($dataFile) ? @file_get_contents($dataFile) : false;
        if ($content === false) {
            throw new \RuntimeException('Bad-IP data file not found: ' . $dataFile);
        }

        return $content;
    }

    /**
     * The addresses in the content of a snapshot file: one per line, without
     * blank lines and `#` comments.
     *
     * @return list<string>
     */
    public static function parse(string $content): array
    {
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
