<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps;

use Flowd\Phirewall\Portable\PortableConfig;

/**
 * Threat-intelligence IP blocklist preset.
 *
 * Returns a {@see PortableConfig} - also a {@see \Flowd\Phirewall\ConfigLayer} -
 * that you materialize on your own cache with {@see \Flowd\Phirewall\Config::with()}:
 *
 * ```php
 * $config = (new Config($cache))->with(Presets::blocklist());
 * ```
 *
 * The blocked addresses come from the bundled `resources/bad-ips.data` snapshot
 * (see `bin/badip-import`). The rule resolves the client IP from `REMOTE_ADDR`;
 * behind a proxy or CDN configure a trusted client-IP resolver on the Config so
 * it sees the real client rather than the proxy.
 */
final class Presets
{
    public const BLOCKLIST_RULE = 'preset.bad-ips.blocklist';

    public const TRACK_RULE = 'preset.bad-ips.track';

    /**
     * Block requests whose client IP is in the bundled snapshot.
     */
    public static function blocklist(?string $dataFile = null): PortableConfig
    {
        return PortableConfig::create()->blocklist(
            self::BLOCKLIST_RULE,
            PortableConfig::filterIp(BadIpList::load($dataFile)),
        );
    }

    /**
     * Count - without blocking - requests whose client IP is in the snapshot,
     * for tuning false positives before switching to {@see blocklist()}.
     */
    public static function track(int $period = 3600, ?string $dataFile = null): PortableConfig
    {
        return PortableConfig::create()->track(
            self::TRACK_RULE,
            period: $period,
            filter: PortableConfig::filterIp(BadIpList::load($dataFile)),
            key: PortableConfig::keyIp(),
        );
    }

    /**
     * The bundled feed snapshot's release tag (its import timestamp).
     */
    public static function snapshotImportedAt(?string $resourceDirectory = null): string
    {
        return Manifest::read($resourceDirectory)->importedAt;
    }
}
