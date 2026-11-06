<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\ConfigLayer;

/**
 * Threat-intelligence IP blocklist preset.
 *
 * Each factory returns a {@see ConfigLayer} for {@see Config::with()}:
 *
 * ```php
 * $config = (new Config($cache))->with(Presets::blocklist());
 * ```
 *
 * The blocked addresses come from the bundled `resources/bad-ips.data` snapshot
 * (see `bin/badip-import`) and load lazily on the first evaluated request; with
 * a compiled-data cache on the Config ({@see Config::setCompiledDataCache()})
 * the parsed list and its binary lookup tables come from compiled artifacts.
 * The rule resolves the client IP through the Config's resolver; behind a
 * proxy or CDN configure a trusted client-IP resolver so it sees the real
 * client rather than the proxy. The raw address list stays available through
 * {@see BadIpList::load()}.
 */
final class Presets
{
    public const BLOCKLIST_RULE = 'preset.bad-ips.blocklist';

    public const TRACK_RULE = 'preset.bad-ips.track';

    private function __construct()
    {
    }

    /**
     * Block requests whose client IP is in the bundled snapshot.
     */
    public static function blocklist(?string $dataFile = null): ConfigLayer
    {
        return self::layer(static function (Config $config) use ($dataFile): void {
            $config->blocklists->addRule(new BlocklistRule(
                self::BLOCKLIST_RULE,
                BadIpListMatcher::fromDataFile($dataFile),
            ));
        });
    }

    /**
     * Count - without blocking - requests whose client IP is in the snapshot,
     * for tuning false positives before switching to {@see blocklist()}.
     * Keyless: the counter keys on the resolved client IP.
     */
    public static function track(int $period = 3600, ?string $dataFile = null): ConfigLayer
    {
        return self::layer(static function (Config $config) use ($period, $dataFile): void {
            $config->tracks->addRule(new TrackRule(
                self::TRACK_RULE,
                $period,
                BadIpListMatcher::fromDataFile($dataFile),
                null,
                null,
            ));
        });
    }

    /**
     * The bundled feed snapshot's release tag (its import timestamp).
     */
    public static function snapshotImportedAt(?string $resourceDirectory = null): string
    {
        return Manifest::read($resourceDirectory)->importedAt;
    }

    /**
     * Wrap a rule-registration callback as a layer that populates a fresh Config
     * bound to the base infrastructure, then folds it onto the base.
     *
     * @param \Closure(Config): void $register
     */
    private static function layer(\Closure $register): ConfigLayer
    {
        return new class ($register) implements ConfigLayer {
            /** @param \Closure(Config): void $register */
            public function __construct(private readonly \Closure $register)
            {
            }

            public function applyTo(Config $config): Config
            {
                $layer = (new Config($config->cache, $config->eventDispatcher, $config->clock))
                    ->setEnabled($config->isEnabled());
                ($this->register)($layer);

                return $config->with($layer);
            }
        };
    }
}
