<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBots;

use Flowd\Phirewall\Portable\PortableConfig;

/**
 * Bot and AI-crawler control presets.
 *
 * Each accessor returns a fresh {@see PortableConfig} - inspectable, serializable
 * data, and a {@see \Flowd\Phirewall\ConfigLayer} - that you materialize on your
 * own cache with {@see \Flowd\Phirewall\Config::with()}:
 *
 * ```php
 * $config = (new Config($cache))->with(
 *     Presets::blockAiCrawlers(),
 *     Presets::throttleSeoCrawlers(),
 * );
 * ```
 *
 * Rules are namespaced `preset.bots.*` so a later layer can override one by name.
 *
 * Matching is by User-Agent and therefore enforces policy for crawlers that
 * identify truthfully (AI opt-out, curbing aggressive SEO bots). It is not a
 * defence against hostile scrapers, which can forge any User-Agent.
 *
 * IP-keyed throttles resolve the client from `REMOTE_ADDR`. Behind a proxy or
 * CDN that is the proxy address, so configure a trusted client-IP resolver on
 * the Config (or override the throttle by name) for those deployments.
 */
final class Presets
{
    /**
     * Version of the bundled crawler catalogue. Bumped whenever the token lists
     * change in a way integrators should review.
     */
    public const VERSION = '1.0.0';

    public const AI_BLOCK_RULE = 'preset.bots.ai-block';

    public const AI_THROTTLE_RULE = 'preset.bots.ai-throttle';

    public const SEO_THROTTLE_RULE = 'preset.bots.seo-throttle';

    public static function version(): string
    {
        return self::VERSION;
    }

    /**
     * Block requests whose User-Agent identifies a known AI/LLM crawler.
     */
    public static function blockAiCrawlers(): PortableConfig
    {
        return PortableConfig::create()->blocklist(
            self::AI_BLOCK_RULE,
            PortableConfig::filterHeaderRegex('User-Agent', self::aiCrawlerRegex()),
        );
    }

    /**
     * Rate-limit AI/LLM crawlers per client IP instead of blocking them, for
     * sites that want to stay indexable but cap the load.
     */
    public static function throttleAiCrawlers(int $limit = 60, int $period = 60): PortableConfig
    {
        return PortableConfig::create()->throttle(
            self::AI_THROTTLE_RULE,
            limit: $limit,
            period: $period,
            key: PortableConfig::keyIp(),
            sliding: true,
            scope: PortableConfig::filterHeaderRegex('User-Agent', self::aiCrawlerRegex()),
        );
    }

    /**
     * Rate-limit aggressive SEO/marketing crawlers per client IP.
     */
    public static function throttleSeoCrawlers(int $limit = 60, int $period = 60): PortableConfig
    {
        return PortableConfig::create()->throttle(
            self::SEO_THROTTLE_RULE,
            limit: $limit,
            period: $period,
            key: PortableConfig::keyIp(),
            sliding: true,
            scope: PortableConfig::filterHeaderRegex('User-Agent', self::seoCrawlerRegex()),
        );
    }

    private static function aiCrawlerRegex(): string
    {
        return CrawlerCatalog::userAgentRegex(CrawlerCatalog::aiCrawlerUserAgents());
    }

    private static function seoCrawlerRegex(): string
    {
        return CrawlerCatalog::userAgentRegex(CrawlerCatalog::seoCrawlerUserAgents());
    }
}
