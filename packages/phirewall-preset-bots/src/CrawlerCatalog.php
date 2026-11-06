<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBots;

/**
 * Curated User-Agent substring tokens for known crawler categories.
 *
 * Each token is matched case-insensitively as a substring of the request's
 * User-Agent header.
 *
 * The AI list holds tokens crawlers actually send in their User-Agent.
 * Deliberately excluded:
 *  - robots.txt-only opt-out controls that never appear in a User-Agent
 *    (`Google-Extended`, `Applebot-Extended`, `Webzio-Extended`) - set those in robots.txt;
 *  - general web-search crawlers whose blocking would de-index the site
 *    (`Googlebot`, `bingbot`, `Applebot`, `Bravebot`, `GoogleOther`);
 *  - generic tokens that would over-match (`Operator`, `Scrapy`).
 *
 * Matching a User-Agent is policy enforcement for honest crawlers, not a
 * security control: a hostile scraper can send any User-Agent.
 */
final class CrawlerCatalog
{
    /**
     * AI and LLM crawlers/scrapers that identify themselves truthfully.
     *
     * @var list<string>
     */
    public const AI_CRAWLER_USER_AGENTS = [
        // OpenAI
        'GPTBot',
        'OAI-SearchBot',
        'ChatGPT-User',
        // Anthropic
        'ClaudeBot',
        'anthropic-ai',
        'Claude-Web',
        'Claude-User',
        'Claude-SearchBot',
        // Common Crawl (feeds many training sets)
        'CCBot',
        // ByteDance
        'Bytespider',
        'TikTokSpider',
        // Perplexity
        'PerplexityBot',
        'Perplexity-User',
        // Amazon
        'Amazonbot',
        // Meta
        'Meta-ExternalAgent',
        'Meta-ExternalFetcher',
        'FacebookBot',
        // Cohere
        'cohere-ai',
        'cohere-training-data-crawler',
        // Other vendor AI crawlers and scrapers
        'Diffbot',
        'omgili',
        'ImagesiftBot',
        'Timpibot',
        'YouBot',
        'DuckAssistBot',
        'AI2Bot',
        'Ai2Bot-Dolma',
        'PanguBot',
        'DeepSeekBot',
        'MistralAI-User',
        'YandexAdditional',
        'ICC-Crawler',
        'ISSCyberRiskCrawler',
        'img2dataset',
        'VelenPublicWebCrawler',
        'PhindBot',
        'SBIntuitionsBot',
        'Iaskspider',
        'LinerBot',
        'QuillBot',
        'Andibot',
        'FirecrawlAgent',
        'Crawlspace',
        'TerraCotta',
        'Cotoyogi',
        'aiHitBot',
        'FriendlyCrawler',
        'Google-CloudVertexBot',
        'Kangaroo Bot',
        'Sidetrade indexer bot',
        'Poseidon Research Crawler',
    ];

    /**
     * SEO/marketing crawlers that are not malicious but crawl aggressively;
     * rate-limited rather than blocked. Includes search engines (SeznamBot, Sogou)
     * that are throttled, not blocked, so the site stays indexed - override the
     * rule by name to exclude one in markets where it matters.
     *
     * @var list<string>
     */
    public const SEO_CRAWLER_USER_AGENTS = [
        'AhrefsBot',
        'SemrushBot',
        'MJ12bot',
        'DotBot',
        'DataForSeoBot',
        'BLEXBot',
        'rogerbot',
        'SeznamBot',
        'Barkrowler',
        'PetalBot',
        'MegaIndex',
        'serpstatbot',
        'Sogou',
    ];

    /**
     * @return list<string>
     */
    public static function aiCrawlerUserAgents(): array
    {
        return self::AI_CRAWLER_USER_AGENTS;
    }

    /**
     * @return list<string>
     */
    public static function seoCrawlerUserAgents(): array
    {
        return self::SEO_CRAWLER_USER_AGENTS;
    }

    /**
     * Build a case-insensitive PCRE matching any of the tokens in a User-Agent.
     *
     * Tokens are bounded by `\b` so they match as whole tokens (the way crawlers
     * delimit them with spaces, `/` or `;`) rather than as coincidental substrings
     * inside an unrelated word.
     *
     * @param list<string> $tokens
     * @throws \InvalidArgumentException When no tokens are given.
     */
    public static function userAgentRegex(array $tokens): string
    {
        if ($tokens === []) {
            throw new \InvalidArgumentException('At least one User-Agent token is required to build a regex.');
        }

        $quoted = array_map(static fn(string $token): string => preg_quote($token, '#'), $tokens);

        return '#\b(?:' . implode('|', $quoted) . ')\b#i';
    }
}
