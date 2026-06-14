<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBots\Tests\Unit;

use Flowd\PhirewallPresetBots\CrawlerCatalog;
use PHPUnit\Framework\TestCase;

final class CrawlerCatalogTest extends TestCase
{
    private const BROWSER_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';

    public function testTokenListsAreNonEmptyAndUnique(): void
    {
        $ai = CrawlerCatalog::aiCrawlerUserAgents();
        $seo = CrawlerCatalog::seoCrawlerUserAgents();

        $this->assertNotEmpty($ai);
        $this->assertNotEmpty($seo);
        $this->assertSame(array_values(array_unique($ai)), $ai, 'AI token list must not contain duplicates');
        $this->assertSame(array_values(array_unique($seo)), $seo, 'SEO token list must not contain duplicates');
    }

    public function testAiRegexMatchesKnownCrawlerUserAgents(): void
    {
        $regex = CrawlerCatalog::userAgentRegex(CrawlerCatalog::aiCrawlerUserAgents());

        $this->assertMatchesRegularExpression($regex, 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)');
        $this->assertMatchesRegularExpression($regex, 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)');
        $this->assertMatchesRegularExpression($regex, 'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/bot)');
        $this->assertMatchesRegularExpression($regex, 'Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)');
    }

    public function testAiRegexDoesNotMatchBrowserOrLegitimateCrawlers(): void
    {
        $regex = CrawlerCatalog::userAgentRegex(CrawlerCatalog::aiCrawlerUserAgents());

        $this->assertDoesNotMatchRegularExpression($regex, self::BROWSER_USER_AGENT);
        // Search/indexing and link-preview agents must not be caught by the AI list.
        $this->assertDoesNotMatchRegularExpression($regex, 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
        $this->assertDoesNotMatchRegularExpression($regex, 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)');
        $this->assertDoesNotMatchRegularExpression($regex, 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)');
        $this->assertDoesNotMatchRegularExpression($regex, 'Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)');
    }

    public function testSeoRegexMatchesKnownCrawlersButNotABrowser(): void
    {
        $regex = CrawlerCatalog::userAgentRegex(CrawlerCatalog::seoCrawlerUserAgents());

        $this->assertMatchesRegularExpression($regex, 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)');
        $this->assertMatchesRegularExpression($regex, 'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)');
        $this->assertDoesNotMatchRegularExpression($regex, self::BROWSER_USER_AGENT);
    }

    public function testRegexIsCaseInsensitive(): void
    {
        $regex = CrawlerCatalog::userAgentRegex(['GPTBot']);

        $this->assertMatchesRegularExpression($regex, 'some gptbot variant');
    }

    public function testTokensMatchAsWholeTokensNotCoincidentalSubstrings(): void
    {
        $regex = CrawlerCatalog::userAgentRegex(CrawlerCatalog::aiCrawlerUserAgents());

        // 'omgili' / 'YouBot' must not fire inside an unrelated word.
        $this->assertDoesNotMatchRegularExpression($regex, 'Mozilla/5.0 homgilike/1.0');
        $this->assertDoesNotMatchRegularExpression($regex, 'Mozilla/5.0 playYouBoticious/2.0');
        // ...but still match when the crawler delimits the token normally.
        $this->assertMatchesRegularExpression($regex, 'Mozilla/5.0 (compatible; omgili/0.5; +http://omgili.com)');
    }

    public function testRegexBuilderRejectsAnEmptyTokenList(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        CrawlerCatalog::userAgentRegex([]);
    }
}
