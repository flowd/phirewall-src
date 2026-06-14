<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBots\Tests\Unit;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetBots\Presets;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class PresetsTest extends TestCase
{
    public function testBlockAiCrawlersBlocksAnAiCrawlerAndPassesABrowser(): void
    {
        $config = (new Config(new InMemoryCache()))->with(Presets::blockAiCrawlers());
        $firewall = new Firewall($config);

        $this->assertTrue($firewall->decide($this->requestWithUserAgent('GPTBot/1.2 (+https://openai.com/gptbot)'))->isBlocked());
        $this->assertTrue($firewall->decide($this->browserRequest())->isPass());
    }

    public function testBlockAiCrawlersRegistersTheNamedRule(): void
    {
        $portableConfig = Presets::blockAiCrawlers();
        $this->assertInstanceOf(PortableConfig::class, $portableConfig);

        $blocklistNames = array_column($portableConfig->toArray()['blocklists'], 'name');
        $this->assertContains(Presets::AI_BLOCK_RULE, $blocklistNames);
    }

    public function testThrottleSeoCrawlersLimitsAfterTheConfiguredCount(): void
    {
        $config = (new Config(new InMemoryCache()))->with(Presets::throttleSeoCrawlers(limit: 2, period: 60));
        $firewall = new Firewall($config);
        $request = $this->requestWithUserAgent('Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)', '203.0.113.10');

        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($request)->outcome);
    }

    public function testThrottleDoesNotAffectABrowser(): void
    {
        $config = (new Config(new InMemoryCache()))->with(Presets::throttleSeoCrawlers(limit: 1, period: 60));
        $firewall = new Firewall($config);

        $this->assertTrue($firewall->decide($this->browserRequest())->isPass());
        $this->assertTrue($firewall->decide($this->browserRequest())->isPass());
    }

    public function testThrottleAiCrawlersReturnsAConfiguredPortableConfig(): void
    {
        $config = (new Config(new InMemoryCache()))->with(Presets::throttleAiCrawlers(limit: 1, period: 60));
        $firewall = new Firewall($config);
        $request = $this->requestWithUserAgent('CCBot/2.0 (https://commoncrawl.org/faq/)', '198.51.100.7');

        $this->assertTrue($firewall->decide($request)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($request)->outcome);
    }

    public function testVersionIsExposedAsSemver(): void
    {
        $this->assertSame(Presets::VERSION, Presets::version());
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/', Presets::version());
    }

    private function requestWithUserAgent(string $userAgent, string $remoteAddr = '203.0.113.1'): ServerRequestInterface
    {
        return new ServerRequest('GET', 'https://example.test/', ['User-Agent' => $userAgent], null, '1.1', ['REMOTE_ADDR' => $remoteAddr]);
    }

    private function browserRequest(): ServerRequestInterface
    {
        return $this->requestWithUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36');
    }
}
