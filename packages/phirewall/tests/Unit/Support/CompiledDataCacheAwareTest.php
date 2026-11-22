<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Config\ClosureKeyExtractor;
use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Config\Rule\Allow2BanRule;
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\Phirewall\Config\Rule\Fail2BanRule;
use Flowd\Phirewall\Config\Rule\SafelistRule;
use Flowd\Phirewall\Config\Rule\TrackRule;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Matchers\CompiledDataCacheAware;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\Phirewall\Support\CompiledDataCache;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class CompiledDataCacheAwareTest extends TestCase
{
    use TemporaryFiles;

    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    /**
     * @return RequestMatcherInterface&CompiledDataCacheAware&object{received: ?CompiledDataCache}
     */
    private function recordingAwareMatcher(): RequestMatcherInterface
    {
        return new class () implements RequestMatcherInterface, CompiledDataCacheAware {
            public ?CompiledDataCache $received = null;

            public function match(ServerRequestInterface $serverRequest): MatchResult
            {
                return MatchResult::noMatch();
            }

            public function useCompiledDataCache(CompiledDataCache $compiledDataCache): void
            {
                $this->received = $compiledDataCache;
            }
        };
    }

    public function testConfigCarriesTheCompiledDataCache(): void
    {
        $config = new Config(new InMemoryCache());
        $this->assertNull($config->compiledDataCache());

        $compiledDataCache = new CompiledDataCache($this->temporaryPath());
        $config->setCompiledDataCache($compiledDataCache);

        $this->assertSame($compiledDataCache, $config->compiledDataCache());
    }

    public function testCompositionInheritsTheCacheFromTheBaseLayer(): void
    {
        $baseCache = new CompiledDataCache($this->temporaryPath('cache/base'));
        $overlayCache = new CompiledDataCache($this->temporaryPath('cache2/overlay'));

        $base = (new Config(new InMemoryCache()))->setCompiledDataCache($baseCache);
        $overlay = (new Config(new InMemoryCache()))->setCompiledDataCache($overlayCache);

        $this->assertSame($baseCache, $base->with($overlay)->compiledDataCache());
    }

    public function testFirewallInjectsTheCacheIntoAwareMatchersOfEverySection(): void
    {
        $compiledDataCache = new CompiledDataCache($this->temporaryPath());
        $config = (new Config(new InMemoryCache()))->setCompiledDataCache($compiledDataCache);
        $keyExtractor = new ClosureKeyExtractor(fn(ServerRequestInterface $serverRequest): string => '203.0.113.5');

        $matchers = [
            'safelist' => $this->recordingAwareMatcher(),
            'blocklist' => $this->recordingAwareMatcher(),
            'fail2ban' => $this->recordingAwareMatcher(),
            'allow2ban' => $this->recordingAwareMatcher(),
            'track' => $this->recordingAwareMatcher(),
            'throttleScope' => $this->recordingAwareMatcher(),
        ];

        $config->safelists->addRule(new SafelistRule('s', $matchers['safelist']));
        $config->blocklists->addRule(new BlocklistRule('b', $matchers['blocklist']));
        $config->fail2ban->addRule(new Fail2BanRule('f', 3, 60, 600, $matchers['fail2ban'], $keyExtractor));
        $config->allow2ban->addRule(new Allow2BanRule('a', 3, 60, 600, $keyExtractor, $matchers['allow2ban']));
        $config->tracks->addRule(new TrackRule('t', 60, $matchers['track'], $keyExtractor, null));
        $config->throttles->addRule(new Config\Rule\ThrottleRule('th', 10, 60, $keyExtractor, false, $matchers['throttleScope']));

        new Firewall($config);

        foreach ($matchers as $section => $matcher) {
            $this->assertSame($compiledDataCache, $matcher->received, "Matcher of section {$section} must receive the cache.");
        }
    }

    public function testNoInjectionWithoutAConfiguredCache(): void
    {
        $config = new Config(new InMemoryCache());
        $matcher = $this->recordingAwareMatcher();
        $config->blocklists->addRule(new BlocklistRule('b', $matcher));

        new Firewall($config);

        $this->assertNull($matcher->received);
    }

    public function testIpMatcherCompilesLazilyAndWritesAnArtifact(): void
    {
        $compiledDataCache = new CompiledDataCache($this->temporaryPath());

        $ipMatcher = new \Flowd\Phirewall\Matchers\IpMatcher(['203.0.113.0/24', '198.51.100.7']);
        $ipMatcher->useCompiledDataCache($compiledDataCache);

        $request = new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.99']);
        $this->assertTrue($ipMatcher->match($request)->isMatch());
        $this->assertNotSame([], $this->entriesIn($this->temporaryPath()), 'The compiled tables must be persisted.');
    }

    public function testIpMatcherConsumesTheCompiledArtifact(): void
    {
        $compiledDataCache = new CompiledDataCache($this->temporaryPath());
        $entries = ['203.0.113.0/24'];

        // Seed the content-addressed artifact with tables for a DIFFERENT
        // address; the matcher must follow the artifact, proving it never
        // recompiles the entries.
        $identifier = 'ip-matcher-v2-' . sha1(implode("\n", $entries));
        $crafted = ['exact' => [inet_pton('192.0.2.1') => true], 'networks' => []];
        $compiledDataCache->load($identifier, [], static fn(): array => $crafted);
        CompiledDataCache::clearProcessCache();

        $ipMatcher = new \Flowd\Phirewall\Matchers\IpMatcher($entries);
        $ipMatcher->useCompiledDataCache($compiledDataCache);

        $craftedRequest = new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '192.0.2.1']);
        $originalRequest = new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.99']);

        $this->assertTrue($ipMatcher->match($craftedRequest)->isMatch());
        $this->assertFalse($ipMatcher->match($originalRequest)->isMatch());
    }

    public function testIpMatcherRecompilesWhenTheArtifactShapeIsUnexpected(): void
    {
        $compiledDataCache = new CompiledDataCache($this->temporaryPath());
        $entries = ['203.0.113.0/24'];

        // Seed a parseable but wrong-shape artifact (no exact/networks keys).
        // The matcher must fall back to compiling from its entries, not match
        // nothing (which for a blocklist would be fail-open).
        $identifier = 'ip-matcher-v2-' . sha1(implode("\n", $entries));
        $compiledDataCache->load($identifier, [], static fn(): array => ['unexpected' => true]);
        CompiledDataCache::clearProcessCache();

        $ipMatcher = new \Flowd\Phirewall\Matchers\IpMatcher($entries);
        $ipMatcher->useCompiledDataCache($compiledDataCache);

        $request = new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.99']);
        $this->assertTrue($ipMatcher->match($request)->isMatch());
    }

    public function testIpMatcherIgnoresArtifactsOfTheLookupTablesBeforeTheirCurrentForm(): void
    {
        $compiledDataCache = new CompiledDataCache($this->temporaryPath());
        $entries = ['203.0.113.0/24', '198.51.100.7'];

        // An artifact as an earlier version wrote it, with tables that match nothing.
        $compiledDataCache->load('ip-matcher-v1-' . sha1(implode("\n", $entries)), [], static fn(): array => ['cidrs' => [], 'exact' => []]);
        CompiledDataCache::clearProcessCache();

        $ipMatcher = new \Flowd\Phirewall\Matchers\IpMatcher($entries);
        $ipMatcher->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($ipMatcher->match(new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.99']))->isMatch());
        $this->assertTrue($ipMatcher->match(new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '198.51.100.7']))->isMatch());
        $this->assertCount(2, $this->entriesIn($this->temporaryPath()), 'The current form gets an artifact of its own.');
    }

    public function testIpMatcherServedFromItsArtifactDecidesLikeWithoutACache(): void
    {
        $compiledDataCache = new CompiledDataCache($this->temporaryPath());
        $entries = ['203.0.113.0/24', '198.51.100.7', '::ffff:192.0.2.0/120', '2001:db8::/33', '10.32.0.0/11', '49.50.51.52', 'garbage'];
        $addresses = ['203.0.113.1', '203.0.114.1', '198.51.100.7', '198.51.100.8', '192.0.2.200', '::ffff:192.0.2.200', '2001:db8:7fff::1', '2001:db8:8000::1', '10.63.0.1', '10.64.0.1', '49.50.51.52', '49.50.51.53', 'garbage'];

        $decisions = static function (\Flowd\Phirewall\Matchers\IpMatcher $ipMatcher) use ($addresses): array {
            $decisions = [];
            foreach ($addresses as $address) {
                $decisions[$address] = $ipMatcher->match(new \Nyholm\Psr7\ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => $address]))->isMatch();
            }

            return $decisions;
        };

        $expected = $decisions(new \Flowd\Phirewall\Matchers\IpMatcher($entries));
        $this->assertContains(true, $expected);
        $this->assertContains(false, $expected);

        // The first matcher writes the artifact, the second one reads it.
        foreach ([1, 2] as $run) {
            CompiledDataCache::clearProcessCache();
            $ipMatcher = new \Flowd\Phirewall\Matchers\IpMatcher($entries);
            $ipMatcher->useCompiledDataCache($compiledDataCache);

            $this->assertSame($expected, $decisions($ipMatcher), 'run ' . $run);
        }

        $this->assertCount(1, $this->entriesIn($this->temporaryPath()));
    }
}
