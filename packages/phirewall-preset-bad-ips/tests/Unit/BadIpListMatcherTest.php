<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\Unit;

use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetBadIps\BadIpListMatcher;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class BadIpListMatcherTest extends TestCase
{
    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    public function testLoadsLazilyOnFirstMatchOnly(): void
    {
        // A missing data file must not throw at construction time ...
        $matcher = BadIpListMatcher::fromDataFile('vfs://resources/missing.data');

        // ... but on first use.
        vfsStream::setup('resources');
        $this->expectException(\RuntimeException::class);
        $matcher->match($this->requestFrom('192.0.2.1'));
    }

    public function testMatchesListedIpsAndPassesOthers(): void
    {
        $root = vfsStream::setup('resources', null, ['bad-ips.data' => "192.0.2.1\n203.0.113.0/24\n"]);
        $matcher = BadIpListMatcher::fromDataFile($root->url() . '/bad-ips.data');

        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertTrue($matcher->match($this->requestFrom('203.0.113.42'))->isMatch());
        $this->assertFalse($matcher->match($this->requestFrom('8.8.8.8'))->isMatch());
    }

    public function testCompiledDataCacheServesTheListWithoutReparsing(): void
    {
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n");
        $dataFile->lastModified(1_000_000);

        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        $first = BadIpListMatcher::fromDataFile($dataFile->url());
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertNotSame([], $cacheDirectory->getChildren(), 'The compiled artifacts must be written.');

        // Corrupt the source while keeping its mtime: a fresh process must be
        // served entirely from the compiled artifacts and never re-parse.
        $dataFile->setContent('# nothing here');
        $dataFile->lastModified(1_000_000);
        clearstatcache();
        CompiledDataCache::clearProcessCache();

        $second = BadIpListMatcher::fromDataFile($dataFile->url());
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match($this->requestFrom('192.0.2.1'))->isMatch());
    }

    public function testUnexpectedArtifactShapeFallsBackToParsingTheSource(): void
    {
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n");
        $dataFile->lastModified(1_000_000);

        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        // Seed a parseable but wrong-shape artifact (not a list<string>) under
        // the identifier the matcher will look up.
        $identifier = 'bad-ips-v1-' . substr(sha1($dataFile->url()), 0, 12);
        $compiledDataCache->load($identifier, [$dataFile->url()], static fn(): array => ['unexpected' => 'shape']);
        CompiledDataCache::clearProcessCache();

        $matcher = BadIpListMatcher::fromDataFile($dataFile->url());
        $matcher->useCompiledDataCache($compiledDataCache);

        // The matcher must ignore the bad artifact and parse the source, so the
        // listed address still matches instead of the list being empty.
        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
    }

    public function testCacheInjectedAfterAFirstMatchStillTakesEffect(): void
    {
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n");
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        $matcher = BadIpListMatcher::fromDataFile($dataFile->url());

        // Match once WITHOUT a cache: the inner matcher is built eagerly.
        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertSame([], $cacheDirectory->getChildren(), 'No artifact without a cache.');

        // Injecting the cache afterwards must still activate it.
        $matcher->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertNotSame([], $cacheDirectory->getChildren(), 'The cache injected late must write artifacts.');
    }

    private function requestFrom(string $ip): ServerRequestInterface
    {
        return new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }
}
