<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\Unit;

use Flowd\Phirewall\Matchers\IpMatcher;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetBadIps\BadIpList;
use Flowd\PhirewallPresetBadIps\BadIpListMatcher;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\DataProvider;
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

    public function testAMissingDataFileThrowsWithACacheAsWithout(): void
    {
        $root = vfsStream::setup('resources');
        $matcher = BadIpListMatcher::fromDataFile($root->url() . '/missing.data');
        $matcher->useCompiledDataCache(new CompiledDataCache($root->url() . '/cache'));

        try {
            $matcher->match($this->requestFrom('192.0.2.1'));
            $this->fail('A missing data file must be reported.');
        } catch (\RuntimeException $runtimeException) {
            $this->assertStringContainsString('not found', $runtimeException->getMessage());
        }

        $this->assertFalse($root->hasChild('cache'), 'Nothing is cached for a file that is not there.');
    }

    public function testAMissingDataFileIsReportedBeforeTheClientIpIsLookedAt(): void
    {
        $root = vfsStream::setup('resources');
        $matcher = BadIpListMatcher::fromDataFile($root->url() . '/missing.data');

        $this->expectException(\RuntimeException::class);
        $matcher->matchWithResolver($this->requestFrom('192.0.2.1'), static fn(): ?string => null);
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
        $this->assertCount(1, $cacheDirectory->getChildren(), 'One compiled artifact must be written.');

        // Corrupt the source while keeping its mtime and size: a fresh process
        // must be served entirely from the compiled artifact and never re-parse.
        $dataFile->setContent("#nothing.\n");
        $dataFile->lastModified(1_000_000);
        clearstatcache();
        CompiledDataCache::clearProcessCache();

        $second = BadIpListMatcher::fromDataFile($dataFile->url());
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertFalse($second->match($this->requestFrom('192.0.2.2'))->isMatch());
    }

    public function testAChangedDataFileRebuildsTheArtifact(): void
    {
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n");
        $dataFile->lastModified(1_000_000);

        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        $first = BadIpListMatcher::fromDataFile($dataFile->url());
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());

        $dataFile->setContent("203.0.113.7\n198.51.100.0/24\n");
        $dataFile->lastModified(1_000_100);
        clearstatcache();

        // In the same process (a long-running worker building a new Config) ...
        $second = BadIpListMatcher::fromDataFile($dataFile->url());
        $second->useCompiledDataCache($compiledDataCache);
        $this->assertFalse($second->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertTrue($second->match($this->requestFrom('203.0.113.7'))->isMatch());
        $this->assertTrue($second->match($this->requestFrom('198.51.100.200'))->isMatch());

        // ... and in a fresh one, which finds the rebuilt artifact.
        CompiledDataCache::clearProcessCache();
        $dataFile->setContent("#..........\n#..............\n");
        $dataFile->lastModified(1_000_100);
        clearstatcache();

        $third = BadIpListMatcher::fromDataFile($dataFile->url());
        $third->useCompiledDataCache($compiledDataCache);
        $this->assertFalse($third->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertTrue($third->match($this->requestFrom('203.0.113.7'))->isMatch());
        $this->assertCount(1, $cacheDirectory->getChildren(), 'The artifact of a data file is replaced, not added to.');
    }

    public function testAnArtifactIsNotUsedForADataFileOfAnotherSize(): void
    {
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n");
        $dataFile->lastModified(1_000_000);

        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        $first = BadIpListMatcher::fromDataFile($dataFile->url());
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());

        // Replaced by a file with the same modification time, as deployments
        // that set every file to one fixed time do.
        $dataFile->setContent("203.0.113.7\n198.51.100.9\n");
        $dataFile->lastModified(1_000_000);
        clearstatcache();
        CompiledDataCache::clearProcessCache();

        $second = BadIpListMatcher::fromDataFile($dataFile->url());
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match($this->requestFrom('203.0.113.7'))->isMatch());
        $this->assertTrue($second->match($this->requestFrom('198.51.100.9'))->isMatch());
        $this->assertFalse($second->match($this->requestFrom('192.0.2.1'))->isMatch());
    }

    public function testAnArtifactOfADataFileOfAnotherSizeIsReplaced(): void
    {
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n");
        $dataFile->lastModified(1_000_000);

        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        $first = BadIpListMatcher::fromDataFile($dataFile->url());
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());

        // Another file with the same modification time, in a fresh process ...
        $dataFile->setContent("203.0.113.7\n198.51.100.9\n");
        $dataFile->lastModified(1_000_000);
        clearstatcache();
        CompiledDataCache::clearProcessCache();

        $second = BadIpListMatcher::fromDataFile($dataFile->url());
        $second->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($second->match($this->requestFrom('203.0.113.7'))->isMatch());

        // ... leaves an artifact that serves the next process on its own: the
        // source is now nothing but a comment of the same size and time.
        $dataFile->setContent('#' . str_repeat('.', 23) . "\n");
        $dataFile->lastModified(1_000_000);
        clearstatcache();
        CompiledDataCache::clearProcessCache();

        $third = BadIpListMatcher::fromDataFile($dataFile->url());
        $third->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($third->match($this->requestFrom('203.0.113.7'))->isMatch());
        $this->assertTrue($third->match($this->requestFrom('198.51.100.9'))->isMatch());
        $this->assertFalse($third->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertCount(1, $cacheDirectory->getChildren(), 'The artifact is replaced, not added to.');
    }

    /**
     * @param array<mixed> $artifact
     */
    #[DataProvider('unusableArtifacts')]
    public function testUnexpectedArtifactShapeFallsBackToParsingTheSource(array $artifact): void
    {
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n203.0.113.0/24\n");
        $dataFile->lastModified(1_000_000);

        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        // Seed a parseable but unusable artifact under the identifier the
        // matcher will look up.
        $compiledDataCache->load($this->identifier($dataFile->url()), [$dataFile->url()], static fn(): array => $artifact);
        CompiledDataCache::clearProcessCache();

        $matcher = BadIpListMatcher::fromDataFile($dataFile->url());
        $matcher->useCompiledDataCache($compiledDataCache);

        // The matcher must ignore the bad artifact and parse the source, so the
        // listed addresses still match instead of the list being empty.
        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertTrue($matcher->match($this->requestFrom('203.0.113.200'))->isMatch());
        $this->assertFalse($matcher->match($this->requestFrom('8.8.8.8'))->isMatch());
    }

    /**
     * @return iterable<string, array{array<mixed>}>
     */
    public static function unusableArtifacts(): iterable
    {
        // The data file of the test has 25 bytes.
        yield 'another shape' => [['unexpected' => 'shape']];
        yield 'empty' => [[]];
        yield 'the address list of earlier versions' => [['192.0.2.1', '203.0.113.0/24']];
        yield 'tables without a size' => [['exact' => [], 'networks' => []]];
        yield 'tables of another size' => [['size' => 24, 'exact' => [], 'networks' => []]];
        yield 'size as text' => [['size' => '25', 'exact' => [], 'networks' => []]];
        yield 'no networks' => [['size' => 25, 'exact' => []]];
        yield 'no addresses' => [['size' => 25, 'networks' => []]];
        yield 'addresses that are no table' => [['size' => 25, 'exact' => 'none', 'networks' => []]];
    }

    public function testTheSeededArtifactIsTheOneTheMatcherReads(): void
    {
        // Guards the fallback tests above: a wrong identifier there would pass for the wrong reason.
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n203.0.113.0/24\n");
        $dataFile->lastModified(1_000_000);

        $compiledDataCache = new CompiledDataCache($root->url() . '/cache');

        $crafted = ['size' => 25, 'exact' => [inet_pton('198.51.100.1') => true], 'networks' => []];
        $compiledDataCache->load($this->identifier($dataFile->url()), [$dataFile->url()], static fn(): array => $crafted);
        CompiledDataCache::clearProcessCache();

        $matcher = BadIpListMatcher::fromDataFile($dataFile->url());
        $matcher->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($matcher->match($this->requestFrom('198.51.100.1'))->isMatch());
        $this->assertFalse($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
    }

    public function testACorruptArtifactFallsBackToParsingTheSource(): void
    {
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n");
        $dataFile->lastModified(1_000_000);

        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        $first = BadIpListMatcher::fromDataFile($dataFile->url());
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());

        $artifacts = $cacheDirectory->getChildren();
        $this->assertCount(1, $artifacts);

        foreach (['<?php return [', '<?php return 7;', '', '<?php throw new \LogicException("broken");'] as $content) {
            file_put_contents($artifacts[0]->url(), $content);
            clearstatcache();
            CompiledDataCache::clearProcessCache();

            $matcher = BadIpListMatcher::fromDataFile($dataFile->url());
            $matcher->useCompiledDataCache($compiledDataCache);

            $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch(), $content);
            $this->assertFalse($matcher->match($this->requestFrom('192.0.2.2'))->isMatch(), $content);
        }
    }

    public function testACacheDirectoryThatCannotBeWrittenStillMatches(): void
    {
        $root = vfsStream::setup('resources', null, ['bad-ips.data' => "192.0.2.1\n", 'blocked' => 'a file where the cache directory should be']);
        $matcher = BadIpListMatcher::fromDataFile($root->url() . '/bad-ips.data');
        $matcher->useCompiledDataCache(new CompiledDataCache($root->url() . '/blocked/cache'));

        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertFalse($matcher->match($this->requestFrom('192.0.2.2'))->isMatch());
    }

    public function testDecidesLikeTheCoreIpMatcherOverTheSameList(): void
    {
        $content = "# header\n192.0.2.1\n::ffff:192.0.2.9\n203.0.113.0/24\n10.32.0.0/11\n::ffff:198.51.100.0/120\n2001:db8::/33\n2001:db8:ffff::1\nnot-an-address\n49.50.51.52\n\n";
        $root = vfsStream::setup('resources', null, ['bad-ips.data' => $content]);
        $dataFile = $root->url() . '/bad-ips.data';
        $compiledDataCache = new CompiledDataCache($root->url() . '/cache');

        $addresses = [
            '192.0.2.1', '192.0.2.2', '::ffff:192.0.2.1', '192.0.2.9', '203.0.113.255', '203.0.114.0', '10.31.255.255', '10.32.0.0',
            '10.63.255.255', '10.64.0.0', '198.51.100.77', '::ffff:198.51.100.77', '198.51.101.1', '2001:db8:7fff::1', '2001:db8:8000::1',
            '2001:db8:ffff::1', '2001:db9::1', '49.50.51.52', '49.50.51.53', 'not-an-address', '',
        ];

        $ipMatcher = new IpMatcher(BadIpList::load($dataFile));
        $withoutCache = BadIpListMatcher::fromDataFile($dataFile);
        $writesArtifact = BadIpListMatcher::fromDataFile($dataFile);
        $writesArtifact->useCompiledDataCache($compiledDataCache);

        $matched = 0;
        foreach ($addresses as $address) {
            $expected = $ipMatcher->match($this->requestFrom($address));
            $matched += (int) $expected->isMatch();
            foreach ([$withoutCache, $writesArtifact] as $matcher) {
                $actual = $matcher->match($this->requestFrom($address));
                $this->assertSame($expected->isMatch(), $actual->isMatch(), $address);
                $this->assertSame($expected->source(), $actual->source(), $address);
                $this->assertSame($expected->metadata(), $actual->metadata(), $address);
            }
        }

        $this->assertSame(11, $matched);

        CompiledDataCache::clearProcessCache();
        $readsArtifact = BadIpListMatcher::fromDataFile($dataFile);
        $readsArtifact->useCompiledDataCache($compiledDataCache);
        foreach ($addresses as $address) {
            $this->assertSame($ipMatcher->match($this->requestFrom($address))->isMatch(), $readsArtifact->match($this->requestFrom($address))->isMatch(), $address);
        }
    }

    public function testTheClientIpComesFromTheGivenResolver(): void
    {
        $root = vfsStream::setup('resources', null, ['bad-ips.data' => "192.0.2.1\n"]);
        $matcher = BadIpListMatcher::fromDataFile($root->url() . '/bad-ips.data');
        $request = $this->requestFrom('8.8.8.8');

        $matchResult = $matcher->matchWithResolver($request, static fn(): string => '192.0.2.1');
        $this->assertTrue($matchResult->isMatch());
        $this->assertSame('ip_match', $matchResult->source());
        $this->assertSame(['ip' => '192.0.2.1'], $matchResult->metadata());

        $this->assertFalse($matcher->matchWithResolver($request, static fn(): ?string => null)->isMatch());
        $this->assertFalse($matcher->match($request)->isMatch());
        $this->assertFalse($matcher->match(new ServerRequest('GET', 'https://example.test/'))->isMatch());
    }

    public function testTwoDataFilesNeverShareAnArtifact(): void
    {
        $root = vfsStream::setup('resources', null, ['one.data' => "192.0.2.1\n", 'two.data' => "192.0.2.2\n"]);
        foreach (['one.data', 'two.data'] as $name) {
            $root->getChild($name)->lastModified(1_000_000);
        }

        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        foreach ([1, 2] as $run) {
            CompiledDataCache::clearProcessCache();
            $one = BadIpListMatcher::fromDataFile($root->url() . '/one.data');
            $one->useCompiledDataCache($compiledDataCache);
            $two = BadIpListMatcher::fromDataFile($root->url() . '/two.data');
            $two->useCompiledDataCache($compiledDataCache);

            $this->assertTrue($one->match($this->requestFrom('192.0.2.1'))->isMatch(), 'run ' . $run);
            $this->assertFalse($one->match($this->requestFrom('192.0.2.2'))->isMatch(), 'run ' . $run);
            $this->assertTrue($two->match($this->requestFrom('192.0.2.2'))->isMatch(), 'run ' . $run);
            $this->assertFalse($two->match($this->requestFrom('192.0.2.1'))->isMatch(), 'run ' . $run);
        }

        $this->assertCount(2, $cacheDirectory->getChildren());
    }

    /**
     * An application that turns every warning into an exception, also the
     * ones silenced with `@`, must not lose the blocklist over it.
     */
    public function testRaisesNothingUnderAStrictErrorHandler(): void
    {
        $root = vfsStream::setup('resources', null, ['bad-ips.data' => "192.0.2.1\n203.0.113.0/24\n"]);
        $dataFile = $root->url() . '/bad-ips.data';
        $compiledDataCache = new CompiledDataCache($root->url() . '/cache');

        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });
        try {
            $decisions = [];
            // Without a cache, writing the artifact, reading it in a fresh process, reading it from the process cache.
            foreach ([false, true, true, true] as $run => $withCache) {
                if ($run < 3) {
                    CompiledDataCache::clearProcessCache();
                }

                $matcher = BadIpListMatcher::fromDataFile($dataFile);
                if ($withCache) {
                    $matcher->useCompiledDataCache($compiledDataCache);
                }

                $decisions[] = [
                    $matcher->match($this->requestFrom('192.0.2.1'))->isMatch(),
                    $matcher->match($this->requestFrom('203.0.113.9'))->isMatch(),
                    $matcher->match($this->requestFrom('8.8.8.8'))->isMatch(),
                ];
            }
        } finally {
            restore_error_handler();
        }

        $this->assertSame(array_fill(0, 4, [true, true, false]), $decisions);
    }

    public function testCacheInjectedAfterAFirstMatchStillTakesEffect(): void
    {
        $root = vfsStream::setup('resources');
        $dataFile = vfsStream::newFile('bad-ips.data')->at($root)->setContent("192.0.2.1\n");
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        $matcher = BadIpListMatcher::fromDataFile($dataFile->url());

        // Match once WITHOUT a cache: the table is built from the data file.
        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertSame([], $cacheDirectory->getChildren(), 'No artifact without a cache.');

        // Injecting the cache afterwards must still activate it.
        $matcher->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertCount(1, $cacheDirectory->getChildren(), 'The cache injected late must write the artifact.');
        $this->assertFalse($matcher->match($this->requestFrom('192.0.2.2'))->isMatch());
    }

    private function identifier(string $dataFile): string
    {
        return 'bad-ips-v2-' . hash('sha256', $dataFile);
    }

    private function requestFrom(string $ip): ServerRequestInterface
    {
        return new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }
}
