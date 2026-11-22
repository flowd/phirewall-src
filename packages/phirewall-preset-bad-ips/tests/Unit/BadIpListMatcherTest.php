<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\Unit;

use Flowd\Phirewall\Matchers\IpMatcher;
use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetBadIps\BadIpList;
use Flowd\PhirewallPresetBadIps\BadIpListMatcher;
use Flowd\PhirewallPresetBadIps\Tests\TemporaryFiles;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class BadIpListMatcherTest extends TestCase
{
    use TemporaryFiles;

    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    public function testLoadsLazilyOnFirstMatchOnly(): void
    {
        // A missing data file must not throw at construction time ...
        $matcher = BadIpListMatcher::fromDataFile($this->temporaryPath('missing.data'));

        // ... but on first use.
        $this->expectException(\RuntimeException::class);
        $matcher->match($this->requestFrom('192.0.2.1'));
    }

    public function testMatchesListedIpsAndPassesOthers(): void
    {
        $matcher = BadIpListMatcher::fromDataFile($this->temporaryFile('bad-ips.data', "192.0.2.1\n203.0.113.0/24\n"));

        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertTrue($matcher->match($this->requestFrom('203.0.113.42'))->isMatch());
        $this->assertFalse($matcher->match($this->requestFrom('8.8.8.8'))->isMatch());
    }

    public function testAMissingDataFileThrowsWithACacheAsWithout(): void
    {
        $matcher = BadIpListMatcher::fromDataFile($this->temporaryPath('missing.data'));
        $matcher->useCompiledDataCache(new CompiledDataCache($this->temporaryPath('cache')));

        try {
            $matcher->match($this->requestFrom('192.0.2.1'));
            $this->fail('A missing data file must be reported.');
        } catch (\RuntimeException $runtimeException) {
            $this->assertStringContainsString('not found', $runtimeException->getMessage());
        }

        $this->assertFileDoesNotExist($this->temporaryPath('cache'), 'Nothing is cached for a file that is not there.');
    }

    public function testAMissingDataFileIsReportedBeforeTheClientIpIsLookedAt(): void
    {
        $matcher = BadIpListMatcher::fromDataFile($this->temporaryPath('missing.data'));

        $this->expectException(\RuntimeException::class);
        $matcher->matchWithResolver($this->requestFrom('192.0.2.1'), static fn(): ?string => null);
    }

    public function testCompiledDataCacheServesTheListWithoutReparsing(): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n", 1_000_000);

        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        $first = BadIpListMatcher::fromDataFile($dataFile);
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertCount(1, $this->entriesIn($cacheDirectory), 'One compiled artifact must be written.');

        // Corrupt the source while keeping its mtime and size: a fresh process
        // must be served entirely from the compiled artifact and never re-parse.
        $this->temporaryFile('bad-ips.data', "#nothing.\n", 1_000_000);
        CompiledDataCache::clearProcessCache();

        $second = BadIpListMatcher::fromDataFile($dataFile);
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertFalse($second->match($this->requestFrom('192.0.2.2'))->isMatch());
    }

    public function testAChangedDataFileRebuildsTheArtifact(): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n", 1_000_000);

        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        $first = BadIpListMatcher::fromDataFile($dataFile);
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());

        $this->temporaryFile('bad-ips.data', "203.0.113.7\n198.51.100.0/24\n", 1_000_100);

        // In the same process (a long-running worker building a new Config) ...
        $second = BadIpListMatcher::fromDataFile($dataFile);
        $second->useCompiledDataCache($compiledDataCache);
        $this->assertFalse($second->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertTrue($second->match($this->requestFrom('203.0.113.7'))->isMatch());
        $this->assertTrue($second->match($this->requestFrom('198.51.100.200'))->isMatch());

        // ... and in a fresh one, which finds the rebuilt artifact.
        CompiledDataCache::clearProcessCache();
        $this->temporaryFile('bad-ips.data', "#..........\n#..............\n", 1_000_100);

        $third = BadIpListMatcher::fromDataFile($dataFile);
        $third->useCompiledDataCache($compiledDataCache);
        $this->assertFalse($third->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertTrue($third->match($this->requestFrom('203.0.113.7'))->isMatch());
        $this->assertCount(1, $this->entriesIn($cacheDirectory), 'The artifact of a data file is replaced, not added to.');
    }

    public function testAChangedDataFileIsNoticedByAProcessThatLookedAtItLast(): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n", 1_000_000);

        $compiledDataCache = new CompiledDataCache($this->temporaryDirectory('cache'));

        // A long-running worker that builds a new Config: the second matcher is
        // served from the process, and the data file is the last file PHP asked
        // about, so PHP remembers its time and size.
        foreach ([1, 2] as $ignored) {
            $matcher = BadIpListMatcher::fromDataFile($dataFile);
            $matcher->useCompiledDataCache($compiledDataCache);
            $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        }

        // Replaced by another process, as an update is: PHP still remembers the
        // old time and size, and the matcher must not rely on that.
        $this->replaceFromAnotherProcess($dataFile, "203.0.113.7\n198.51.100.9\n", 1_000_100);

        $third = BadIpListMatcher::fromDataFile($dataFile);
        $third->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($third->match($this->requestFrom('203.0.113.7'))->isMatch());
        $this->assertFalse($third->match($this->requestFrom('192.0.2.1'))->isMatch());
    }

    public function testAnArtifactIsNotUsedForADataFileOfAnotherSize(): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n", 1_000_000);

        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        $first = BadIpListMatcher::fromDataFile($dataFile);
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());

        // Replaced by a file with the same modification time, as deployments
        // that set every file to one fixed time do.
        $this->temporaryFile('bad-ips.data', "203.0.113.7\n198.51.100.9\n", 1_000_000);
        CompiledDataCache::clearProcessCache();

        $second = BadIpListMatcher::fromDataFile($dataFile);
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match($this->requestFrom('203.0.113.7'))->isMatch());
        $this->assertTrue($second->match($this->requestFrom('198.51.100.9'))->isMatch());
        $this->assertFalse($second->match($this->requestFrom('192.0.2.1'))->isMatch());
    }

    public function testAnArtifactOfADataFileOfAnotherSizeIsReplaced(): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n", 1_000_000);

        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        $first = BadIpListMatcher::fromDataFile($dataFile);
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());

        // Another file with the same modification time, in a fresh process ...
        $this->temporaryFile('bad-ips.data', "203.0.113.7\n198.51.100.9\n", 1_000_000);
        CompiledDataCache::clearProcessCache();

        $second = BadIpListMatcher::fromDataFile($dataFile);
        $second->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($second->match($this->requestFrom('203.0.113.7'))->isMatch());

        // ... leaves an artifact that serves the next process on its own: the
        // source is now nothing but a comment of the same size and time.
        $this->temporaryFile('bad-ips.data', '#' . str_repeat('.', 23) . "\n", 1_000_000);
        CompiledDataCache::clearProcessCache();

        $third = BadIpListMatcher::fromDataFile($dataFile);
        $third->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($third->match($this->requestFrom('203.0.113.7'))->isMatch());
        $this->assertTrue($third->match($this->requestFrom('198.51.100.9'))->isMatch());
        $this->assertFalse($third->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertCount(1, $this->entriesIn($cacheDirectory), 'The artifact is replaced, not added to.');
    }

    /**
     * @param array<mixed> $artifact
     */
    #[DataProvider('unusableArtifacts')]
    public function testUnexpectedArtifactShapeFallsBackToParsingTheSource(array $artifact): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n203.0.113.0/24\n", 1_000_000);

        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        // Seed a parseable but unusable artifact under the identifier the
        // matcher will look up.
        $compiledDataCache->load($this->identifier($dataFile), [$dataFile], static fn(): array => $artifact);
        CompiledDataCache::clearProcessCache();

        $matcher = BadIpListMatcher::fromDataFile($dataFile);
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
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n203.0.113.0/24\n", 1_000_000);

        $compiledDataCache = new CompiledDataCache($this->temporaryPath('cache'));

        $crafted = ['size' => 25, 'exact' => [inet_pton('198.51.100.1') => true], 'networks' => []];
        $compiledDataCache->load($this->identifier($dataFile), [$dataFile], static fn(): array => $crafted);
        CompiledDataCache::clearProcessCache();

        $matcher = BadIpListMatcher::fromDataFile($dataFile);
        $matcher->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($matcher->match($this->requestFrom('198.51.100.1'))->isMatch());
        $this->assertFalse($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
    }

    public function testACorruptArtifactFallsBackToParsingTheSource(): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n", 1_000_000);

        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        $first = BadIpListMatcher::fromDataFile($dataFile);
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match($this->requestFrom('192.0.2.1'))->isMatch());

        $artifacts = $this->entriesIn($cacheDirectory);
        $this->assertCount(1, $artifacts);

        foreach (['<?php return [', '<?php return 7;', '', '<?php throw new \LogicException("broken");'] as $content) {
            file_put_contents($artifacts[0], $content);
            CompiledDataCache::clearProcessCache();

            $matcher = BadIpListMatcher::fromDataFile($dataFile);
            $matcher->useCompiledDataCache($compiledDataCache);

            $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch(), $content);
            $this->assertFalse($matcher->match($this->requestFrom('192.0.2.2'))->isMatch(), $content);
        }
    }

    public function testACacheDirectoryThatCannotBeWrittenStillMatches(): void
    {
        $matcher = BadIpListMatcher::fromDataFile($this->temporaryFile('bad-ips.data', "192.0.2.1\n"));
        $blocked = $this->temporaryFile('blocked', 'a file where the cache directory should be');
        $matcher->useCompiledDataCache(new CompiledDataCache($blocked . '/cache'));

        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertFalse($matcher->match($this->requestFrom('192.0.2.2'))->isMatch());
    }

    public function testDecidesLikeTheCoreIpMatcherOverTheSameList(): void
    {
        $content = "# header\n192.0.2.1\n::ffff:192.0.2.9\n203.0.113.0/24\n10.32.0.0/11\n::ffff:198.51.100.0/120\n2001:db8::/33\n2001:db8:ffff::1\nnot-an-address\n49.50.51.52\n\n";
        $dataFile = $this->temporaryFile('bad-ips.data', $content);
        $compiledDataCache = new CompiledDataCache($this->temporaryPath('cache'));

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
        $matcher = BadIpListMatcher::fromDataFile($this->temporaryFile('bad-ips.data', "192.0.2.1\n"));
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
        $oneFile = $this->temporaryFile('one.data', "192.0.2.1\n", 1_000_000);
        $twoFile = $this->temporaryFile('two.data', "192.0.2.2\n", 1_000_000);

        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        foreach ([1, 2] as $run) {
            CompiledDataCache::clearProcessCache();
            $one = BadIpListMatcher::fromDataFile($oneFile);
            $one->useCompiledDataCache($compiledDataCache);
            $two = BadIpListMatcher::fromDataFile($twoFile);
            $two->useCompiledDataCache($compiledDataCache);

            $this->assertTrue($one->match($this->requestFrom('192.0.2.1'))->isMatch(), 'run ' . $run);
            $this->assertFalse($one->match($this->requestFrom('192.0.2.2'))->isMatch(), 'run ' . $run);
            $this->assertTrue($two->match($this->requestFrom('192.0.2.2'))->isMatch(), 'run ' . $run);
            $this->assertFalse($two->match($this->requestFrom('192.0.2.1'))->isMatch(), 'run ' . $run);
        }

        $this->assertCount(2, $this->entriesIn($cacheDirectory));
    }

    /**
     * An application that turns every warning into an exception, also the
     * ones silenced with `@`, must not lose the blocklist over it.
     */
    public function testRaisesNothingUnderAStrictErrorHandler(): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n203.0.113.0/24\n");
        $compiledDataCache = new CompiledDataCache($this->temporaryPath('cache'));

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
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n");
        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        $matcher = BadIpListMatcher::fromDataFile($dataFile);

        // Match once WITHOUT a cache: the table is built from the data file.
        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertSame([], $this->entriesIn($cacheDirectory), 'No artifact without a cache.');

        // Injecting the cache afterwards must still activate it.
        $matcher->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($matcher->match($this->requestFrom('192.0.2.1'))->isMatch());
        $this->assertCount(1, $this->entriesIn($cacheDirectory), 'The cache injected late must write the artifact.');
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
