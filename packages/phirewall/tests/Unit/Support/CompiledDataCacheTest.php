<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use Flowd\Phirewall\Support\CompiledDataCache;
use PHPUnit\Framework\TestCase;

final class CompiledDataCacheTest extends TestCase
{
    use TemporaryFiles;

    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    /**
     * List the compiled artifacts in a directory.
     *
     * @return list<string>
     */
    private function compiledFiles(string $directory): array
    {
        $entries = @scandir($directory);
        if ($entries === false) {
            return [];
        }

        $files = [];
        foreach ($entries as $entry) {
            if (str_starts_with($entry, 'phirewall-') && str_ends_with($entry, '.php')) {
                $files[] = $directory . '/' . $entry;
            }
        }

        return $files;
    }

    /**
     * @param array<mixed> $data
     * @return array{0: callable(): array<mixed>, 1: object{count: int}}
     */
    private function countingBuilder(array $data = ['value' => 42]): array
    {
        $counter = new class () {
            public int $count = 0;
        };

        $builder = static function () use ($counter, $data): array {
            ++$counter->count;
            return $data;
        };

        return [$builder, $counter];
    }

    public function testBuildsOnceAndWritesTheCompiledArtifact(): void
    {
        $cache = new CompiledDataCache($this->temporaryPath());
        [$builder, $counter] = $this->countingBuilder();

        $first = $cache->load('crs-rules', [], $builder);
        $second = $cache->load('crs-rules', [], $builder);

        $this->assertSame(['value' => 42], $first);
        $this->assertSame(['value' => 42], $second);
        $this->assertSame(1, $counter->count);
        $this->assertCount(1, $this->compiledFiles($this->temporaryPath()));
    }

    public function testLoadsFromTheCompiledFileWithoutTheBuilder(): void
    {
        [$builder, $counter] = $this->countingBuilder(['ips' => ['203.0.113.9']]);
        (new CompiledDataCache($this->temporaryPath()))->load('bad-ips', [], $builder);
        $this->assertSame(1, $counter->count);

        // A fresh process: the compiled artifact must satisfy the load alone.
        CompiledDataCache::clearProcessCache();
        $data = (new CompiledDataCache($this->temporaryPath()))->load('bad-ips', [], static function (): array {
            throw new \LogicException('The builder must not run on a compiled-file hit.');
        });

        $this->assertSame(['ips' => ['203.0.113.9']], $data);
    }

    public function testAForgottenIdentifierIsBuiltAgain(): void
    {
        $cache = new CompiledDataCache($this->temporaryPath());
        [$builder, $counter] = $this->countingBuilder();
        $cache->load('bad-ips', [], $builder);
        $cache->load('crs-rules', [], $builder);
        $this->assertCount(2, $this->compiledFiles($this->temporaryPath()));

        $cache->forget('bad-ips');

        $this->assertCount(1, $this->compiledFiles($this->temporaryPath()), 'Only the artifact of the identifier is removed.');
        $this->assertSame(['value' => 1], $cache->load('bad-ips', [], static fn(): array => ['value' => 1]));
        $this->assertSame(['value' => 42], $cache->load('crs-rules', [], $builder));
        $this->assertSame(2, $counter->count, 'The other identifier is still served from the cache.');

        // A fresh process finds the artifact that was built after forgetting.
        CompiledDataCache::clearProcessCache();
        $this->assertSame(['value' => 1], $cache->load('bad-ips', [], static function (): array {
            throw new \LogicException('The builder must not run on a compiled-file hit.');
        }));
    }

    public function testForgettingWhatWasNeverBuiltDoesNothing(): void
    {
        (new CompiledDataCache($this->temporaryPath('missing')))->forget('bad-ips');

        $this->assertFileDoesNotExist($this->temporaryPath('missing'));
    }

    public function testRebuildsWhenASourceFileChanges(): void
    {
        $sourceFile = $this->temporaryFile('rules.conf', 'rule v1', 1_000_000);

        $cache = new CompiledDataCache($this->temporaryPath());
        [$builder, $counter] = $this->countingBuilder();

        $cache->load('rules', [$sourceFile], $builder);
        $this->assertSame(1, $counter->count);

        // Unchanged source: both the process cache and the artifact stay valid.
        $cache->load('rules', [$sourceFile], $builder);
        $this->assertSame(1, $counter->count);

        // A newer source mtime invalidates even the warm process cache.
        $this->temporaryFile('rules.conf', 'rule v1', 1_000_100);
        $cache->load('rules', [$sourceFile], $builder);
        $this->assertSame(2, $counter->count);
    }

    public function testCorruptCompiledFileFallsBackToTheBuilder(): void
    {
        [$builder, $counter] = $this->countingBuilder();
        (new CompiledDataCache($this->temporaryPath()))->load('rules', [], $builder);

        $compiledFiles = $this->compiledFiles($this->temporaryPath());
        $this->assertCount(1, $compiledFiles);
        file_put_contents($compiledFiles[0], '<?php this is not valid php');

        CompiledDataCache::clearProcessCache();
        $data = (new CompiledDataCache($this->temporaryPath()))->load('rules', [], $builder);

        $this->assertSame(['value' => 42], $data);
        $this->assertSame(2, $counter->count);
    }

    public function testWrongShapeArtifactFallsBackToTheBuilder(): void
    {
        [$builder, $counter] = $this->countingBuilder();
        (new CompiledDataCache($this->temporaryPath()))->load('rules', [], $builder);

        $compiledFiles = $this->compiledFiles($this->temporaryPath());
        $this->assertCount(1, $compiledFiles);

        // Parses fine, but data is not an array.
        file_put_contents($compiledFiles[0], "<?php return ['sourcesMtime' => 0, 'data' => 'not-an-array'];");
        CompiledDataCache::clearProcessCache();
        (new CompiledDataCache($this->temporaryPath()))->load('rules', [], $builder);
        $this->assertSame(2, $counter->count);

        // Parses fine, but the artifact is not the expected structure at all.
        file_put_contents($compiledFiles[0], '<?php return 42;');
        CompiledDataCache::clearProcessCache();
        (new CompiledDataCache($this->temporaryPath()))->load('rules', [], $builder);
        $this->assertSame(3, $counter->count);
    }

    public function testRebuildsWhenTheSourceMtimeMovesBackwards(): void
    {
        $sourceFile = $this->temporaryFile('rules.conf', 'rule v2', 1_000_100);

        $cache = new CompiledDataCache($this->temporaryPath());
        [$builder, $counter] = $this->countingBuilder();
        $cache->load('rules', [$sourceFile], $builder);
        $this->assertSame(1, $counter->count);

        // A rollback restores an OLDER mtime; the equality check must
        // still treat it as a change.
        $this->temporaryFile('rules.conf', 'rule v2', 1_000_000);
        $cache->load('rules', [$sourceFile], $builder);
        $this->assertSame(2, $counter->count);
    }

    public function testRejectsTopLevelObjects(): void
    {
        $cache = new CompiledDataCache($this->temporaryPath());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('plain data');
        $cache->load('rules', [], static fn(): array => [new \stdClass()]);
    }

    public function testUnwritableDirectoryStillServesTheData(): void
    {
        $directory = $this->temporaryPath();
        chmod($directory, 0o555);
        if (is_writable($directory)) {
            chmod($directory, 0o755);
            $this->markTestSkipped('This user writes to every directory, whatever its permissions (root).');
        }

        try {
            $cache = new CompiledDataCache($directory);
            [$builder, $counter] = $this->countingBuilder();

            $this->assertSame(['value' => 42], $cache->load('rules', [], $builder));
            $this->assertSame([], $this->compiledFiles($directory));

            // The process memoization still prevents a rebuild per call.
            $cache->load('rules', [], $builder);
            $this->assertSame(1, $counter->count);
        } finally {
            chmod($directory, 0o755);
        }
    }

    public function testMissingDirectoryIsCreatedForTheArtifact(): void
    {
        $cache = new CompiledDataCache($this->temporaryPath('nested/cache'));
        [$builder] = $this->countingBuilder();

        $cache->load('rules', [], $builder);

        $this->assertCount(1, $this->compiledFiles($this->temporaryPath('nested/cache')));
    }

    public function testRejectsObjectsInTheBuiltData(): void
    {
        $cache = new CompiledDataCache($this->temporaryPath());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('plain data');
        $cache->load('rules', [], static fn(): array => ['nested' => ['object' => new \stdClass()]]);
    }

    public function testIdentifiersAreSanitizedIntoDistinctFilesInsideTheDirectory(): void
    {
        $cache = new CompiledDataCache($this->temporaryPath());
        [$builder] = $this->countingBuilder();

        $cache->load('../escape/attempt', [], $builder);
        $cache->load('good.id', [], $builder);

        $compiledFiles = $this->compiledFiles($this->temporaryPath());
        $this->assertCount(2, $compiledFiles);
        $this->assertFileDoesNotExist($this->temporaryPath('escape'));
    }
}
