<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

/**
 * With a compiled-data cache, the phrases of `@pm` and `@pmFromFile` rules are
 * part of the compiled rule data: a request does not read the phrase files.
 */
final class CoreRuleSetMatcherCompiledPhrasesTest extends TestCase
{
    /**
     * %s is the phrase file, named differently in every test: phrase files
     * that are read when a rule is used are remembered per process.
     */
    private const RULES = <<<'RULES'
        SecRule REQUEST_URI "@pmFromFile %s" "id:410001,phase:2,deny,msg:'Phrase file'"
        SecRule REQUEST_URI "@pmFromFile other.txt" "id:410002,phase:2,deny,msg:'File that is not watched'"
        SecRule REQUEST_URI "@pm inline-one inline-two" "id:410003,phase:2,deny,msg:'Inline phrases'"
        RULES;

    private const RULES_DIRECTORY = 'vfs://crs/rules';

    private const CACHE_DIRECTORY = 'vfs://crs/cache';

    private static int $testNumber = 0;

    private string $phraseFile = '';

    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();

        vfsStream::setup('crs');
        mkdir(self::RULES_DIRECTORY);
        mkdir(self::CACHE_DIRECTORY);
        $this->phraseFile = self::RULES_DIRECTORY . '/phrases-' . ++self::$testNumber . '.data';
        $this->write(self::RULES_DIRECTORY . '/REQUEST-410-TEST.pl1.conf', sprintf(self::RULES, basename($this->phraseFile)), 1_000_000);
        $this->write($this->phraseFile, "# comment\nalpha\nBeta\nalpha\n", 1_000_000);
        $this->write(self::RULES_DIRECTORY . '/other.txt', "gamma\n", 1_000_000);
    }

    private function write(string $file, string $content, int $modified): void
    {
        file_put_contents($file, $content);
        touch($file, $modified);
    }

    /**
     * A matcher as a new request would build it: nothing kept from the one before.
     */
    private function matcher(bool $withCache = true): CoreRuleSetMatcher
    {
        clearstatcache();
        CompiledDataCache::clearProcessCache();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, self::RULES_DIRECTORY, null, 1);
        if ($withCache) {
            $matcher->useCompiledDataCache(new CompiledDataCache(self::CACHE_DIRECTORY));
        }

        return $matcher;
    }

    private function matchedRule(CoreRuleSetMatcher $coreRuleSetMatcher, string $path): ?int
    {
        $ruleId = $coreRuleSetMatcher->match(new ServerRequest('GET', $path))->metadata()['owasp_rule_id'] ?? null;

        return is_int($ruleId) ? $ruleId : null;
    }

    /**
     * The name under which the matcher keeps its compiled rules, and the files they are compiled from.
     * The name stands for one state of those files: their paths, times and sizes.
     *
     * @return array{0: string, 1: list<string>}
     */
    private function artifactIdentity(): array
    {
        clearstatcache();
        $sourceFiles = [...RuleSetLoader::ruleFiles(ParanoiaLevel::Level1, self::RULES_DIRECTORY), ...RuleSetLoader::dataFiles(self::RULES_DIRECTORY)];

        return ['owasp-crs-v3-pl1-' . RuleSetLoader::fingerprint($sourceFiles), $sourceFiles];
    }

    /**
     * @return array<mixed>
     */
    private function artifact(): array
    {
        [$identifier] = $this->artifactIdentity();
        CompiledDataCache::clearProcessCache();

        return (new CompiledDataCache(self::CACHE_DIRECTORY))->load($identifier, [], static function (): array {
            self::fail('The artifact is expected to exist.');
        });
    }

    public function testCachedAndUncachedMatchersAgree(): void
    {
        foreach (['/alpha' => 410001, '/x-BETA-y' => 410001, '/GAMMA' => 410002, '/Inline-Two' => 410003, '/nothing' => null] as $path => $expected) {
            $this->assertSame($expected, $this->matchedRule($this->matcher(false), $path), 'without cache: ' . $path);
            $this->assertSame($expected, $this->matchedRule($this->matcher(), $path), 'building the artifact: ' . $path);
            $this->assertSame($expected, $this->matchedRule($this->matcher(), $path), 'from the artifact: ' . $path);
        }
    }

    public function testTheArtifactCarriesPhrasesAndPrefilterOfWatchedFilesAndInlineLists(): void
    {
        $this->matchedRule($this->matcher(), '/');
        $phraseSets = array_column($this->artifact(), 'phraseSet', 'id');

        $this->assertSame(['phrases' => ['alpha', 'Beta'], 'prefilter' => '~(?:alpha|beta)~'], $phraseSets[410001] ?? null);
        $this->assertSame(['phrases' => ['inline-one', 'inline-two'], 'prefilter' => '~inline\-(?:one|two)~'], $phraseSets[410003] ?? null);
        $this->assertArrayNotHasKey(410002, $phraseSets, 'A file that is not watched for changes is not compiled in.');
    }

    public function testAWatchedPhraseFileIsNotReadAgain(): void
    {
        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/alpha'));

        // Other content of the same size and time: only reading the file would notice.
        $this->write($this->phraseFile, "# comment\ndelta\nBeta\ndelta\n", 1_000_000);

        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/alpha'));
        $this->assertNull($this->matchedRule($this->matcher(), '/delta'));
    }

    public function testAChangedPhraseFileIsNoticedEvenWhenAnotherFileIsNewer(): void
    {
        // The rule file is the newest source, before and after.
        $this->write(self::RULES_DIRECTORY . '/REQUEST-410-TEST.pl1.conf', sprintf(self::RULES, basename($this->phraseFile)), 3_000_000);
        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/alpha'));
        $this->assertNull($this->matchedRule($this->matcher(), '/delta'));

        // As a copy that keeps times would leave it: changed, with a time that is not the newest.
        $this->write($this->phraseFile, "alpha\ndelta\n", 2_000_000);

        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/delta'), 'A phrase that was added must be found.');

        $this->write($this->phraseFile, "gamma\n", 2_500_000);

        $this->assertNull($this->matchedRule($this->matcher(), '/alpha'), 'A phrase that was removed must be gone.');
        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/gamma'));
    }

    public function testAPhraseFileOfAnotherSizeIsNoticedEvenWhenItsTimeDidNotMove(): void
    {
        // Compiled while the file was only half written ...
        $this->write($this->phraseFile, "alp", 1_000_000);
        $this->assertNull($this->matchedRule($this->matcher(), '/beta'));

        // ... and completed within the same second.
        $this->write($this->phraseFile, "alpha\nbeta\n", 1_000_000);

        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/beta'));
    }

    public function testAChangedPhraseFileRebuildsTheArtifact(): void
    {
        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/alpha'));

        $this->write($this->phraseFile, "delta\n", 2_000_000);

        $this->assertNull($this->matchedRule($this->matcher(), '/alpha'));
        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/delta'));
    }

    public function testARemovedPhraseFileRebuildsTheArtifact(): void
    {
        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/alpha'));

        unlink($this->phraseFile);

        $this->assertNull($this->matchedRule($this->matcher(), '/alpha'), 'A rule without its file has no phrases, as without a cache.');
        $this->assertNull($this->matchedRule($this->matcher(false), '/alpha'));
    }

    public function testCompilingReadsThePhraseFileEvenWhenTheProcessRememberedIt(): void
    {
        // Without a cache the file is read when the rule is used, and remembered for the process.
        $this->assertSame(410001, $this->matchedRule($this->matcher(false), '/alpha'));

        $this->write($this->phraseFile, "delta\n", 2_000_000);

        // What is compiled outlives the process, so it has to be what the file says now.
        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/delta'));
        $this->assertNull($this->matchedRule($this->matcher(), '/alpha'));
    }

    public function testMalformedPhraseDataFallsBackToReparsing(): void
    {
        $this->matchedRule($this->matcher(), '/');
        $artifact = $this->artifact();
        foreach ($artifact as $position => $rule) {
            if (is_array($rule) && ($rule['id'] ?? null) === 410001) {
                // Half the phrases, and one that is not a string.
                $rule['phraseSet'] = ['phrases' => ['alpha', 7], 'prefilter' => null];
                $artifact[$position] = $rule;
            }
        }

        [$identifier] = $this->artifactIdentity();
        foreach (scandir(self::CACHE_DIRECTORY) ?: [] as $file) {
            if (is_file(self::CACHE_DIRECTORY . '/' . $file)) {
                unlink(self::CACHE_DIRECTORY . '/' . $file);
            }
        }

        CompiledDataCache::clearProcessCache();
        (new CompiledDataCache(self::CACHE_DIRECTORY))->load($identifier, [], static fn(): array => $artifact);

        $this->assertSame(410001, $this->matchedRule($this->matcher(), '/beta'), 'The rule must come from the source, with all its phrases.');
    }

    public function testAnUnsafeOperandStillFailsClosedWithACache(): void
    {
        $this->write(self::RULES_DIRECTORY . '/REQUEST-411-TEST.pl1.conf', 'SecRule REQUEST_URI "@pmFromFile ../outside.data" "id:411001,phase:2,deny"', 1_000_000);

        $uncached = $this->matcher(false)->match(new ServerRequest('GET', '/nothing'));
        $building = $this->matcher()->match(new ServerRequest('GET', '/nothing'));
        $cached = $this->matcher()->match(new ServerRequest('GET', '/nothing'));

        $this->assertTrue($uncached->isMatch());
        $this->assertSame($uncached->metadata(), $building->metadata());
        $this->assertSame($uncached->metadata(), $cached->metadata());
    }
}
