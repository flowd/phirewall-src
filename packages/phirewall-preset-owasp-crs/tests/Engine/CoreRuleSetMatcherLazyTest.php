<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Flowd\PhirewallPresetOwaspCrs\Tests\TemporaryFiles;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetMatcherLazyTest extends TestCase
{
    use TemporaryFiles;

    private const RULE_TEXT = "SecRule REQUEST_URI \"@rx ^/admin\\b\" \"id:400001,phase:2,deny,msg:'Block admin path'\"";

    private const RULE_FILE = 'rules/REQUEST-400-TEST.pl1.conf';

    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    /**
     * @return array{0: string, 1: string} The rules directory and the rule file in it.
     */
    private function rulesDirectory(): array
    {
        $ruleFile = $this->temporaryFile(self::RULE_FILE, self::RULE_TEXT, 1_000_000);

        return [dirname($ruleFile), $ruleFile];
    }

    /**
     * Puts rule data in the place of the artifact the matcher will read, as
     * made from the rule files as they are now.
     *
     * @param array<mixed> $rules
     */
    private function seedArtifact(CompiledDataCache $compiledDataCache, string $rulesDirectory, array $rules): void
    {
        clearstatcache();
        $artifact = [
            'sources' => RuleSetLoader::fingerprint(RuleSetLoader::ruleFiles(ParanoiaLevel::Level1, $rulesDirectory)),
            'rules' => $rules,
        ];
        $compiledDataCache->load('owasp-crs-v4-pl1-' . sha1($rulesDirectory), [], static fn(): array => $artifact);
        CompiledDataCache::clearProcessCache();
    }

    public function testLazyMatcherParsesOnFirstMatchOnly(): void
    {
        // An invalid directory must not throw at construction time ...
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $this->temporaryPath('missing'));

        // ... but on first use.
        $this->expectException(\InvalidArgumentException::class);
        $matcher->match(new ServerRequest('GET', '/admin'));
    }

    public function testLazyMatcherMatchesAndCarriesTheUsualMetadata(): void
    {
        [$rulesDir] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);

        $matchResult = $matcher->match(new ServerRequest('GET', '/admin'));

        $this->assertTrue($matchResult->isMatch());
        $meta = $matchResult->metadata();
        $this->assertSame(400001, $meta['owasp_rule_id'] ?? null);
        $this->assertSame([
            'X-Phirewall-Owasp-Rule' => '400001',
            'X-Phirewall-Owasp-Score' => '5/5',
        ], $meta['diagnostic_headers'] ?? null);
    }

    public function testAnomalyThresholdAndTuningAreAppliedOnTheLazyPath(): void
    {
        [$rulesDir] = $this->rulesDirectory();

        // Threshold 6 keeps the single CRITICAL rule (score 5) below the block line.
        $tolerant = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir, null, 6);
        $this->assertFalse($tolerant->match(new ServerRequest('GET', '/admin'))->isMatch());

        // Queued exclusion before first use silences the rule's only target.
        $tuned = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $tuned->excludeTargetById(400001, 'REQUEST_URI');
        $this->assertFalse($tuned->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testQueuedInvalidSelectorFailsEagerly(): void
    {
        [$rulesDir] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);

        $this->expectException(\InvalidArgumentException::class);

        $matcher->excludeTarget('QUERY_STRING:utm_source');
    }

    public function testQueuedNegatedSelectorFailsEagerly(): void
    {
        // A negated exclusion must be rejected at registration, not on the first
        // request: on the lazy path a first-request throw would be swallowed by a
        // fail-open middleware and silently disable the whole rule set.
        [$rulesDir] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('implicitly negated');

        $matcher->excludeTarget('!ARGS:sessionid');
    }

    public function testTogglesBeforeFirstUseAreQueuedAndApplied(): void
    {
        [$rulesDir] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);

        $matcher->disable(400001);

        $this->assertFalse($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertFalse($matcher->isEnabled(400001));

        $matcher->enable(400001);
        $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testCompiledDataCacheServesTheRulesWithoutReparsing(): void
    {
        [$rulesDir] = $this->rulesDirectory();
        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        $first = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertNotSame([], $this->entriesIn($cacheDirectory), 'The compiled artifact must be written.');

        // Corrupt the source while keeping its mtime and size: a fresh process
        // must be served entirely from the compiled artifact and never re-parse.
        $this->temporaryFile(self::RULE_FILE, str_pad('SecRule GARBAGE', strlen(self::RULE_TEXT), '#'), 1_000_000);
        CompiledDataCache::clearProcessCache();

        $second = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testUnexpectedArtifactShapeFallsBackToReparsing(): void
    {
        [$rulesDir] = $this->rulesDirectory();
        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        // Seed a parseable but malformed artifact (a rule entry without the
        // expected keys) under the identifier the matcher will look up.
        $this->seedArtifact($compiledDataCache, $rulesDir, [['not' => 'a valid rule']]);

        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $matcher->useCompiledDataCache($compiledDataCache);

        // The malformed artifact must be discarded and the source reparsed, so
        // the rule still matches instead of being silently dropped (fail-open).
        $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testEmptyArtifactWithRuleFilesFallsBackToReparsing(): void
    {
        [$rulesDir] = $this->rulesDirectory();
        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        // Seed a well-formed but EMPTY artifact under the matcher's identifier.
        $this->seedArtifact($compiledDataCache, $rulesDir, []);

        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $matcher->useCompiledDataCache($compiledDataCache);

        // Zero rules despite rule files present must not silently disable the
        // CRS - the source is reparsed and the rule still matches.
        $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testWrongElementTypesInArtifactFallBackToReparsing(): void
    {
        [$rulesDir] = $this->rulesDirectory();
        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);

        // A rule with the right keys/top-level types but a non-string element in
        // "variables" - type-invalid, so fromArray() must reject it.
        $this->seedArtifact($compiledDataCache, $rulesDir, [[
            'id' => 400001,
            'variables' => [123],
            'operator' => '@rx',
            'operatorArgument' => '^/admin',
            'actions' => ['deny' => true],
            'contextFolder' => null,
        ]]);

        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $matcher->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testTheSeededArtifactIsTheOneTheMatcherReads(): void
    {
        // Guards the fallback tests above: a wrong name or source state there would pass for the wrong reason.
        [$rulesDir] = $this->rulesDirectory();
        $compiledDataCache = new CompiledDataCache($this->temporaryDirectory('cache'));

        $this->seedArtifact($compiledDataCache, $rulesDir, [[
            'id' => 400002,
            'variables' => ['REQUEST_URI'],
            'operator' => '@rx',
            'operatorArgument' => '^/seeded',
            'actions' => ['deny' => true],
            'contextFolder' => null,
        ]]);

        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $matcher->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($matcher->match(new ServerRequest('GET', '/seeded'))->isMatch());
        $this->assertFalse($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testAnUnusableArtifactIsReplacedByOneThatServesTheNextProcess(): void
    {
        [$rulesDir] = $this->rulesDirectory();
        $cacheDirectory = $this->temporaryDirectory('cache');
        $compiledDataCache = new CompiledDataCache($cacheDirectory);
        $this->seedArtifact($compiledDataCache, $rulesDir, [['not' => 'a valid rule']]);

        $first = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match(new ServerRequest('GET', '/admin'))->isMatch());

        // The source is unreadable as rules now, with the same time and size:
        // the next process can only answer from the artifact.
        $this->temporaryFile(self::RULE_FILE, str_pad('SecRule GARBAGE', strlen(self::RULE_TEXT), '#'), 1_000_000);
        CompiledDataCache::clearProcessCache();

        $second = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertCount(1, $this->entriesIn($cacheDirectory), 'The artifact is replaced, not added to.');
    }

    public function testAChangedRuleFileIsNoticedByAProcessThatLookedAtItLast(): void
    {
        [$rulesDir, $ruleFile] = $this->rulesDirectory();
        $compiledDataCache = new CompiledDataCache($this->temporaryDirectory('cache'));

        // A long-running worker that builds a new Config: the second matcher is
        // served from the process, and the only rule file is the last file PHP
        // asked about, so PHP remembers its time and size.
        foreach ([1, 2] as $ignored) {
            $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
            $matcher->useCompiledDataCache($compiledDataCache);
            $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
        }

        // Replaced by another process, as an update is: PHP still remembers the
        // old time and size, and the matcher must not rely on that.
        $this->replaceFromAnotherProcess(
            $ruleFile,
            "SecRule REQUEST_URI \"@rx ^/private\\b\" \"id:400001,phase:2,deny,msg:'Block private path'\"",
            1_000_100,
        );

        $third = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $third->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($third->match(new ServerRequest('GET', '/private'))->isMatch());
        $this->assertFalse($third->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testEagerConstructionIgnoresTheCompiledDataCache(): void
    {
        [$rulesDir] = $this->rulesDirectory();
        $eager = new CoreRuleSetMatcher(
            RuleSetLoader::load(ParanoiaLevel::Level1, $rulesDir),
        );
        $eager->useCompiledDataCache(new CompiledDataCache($this->temporaryPath('cache')));

        $this->assertTrue($eager->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertFileDoesNotExist($this->temporaryPath('cache'), 'Eager matchers must not write artifacts.');
    }
}
