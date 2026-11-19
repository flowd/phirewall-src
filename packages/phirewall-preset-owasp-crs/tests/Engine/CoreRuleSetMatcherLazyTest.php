<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use org\bovigo\vfs\vfsStreamDirectory;
use org\bovigo\vfs\vfsStreamFile;
use PHPUnit\Framework\TestCase;

final class CoreRuleSetMatcherLazyTest extends TestCase
{
    private const RULE_TEXT = "SecRule REQUEST_URI \"@rx ^/admin\\b\" \"id:400001,phase:2,deny,msg:'Block admin path'\"";

    protected function setUp(): void
    {
        CompiledDataCache::clearProcessCache();
    }

    /**
     * @return array{0: vfsStreamDirectory, 1: vfsStreamFile}
     */
    private function rulesDirectory(): array
    {
        $root = vfsStream::setup('crs');
        $rulesDirectory = vfsStream::newDirectory('rules')->at($root);
        $ruleFile = vfsStream::newFile('REQUEST-400-TEST.pl1.conf')->at($rulesDirectory)->setContent(self::RULE_TEXT);
        $ruleFile->lastModified(1_000_000);

        return [$root, $ruleFile];
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
        $compiledDataCache->load('owasp-crs-v3-pl1-' . sha1($rulesDirectory), [], static fn(): array => $artifact);
        CompiledDataCache::clearProcessCache();
    }

    public function testLazyMatcherParsesOnFirstMatchOnly(): void
    {
        // An invalid directory must not throw at construction time ...
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, 'vfs://crs/missing');

        // ... but on first use.
        vfsStream::setup('crs');
        $this->expectException(\InvalidArgumentException::class);
        $matcher->match(new ServerRequest('GET', '/admin'));
    }

    public function testLazyMatcherMatchesAndCarriesTheUsualMetadata(): void
    {
        [$root] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');

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
        [$root] = $this->rulesDirectory();

        // Threshold 6 keeps the single CRITICAL rule (score 5) below the block line.
        $tolerant = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules', null, 6);
        $this->assertFalse($tolerant->match(new ServerRequest('GET', '/admin'))->isMatch());

        // Queued exclusion before first use silences the rule's only target.
        $tuned = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');
        $tuned->excludeTargetById(400001, 'REQUEST_URI');
        $this->assertFalse($tuned->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testQueuedInvalidSelectorFailsEagerly(): void
    {
        [$root] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');

        $this->expectException(\InvalidArgumentException::class);

        $matcher->excludeTarget('QUERY_STRING:utm_source');
    }

    public function testQueuedNegatedSelectorFailsEagerly(): void
    {
        // A negated exclusion must be rejected at registration, not on the first
        // request: on the lazy path a first-request throw would be swallowed by a
        // fail-open middleware and silently disable the whole rule set.
        [$root] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('implicitly negated');

        $matcher->excludeTarget('!ARGS:sessionid');
    }

    public function testTogglesBeforeFirstUseAreQueuedAndApplied(): void
    {
        [$root] = $this->rulesDirectory();
        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');

        $matcher->disable(400001);

        $this->assertFalse($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertFalse($matcher->isEnabled(400001));

        $matcher->enable(400001);
        $this->assertTrue($matcher->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testCompiledDataCacheServesTheRulesWithoutReparsing(): void
    {
        [$root, $ruleFile] = $this->rulesDirectory();
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

        $first = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertNotSame([], $cacheDirectory->getChildren(), 'The compiled artifact must be written.');

        // Corrupt the source while keeping its mtime and size: a fresh process
        // must be served entirely from the compiled artifact and never re-parse.
        $ruleFile->setContent(str_pad('SecRule GARBAGE', strlen(self::RULE_TEXT), '#'));
        $ruleFile->lastModified(1_000_000);
        clearstatcache();
        CompiledDataCache::clearProcessCache();

        $second = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $root->url() . '/rules');
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match(new ServerRequest('GET', '/admin'))->isMatch());
    }

    public function testUnexpectedArtifactShapeFallsBackToReparsing(): void
    {
        [$root] = $this->rulesDirectory();
        $rulesDir = $root->url() . '/rules';
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

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
        [$root] = $this->rulesDirectory();
        $rulesDir = $root->url() . '/rules';
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

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
        [$root] = $this->rulesDirectory();
        $rulesDir = $root->url() . '/rules';
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());

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
        [$root] = $this->rulesDirectory();
        $rulesDir = $root->url() . '/rules';
        $compiledDataCache = new CompiledDataCache(vfsStream::newDirectory('cache')->at($root)->url());

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
        [$root, $ruleFile] = $this->rulesDirectory();
        $rulesDir = $root->url() . '/rules';
        $cacheDirectory = vfsStream::newDirectory('cache')->at($root);
        $compiledDataCache = new CompiledDataCache($cacheDirectory->url());
        $this->seedArtifact($compiledDataCache, $rulesDir, [['not' => 'a valid rule']]);

        $first = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $first->useCompiledDataCache($compiledDataCache);
        $this->assertTrue($first->match(new ServerRequest('GET', '/admin'))->isMatch());

        // The source is unreadable as rules now, with the same time and size:
        // the next process can only answer from the artifact.
        $ruleFile->setContent(str_pad('SecRule GARBAGE', strlen(self::RULE_TEXT), '#'));
        $ruleFile->lastModified(1_000_000);
        clearstatcache();
        CompiledDataCache::clearProcessCache();

        $second = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1, $rulesDir);
        $second->useCompiledDataCache($compiledDataCache);

        $this->assertTrue($second->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertCount(1, $cacheDirectory->getChildren(), 'The artifact is replaced, not added to.');
    }

    public function testEagerConstructionIgnoresTheCompiledDataCache(): void
    {
        [$root] = $this->rulesDirectory();
        $eager = new CoreRuleSetMatcher(
            RuleSetLoader::load(ParanoiaLevel::Level1, $root->url() . '/rules'),
        );
        $eager->useCompiledDataCache(new CompiledDataCache($root->url() . '/cache'));

        $this->assertTrue($eager->match(new ServerRequest('GET', '/admin'))->isMatch());
        $this->assertFalse($root->hasChild('cache'), 'Eager matchers must not write artifacts.');
    }
}
