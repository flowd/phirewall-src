<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\Phirewall\Support\CompiledDataCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Spatie\TemporaryDirectory\TemporaryDirectory;

/**
 * The shipped rules served from the compiled-data cache (phrases and their
 * prefilters compiled in) must decide every request of the test corpora
 * exactly like the rules parsed from their files: same decision, same rule,
 * same matched value and log data.
 */
final class CompiledRulesEquivalenceTest extends TestCase
{
    /** One for all tests of the class: compiling the shipped rules takes a moment. */
    private static ?TemporaryDirectory $cacheDirectory = null;

    /** @var array<string, CoreRuleSetMatcher> */
    private static array $matchers = [];

    protected function setUp(): void
    {
        if (!is_file(RuleSetLoader::defaultRulesDirectory() . '/manifest.json')) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::$matchers = [];
        CompiledDataCache::clearProcessCache();
        self::$cacheDirectory?->delete();
        self::$cacheDirectory = null;
    }

    /**
     * @param int $anomalyThreshold 1 reports the first matching rule; the default decides like a site would.
     */
    private function matcher(int $paranoiaLevel, int $anomalyThreshold, bool $compiled): CoreRuleSetMatcher
    {
        $key = $paranoiaLevel . '/' . $anomalyThreshold . '/' . ($compiled ? 'compiled' : 'parsed');
        if (isset(self::$matchers[$key])) {
            return self::$matchers[$key];
        }

        $matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::from($paranoiaLevel), null, null, $anomalyThreshold);
        if ($compiled) {
            self::$cacheDirectory ??= TemporaryDirectory::make();
            $compiledDataCache = new CompiledDataCache(self::$cacheDirectory->path());
            // Build the artifact, then hydrate a second matcher from it as the next request would.
            $builder = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::from($paranoiaLevel), null, null, $anomalyThreshold);
            $builder->useCompiledDataCache($compiledDataCache);
            $builder->isEnabled(0);
            CompiledDataCache::clearProcessCache();
            $matcher->useCompiledDataCache($compiledDataCache);
        }

        return self::$matchers[$key] = $matcher;
    }

    private function assertSameDecision(ServerRequestInterface $serverRequest, int $paranoiaLevel, string $label): void
    {
        foreach ([1, CoreRuleSetMatcher::DEFAULT_ANOMALY_THRESHOLD] as $anomalyThreshold) {
            $parsed = $this->matcher($paranoiaLevel, $anomalyThreshold, false)->match($serverRequest);
            $compiled = $this->matcher($paranoiaLevel, $anomalyThreshold, true)->match($serverRequest);

            $this->assertSame($parsed->isMatch(), $compiled->isMatch(), sprintf('%s @ pl%d, threshold %d', $label, $paranoiaLevel, $anomalyThreshold));
            $this->assertSame($parsed->metadata(), $compiled->metadata(), sprintf('%s @ pl%d, threshold %d', $label, $paranoiaLevel, $anomalyThreshold));
        }
    }

    public function testTheCompiledRulesCarryPrefilters(): void
    {
        $this->matcher(1, 1, true);
        $withPrefilter = 0;
        foreach (glob(self::$cacheDirectory?->path() . '/*.php') ?: [] as $file) {
            $withPrefilter += substr_count((string) file_get_contents($file), "'prefilter' => '~");
        }

        $this->assertGreaterThanOrEqual(10, $withPrefilter, 'The phrase rules of the shipped set are expected to be compiled with a prefilter.');
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function rulePayloads(): iterable
    {
        $path = __DIR__ . '/../Fixtures/rule-payloads.php';
        if (!is_file($path)) {
            return;
        }

        /** @var array{payloads: array<int, array{vector: string, payload_base64: string}>} $fixtures */
        $fixtures = require $path;
        foreach ($fixtures['payloads'] as $id => $entry) {
            yield 'rule ' . $id => [$entry['vector'], (string) base64_decode($entry['payload_base64'], true)];
        }
    }

    #[DataProvider('rulePayloads')]
    public function testRulePayloadsAreDecidedAlike(string $vector, string $payload): void
    {
        $request = EveryRulePayloadTest::buildRequest($vector, $payload);

        foreach ([1, 4] as $paranoiaLevel) {
            $this->assertSameDecision($request, $paranoiaLevel, 'payload');
        }
    }

    /**
     * @return iterable<string, array{array{method: string, uri: string, headers?: array<string, string>, cookies?: array<string, string>, body?: array<string, string>|null}}>
     */
    public static function corpusRequests(): iterable
    {
        foreach (['attack-requests.php', 'benign-requests.php', 'known-evasions.php'] as $fixture) {
            $path = __DIR__ . '/../Fixtures/' . $fixture;
            if (!is_file($path)) {
                continue;
            }

            $descriptors = require $path;
            foreach (is_array($descriptors) ? $descriptors : [] as $position => $descriptor) {
                if (is_array($descriptor) && isset($descriptor['method'], $descriptor['uri'])) {
                    /** @var array{method: string, uri: string, headers?: array<string, string>, cookies?: array<string, string>, body?: array<string, string>|null, label?: string} $descriptor */
                    yield $fixture . ' #' . $position . ' ' . ($descriptor['label'] ?? '') => [$descriptor];
                }
            }
        }
    }

    /**
     * @param array{method: string, uri: string, headers?: array<string, string>, cookies?: array<string, string>, body?: array<string, string>|null} $descriptor
     */
    #[DataProvider('corpusRequests')]
    public function testCorpusRequestsAreDecidedAlike(array $descriptor): void
    {
        $request = new ServerRequest($descriptor['method'], $descriptor['uri']);
        foreach ($descriptor['headers'] ?? [] as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        $request = $request->withCookieParams($descriptor['cookies'] ?? []);

        parse_str((string) parse_url($descriptor['uri'], PHP_URL_QUERY), $query);
        $request = $request->withQueryParams($query);
        if (($descriptor['body'] ?? null) !== null) {
            $request = $request->withParsedBody($descriptor['body']);
        }

        foreach ([1, 2, 3, 4] as $paranoiaLevel) {
            $this->assertSameDecision($request, $paranoiaLevel, 'request');
        }
    }
}
