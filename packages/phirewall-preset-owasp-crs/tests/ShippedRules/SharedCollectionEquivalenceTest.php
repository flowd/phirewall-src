<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Rules that list the same targets share what they collect from a request,
 * and rules selected by the same tags share their filtered entries. Neither
 * may change what a rule sees: evaluated together, the rules must match
 * exactly the requests they match when each is evaluated alone, where there
 * is nothing to share.
 */
final class SharedCollectionEquivalenceTest extends TestCase
{
    private const PARANOIA_LEVEL = 2;

    /** @var array<string, CoreRuleSet> */
    private static array $together = [];

    /** @var array<string, array<int, CoreRuleSet>> */
    private static array $alone = [];

    protected function setUp(): void
    {
        if (!is_file(RuleSetLoader::defaultRulesDirectory() . '/manifest.json')) {
            self::markTestSkipped('No imported CRS rules present. Run bin/crs-import first.');
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::$together = [];
        self::$alone = [];
    }

    /**
     * Tuning of every kind: for all rules, by tag (also two tags on the same
     * rules), by id, with a condition, a manipulator, and exclusion rules that
     * are armed per request.
     */
    private function tune(CoreRuleSet $coreRuleSet): void
    {
        $coreRuleSet->excludeTarget('REQUEST_COOKIES:session');
        $coreRuleSet->excludeTarget('ARGS:/^utm_/');
        $coreRuleSet->excludeTargetByTag('attack-sqli', 'ARGS:q');
        $coreRuleSet->excludeTargetByTag('attack-sqli', 'ARGS:id', static fn(string $variable, ?string $name, string $value): bool => strlen($value) < 12);
        $coreRuleSet->excludeTargetByTag('OWASP_CRS', 'ARGS:comment', static fn(string $variable, ?string $name, string $value): bool => !str_contains($value, '<'));
        $coreRuleSet->excludeTargetByTag('attack-xss', 'REQUEST_HEADERS:Referer');
        $coreRuleSet->excludeTargetById(942100, 'ARGS:search');
        $coreRuleSet->excludeTargetById(941100, 'ARGS');
        $coreRuleSet->addManipulatorById(932160, static fn(string $variable, ?string $name, string $value): string => str_replace('/bin/', '', $value));
        $coreRuleSet->applyRuleExclusions(<<<'RULES'
            SecRuleUpdateTargetByTag attack-lfi "!ARGS:file"
            SecRuleUpdateTargetById 930120 "!ARGS:path"
            SecRule REQUEST_URI "@beginsWith /admin" "id:9000001,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:filter"
            SecRule REQUEST_URI "@beginsWith /api" "id:9000002,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:query"
            RULES);
    }

    private function together(bool $tuned): CoreRuleSet
    {
        $key = $tuned ? 'tuned' : 'plain';
        if (!isset(self::$together[$key])) {
            self::$together[$key] = Presets::coreRuleSet(ParanoiaLevel::from(self::PARANOIA_LEVEL));
            if ($tuned) {
                $this->tune(self::$together[$key]);
            }
        }

        return self::$together[$key];
    }

    /**
     * @return array<int, CoreRuleSet> One rule set per rule, by rule id.
     */
    private function alone(bool $tuned): array
    {
        $key = $tuned ? 'tuned' : 'plain';
        if (!isset(self::$alone[$key])) {
            self::$alone[$key] = [];
            $all = Presets::coreRuleSet(ParanoiaLevel::from(self::PARANOIA_LEVEL));
            foreach ($all->ids() as $id) {
                $rule = $all->getRule($id);
                $this->assertInstanceOf(CoreRule::class, $rule);
                $single = new CoreRuleSet([$rule]);
                if ($tuned) {
                    $this->tune($single);
                }

                self::$alone[$key][$id] = $single;
            }
        }

        return self::$alone[$key];
    }

    /**
     * @return iterable<string, array{ServerRequestInterface}>
     */
    public static function requests(): iterable
    {
        foreach (['attack-requests.php', 'benign-requests.php'] as $fixture) {
            $path = __DIR__ . '/../Fixtures/' . $fixture;
            if (!is_file($path)) {
                continue;
            }

            /** @var list<array{method: string, uri: string, headers: array<string, string>, cookies: array<string, string>, body: array<string, string>|null}> $descriptors */
            $descriptors = require $path;
            foreach ($descriptors as $position => $descriptor) {
                $request = new ServerRequest($descriptor['method'], $descriptor['uri']);
                foreach ($descriptor['headers'] as $name => $value) {
                    $request = $request->withHeader($name, $value);
                }

                parse_str((string) parse_url($descriptor['uri'], PHP_URL_QUERY), $query);
                $request = $request->withQueryParams($query)->withCookieParams($descriptor['cookies']);
                if ($descriptor['body'] !== null) {
                    $request = $request->withParsedBody($descriptor['body']);
                }

                yield $fixture . ' #' . $position => [$request];
            }
        }

        // Requests that meet the tuning above: excluded, conditionally excluded, manipulated, armed per request.
        $sqli = "1' UNION SELECT username, password FROM users-- -";
        $xss = '<script>alert(document.cookie)</script>';
        foreach ([
            'q' => $sqli, 'id' => $sqli, 'search' => $sqli, 'comment' => $xss, 'utm_source' => $xss, 'file' => '../../../../etc/passwd',
            'path' => '/etc/passwd', 'filter' => $sqli, 'query' => $sqli, 'cmd' => '; /bin/cat /etc/passwd', 'other' => $sqli,
        ] as $name => $value) {
            foreach (['/', '/admin/list', '/api/items'] as $path) {
                yield 'tuning ' . $name . ' on ' . $path => [
                    (new ServerRequest('GET', 'https://example.test' . $path))->withQueryParams([$name => $value, 'page' => '2']),
                ];
            }
        }

        yield 'tuning short id' => [(new ServerRequest('GET', 'https://example.test/'))->withQueryParams(['id' => "1' or 1=1"])];
        yield 'tuning harmless comment' => [(new ServerRequest('GET', 'https://example.test/'))->withQueryParams(['comment' => "it's 1 or 1=1 --"])];
        yield 'tuning cookie' => [(new ServerRequest('GET', 'https://example.test/'))->withCookieParams(['session' => $sqli, 'other' => $xss])];
        yield 'tuning referer' => [(new ServerRequest('GET', 'https://example.test/'))->withHeader('Referer', 'https://example.test/?x=' . $xss)];
        yield 'a value beyond the inspection limit' => [(new ServerRequest('GET', 'https://example.test/'))->withQueryParams(['a' => 'fine', 'b' => str_repeat('x', 5000)])];
    }

    #[DataProvider('requests')]
    public function testRulesMatchTogetherWhatTheyMatchAlone(ServerRequestInterface $serverRequest): void
    {
        foreach ([false, true] as $tuned) {
            $together = $this->together($tuned)->evaluate($serverRequest, stopWhenThresholdReached: false);

            $expected = [];
            foreach ($this->alone($tuned) as $id => $single) {
                $evaluation = $single->evaluate($serverRequest, stopWhenThresholdReached: false);
                foreach ($evaluation->ruleMatches as $ruleMatch) {
                    $expected[$id] = [$ruleMatch->matchedVariableName, $ruleMatch->matchedValue, $ruleMatch->failClosed];
                }

                if ($evaluation->failClosed) {
                    break; // together, evaluation stops at the first rule that fails closed
                }
            }

            $actual = [];
            foreach ($together->ruleMatches as $ruleMatch) {
                $actual[$ruleMatch->ruleId] = [$ruleMatch->matchedVariableName, $ruleMatch->matchedValue, $ruleMatch->failClosed];
            }

            $this->assertSame($expected, $actual, $tuned ? 'with tuning' : 'without tuning');
        }
    }

    public function testTheCorpusExercisesTheTuning(): void
    {
        $sqli = "1' UNION SELECT username, password FROM users-- -";
        $matched = static fn(CoreRuleSet $coreRuleSet, string $path, string $name): array => $coreRuleSet
            ->evaluate((new ServerRequest('GET', 'https://example.test' . $path))->withQueryParams([$name => $sqli]), stopWhenThresholdReached: false)
            ->matchedRuleIds();

        $this->assertNotSame([], $matched($this->together(false), '/', 'q'));
        $this->assertNotSame($matched($this->together(false), '/', 'q'), $matched($this->together(true), '/', 'q'), 'The exclusion by tag is expected to change the result.');
        $this->assertNotSame($matched($this->together(true), '/', 'filter'), $matched($this->together(true), '/admin/x', 'filter'), 'The exclusion armed per request is expected to change the result.');
    }
}
