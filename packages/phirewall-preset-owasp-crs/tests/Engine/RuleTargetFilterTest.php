<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\RuleTargetFilter;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\CallableTargetExclusionCondition;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetExclusion;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

/**
 * Exclusions that name one member are found by that name, rules selected by
 * the same tags share their filtered entries. Neither may change which
 * entries are excluded: the reference here asks every exclusion for every
 * entry, as the filter did before.
 */
final class RuleTargetFilterTest extends TestCase
{
    /**
     * @param list<string> $variables
     * @param list<string> $tags
     */
    private function rule(int $id, array $variables = ['ARGS'], array $tags = []): CoreRule
    {
        return new CoreRule($id, $variables, '@contains', 'suspicious', ['deny' => true], null, 5, 'CRITICAL', 1, $tags);
    }

    /**
     * @param list<TargetExclusion> $exclusions
     * @param list<array{name: ?string, value: string}> $entries
     * @return list<array{name: ?string, value: string}>
     */
    private function askingEveryExclusion(array $exclusions, array $entries, ServerRequest $serverRequest): array
    {
        $kept = [];
        foreach ($entries as $entry) {
            foreach ($exclusions as $exclusion) {
                if ($exclusion->excludes($entry['name'], $entry['value'], $serverRequest)) {
                    continue 2;
                }
            }

            $kept[] = $entry;
        }

        return $kept;
    }

    public function testTheSameEntriesAreExcludedAsWhenEveryExclusionIsAsked(): void
    {
        $serverRequest = new ServerRequest('GET', '/');
        $onlyShort = new CallableTargetExclusionCondition(static fn(string $variable, ?string $name, string $value): bool => strlen($value) < 4);

        $selectorsByVariable = [
            'ARGS' => ['ARGS:token', 'ARGS:Token', 'ARGS:123', 'ARGS:0123', 'ARGS:a[b]', 'ARGS:/^utm_/', 'ARGS:/^TX_/i', 'ARGS:1.0', 'ARGS:-5', 'ARGS:'. str_repeat('n', 300)],
            'REQUEST_HEADERS' => ['REQUEST_HEADERS:X-Forwarded-For', 'REQUEST_HEADERS:x-token', 'REQUEST_HEADERS:/^x-ignore-/', 'REQUEST_HEADERS:123'],
            'REQUEST_COOKIES' => ['REQUEST_COOKIES:session', 'REQUEST_COOKIES:/^_ga/'],
        ];
        $names = [null, 'token', 'Token', 'TOKEN', '123', '0123', '+123', '123 ', 'a[b]', 'a', 'utm_source', 'UTM_source', 'tx_news', '1.0', '1', '-5', '5', '', str_repeat('n', 300),
            'X-Forwarded-For', 'x-forwarded-for', 'X-FORWARDED-FOR', 'X-Token', 'x-ignore-me', 'X-Ignore-Me', 'session', 'Session', '_ga_123', 'other'];

        foreach ($selectorsByVariable as $variable => $selectors) {
            $exclusions = [];
            foreach ($selectors as $position => $selector) {
                // Every other exclusion with a condition, and each selector a second time with the other choice.
                $exclusions[] = new TargetExclusion(TargetSelector::parseExclusion($selector), $position % 2 === 0 ? null : $onlyShort);
                $exclusions[] = new TargetExclusion(TargetSelector::parseExclusion($selector), $position % 2 === 0 ? $onlyShort : null);
            }

            $entries = [];
            foreach ($names as $name) {
                $entries[] = ['name' => $name, 'value' => 'abc'];
                $entries[] = ['name' => $name, 'value' => 'a longer value'];
            }

            foreach ([$exclusions, array_reverse($exclusions), array_slice($exclusions, 0, 3), array_slice($exclusions, 5)] as $subset) {
                $ruleTargetFilter = new RuleTargetFilter([$variable => array_values($subset)], []);

                $this->assertSame(
                    $this->askingEveryExclusion(array_values($subset), $entries, $serverRequest),
                    $ruleTargetFilter->apply($variable, $entries, $serverRequest),
                    $variable,
                );
                // The index is built on first use; a second call must not differ.
                $this->assertSame(
                    $this->askingEveryExclusion(array_values($subset), $entries, $serverRequest),
                    $ruleTargetFilter->apply($variable, $entries, $serverRequest),
                    $variable . ', second call',
                );
            }
        }
    }

    public function testAVariableWithoutExclusionsIsReturnedAsIs(): void
    {
        $ruleTargetFilter = new RuleTargetFilter(['ARGS' => [new TargetExclusion(TargetSelector::parseExclusion('ARGS:a'))]], []);
        $entries = [['name' => 'a', 'value' => 'x']];

        $this->assertSame($entries, $ruleTargetFilter->apply('REQUEST_COOKIES', $entries, new ServerRequest('GET', '/')));
        $this->assertSame([], $ruleTargetFilter->apply('ARGS', $entries, new ServerRequest('GET', '/')));
        $this->assertSame([], $ruleTargetFilter->apply('ARGS', [], new ServerRequest('GET', '/')));
    }

    public function testHeaderNamesAreFoundWithoutRegardToCase(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->rule(210001, ['REQUEST_HEADERS'])]);
        $coreRuleSet->excludeTarget('REQUEST_HEADERS:X-Trace');

        $excluded = (new ServerRequest('GET', '/'))->withHeader('x-TRACE', 'suspicious');
        $this->assertFalse($coreRuleSet->evaluate($excluded)->isBlocked());

        $inspected = (new ServerRequest('GET', '/'))->withHeader('X-Trace-Id', 'suspicious');
        $this->assertTrue($coreRuleSet->evaluate($inspected)->isBlocked());
    }

    public function testArgumentNamesAreFoundByTheirExactSpelling(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->rule(210002)]);
        $coreRuleSet->excludeTarget('ARGS:Comment')->excludeTarget('ARGS:123');

        $evaluate = static fn(string $name): bool => $coreRuleSet
            ->evaluate((new ServerRequest('GET', '/'))->withQueryParams([$name => 'suspicious']))
            ->isBlocked();

        $this->assertFalse($evaluate('Comment'));
        $this->assertTrue($evaluate('comment'), 'Argument names are case-sensitive.');
        $this->assertFalse($evaluate('123'));
        $this->assertTrue($evaluate('0123'), 'A name that only reads like the same number is another name.');
    }

    public function testRulesWithTheSameTagsAskAConditionOncePerEntry(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->rule(210010, ['ARGS'], ['attack-sqli', 'OWASP_CRS']),
            $this->rule(210011, ['ARGS'], ['OWASP_CRS', 'attack-sqli']),
            $this->rule(210012, ['ARGS'], ['attack-sqli', 'OWASP_CRS', 'paranoia-level/1']),
            $this->rule(210013, ['ARGS'], ['attack-xss', 'OWASP_CRS']),
        ]);
        $asked = [];
        $coreRuleSet->excludeTargetByTag('attack-sqli', 'ARGS:comment', static function (string $variable, ?string $name, string $value) use (&$asked): bool {
            $asked[] = $name . '=' . $value;

            return true;
        });

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['comment' => 'suspicious', 'q' => 'fine']);
        $evaluation = $coreRuleSet->evaluate($request, stopWhenThresholdReached: false);

        $this->assertSame([210013], $evaluation->matchedRuleIds(), 'Only the rule without the tag still inspects the parameter.');
        // Once for the value and once for the injected name entry, not once per rule.
        $this->assertSame(['comment=suspicious', 'comment=comment'], $asked);
    }

    public function testExclusionsAreAskedInTheOrderTheyWereRegistered(): void
    {
        $asked = [];
        $condition = static function (string $label, bool $answer) use (&$asked): \Closure {
            return static function () use (&$asked, $label, $answer): bool {
                $asked[] = $label;

                return $answer;
            };
        };

        // A whole-variable exclusion registered first settles every entry: what follows is never asked.
        $coreRuleSet = new CoreRuleSet([$this->rule(210060, ['ARGS'], ['t'])]);
        $coreRuleSet->excludeTargetByTag('t', 'ARGS');
        $coreRuleSet->excludeTargetByTag('t', 'ARGS:q', static fn(): bool => throw new \LogicException('must not be asked'));
        $this->assertSame([], $coreRuleSet->evaluate((new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']))->matchedRuleIds());

        // By name, by pattern and for the whole variable, mixed: asked as registered, up to the first that excludes.
        $coreRuleSet = new CoreRuleSet([$this->rule(210061, ['ARGS'], ['t'])]);
        $coreRuleSet->excludeTargetByTag('t', 'ARGS:/^q/', $condition('pattern', false));
        $coreRuleSet->excludeTargetByTag('t', 'ARGS:q', $condition('name', false));
        $coreRuleSet->excludeTargetByTag('t', 'ARGS', $condition('whole', true));
        $coreRuleSet->excludeTargetByTag('t', 'ARGS:q', $condition('name again', true));

        $evaluation = $coreRuleSet->evaluate((new ServerRequest('GET', '/'))->withQueryParams(['q' => 'suspicious']), stopWhenThresholdReached: false);

        $this->assertSame([], $evaluation->matchedRuleIds());
        // Once for the value and once for the name entry.
        $this->assertSame(['pattern', 'name', 'whole', 'pattern', 'name', 'whole'], $asked);
    }

    public function testRulesThatListTheirTagsInAnotherOrderAskInTheirOwnOrder(): void
    {
        $asked = [];
        $coreRuleSet = new CoreRuleSet([
            $this->rule(210070, ['ARGS'], ['a', 'b']),
            $this->rule(210071, ['ARGS'], ['b', 'a']),
        ]);
        $coreRuleSet->excludeTargetByTag('a', 'ARGS:q', static function () use (&$asked): bool {
            $asked[] = 'a';

            return true;
        });
        $coreRuleSet->excludeTargetByTag('b', 'ARGS:q', static function () use (&$asked): bool {
            $asked[] = 'b';

            return true;
        });

        $coreRuleSet->evaluate((new ServerRequest('GET', '/'))->withQueryParams(['q' => 'x']), stopWhenThresholdReached: false);

        // Each rule asks the exclusions of its first tag first; value and name entry each.
        $this->assertSame(['a', 'a', 'b', 'b'], $asked);
    }

    public function testRulesWithDifferentTagsDoNotShareExclusions(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->rule(210020, ['ARGS'], ['attack-sqli']),
            $this->rule(210021, ['ARGS'], ['attack-sqli', 'attack-xss']),
            $this->rule(210022, ['ARGS'], ['attack-xss']),
            $this->rule(210023, ['ARGS'], []),
        ]);
        $coreRuleSet->excludeTargetByTag('attack-sqli', 'ARGS:a');
        $coreRuleSet->excludeTargetByTag('attack-xss', 'ARGS:b');

        $matched = static fn(string $name): array => $coreRuleSet
            ->evaluate((new ServerRequest('GET', '/'))->withQueryParams([$name => 'suspicious']), stopWhenThresholdReached: false)
            ->matchedRuleIds();

        $this->assertSame([210022, 210023], $matched('a'));
        $this->assertSame([210020, 210023], $matched('b'));
        $this->assertSame([210020, 210021, 210022, 210023], $matched('c'));
    }

    public function testExclusionsByIdAndByTagAddUp(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->rule(210030, ['ARGS'], ['attack-sqli']),
            $this->rule(210031, ['ARGS'], ['attack-sqli']),
        ]);
        $coreRuleSet->excludeTargetByTag('attack-sqli', 'ARGS:a');
        $coreRuleSet->excludeTargetById(210030, 'ARGS:b');

        $matched = static fn(string $name): array => $coreRuleSet
            ->evaluate((new ServerRequest('GET', '/'))->withQueryParams([$name => 'suspicious']), stopWhenThresholdReached: false)
            ->matchedRuleIds();

        $this->assertSame([], $matched('a'));
        $this->assertSame([210031], $matched('b'), 'The exclusion by id belongs to one rule only.');
        $this->assertSame([210030, 210031], $matched('c'));
    }

    public function testAnExclusionByTagAddedBetweenRequestsTakesEffect(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->rule(210040, ['ARGS'], ['attack-sqli']),
            $this->rule(210041, ['ARGS'], ['attack-sqli']),
        ]);
        $coreRuleSet->excludeTargetByTag('attack-sqli', 'ARGS:a');

        $request = (new ServerRequest('GET', '/'))->withQueryParams(['b' => 'suspicious']);

        $this->assertSame([210040, 210041], $coreRuleSet->evaluate($request, stopWhenThresholdReached: false)->matchedRuleIds());

        $coreRuleSet->excludeTargetByTag('attack-sqli', 'ARGS:b');

        $this->assertSame([], $coreRuleSet->evaluate($request, stopWhenThresholdReached: false)->matchedRuleIds());
    }

    public function testEachRequestIsFilteredOnItsOwn(): void
    {
        $coreRuleSet = new CoreRuleSet([$this->rule(210050, ['ARGS'], ['attack-sqli']), $this->rule(210051, ['ARGS'], ['attack-sqli'])]);
        $coreRuleSet->excludeTargetByTag('attack-sqli', 'ARGS:a', static fn(string $variable, ?string $name, string $value): bool => $value !== 'suspicious');

        $first = (new ServerRequest('GET', '/'))->withQueryParams(['a' => 'harmless']);
        $second = (new ServerRequest('GET', '/'))->withQueryParams(['a' => 'suspicious']);

        $this->assertSame([], $coreRuleSet->evaluate($first, stopWhenThresholdReached: false)->matchedRuleIds());
        $this->assertSame([210050, 210051], $coreRuleSet->evaluate($second, stopWhenThresholdReached: false)->matchedRuleIds());
        $this->assertSame([], $coreRuleSet->evaluate($first, stopWhenThresholdReached: false)->matchedRuleIds());
    }
}
