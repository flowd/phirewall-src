<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\RuleOutcome;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

/**
 * The operator of a rule reads each value after the rule's transformations
 * (`t:` actions), so a payload cannot hide from the rule behind an encoding
 * the rule itself undoes.
 */
final class CoreRuleTransformationTest extends TestCase
{
    public function testAPercentEncodedPathMatchesARuleThatDecodes(): void
    {
        $rule = $this->rule(['REQUEST_FILENAME'], '@pm', '.env .htaccess', ['urlDecodeUni']);

        $this->assertTrue($rule->matches(new ServerRequest('GET', 'https://example.test/.env')));
        $this->assertTrue($rule->matches(new ServerRequest('GET', 'https://example.test/%2eenv')));
        $this->assertTrue($rule->matches(new ServerRequest('GET', 'https://example.test/.htacces%73')));
        $this->assertFalse($rule->matches(new ServerRequest('GET', 'https://example.test/environment')));
    }

    public function testARuleWithoutTransformationsReadsTheValueAsCollected(): void
    {
        foreach ([[], ['none'], ['urlDecodeUni', 'none']] as $transformations) {
            $rule = $this->rule(['REQUEST_FILENAME'], '@contains', '.env', $transformations);

            $this->assertTrue($rule->matches(new ServerRequest('GET', 'https://example.test/.env')));
            $this->assertFalse($rule->matches(new ServerRequest('GET', 'https://example.test/%2eenv')));
        }
    }

    public function testTheRawQueryStringIsDecodedForTheRule(): void
    {
        $rule = $this->rule(['QUERY_STRING'], '@rx', '=https?://', ['urlDecodeUni']);

        $this->assertTrue($rule->matches(new ServerRequest('GET', 'https://example.test/?file=https://evil.example/x')));
        $this->assertTrue($rule->matches(new ServerRequest('GET', 'https://example.test/?file=https%3a%2f%2fevil.example/x')));
    }

    public function testAParameterIsDecodedOnceMoreThanPhpDid(): void
    {
        $rule = $this->rule(['ARGS'], '@contains', '<script', ['urlDecodeUni']);

        // What PHP hands over for "?q=%253Cscript": the value is still encoded once.
        $this->assertTrue($rule->matches($this->argsRequest('%3Cscript')));
    }

    public function testTransformationsRunInTheOrderOfTheRule(): void
    {
        $decodeFirst = $this->rule(['ARGS'], '@rx', '^<a>$', ['urlDecodeUni', 'htmlEntityDecode', 'lowercase']);
        $lowercaseFirst = $this->rule(['ARGS'], '@rx', '^<a>$', ['lowercase', 'urlDecodeUni', 'htmlEntityDecode']);

        $this->assertTrue($decodeFirst->matches($this->argsRequest('%26lt;%41&GT;')));
        // Lowercased first, "&gt;" is decoded - and the "A" appears only afterwards.
        $this->assertFalse($lowercaseFirst->matches($this->argsRequest('%26lt;%41&GT;')));
    }

    public function testTheMatchReportsTheValueTheOperatorRead(): void
    {
        $rule = $this->rule(['ARGS'], '@rx', '<script', ['urlDecodeUni', 'lowercase']);

        $result = $rule->evaluate($this->argsRequest('%3CSCRIPT%3E'));

        $this->assertSame(RuleOutcome::Matched, $result->outcome);
        $this->assertSame('ARGS:q', $result->matchedVariableName);
        $this->assertSame('<script>', $result->matchedValue);
        $this->assertSame(['<script'], $result->captures);
    }

    public function testADecodedByteAboveAsciiDoesNotFailTheRuleClosed(): void
    {
        $rule = $this->rule(['ARGS'], '@rx', 'M\xfcller', ['utf8toUnicode', 'urlDecodeUni']);

        $result = $rule->evaluate($this->argsRequest('Müller'));

        $this->assertSame(RuleOutcome::Matched, $result->outcome);
        $this->assertSame('Müller', $result->matchedValue);
        $this->assertSame(RuleOutcome::NoMatch, $rule->evaluate($this->argsRequest('Grüße aus Köln'))->outcome);
    }

    public function testAValueThatIsNotUtf8AndNotChangedStillFailsClosed(): void
    {
        $rule = $this->rule(['ARGS'], '@rx', 'attack', ['urlDecodeUni']);

        $this->assertSame(RuleOutcome::FailClosed, $rule->evaluate($this->argsRequest("M\xFCller"))->outcome);
    }

    public function testAValueATransformationEmptiesIsDropped(): void
    {
        $rule = $this->rule(['ARGS'], '@rx', '^$', ['removeWhitespace']);

        $this->assertSame(RuleOutcome::NoMatch, $rule->evaluate($this->argsRequest(" \t "))->outcome);
    }

    public function testATransformedValueBeyondTheInspectionLimitFailsClosed(): void
    {
        $rule = $this->rule(['ARGS:q'], '@contains', 'attack', ['utf8toUnicode']);
        // Within the limit as collected, six times as long as "%uHHHH".
        $value = str_repeat('ü', 400);

        $this->assertSame(RuleOutcome::NoMatch, $rule->evaluate($this->argsRequest($value), null, null, 2400)->outcome);

        $result = $rule->evaluate($this->argsRequest($value), null, null, 2399);
        $this->assertSame(RuleOutcome::FailClosed, $result->outcome);
        $this->assertSame('ARGS:q', $result->matchedVariableName);
    }

    public function testAMultiMatchRuleAlsoReadsTheValueBeforeEachTransformation(): void
    {
        $actions = ['deny' => true, 'multiMatch' => true];
        $transformations = ['urlDecodeUni', 'htmlEntityDecode'];
        $multiMatch = new CoreRule(1, ['ARGS'], '@rx', '^&lt;b$', $actions, transformations: $transformations);
        $lastOnly = new CoreRule(2, ['ARGS'], '@rx', '^&lt;b$', ['deny' => true], transformations: $transformations);

        // "&lt;b" exists after the first transformation only.
        $serverRequest = $this->argsRequest('%26lt;b');

        $result = $multiMatch->evaluate($serverRequest);
        $this->assertSame(RuleOutcome::Matched, $result->outcome);
        $this->assertSame('ARGS:q', $result->matchedVariableName);
        $this->assertSame('&lt;b', $result->matchedValue);
        $this->assertFalse($lastOnly->matches($serverRequest));

        $this->assertTrue((new CoreRule(3, ['ARGS'], '@rx', '^%26lt;b$', $actions, transformations: $transformations))->matches($serverRequest));
        $this->assertTrue((new CoreRule(4, ['ARGS'], '@rx', '^<b$', $actions, transformations: $transformations))->matches($serverRequest));
    }

    public function testARuleWithAnUnsupportedTransformationNeverMatches(): void
    {
        $rule = $this->rule(['ARGS'], '@contains', 'attack', ['urlDecodeUni', 'parityEven7bit']);

        $this->assertFalse($rule->matches($this->argsRequest('attack')));
    }

    public function testTheLoaderSkipsARuleWithAnUnsupportedTransformation(): void
    {
        $rules = <<<'RULES'
            SecRule ARGS "@contains attack" "id:1,phase:2,deny,t:none,t:urlDecodeUni"
            SecRule ARGS "@contains attack" "id:2,phase:2,deny,t:none,t:parityEven7bit"
            RULES;

        $this->assertSame([1], SecRuleLoader::fromString($rules)->ids());

        $report = SecRuleLoader::fromStringWithReport($rules);
        $this->assertSame(1, $report['parsed']);
        $this->assertSame(1, $report['skipped']);
        $this->assertSame([SecRuleLoader::SKIP_REASON_UNSUPPORTED_TRANSFORMATION => 1], $report['skippedByReason']);
        $this->assertSame([1], $report['rules']->ids());
    }

    public function testALoadedRuleAppliesTheTransformationsOfItsLine(): void
    {
        $coreRuleSet = SecRuleLoader::fromString(
            'SecRule REQUEST_URI "@rx (?i)unix:[^|]*\|" "id:921240,phase:1,block,capture,t:none,t:urlDecodeUni,t:lowercase"',
        );

        $this->assertSame([921240], $coreRuleSet->evaluate(new ServerRequest('GET', 'https://example.test/UNIX:/run/socket%7C/x'))->matchedRuleIds());
        $this->assertSame([], $coreRuleSet->evaluate(new ServerRequest('GET', 'https://example.test/unix/run/socket'))->matchedRuleIds());
    }

    public function testTransformationsSurviveTheCompiledData(): void
    {
        $rule = $this->rule(['REQUEST_FILENAME'], '@contains', '.env', ['none', 'urlDecodeUni']);

        $data = $rule->toArray();
        $this->assertSame(['none', 'urlDecodeUni'], $data['transformations']);

        $hydrated = CoreRule::fromArray($data);
        $this->assertSame(['none', 'urlDecodeUni'], $hydrated->transformations);
        $this->assertTrue($hydrated->matches(new ServerRequest('GET', 'https://example.test/%2eenv')));
    }

    public function testCompiledDataWithoutTransformationsIsARuleWithoutThem(): void
    {
        $data = $this->rule(['REQUEST_FILENAME'], '@contains', '.env', ['urlDecodeUni'])->toArray();
        unset($data['transformations']);

        $this->assertSame([], CoreRule::fromArray($data)->transformations);
    }

    public function testCompiledDataWithATransformationThatIsNoStringIsRejected(): void
    {
        $data = $this->rule(['ARGS'], '@contains', 'x', ['urlDecodeUni'])->toArray();
        $data['transformations'] = ['urlDecodeUni', 7];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('"transformations" must be a list of strings');

        CoreRule::fromArray($data);
    }

    public function testRulesWithTheSameTargetsAndOtherTransformationsReadTheirOwnValues(): void
    {
        $coreRuleSet = new CoreRuleSet([
            $this->rule(['ARGS'], '@rx', '^%3Cb$', [], 1),
            $this->rule(['ARGS'], '@rx', '^<b$', ['urlDecodeUni'], 2),
            $this->rule(['ARGS'], '@rx', '^<B$', ['urlDecodeUni', 'uppercase'], 3),
            $this->rule(['ARGS'], '@rx', '^<b$', ['urlDecodeUni'], 4),
            $this->rule(['ARGS'], '@rx', '^%3cb$', ['lowercase'], 5),
            $this->rule(['ARGS'], '@rx', '^<b$', ['lowercase'], 6),
        ]);

        $evaluation = $coreRuleSet->evaluate($this->argsRequest('%3Cb'), stopWhenThresholdReached: false);

        $this->assertSame([1, 2, 3, 4, 5], $evaluation->matchedRuleIds());
    }

    public function testBeyondTheMemoryForTransformedValuesRulesStillReadTheSame(): void
    {
        $first = $this->rule(['ARGS'], '@rx', '^<b>A+$', ['urlDecodeUni'], 1);
        $second = $this->rule(['ARGS'], '@rx', '^<b>A+$', ['urlDecodeUni'], 2);
        $third = $this->rule(['ARGS'], '@rx', '^<b>a+$', ['urlDecodeUni', 'lowercase'], 3);

        // Every value decodes to 2003 bytes; the memory for transformed values holds 2094 of them.
        $parameters = [];
        for ($index = 0; $index < 2200; ++$index) {
            $parameters['p' . $index] = '%3Cb%3E' . str_repeat('A', 2000 - strlen((string) $index)) . $index;
        }

        $serverRequest = (new ServerRequest('GET', 'https://example.test/'))->withQueryParams(['q' => '%3Cb%3EAAA'] + $parameters);
        $requestVariableValues = new RequestVariableValues($serverRequest, 10_000);

        $this->assertTrue($requestVariableValues->keepsTransformedValues());
        $this->assertTrue($first->matches($serverRequest, $requestVariableValues));
        $this->assertFalse($requestVariableValues->keepsTransformedValues());

        // Nothing more is kept; the rules transform the values again.
        $this->assertTrue($second->matches($serverRequest, $requestVariableValues));
        $this->assertTrue($third->matches($serverRequest, $requestVariableValues));
        $this->assertSame('<b>AAA', $second->evaluate($serverRequest, $requestVariableValues)->matchedValue);
    }

    /**
     * @param list<string> $variables
     * @param list<string> $transformations
     */
    private function rule(array $variables, string $operator, string $operatorArgument, array $transformations, int $id = 1): CoreRule
    {
        return new CoreRule($id, $variables, $operator, $operatorArgument, ['deny' => true], transformations: $transformations);
    }

    private function argsRequest(string $value): ServerRequest
    {
        return (new ServerRequest('GET', 'https://example.test/'))->withQueryParams(['q' => $value]);
    }
}
