<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine\Operator;

use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\NegatedOperatorEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorFactory;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\RegexEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\StringEqualEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\UnsupportedOperatorEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\RuleOutcome;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class NegatedOperatorEvaluatorTest extends TestCase
{
    public function testMatchesTheFirstValueTheInnerOperatorDoesNotMatch(): void
    {
        $evaluator = new NegatedOperatorEvaluator(new RegexEvaluator('^(?:GET|POST)$'));

        $result = $evaluator->outcome(['GET', 'PUT', 'DELETE']);

        $this->assertSame(RuleOutcome::Matched, $result->outcome);
        $this->assertSame(1, $result->matchedValueIndex);
        $this->assertSame([], $result->captures, 'A negated match has no captures');
    }

    public function testDoesNotMatchWhenTheInnerOperatorMatchesEveryValue(): void
    {
        $evaluator = new NegatedOperatorEvaluator(new StringEqualEvaluator('GET'));

        $this->assertSame(RuleOutcome::NoMatch, $evaluator->outcome(['GET', 'get'])->outcome);
        $this->assertFalse($evaluator->evaluate(['GET']));
    }

    public function testDoesNotMatchWithoutValues(): void
    {
        $evaluator = new NegatedOperatorEvaluator(new RegexEvaluator('^GET$'));

        $this->assertSame(RuleOutcome::NoMatch, $evaluator->outcome([])->outcome);
    }

    public function testInnerFailClosedStaysFailClosed(): void
    {
        // A value the regex engine cannot inspect must not turn into "did not match".
        $evaluator = new NegatedOperatorEvaluator(new RegexEvaluator('^GET$'));

        $result = $evaluator->outcome(['GET', "malformed \xC3 utf-8"]);

        $this->assertSame(RuleOutcome::FailClosed, $result->outcome);
        $this->assertSame(1, $result->matchedValueIndex);
    }

    public function testFactoryNegatesSupportedOperators(): void
    {
        $this->assertInstanceOf(NegatedOperatorEvaluator::class, OperatorEvaluatorFactory::create('!@rx', '^GET$'));
        $this->assertInstanceOf(NegatedOperatorEvaluator::class, OperatorEvaluatorFactory::create('!@streq', 'GET'));
        $this->assertInstanceOf(NegatedOperatorEvaluator::class, OperatorEvaluatorFactory::create('!@beginsWith', '/api/'));
        $this->assertInstanceOf(NegatedOperatorEvaluator::class, OperatorEvaluatorFactory::create('!@pm', 'a b'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function neverMatchingNegations(): iterable
    {
        yield 'unsupported operator' => ['!@ipMatch', '10.0.0.0/8'];
        yield 'double negation' => ['!!@rx', 'x'];
        yield 'regex that does not compile' => ['!@rx', '([unclosed'];
        yield 'empty contains needle' => ['!@contains', ''];
        yield 'empty prefix' => ['!@beginsWith', ''];
        yield 'empty suffix' => ['!@endsWith', ''];
        yield 'empty phrase list' => ['!@pm', ''];
    }

    #[DataProvider('neverMatchingNegations')]
    public function testFactoryKeepsNegatedNeverMatchingOperandsNeverMatching(string $operator, string $operand): void
    {
        // The non-negated form never matches these operands by design; inverting that would
        // match - and block - every value.
        $evaluator = OperatorEvaluatorFactory::create($operator, $operand);

        $this->assertInstanceOf(UnsupportedOperatorEvaluator::class, $evaluator);
        $this->assertFalse($evaluator->evaluate(['anything']));
    }

    public function testIsSupportedAcceptsSingleNegationOfImplementedOperatorsOnly(): void
    {
        $this->assertTrue(OperatorEvaluatorFactory::isSupported('@rx'));
        $this->assertTrue(OperatorEvaluatorFactory::isSupported('!@rx'));
        $this->assertTrue(OperatorEvaluatorFactory::isSupported('!@PmFromFile'));
        $this->assertFalse(OperatorEvaluatorFactory::isSupported('@ipMatch'));
        $this->assertFalse(OperatorEvaluatorFactory::isSupported('!@ipMatch'));
        $this->assertFalse(OperatorEvaluatorFactory::isSupported('!!@rx'));
    }
}
