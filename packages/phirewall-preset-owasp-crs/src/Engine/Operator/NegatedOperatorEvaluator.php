<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

use Flowd\PhirewallPresetOwaspCrs\Engine\RuleOutcome;

/**
 * A negated operator (`!@rx ...`, `!@streq ...`): like ModSecurity, the inner operator
 * runs against each value on its own and the result is inverted per value, so the rule
 * matches on the first value the inner operator does NOT match. No values means no
 * match (the operator never runs). A fail-closed inner result stays fail-closed - an
 * un-inspectable value is never turned into a "did not match" decision. A negated match
 * has no captures.
 */
final readonly class NegatedOperatorEvaluator implements DetailedOperatorEvaluatorInterface
{
    public function __construct(private DetailedOperatorEvaluatorInterface $innerEvaluator)
    {
    }

    /** @param list<string> $values */
    public function evaluate(array $values): bool
    {
        return $this->outcome($values) !== OperatorResult::noMatch();
    }

    /** @param list<string> $values */
    public function outcome(array $values): OperatorResult
    {
        foreach ($values as $index => $value) {
            $innerOutcome = $this->innerEvaluator->outcome([$value])->outcome;
            if ($innerOutcome === RuleOutcome::NoMatch) {
                return OperatorResult::matched($index);
            }

            if ($innerOutcome === RuleOutcome::FailClosed) {
                return OperatorResult::failClosed($index);
            }
        }

        return OperatorResult::noMatch();
    }
}
