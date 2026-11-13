<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * Factory that creates the appropriate operator evaluator based on the operator name.
 *
 * The phrase operators accept their phrases ready-made ({@see PhraseSet}), as
 * the compiled rule data delivers them; without, they parse the operand.
 *
 * A leading `!` negates a supported operator ({@see NegatedOperatorEvaluator}). Any other
 * operator is unsupported and gets the never-matching {@see UnsupportedOperatorEvaluator};
 * {@see isSupported()} lets loaders reject such rules visibly instead.
 */
final class OperatorEvaluatorFactory
{
    /**
     * Operators this engine implements (lowercased, without negation).
     */
    private const SUPPORTED_OPERATORS = [
        '@rx',
        '@contains',
        '@streq',
        '@startswith',
        '@beginswith',
        '@endswith',
        '@pm',
        '@pmfromfile',
    ];

    /**
     * Operators whose evaluator never matches an empty operand: negating such an operand
     * would match every value, so a negated empty operand stays never-matching instead.
     */
    private const NEVER_MATCHING_ON_EMPTY_OPERAND = ['@contains', '@startswith', '@beginswith', '@endswith'];

    /**
     * Whether the operator - optionally negated with a single leading `!` - is implemented.
     */
    public static function isSupported(string $operator): bool
    {
        if (str_starts_with($operator, '!')) {
            $operator = substr($operator, 1);
        }

        return in_array(strtolower($operator), self::SUPPORTED_OPERATORS, true);
    }

    public static function create(
        string $operator,
        string $operatorArgument,
        ?string $contextFolder = null,
        ?PhraseSet $phraseSet = null,
    ): OperatorEvaluatorInterface {
        if (str_starts_with($operator, '!')) {
            return self::createNegated(substr($operator, 1), $operatorArgument, $contextFolder);
        }

        return self::createEvaluator($operator, $operatorArgument, $contextFolder, $phraseSet);
    }

    private static function createEvaluator(
        string $operator,
        string $operatorArgument,
        ?string $contextFolder,
        ?PhraseSet $phraseSet = null,
    ): DetailedOperatorEvaluatorInterface {
        return match (strtolower($operator)) {
            '@rx' => new RegexEvaluator($operatorArgument),
            '@contains' => new ContainsEvaluator($operatorArgument),
            '@streq' => new StringEqualEvaluator($operatorArgument),
            '@startswith', '@beginswith' => new StartsWithEvaluator($operatorArgument),
            '@endswith' => new EndsWithEvaluator($operatorArgument),
            '@pm' => new PhraseMatchEvaluator($operatorArgument, $phraseSet),
            '@pmfromfile' => new PhraseMatchFromFileEvaluator($operatorArgument, $contextFolder, $phraseSet),
            default => new UnsupportedOperatorEvaluator(),
        };
    }

    /**
     * Negate the inner operator. An operand the inner evaluator deliberately never matches (a
     * pattern that does not compile, an empty needle or phrase list) is not a real "no match":
     * inverting it would match every value and block all traffic, so such a negated rule stays
     * never-matching like its non-negated form. A negated phrase operator always parses its
     * operand: the compiled rule data holds ready-made phrases for the plain operators only.
     */
    private static function createNegated(
        string $operator,
        string $operatorArgument,
        ?string $contextFolder,
    ): DetailedOperatorEvaluatorInterface {
        if (str_starts_with($operator, '!')) {
            return new UnsupportedOperatorEvaluator(); // no double negation in ModSecurity
        }

        $innerEvaluator = self::createEvaluator($operator, $operatorArgument, $contextFolder);
        $normalizedOperator = strtolower($operator);
        $neverMatchingOperand = $innerEvaluator instanceof UnsupportedOperatorEvaluator
            || ($innerEvaluator instanceof RegexEvaluator && !$innerEvaluator->patternCompiles())
            || ($operatorArgument === '' && in_array($normalizedOperator, self::NEVER_MATCHING_ON_EMPTY_OPERAND, true))
            || ($normalizedOperator === '@pm' && PhraseListParser::parse($operatorArgument) === []);

        return $neverMatchingOperand
            ? new UnsupportedOperatorEvaluator()
            : new NegatedOperatorEvaluator($innerEvaluator);
    }
}
