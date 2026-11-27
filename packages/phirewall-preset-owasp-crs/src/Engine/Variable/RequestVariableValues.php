<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Flowd\Phirewall\Http\RequestView;
use Flowd\PhirewallPresetOwaspCrs\Engine\Transformation\TransformationPipeline;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Per-request memo for collected variable values.
 *
 * A single request is typically evaluated against many CRS rules, and several of
 * those rules target the same variable (e.g. ARGS or REQUEST_HEADERS). Deriving the
 * same request data once per rule re-runs getQueryParams()/getParsedBody(), re-flattens
 * headers and re-concatenates the URI N times. This memo collects each DISTINCT variable
 * exactly once per request — keyed by variable name — and shares the result across rules.
 *
 * Collected values per variable are capped at {@see $maxValuesPerCrsVariable} (default
 * {@see self::defaultMaxValuesPerCrsVariable()}) to bound the per-request evaluation cost of
 * attacker-controlled, count-unbounded variables (e.g. ARGS with thousands of parameters).
 * The cap is per variable, not aggregate, so padding one variable cannot short-circuit
 * evaluation of a rule that targets another. When a variable IS truncated, {@see wasCapped()}
 * reports it so callers can fail closed rather than silently evaluating a partial value set —
 * silent truncation would otherwise let an attacker push a payload past the cap to evade a
 * rule targeting that same variable.
 *
 * The values come from the {@see RequestView} of the request: those of the PSR-7 request,
 * then those of its server parameters the request does not hold. A query string, cookie
 * header or form body with more parameters than the view reads (or a form body with more
 * bytes) is un-inspectable in the same way, and the variables collected from it report
 * {@see wasCapped()} too.
 */
final class RequestVariableValues
{
    /**
     * Fallback per-variable value cap (= 2 × the conventional `max_input_vars` default of
     * 1000), used when PHP's `max_input_vars` is unavailable or non-positive.
     */
    public const DEFAULT_MAX_VALUES_PER_CRS_VARIABLE = 2000;

    /**
     * How many bytes of transformed values a request keeps for further rules,
     * see {@see transformed()}.
     */
    public const MAX_KEPT_TRANSFORMED_BYTES = 4_194_304;

    /**
     * Collected entries cache keyed by variable name.
     *
     * @var array<string, list<array{name: ?string, value: string, isNameEntry?: bool}>>
     */
    private array $entriesByVariableName = [];

    /**
     * Names of variables whose collected values were truncated at the cap this request.
     *
     * @var array<string, true>
     */
    private array $cappedVariables = [];

    /**
     * What rules collected from this request, by the text of their target list.
     *
     * @var array<string, array{0: list<?string>, 1: list<string>, 2: int}>
     */
    private array $collections = [];

    /**
     * Values after the transformations of a rule, by the key of the pipeline and by the value as collected.
     *
     * @var array<string, array<string, string>>
     */
    private array $transformedValues = [];

    private int $keptTransformedBytes = 0;

    private bool $keepsTransformedValues = true;

    private readonly int $maxValuesPerCrsVariable;

    private readonly RequestView $requestView;

    /**
     * @param bool $inspectServerParameters False collects from the PSR-7 request alone; see
     *                                      {@see \Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet::inspectServerParameters()}.
     * @param bool $inspectBodiesWithoutContentType False reads a body as a form only when its content type says so; see
     *                                              {@see \Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet::inspectBodiesWithoutContentType()}.
     *
     * @throws \InvalidArgumentException When an explicit $maxValuesPerCrsVariable is not a positive
     *                                   integer. A non-positive cap would truncate every collected variable to (at most) nothing
     *                                   and mark it capped, making every deny rule fail closed — i.e. silently block all traffic.
     */
    public function __construct(
        private readonly ServerRequestInterface $serverRequest,
        ?int $maxValuesPerCrsVariable = null,
        bool $inspectServerParameters = true,
        private readonly bool $inspectBodiesWithoutContentType = true,
    ) {
        if ($maxValuesPerCrsVariable !== null && $maxValuesPerCrsVariable < 1) {
            throw new \InvalidArgumentException(
                sprintf('$maxValuesPerCrsVariable must be a positive integer, %d given.', $maxValuesPerCrsVariable),
            );
        }

        $this->maxValuesPerCrsVariable = $maxValuesPerCrsVariable ?? self::defaultMaxValuesPerCrsVariable();
        $this->requestView = $inspectServerParameters ? RequestView::of($serverRequest) : RequestView::ofPsr7Only($serverRequest);
    }

    /**
     * The request the values are collected from.
     */
    public function serverRequest(): ServerRequestInterface
    {
        return $this->serverRequest;
    }

    /**
     * Default per-variable value cap: twice PHP's `max_input_vars` directive. The cap counts
     * collected values, and variables such as ARGS emit both a name and a value per parameter
     * (~2 values per input var), so doubling max_input_vars sizes the budget to the parameter
     * count the runtime actually accepts — a request PHP can fully parse is never falsely
     * truncated (and thus never falsely fails closed). Falls back to
     * {@see self::DEFAULT_MAX_VALUES_PER_CRS_VARIABLE} when the directive is unset or non-positive
     * (e.g. `-1` / "unlimited"), where the firewall deliberately imposes its own floor rather
     * than inherit an unbounded budget that would defeat the DoS protection.
     */
    public static function defaultMaxValuesPerCrsVariable(): int
    {
        $configured = (int) ini_get('max_input_vars');

        return $configured > 0 ? $configured * 2 : self::DEFAULT_MAX_VALUES_PER_CRS_VARIABLE;
    }

    /**
     * The effective per-variable value cap in force for this request.
     */
    public function maxValuesPerCrsVariable(): int
    {
        return $this->maxValuesPerCrsVariable;
    }

    /**
     * Return the collected entries for the given variable name, collecting them once and
     * caching the result for subsequent rules. Unknown variable names yield an empty list.
     *
     * The per-variable cap counts entries and is applied here, before any exclusion or
     * manipulation: a request padded past the cap fails closed regardless of how many of
     * its entries a rule would later exclude.
     *
     * @return list<array{name: ?string, value: string, isNameEntry?: bool}>
     */
    public function entriesFor(string $variableName): array
    {
        if (isset($this->entriesByVariableName[$variableName])) {
            return $this->entriesByVariableName[$variableName];
        }

        $collector = VariableCollectorFactory::create($variableName, $this->inspectBodiesWithoutContentType);
        if (!$collector instanceof VariableCollectorInterface) {
            return $this->entriesByVariableName[$variableName] = [];
        }

        $collected = $collector->collect($this->serverRequest, $this->requestView);
        if (count($collected) > $this->maxValuesPerCrsVariable) {
            $collected = array_slice($collected, 0, $this->maxValuesPerCrsVariable);
            $this->cappedVariables[$variableName] = true;
        }

        $complete = match ($variableName) {
            'ARGS', 'ARGS_NAMES' => $this->requestView->queryParametersComplete() && $this->requestView->bodyParametersComplete($this->serverRequest, $this->inspectBodiesWithoutContentType),
            'REQUEST_COOKIES', 'REQUEST_COOKIES_NAMES' => $this->requestView->cookiesComplete(),
            default => true,
        };
        if (!$complete) {
            $this->cappedVariables[$variableName] = true;
        }

        return $this->entriesByVariableName[$variableName] = $collected;
    }

    /**
     * What a rule with this target list collected from the request, when a
     * rule with the same list already did: labels, values and the length of
     * the longest value. Rules that list the same targets see the same
     * values, so the list is worked out once per request.
     *
     * @internal Only valid without target exclusions and manipulators; with them {@see \Flowd\PhirewallPresetOwaspCrs\Engine\RuleTargetSession} keeps the collections.
     *
     * @return array{0: list<?string>, 1: list<string>, 2: int}|null
     */
    public function collection(string $targetList): ?array
    {
        return $this->collections[$targetList] ?? null;
    }

    /**
     * @internal
     *
     * @param array{0: list<?string>, 1: list<string>, 2: int} $collection
     */
    public function rememberCollection(string $targetList, array $collection): void
    {
        $this->collections[$targetList] = $collection;
    }

    /**
     * The values after the transformations of a rule, at the positions they
     * came at; null when none of them changes. Rules with the same transformations get the
     * result that was worked out for the first of them.
     *
     * A value the transformations change is a string of its own, and a large
     * request whose values they all change would be held once per kind of
     * rule. Up to {@see self::MAX_KEPT_TRANSFORMED_BYTES} of such strings are
     * kept; beyond that every rule transforms its values again, which costs
     * time and no memory, and {@see keepsTransformedValues()} says so.
     *
     * @internal
     *
     * @param list<string> $values
     * @return array<int, string>|null
     */
    public function transformed(TransformationPipeline $transformationPipeline, array $values): ?array
    {
        $known = &$this->transformedValues[$transformationPipeline->key];
        $known ??= [];

        $transformedValues = null;
        foreach ($values as $index => $value) {
            $transformed = $known[$value] ?? null;
            if ($transformed === null) {
                $transformed = $transformationPipeline->apply($value);
                if ($transformed === $value) {
                    $known[$value] = $value;
                    continue;
                }

                $length = strlen($transformed);
                if ($this->keptTransformedBytes + $length > self::MAX_KEPT_TRANSFORMED_BYTES) {
                    $this->keepsTransformedValues = false;
                } else {
                    $this->keptTransformedBytes += $length;
                    $known[$value] = $transformed;
                }
            } elseif ($transformed === $value) {
                continue;
            }

            $transformedValues ??= $values;
            $transformedValues[$index] = $transformed;
        }

        return $transformedValues;
    }

    /**
     * False once a transformed value was not kept: what is built from the
     * values of this request from then on must not be kept either.
     *
     * @internal
     */
    public function keepsTransformedValues(): bool
    {
        return $this->keepsTransformedValues;
    }

    /**
     * The collected values for the given variable name, without member-name attribution.
     *
     * @return list<string>
     */
    public function valuesFor(string $variableName): array
    {
        return array_column($this->entriesFor($variableName), 'value');
    }

    /**
     * Whether the named variable's values were truncated at the per-variable cap on this
     * request. Only meaningful once {@see valuesFor()} has been called for the variable —
     * callers that have collected the variable fail closed on a true result instead of
     * evaluating a partially-inspected value set.
     */
    public function wasCapped(string $variableName): bool
    {
        return isset($this->cappedVariables[$variableName]);
    }
}
