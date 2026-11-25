<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\DetailedOperatorEvaluatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorFactory;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\PhraseSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\Transformation\TransformationPipeline;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetSelector;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Minimal representation of a single OWASP CRS rule.
 * This is a pragmatic subset that supports common patterns (REQUEST_URI + @rx) and a few additional operators/variables.
 *
 * Variable collection is delegated to VariableCollectorInterface implementations.
 * Operator evaluation is delegated to OperatorEvaluatorInterface implementations.
 * Named selectors (`REQUEST_HEADERS:User-Agent`) restrict collection to that
 * member; negated selectors (`!REQUEST_HEADERS:Cookie`) exclude members from
 * the rule's bare selector of the same variable. Selectors of unsupported
 * variables (e.g. `XML:/*`) collect nothing (partial evaluation).
 *
 * The operator reads each collected value after the rule's transformations
 * (`t:urlDecodeUni`, `t:lowercase`, ...), see {@see TransformationPipeline}.
 * A rule that asks for a transformation the engine does not have never matches.
 */
final readonly class CoreRule
{
    /**
     * Default longest single collected value an operator inspects. A longer value
     * is un-inspectable and the rule fails closed: matching only a head window
     * would let a payload evade by padding past the limit (@rx), and the
     * phrase/substring operators would otherwise scan the whole value, turning
     * one oversized field into unbounded CPU. This mirrors the fail-closed
     * contract of the per-variable count cap in {@see RequestVariableValues}.
     * It also bounds worst-case regex backtracking, since no value longer than
     * this ever reaches the pattern. Override per rule set via
     * {@see CoreRuleSet::setMaxInspectableValueLength()}.
     */
    public const MAX_INSPECTABLE_VALUE_LENGTH = 2048;

    /** Resolved operator evaluator for this rule. */
    private OperatorEvaluatorInterface $operatorEvaluator;

    /**
     * Positive targets this rule inspects, parsed from {@see $variables}.
     *
     * @var list<TargetSelector>
     */
    private array $targets;

    /**
     * Negated selectors from the rule text, grouped by collection variable.
     *
     * @var array<string, list<TargetSelector>>
     */
    private array $textExclusions;

    /**
     * The target list as one text. Rules with the same text collect the same
     * values from a request, see {@see collect()}.
     */
    private string $targetList;

    /**
     * The rule's transformations; null when one of them is not supported.
     */
    private ?TransformationPipeline $transformationPipeline;

    /**
     * Whether the operator also reads the value as collected and after
     * every single transformation, not only after the last (`multiMatch`).
     */
    private bool $multiMatch;

    /**
     * The target list and the transformations as one text. Rules with the
     * same text hand the same values to their operator.
     */
    private string $transformedTargetList;

    /**
     * @param list<string> $variables
     * @param array<string, int|string|bool> $actions
     * @param list<string> $tags
     * @param PhraseSet|null $phraseSet The phrases of a `@pm` / `@pmFromFile` operator, ready-made as the compiled
     *                                  rule data delivers them; without, the operator parses its operand or reads its file.
     * @param list<string> $transformations The names of the rule's `t:` actions in the order they are written, `none` included.
     */
    public function __construct(
        public int $id,
        public array $variables, // list of variable identifiers (e.g., ['REQUEST_URI'])
        public string $operator, // e.g., '@rx', '@contains'
        public string $operatorArgument, // e.g., pattern for @rx or needle for @contains
        public array $actions, // parsed action map (e.g., ['phase' => '2', 'deny' => true, 'msg' => '...'])
        public ?string $contextFolder = null, // folder path for context (e.g., for @pmFromFile)
        public int $anomalyScore = 5, // rules without a recognizable severity score as CRITICAL (fail closed)
        public ?string $severity = null, // normalized severity name, null when the source had none
        public int $paranoiaLevel = 1,
        public array $tags = [],
        private ?PhraseSet $phraseSet = null,
        public array $transformations = [],
    ) {
        if ($anomalyScore < 1) {
            throw new \InvalidArgumentException(
                sprintf('$anomalyScore must be a positive integer, %d given.', $anomalyScore),
            );
        }

        if ($paranoiaLevel < 1 || $paranoiaLevel > 4) {
            throw new \InvalidArgumentException(
                sprintf('$paranoiaLevel must be between 1 and 4, %d given.', $paranoiaLevel),
            );
        }

        $this->operatorEvaluator = OperatorEvaluatorFactory::create(
            $this->operator,
            $this->operatorArgument,
            $this->contextFolder,
            $this->phraseSet,
        );

        $targets = [];
        $textExclusions = [];
        foreach ($variables as $variable) {
            $selector = TargetSelector::tryParse($variable);
            if (!$selector instanceof TargetSelector) {
                continue; // unsupported selector: collects nothing (partial evaluation)
            }

            if ($selector->negated) {
                $textExclusions[$selector->variable][] = $selector;
                continue;
            }

            $targets[] = $selector;
        }

        $this->targets = $targets;
        $this->textExclusions = $textExclusions;
        $this->targetList = serialize($variables);

        $multiMatch = false;
        foreach ($actions as $actionName => $actionValue) {
            if ($actionValue === true && strtolower($actionName) === 'multimatch') {
                $multiMatch = true;
            }
        }

        $this->multiMatch = $multiMatch;
        $this->transformationPipeline = TransformationPipeline::fromNames($transformations);
        $this->transformedTargetList = ($multiMatch ? 'm' : 't') . "\0" . $this->transformationPipeline?->key . "\0" . $this->targetList;
    }

    /**
     * The rule as var_export-able plain data for {@see \Flowd\Phirewall\Support\CompiledDataCache}.
     *
     * A rule that was given its phrases ready-made carries them along as "phraseSet".
     *
     * @return array{id: int, variables: list<string>, operator: string, operatorArgument: string, actions: array<string, int|string|bool>, contextFolder: ?string, anomalyScore: int, severity: ?string, paranoiaLevel: int, tags: list<string>, transformations: list<string>, phraseSet?: array{phrases: list<string>, prefilter: ?string}}
     */
    public function toArray(): array
    {
        $data = [
            'id' => $this->id,
            'variables' => $this->variables,
            'operator' => $this->operator,
            'operatorArgument' => $this->operatorArgument,
            'actions' => $this->actions,
            'contextFolder' => $this->contextFolder,
            'anomalyScore' => $this->anomalyScore,
            'severity' => $this->severity,
            'paranoiaLevel' => $this->paranoiaLevel,
            'tags' => $this->tags,
            'transformations' => $this->transformations,
        ];

        if ($this->phraseSet instanceof PhraseSet) {
            $data['phraseSet'] = $this->phraseSet->toArray();
        }

        return $data;
    }

    /**
     * Rebuild a rule from compiled-cache data. Reads defensively (the input is
     * a deserialized artifact, not necessarily trustworthy): missing keys use
     * `??` rather than emitting undefined-index warnings, and a value of the
     * wrong type raises an `InvalidArgumentException` for the caller to handle.
     *
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $id = $data['id'] ?? null;
        $variables = $data['variables'] ?? null;
        $operator = $data['operator'] ?? null;
        $operatorArgument = $data['operatorArgument'] ?? null;
        $actions = $data['actions'] ?? null;
        $contextFolder = $data['contextFolder'] ?? null;
        $anomalyScore = $data['anomalyScore'] ?? 5;
        $severity = $data['severity'] ?? null;
        $paranoiaLevel = $data['paranoiaLevel'] ?? 1;
        $tags = $data['tags'] ?? [];
        $transformations = $data['transformations'] ?? [];

        if (!is_int($id)
            || !is_array($variables)
            || !is_string($operator)
            || !is_string($operatorArgument)
            || !is_array($actions)
            || ($contextFolder !== null && !is_string($contextFolder))
            || !is_int($anomalyScore)
            || ($severity !== null && !is_string($severity))
            || !is_int($paranoiaLevel)
            || !is_array($tags)
            || !is_array($transformations)
        ) {
            throw new \InvalidArgumentException('Compiled CRS rule data has an unexpected shape.');
        }

        // Validate element types too: a wrong-typed value (e.g. a non-bool
        // actions['deny']) would otherwise hydrate a rule that never matches,
        // silently bypassing the fallback (fail-open).
        $validatedVariables = [];
        foreach ($variables as $variable) {
            if (!is_string($variable)) {
                throw new \InvalidArgumentException('Compiled CRS rule "variables" must be a list of strings.');
            }

            $validatedVariables[] = $variable;
        }

        $validatedActions = [];
        foreach ($actions as $actionName => $actionValue) {
            if (!is_string($actionName) || (!is_int($actionValue) && !is_string($actionValue) && !is_bool($actionValue))) {
                throw new \InvalidArgumentException('Compiled CRS rule "actions" must map string keys to int/string/bool values.');
            }

            $validatedActions[$actionName] = $actionValue;
        }

        $validatedTags = [];
        foreach ($tags as $tag) {
            if (!is_string($tag)) {
                throw new \InvalidArgumentException('Compiled CRS rule "tags" must be a list of strings.');
            }

            $validatedTags[] = $tag;
        }

        // A rule hydrated without one of its transformations would read other
        // values than the rule in the source.
        $validatedTransformations = [];
        foreach ($transformations as $transformation) {
            if (!is_string($transformation)) {
                throw new \InvalidArgumentException('Compiled CRS rule "transformations" must be a list of strings.');
            }

            $validatedTransformations[] = $transformation;
        }

        // Throws for phrase data of the wrong shape: a rule hydrated with half its
        // phrases would match less than the rule in the source.
        $phraseSet = isset($data['phraseSet']) ? PhraseSet::fromArray($data['phraseSet']) : null;

        return new self(
            $id,
            $validatedVariables,
            $operator,
            $operatorArgument,
            $validatedActions,
            $contextFolder,
            $anomalyScore,
            $severity,
            $paranoiaLevel,
            $validatedTags,
            $phraseSet,
            $validatedTransformations,
        );
    }

    /**
     * Evaluate the rule against the request; the boolean view of {@see evaluate()}.
     *
     * When evaluating many rules for the same request, pass a shared {@see RequestVariableValues}
     * memo so each distinct variable is collected only once across all rules.
     */
    public function matches(ServerRequestInterface $serverRequest, ?RequestVariableValues $requestVariableValues = null): bool
    {
        return $this->evaluate($serverRequest, $requestVariableValues)->outcome !== RuleOutcome::NoMatch;
    }

    /**
     * Evaluate the rule against the request with match detail (matched target,
     * matched value, operator captures) for scoring and logdata expansion.
     *
     * A {@see RuleTargetSession} applies runtime exclusions and manipulators to
     * the collected entries before the operator sees them; the rule's
     * transformations come after both.
     */
    public function evaluate(
        ServerRequestInterface $serverRequest,
        ?RequestVariableValues $requestVariableValues = null,
        ?RuleTargetSession $ruleTargetSession = null,
        int $maxInspectableValueLength = self::MAX_INSPECTABLE_VALUE_LENGTH,
    ): CoreRuleResult {
        // A non-positive limit would fail every non-empty value closed, silently blocking
        // all traffic. CoreRuleSet/CoreRuleSetMatcher already enforce this; enforce it here
        // too so a direct caller cannot pass 0/negative unnoticed.
        if ($maxInspectableValueLength < 1) {
            throw new \InvalidArgumentException(
                sprintf('$maxInspectableValueLength must be a positive integer, %d given.', $maxInspectableValueLength),
            );
        }

        // Only evaluate when rule is a blocking (deny) rule. Non-deny rules are ignored here.
        if (($this->actions['deny'] ?? false) !== true) {
            return CoreRuleResult::noMatch();
        }

        // A rule that asks for a transformation the engine does not have cannot be
        // evaluated as written. Like a rule with an unsupported operator it never matches.
        if (!$this->transformationPipeline instanceof TransformationPipeline) {
            return CoreRuleResult::noMatch();
        }

        $requestVariableValues ??= new RequestVariableValues($serverRequest);

        $collection = $this->collect($requestVariableValues, $ruleTargetSession);
        [$labels, $values, $longestValue] = $collection;

        // Fail closed: if a variable this rule inspects was truncated at the per-variable
        // cap, the dropped portion is un-inspectable, so treat the oversized request as a
        // match rather than letting a payload padded past the cap slip through unevaluated.
        foreach ($this->targets as $target) {
            if ($requestVariableValues->wasCapped($target->variable)) {
                return CoreRuleResult::failClosed($target->variable);
            }
        }

        // Fail closed on any single value longer than the inspection limit: its tail is
        // un-inspectable, so head-only matching would let a payload evade by padding, and
        // the phrase/substring operators would scan the full value at unbounded cost. This
        // also keeps oversized subjects away from the regex engine, bounding backtracking.
        if ($longestValue > $maxInspectableValueLength) {
            foreach ($values as $index => $value) {
                if (strlen($value) > $maxInspectableValueLength) {
                    return CoreRuleResult::failClosed($labels[$index] ?? null);
                }
            }
        }

        if ($values === []) {
            return CoreRuleResult::noMatch();
        }

        if (!$this->transformationPipeline->isEmpty()) {
            [$labels, $values, $longestValue] = $this->collect($requestVariableValues, $ruleTargetSession, $collection);

            // The limit is for what the operator reads, and utf8toUnicode makes a value longer.
            if ($longestValue > $maxInspectableValueLength) {
                foreach ($values as $index => $value) {
                    if (strlen($value) > $maxInspectableValueLength) {
                        return CoreRuleResult::failClosed($labels[$index] ?? null);
                    }
                }
            }

            if ($values === []) {
                return CoreRuleResult::noMatch();
            }
        }

        if ($this->operatorEvaluator instanceof DetailedOperatorEvaluatorInterface) {
            $operatorResult = $this->operatorEvaluator->outcome($values);
            $matchedLabel = $operatorResult->matchedValueIndex !== null
                ? ($labels[$operatorResult->matchedValueIndex] ?? null)
                : null;

            return match ($operatorResult->outcome) {
                RuleOutcome::NoMatch => CoreRuleResult::noMatch(),
                RuleOutcome::Matched => CoreRuleResult::matched(
                    $matchedLabel,
                    $operatorResult->matchedValueIndex !== null ? ($values[$operatorResult->matchedValueIndex] ?? null) : null,
                    $operatorResult->captures,
                ),
                RuleOutcome::FailClosed => CoreRuleResult::failClosed($matchedLabel),
            };
        }

        return $this->operatorEvaluator->evaluate($values)
            ? CoreRuleResult::matched(null, null)
            : CoreRuleResult::noMatch();
    }

    /**
     * This rule's target values, with their labels and the length of the
     * longest one. Most rules list the same targets as other rules, and what
     * a target list yields depends on nothing else of the rule; so the list
     * is assembled once per request and exclusion scope, and every further
     * rule with the same list takes the result.
     *
     * Given the values as collected, the result is these values after the
     * rule's transformations. That depends on the target list and on the
     * transformations only, and is shared in the same way.
     *
     * @param array{0: list<?string>, 1: list<string>, 2: int}|null $untransformed
     * @return array{0: list<?string>, 1: list<string>, 2: int}
     */
    private function collect(
        RequestVariableValues $requestVariableValues,
        ?RuleTargetSession $ruleTargetSession,
        ?array $untransformed = null,
    ): array {
        $list = $untransformed === null ? $this->targetList : $this->transformedTargetList;

        if (!$ruleTargetSession instanceof RuleTargetSession) {
            $collection = $requestVariableValues->collection($list);
            if ($collection === null) {
                [$collection, $remember] = $this->assemble($requestVariableValues, null, $untransformed);
                if ($remember) {
                    $requestVariableValues->rememberCollection($list, $collection);
                }
            }

            return $collection;
        }

        $scope = $ruleTargetSession->collectionScope($this);
        if ($scope === null) {
            return $this->assemble($requestVariableValues, $ruleTargetSession, $untransformed)[0];
        }

        $key = $scope . ':' . $list;
        $collection = $ruleTargetSession->collection($key);
        if ($collection === null) {
            [$collection, $remember] = $this->assemble($requestVariableValues, $ruleTargetSession, $untransformed);
            if ($remember) {
                $ruleTargetSession->rememberCollection($key, $collection);
            }
        }

        return $collection;
    }

    /**
     * What {@see collect()} looks for, built anew, and whether to keep it
     * for the rules to come.
     *
     * @param array{0: list<?string>, 1: list<string>, 2: int}|null $untransformed
     * @return array{0: array{0: list<?string>, 1: list<string>, 2: int}, 1: bool}
     */
    private function assemble(
        RequestVariableValues $requestVariableValues,
        ?RuleTargetSession $ruleTargetSession,
        ?array $untransformed,
    ): array {
        if ($untransformed === null) {
            return [$this->measured($this->collectTargetValues($requestVariableValues, $ruleTargetSession)), true];
        }

        return $this->transform($requestVariableValues, $untransformed);
    }

    /**
     * The collected values after this rule's transformations. A value that
     * a transformation empties is dropped, like a value collected empty.
     *
     * @param array{0: list<?string>, 1: list<string>, 2: int} $untransformed
     * @return array{0: array{0: list<?string>, 1: list<string>, 2: int}, 1: bool}
     */
    private function transform(RequestVariableValues $requestVariableValues, array $untransformed): array
    {
        $transformationPipeline = $this->transformationPipeline;
        if (!$transformationPipeline instanceof TransformationPipeline) {
            return [$untransformed, true];
        }

        if ($this->multiMatch) {
            return [$this->stages($transformationPipeline, $untransformed), false];
        }

        $transformed = $requestVariableValues->transformed($transformationPipeline, $untransformed[1]);
        if ($transformed === null) {
            // Nothing to transform in any of the values, as in most requests.
            return [$untransformed, true];
        }

        $labels = [];
        $values = [];
        $longestValue = 0;
        foreach ($transformed as $index => $value) {
            if ($value === '') {
                continue;
            }

            $labels[] = $untransformed[0][$index] ?? null;
            $values[] = $value;
            $longestValue = max($longestValue, strlen($value));
        }

        return [[$labels, $values, $longestValue], $requestVariableValues->keepsTransformedValues()];
    }

    /**
     * What a `multiMatch` rule hands to its operator: every value as
     * collected and after each transformation that changes it. These are
     * worked out for the one rule and not counted against the memory of the
     * request, so they are not kept for further rules either.
     *
     * @param array{0: list<?string>, 1: list<string>, 2: int} $untransformed
     * @return array{0: list<?string>, 1: list<string>, 2: int}
     */
    private function stages(TransformationPipeline $transformationPipeline, array $untransformed): array
    {
        $labels = [];
        $values = [];
        $longestValue = 0;
        // A parameter name is collected as a name and as a member of ARGS; its stages are the same.
        $stagesByValue = [];
        foreach ($untransformed[1] as $index => $value) {
            foreach ($stagesByValue[$value] ??= $transformationPipeline->stages($value) as $stage) {
                if ($stage === '') {
                    continue;
                }

                $labels[] = $untransformed[0][$index] ?? null;
                $values[] = $stage;
                $longestValue = max($longestValue, strlen($stage));
            }
        }

        return [$labels, $values, $longestValue];
    }

    /**
     * @param array{0: list<?string>, 1: list<string>} $collected
     * @return array{0: list<?string>, 1: list<string>, 2: int}
     */
    private function measured(array $collected): array
    {
        $longestValue = 0;
        foreach ($collected[1] as $value) {
            $longestValue = max($longestValue, strlen($value));
        }

        return [$collected[0], $collected[1], $longestValue];
    }

    /**
     * Assemble this rule's target values from the shared per-request memo, applying
     * the rule's own named selectors and negated (`!`) exclusions. Returns the
     * matched-target labels (`ARGS:utm_content`, `QUERY_STRING`) parallel to the values.
     *
     * Empty values are dropped. Each targeted variable's entries are independently
     * capped by {@see RequestVariableValues::entriesFor()}; there is deliberately NO
     * aggregate cap across variables here, so a high-volume earlier variable cannot
     * short-circuit evaluation of a later one. A variable truncated at its cap is
     * surfaced via {@see RequestVariableValues::wasCapped()} and handled (fail-closed)
     * in {@see evaluate()}, not here.
     *
     * @return array{0: list<?string>, 1: list<string>}
     */
    private function collectTargetValues(RequestVariableValues $requestVariableValues, ?RuleTargetSession $ruleTargetSession): array
    {
        /** @var list<?string> $labels */
        $labels = [];
        /** @var list<string> $values */
        $values = [];
        foreach ($this->targets as $target) {
            $exclusions = $this->textExclusions[$target->variable] ?? [];
            // Injected name entries (the ARGS hardening entries carrying a parameter
            // name as their value) are semantically members of the variable's _NAMES
            // counterpart: a named selector such as ARGS:redirect targets the
            // parameter's value and skips them, and !ARGS_NAMES:... rule-text
            // exclusions suppress them.
            $nameEntryExclusions = $this->textExclusions[$target->variable . '_NAMES'] ?? [];
            $entries = $ruleTargetSession instanceof RuleTargetSession
                ? $ruleTargetSession->entriesFor($this, $target->variable)
                : $requestVariableValues->entriesFor($target->variable);
            foreach ($entries as $entry) {
                if ($entry['value'] === '') {
                    continue;
                }

                if (!$target->selectsForInclusion($entry['name'])) {
                    continue;
                }

                $isNameEntry = $entry['isNameEntry'] ?? false;
                if ($isNameEntry && !$target->isBare()) {
                    continue;
                }

                foreach ($exclusions as $exclusion) {
                    if ($exclusion->matchesName($entry['name'])) {
                        continue 2;
                    }
                }

                if ($isNameEntry) {
                    foreach ($nameEntryExclusions as $nameEntryExclusion) {
                        if ($nameEntryExclusion->matchesName($entry['name'])) {
                            continue 2;
                        }
                    }
                }

                $labels[] = $target->variable . ($entry['name'] !== null ? ':' . $entry['name'] : '');
                $values[] = $entry['value'];
            }
        }

        return [$labels, $values];
    }
}
