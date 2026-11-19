<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Exclusion\RuntimeExclusions;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;

/**
 * Per-request view of the rule set's target configuration.
 *
 * Entries filtered by the global exclusions/manipulators are computed once per
 * variable and shared across all rules; rules with id- or tag-specific
 * configuration specialize from that shared result, once per filter and
 * variable (rules selected by the same tags share a filter, see
 * {@see RuleTargetConfig}), and exclusions armed by matched runtime exclusion
 * rules apply last. A condition or manipulator is therefore asked once per
 * request for an entry, not once per rule. Filtering happens after the
 * collection cap in {@see RequestVariableValues::entriesFor()}, so an
 * excluded parameter still counts toward the cap (exclusion cannot "un-cap").
 */
final class RuleTargetSession
{
    /** @var array<string, list<array{name: ?string, value: string, isNameEntry?: bool}>> */
    private array $globalCache = [];

    /**
     * The rule-specific filters seen so far, by object id. The session holds
     * on to them, so an id stands for the same filter as long as it lives.
     *
     * @var array<int, RuleTargetFilter>
     */
    private array $ruleSpecificFilters = [];

    /**
     * Entries after a rule-specific filter, by the filter's object id and by variable.
     *
     * @var array<int, array<string, list<array{name: ?string, value: string, isNameEntry?: bool}>>>
     */
    private array $ruleSpecificCache = [];

    /**
     * What rules collected, by {@see collectionScope()} and the text of their target list.
     *
     * @var array<string, array{0: list<?string>, 1: list<string>, 2: int}>
     */
    private array $collections = [];

    public function __construct(
        private readonly RuleTargetConfig $ruleTargetConfig,
        private readonly RequestVariableValues $requestVariableValues,
        private readonly ?RuntimeExclusions $runtimeExclusions = null,
    ) {
    }

    /**
     * The entries a rule sees for one of its target variables.
     *
     * @return list<array{name: ?string, value: string, isNameEntry?: bool}>
     */
    public function entriesFor(CoreRule $coreRule, string $variable): array
    {
        if (!array_key_exists($variable, $this->globalCache)) {
            $this->globalCache[$variable] = $this->ruleTargetConfig->globalFilter()->apply(
                $variable,
                $this->requestVariableValues->entriesFor($variable),
                $this->requestVariableValues->serverRequest(),
            );
        }

        $entries = $this->globalCache[$variable];

        $ruleSpecificFilter = $this->ruleTargetConfig->ruleSpecificFilter($coreRule);
        if ($ruleSpecificFilter instanceof RuleTargetFilter) {
            $filterId = $this->filterId($ruleSpecificFilter);
            if (!isset($this->ruleSpecificCache[$filterId][$variable])) {
                $this->ruleSpecificCache[$filterId][$variable] = $ruleSpecificFilter->apply($variable, $entries, $this->requestVariableValues->serverRequest());
            }

            $entries = $this->ruleSpecificCache[$filterId][$variable];
        }

        if ($this->runtimeExclusions instanceof RuntimeExclusions) {
            return $this->applyRuntimeExclusions($coreRule, $variable, $entries);
        }

        return $entries;
    }

    /**
     * Names everything of this session that decides which entries a rule
     * sees: two rules with the same scope and the same target list collect
     * the same values. Null when that cannot be said in advance, because
     * exclusions armed for this request select rules one by one.
     *
     * @internal
     */
    public function collectionScope(CoreRule $coreRule): ?string
    {
        if ($this->runtimeExclusions instanceof RuntimeExclusions) {
            return null;
        }

        $ruleSpecificFilter = $this->ruleTargetConfig->ruleSpecificFilter($coreRule);
        return $ruleSpecificFilter instanceof RuleTargetFilter ? (string) $this->filterId($ruleSpecificFilter) : '';
    }

    private function filterId(RuleTargetFilter $ruleTargetFilter): int
    {
        $filterId = spl_object_id($ruleTargetFilter);
        $this->ruleSpecificFilters[$filterId] ??= $ruleTargetFilter;

        return $filterId;
    }

    /**
     * @internal
     *
     * @return array{0: list<?string>, 1: list<string>, 2: int}|null
     */
    public function collection(string $key): ?array
    {
        return $this->collections[$key] ?? null;
    }

    /**
     * @internal
     *
     * @param array{0: list<?string>, 1: list<string>, 2: int} $collection
     */
    public function rememberCollection(string $key, array $collection): void
    {
        $this->collections[$key] = $collection;
    }

    /**
     * @param list<array{name: ?string, value: string, isNameEntry?: bool}> $entries
     * @return list<array{name: ?string, value: string, isNameEntry?: bool}>
     */
    private function applyRuntimeExclusions(CoreRule $coreRule, string $variable, array $entries): array
    {
        if ($entries === [] || !$this->runtimeExclusions instanceof RuntimeExclusions) {
            return $entries;
        }

        $selectors = $this->runtimeExclusions->exclusionSelectorsFor($coreRule, $variable);
        if ($selectors === []) {
            return $entries;
        }

        $result = [];
        foreach ($entries as $entry) {
            foreach ($selectors as $selector) {
                if ($selector->matchesName($entry['name'])) {
                    continue 2;
                }
            }

            $result[] = $entry;
        }

        return $result;
    }
}
