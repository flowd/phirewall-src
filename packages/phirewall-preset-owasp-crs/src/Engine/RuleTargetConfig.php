<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestValueManipulatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetExclusion;

/**
 * Runtime tuning configuration of a rule set: target exclusions and value
 * manipulators, registered globally, per rule id or per rule tag.
 *
 * This is evaluation-time configuration, deliberately never part of the
 * compiled-rule cache artifact. Per-rule filters are memoized and invalidated
 * by a generation counter so exclusions can be added between requests in
 * long-running workers.
 *
 * Rules that are only reached through the same tags share one filter object.
 * {@see RuleTargetSession} filters the entries of a variable once per filter
 * and request, so an exclusion by tag is worked out once for all rules that
 * carry the tag, not once per rule.
 */
final class RuleTargetConfig
{
    /** @var array<string, list<TargetExclusion>> */
    private array $globalExclusionsByVariable = [];

    /** @var list<RequestValueManipulatorInterface> */
    private array $globalManipulators = [];

    /** @var array<int, array<string, list<TargetExclusion>>> */
    private array $exclusionsByRuleId = [];

    /** @var array<string, array<string, list<TargetExclusion>>> */
    private array $exclusionsByTag = [];

    /** @var array<int, list<RequestValueManipulatorInterface>> */
    private array $manipulatorsByRuleId = [];

    private int $generation = 0;

    private ?RuleTargetFilter $globalFilter = null;

    /** @var array<int, array{0: int, 1: ?RuleTargetFilter}> Per-rule-id cache stamped with the generation it was built for. */
    private array $ruleFilterCache = [];

    /** @var array<string, RuleTargetFilter> Filters of rules without configuration of their own, by the tags that select them. */
    private array $tagFilterCache = [];

    public function isEmpty(): bool
    {
        return $this->globalExclusionsByVariable === []
            && $this->globalManipulators === []
            && $this->exclusionsByRuleId === []
            && $this->exclusionsByTag === []
            && $this->manipulatorsByRuleId === [];
    }

    public function excludeTarget(TargetExclusion $targetExclusion): void
    {
        $this->globalExclusionsByVariable[$targetExclusion->selector->variable][] = $targetExclusion;
        $this->invalidate();
    }

    public function excludeTargetById(int $ruleId, TargetExclusion $targetExclusion): void
    {
        $this->exclusionsByRuleId[$ruleId][$targetExclusion->selector->variable][] = $targetExclusion;
        $this->invalidate();
    }

    public function excludeTargetByTag(string $tag, TargetExclusion $targetExclusion): void
    {
        $this->exclusionsByTag[$tag][$targetExclusion->selector->variable][] = $targetExclusion;
        $this->invalidate();
    }

    public function addManipulator(RequestValueManipulatorInterface $requestValueManipulator): void
    {
        $this->globalManipulators[] = $requestValueManipulator;
        $this->invalidate();
    }

    public function addManipulatorById(int $ruleId, RequestValueManipulatorInterface $requestValueManipulator): void
    {
        $this->manipulatorsByRuleId[$ruleId][] = $requestValueManipulator;
        $this->invalidate();
    }

    /**
     * The filter shared by every rule (global exclusions + global manipulators);
     * its per-variable result is memoized once per request by {@see RuleTargetSession}.
     */
    public function globalFilter(): RuleTargetFilter
    {
        return $this->globalFilter ??= new RuleTargetFilter($this->globalExclusionsByVariable, $this->globalManipulators);
    }

    /**
     * The rule-specific filter (by-id and by-tag exclusions, by-id manipulators),
     * or null when nothing rule-specific applies. Memoized per rule id.
     */
    public function ruleSpecificFilter(CoreRule $coreRule): ?RuleTargetFilter
    {
        $cached = $this->ruleFilterCache[$coreRule->id] ?? null;
        if ($cached !== null && $cached[0] === $this->generation) {
            return $cached[1];
        }

        $tags = [];
        foreach ($coreRule->tags as $tag) {
            if (isset($this->exclusionsByTag[$tag])) {
                $tags[] = $tag;
            }
        }

        $exclusionsByVariable = $this->exclusionsByRuleId[$coreRule->id] ?? [];
        $manipulators = $this->manipulatorsByRuleId[$coreRule->id] ?? [];

        if ($exclusionsByVariable === [] && $manipulators === []) {
            $filter = $tags === [] ? null : $this->tagFilter($tags);
        } else {
            $filter = new RuleTargetFilter($this->withTagExclusions($exclusionsByVariable, $tags), $manipulators);
        }

        $this->ruleFilterCache[$coreRule->id] = [$this->generation, $filter];

        return $filter;
    }

    /**
     * The one filter for all rules that have exactly these tags with
     * exclusions, in this order, and nothing registered by their id. The
     * order is part of it: exclusions are asked tag by tag as the rule lists
     * its tags, and rules that list them alike are the ones that can share.
     *
     * @param non-empty-list<string> $tags
     */
    private function tagFilter(array $tags): RuleTargetFilter
    {
        $tags = array_values(array_unique($tags));

        return $this->tagFilterCache[serialize($tags)] ??= new RuleTargetFilter($this->withTagExclusions([], $tags), []);
    }

    /**
     * @param array<string, list<TargetExclusion>> $exclusionsByVariable
     * @param list<string> $tags
     * @return array<string, list<TargetExclusion>>
     */
    private function withTagExclusions(array $exclusionsByVariable, array $tags): array
    {
        foreach ($tags as $tag) {
            foreach ($this->exclusionsByTag[$tag] ?? [] as $variable => $exclusions) {
                foreach ($exclusions as $exclusion) {
                    $exclusionsByVariable[$variable][] = $exclusion;
                }
            }
        }

        return $exclusionsByVariable;
    }

    private function invalidate(): void
    {
        ++$this->generation;
        $this->globalFilter = null;
        $this->ruleFilterCache = [];
        $this->tagFilterCache = [];
    }
}
