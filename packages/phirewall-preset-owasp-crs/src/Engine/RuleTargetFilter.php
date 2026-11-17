<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\CallableRequestValueManipulator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestValueManipulatorInterface;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\TargetExclusion;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Immutable set of target exclusions and manipulators applied to collected
 * entries at evaluation time: exclusions first, then manipulators. Values
 * manipulated to an empty string are dropped by the rule's collection step.
 *
 * An entry is excluded when any exclusion excludes it. The exclusions are
 * asked in the order they were registered, and none after the first that
 * excludes the entry. Exclusions that name one member are looked up by that
 * name instead of being asked for every entry, so a long list of exclusions
 * costs an entry one lookup plus the few exclusions that select by pattern
 * or take the whole variable.
 */
final class RuleTargetFilter
{
    private const CASE_INSENSITIVE_NAMES = ['REQUEST_HEADERS' => true, 'REQUEST_HEADERS_NAMES' => true];

    /**
     * Per variable: the exclusions that name one member, by that name, and all others;
     * each list keyed by the position at which the exclusion was registered.
     * Built on first use; only a way to find candidates, {@see TargetExclusion::excludes()} still decides.
     *
     * @var array<string, array{byName: array<array-key, array<int, TargetExclusion>>, others: array<int, TargetExclusion>}>
     */
    private array $index = [];

    /**
     * @param array<string, list<TargetExclusion>> $exclusionsByVariable
     * @param list<RequestValueManipulatorInterface> $manipulators
     */
    public function __construct(
        private readonly array $exclusionsByVariable,
        private readonly array $manipulators,
    ) {
    }

    public function isEmpty(): bool
    {
        return $this->exclusionsByVariable === [] && $this->manipulators === [];
    }

    /**
     * Filter and transform the entries of one collection variable. When nothing
     * applies to the variable the input array is returned as-is (no copy).
     *
     * @param list<array{name: ?string, value: string, isNameEntry?: bool}> $entries
     * @return list<array{name: ?string, value: string, isNameEntry?: bool}>
     */
    public function apply(string $variable, array $entries, ServerRequestInterface $serverRequest): array
    {
        $exclusions = $this->exclusionsByVariable[$variable] ?? [];
        if ($exclusions === [] && $this->manipulators === []) {
            return $entries;
        }

        if ($entries === []) {
            return [];
        }

        $index = $this->index[$variable] ??= $this->index($exclusions);
        $foldCase = isset(self::CASE_INSENSITIVE_NAMES[$variable]);

        $result = [];
        foreach ($entries as $entry) {
            $name = $entry['name'];
            $candidates = $index['others'];
            if ($name !== null && $index['byName'] !== []) {
                $named = $index['byName'][$foldCase ? strtolower($name) : $name] ?? [];
                if ($named !== []) {
                    // Both lists are in registration order; together they have to be again.
                    $candidates = $named + $candidates;
                    if ($index['others'] !== []) {
                        ksort($candidates);
                    }
                }
            }

            foreach ($candidates as $candidate) {
                if ($candidate->excludes($name, $entry['value'], $serverRequest)) {
                    continue 2;
                }
            }

            foreach ($this->manipulators as $manipulator) {
                // The adapter forwards the request to closure manipulators; the
                // 3-parameter interface stays untouched for compatibility.
                $entry['value'] = $manipulator instanceof CallableRequestValueManipulator
                    ? $manipulator->manipulate($variable, $entry['name'], $entry['value'], $serverRequest)
                    : $manipulator->manipulate($variable, $entry['name'], $entry['value']);
            }

            $result[] = $entry;
        }

        return $result;
    }

    /**
     * Header names compare without regard to ASCII case
     * ({@see Variable\TargetSelector::matchesName()}),
     * so their exclusions are filed under the lower-cased name.
     *
     * @param list<TargetExclusion> $exclusions All of one variable, in the order they were registered.
     * @return array{byName: array<array-key, array<int, TargetExclusion>>, others: array<int, TargetExclusion>}
     */
    private function index(array $exclusions): array
    {
        $byName = [];
        $others = [];
        foreach ($exclusions as $position => $exclusion) {
            $name = $exclusion->selector->name;
            if ($name === null) {
                $others[$position] = $exclusion;
                continue;
            }

            $byName[isset(self::CASE_INSENSITIVE_NAMES[$exclusion->selector->variable]) ? strtolower($name) : $name][$position] = $exclusion;
        }

        return ['byName' => $byName, 'others' => $others];
    }
}
