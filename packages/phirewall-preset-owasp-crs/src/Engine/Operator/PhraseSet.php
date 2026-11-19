<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Operator;

/**
 * The phrases of a `@pm` / `@pmFromFile` operator, optionally with a
 * prefilter that answers "does this value contain any of the phrases at all?"
 * in one pass.
 *
 * Almost every value of an ordinary request contains none of the phrases, and
 * finding that out phrase by phrase costs one search per phrase. The prefilter
 * is one regular expression built from all phrases as a prefix tree, so the
 * engine walks each value once. It only ever says "none of them" or "look
 * closer": a value it does not rule out goes through the same phrase-by-phrase
 * search as without a prefilter, which also decides which phrase is reported.
 *
 * The prefilter is matched case-sensitively against the lower-cased value and
 * is built from the lower-cased phrases, both lower-cased the way `stripos()`
 * compares (ASCII letters only, independent of the locale), so it rules a
 * value out exactly when no phrase is found in it. If the expression cannot
 * be evaluated (an engine limit, an artifact from another PCRE version), the
 * value is searched phrase by phrase: the prefilter never lets a value pass.
 *
 * Building the prefilter takes longer than one request saves, so it comes
 * with the compiled rule data ({@see toArray()} / {@see fromArray()}) and is
 * left out where rules are parsed on every request.
 */
final readonly class PhraseSet
{
    /**
     * Most bytes the prefix tree may hold. The engine does not compile
     * expressions much beyond this size anyway, so there is no point in
     * building a longer one to find that out.
     */
    private const MAX_PREFILTER_BYTES = 60_000;

    /**
     * @param list<string> $phrases
     * @param string|null $prefilter Expression that matches the lower-cased value when it contains one of the phrases.
     */
    private function __construct(
        public array $phrases,
        public ?string $prefilter,
    ) {
    }

    /**
     * @param list<string> $phrases
     */
    public static function withoutPrefilter(array $phrases): self
    {
        return new self($phrases, null);
    }

    /**
     * The phrases with their prefilter, for the compiled rule data.
     *
     * @param list<string> $phrases
     */
    public static function compile(array $phrases): self
    {
        return new self($phrases, self::buildPrefilter($phrases));
    }

    /**
     * Locate the first value containing any phrase (case-insensitive); the
     * first such phrase in list order is exposed as the TX.0 capture.
     *
     * @param list<string> $values
     */
    public function firstMatch(array $values): OperatorResult
    {
        if ($this->phrases === []) {
            return OperatorResult::noMatch();
        }

        if ($this->prefilter === null) {
            return PhraseMatchEvaluator::firstMatch($values, $this->phrases);
        }

        foreach ($values as $index => $value) {
            // 0 is the only answer that rules the value out; an error (false) does not.
            if (preg_match($this->prefilter, strtolower($value)) === 0) {
                continue;
            }

            foreach ($this->phrases as $phrase) {
                if ($phrase !== '' && stripos($value, $phrase) !== false) {
                    return OperatorResult::matched($index, [$phrase]);
                }
            }
        }

        return OperatorResult::noMatch();
    }

    /**
     * @return array{phrases: list<string>, prefilter: ?string}
     */
    public function toArray(): array
    {
        return ['phrases' => $this->phrases, 'prefilter' => $this->prefilter];
    }

    /**
     * Rebuild a phrase set from compiled-cache data.
     *
     * A prefilter that this PHP installation cannot compile (the artifact may
     * have been written under another PCRE version) is dropped rather than
     * trusted; the phrases then work without it.
     *
     * @throws \InvalidArgumentException When the data has an unexpected shape.
     */
    public static function fromArray(mixed $data): self
    {
        $phrases = is_array($data) ? ($data['phrases'] ?? null) : null;
        $prefilter = is_array($data) ? ($data['prefilter'] ?? null) : null;
        if (!is_array($phrases) || !array_is_list($phrases) || ($prefilter !== null && !is_string($prefilter))) {
            throw new \InvalidArgumentException('Compiled CRS phrase data has an unexpected shape.');
        }

        // Checked in place: the list comes out of the opcode cache as it is and is not copied.
        foreach ($phrases as $phrase) {
            if (!is_string($phrase)) {
                throw new \InvalidArgumentException('Compiled CRS phrases must be a list of strings.');
            }
        }

        if ($prefilter !== null && !self::compiles($prefilter)) {
            $prefilter = null;
        }

        /** @var list<string> $phrases */
        return new self($phrases, $prefilter);
    }

    /**
     * One expression for all phrases, as a prefix tree: `/etc/passwd` and
     * `/etc/shadow` become `/etc/(?:passwd|shadow)`. A phrase that starts
     * with another phrase adds nothing (wherever it occurs, the shorter one
     * does too) and is left out.
     *
     * @param list<string> $phrases
     */
    private static function buildPrefilter(array $phrases): ?string
    {
        $lowerCased = [];
        foreach ($phrases as $phrase) {
            if ($phrase !== '') { // an empty phrase never matches, see firstMatch()
                $lowerCased[strtolower($phrase)] = true;
            }
        }

        if ($lowerCased === []) {
            return null;
        }

        // Sorted, phrases with a common beginning are neighbours and one that is the
        // beginning of others comes first: the tree is read off the list without copying it.
        $sorted = array_map(strval(...), array_keys($lowerCased));
        sort($sorted, SORT_STRING);

        $bytes = 0;
        $expression = self::expression($sorted, 0, count($sorted) - 1, 0, $bytes);
        if ($expression === null) {
            return null;
        }

        $prefilter = '~' . $expression . '~';

        return self::compiles($prefilter) ? $prefilter : null;
    }

    /**
     * The expression for what follows the common beginning of a run of phrases.
     *
     * @param list<string> $phrases Sorted and distinct.
     * @param int $first First phrase of the run.
     * @param int $last Last phrase of the run.
     * @param int $offset Number of bytes all phrases of the run have in common at their beginning.
     * @param int $bytes Bytes of the tree so far.
     * @return string|null Null when the tree grows beyond {@see MAX_PREFILTER_BYTES}.
     */
    private static function expression(array $phrases, int $first, int $last, int $offset, int &$bytes): ?string
    {
        if (strlen($phrases[$first]) === $offset) {
            return ''; // a phrase ends here: every longer one of the run contains it
        }

        if ($first === $last) {
            $rest = substr($phrases[$first], $offset);
            $bytes += strlen($rest);

            return $bytes > self::MAX_PREFILTER_BYTES ? null : preg_quote($rest, '~');
        }

        // The first and the last phrase of a sorted run differ the most: what they share, all share.
        $common = strspn($phrases[$first] ^ $phrases[$last], "\0", $offset);
        if ($common > 0) {
            $bytes += $common;
            if ($bytes > self::MAX_PREFILTER_BYTES) {
                return null;
            }

            $rest = self::expression($phrases, $first, $last, $offset + $common, $bytes);

            return $rest === null ? null : preg_quote(substr($phrases[$first], $offset, $common), '~') . $rest;
        }

        // No phrase ends here and they do not all continue alike: one alternative per next byte.
        $alternatives = [];
        $start = $first;
        while ($start <= $last) {
            $byte = $phrases[$start][$offset];
            $end = $start;
            while ($end < $last && $phrases[$end + 1][$offset] === $byte) {
                ++$end;
            }

            if (++$bytes > self::MAX_PREFILTER_BYTES) {
                return null;
            }

            $rest = self::expression($phrases, $start, $end, $offset + 1, $bytes);
            if ($rest === null) {
                return null;
            }

            $alternatives[] = preg_quote($byte, '~') . $rest;
            $start = $end + 1;
        }

        return '(?:' . implode('|', $alternatives) . ')';
    }

    /**
     * Whether the expression compiles here. A very large phrase list can
     * exceed what the engine accepts; it then works without a prefilter.
     * Only failing to compile reports an internal error: an expression that
     * merely ran into a limit of this installation is well-formed.
     *
     * Not compiling is an ordinary outcome for a long list, so the warning
     * PHP raises for it is taken here and goes no further: an application
     * that turns warnings into exceptions must not lose its rules over it.
     */
    private static function compiles(string $pattern): bool
    {
        set_error_handler(static fn(): bool => true);
        try {
            return preg_match($pattern, '') !== false || preg_last_error() !== PREG_INTERNAL_ERROR;
        } finally {
            restore_error_handler();
        }
    }
}
