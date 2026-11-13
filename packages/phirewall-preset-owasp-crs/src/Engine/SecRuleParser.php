<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

/**
 * Very small SecRule parser to support a pragmatic subset of CRS.
 *
 * The set of supported variables is defined by {@see Variable\VariableCollectorFactory}
 * and the set of supported operators by {@see Operator\OperatorEvaluatorFactory};
 * those factories are the source of truth. Actions: id (required), phase (ignored),
 * the disruptive action (see {@see BLOCKING_DISRUPTIVE_ACTIONS}; resolved into the
 * boolean `deny` action), msg/logdata (optional), severity (resolved to an anomaly
 * score, missing/unknown scores as CRITICAL), tag (collected as a list; the
 * paranoia level is read from a `paranoia-level/N` tag), t (the transformations,
 * collected as a list in the order they are written).
 */
final class SecRuleParser
{
    private const PARANOIA_LEVEL_TAG_PATTERN = '#^paranoia-level/([1-4])$#';

    /**
     * ModSecurity's disruptive actions. When a rule lists several, the last one wins.
     */
    private const DISRUPTIVE_ACTIONS = ['allow', 'block', 'deny', 'drop', 'pass', 'proxy', 'redirect'];

    /**
     * Disruptive actions that intercept the request in ModSecurity. The engine has a single
     * way to intercept - the rule contributes its score to the anomaly total, which blocks
     * at the threshold - so all of them make the rule a blocking (`deny`) rule. `block` is
     * CRS's anomaly-scoring action. `pass`, `allow` and no disruptive action at all (which
     * defers to SecDefaultAction, `pass` by default) leave the rule non-blocking: the engine
     * does not evaluate it.
     */
    private const BLOCKING_DISRUPTIVE_ACTIONS = ['block', 'deny', 'drop', 'proxy', 'redirect'];

    /**
     * Parse a raw CRS "SecRule" line into a CoreRule, or null if unsupported.
     */
    public function parseLine(string $line, ?string $contextFolder = null): ?CoreRule
    {
        return $this->parseLineWithCtl($line, $contextFolder)['rule'] ?? null;
    }

    /**
     * Parse a raw "SecRule" line into the rule plus its raw `ctl:` action
     * values (CRS exclusion syntax, consumed by
     * {@see Exclusion\RuleExclusionParser}). The main rule loading ignores
     * ctl actions; they only take effect through the exclusion API.
     *
     * @return array{rule: CoreRule, ctl: list<string>}|null
     */
    public function parseLineWithCtl(string $line, ?string $contextFolder = null): ?array
    {
        // Defensive: collapse backslash-newline continuations into a single logical line
        // Join "\\\n<indent>" and "\\\r\n<indent>" sequences
        $line = preg_replace("/\\\\\r?\n[ \t]*/", '', $line) ?? $line;

        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            return null;
        }

        if (!str_starts_with($line, 'SecRule ')) {
            return null;
        }

        // Basic pattern: SecRule <VARIABLES> "<OP> <ARG>" "<ACTIONS>"
        // We will extract quoted segments first.
        $parts = $this->splitTopLevel($line);
        if (count($parts) < 3) {
            return null;
        }

        // parts[0] is the full command; remove leading 'SecRule '
        $variablesPart = trim(substr($parts[0], strlen('SecRule ')));
        $operatorPart = $this->stripQuotes($parts[1]);
        $actionsPart = $this->stripQuotes($parts[2]);

        // Variables split by | (handle transforms by ignoring
        $variables = array_values(array_filter(array_map('trim', explode('|', $variablesPart)), static fn($v): bool => $v !== ''));
        if ($variables === []) {
            return null;
        }

        // Operator e.g.: @rx somepattern
        [$op, $arg] = $this->parseOperator($operatorPart);
        if ($op === null || $arg === null) {
            return null;
        }

        // Actions: comma-separated key[:value]
        $parsedActions = $this->parseActions($actionsPart);
        if ($parsedActions['unterminatedQuote'] && $this->quotedRegionMentionsDisruptiveAction($actionsPart)) {
            // A stray quote (e.g. an apostrophe in a msg) leaves the action list unbalanced, so
            // where the quoted values end is unknown. When a disruptive action appears in that
            // region, whether the rule blocks cannot be decided: reject the rule rather than guess.
            return null;
        }

        ['actions' => $actions, 'tags' => $tags, 'ctls' => $ctls, 'transformations' => $transformations] = $parsedActions;
        $id = isset($actions['id']) ? (int)$actions['id'] : 0;
        if ($id <= 0) {
            return null; // require id
        }

        // Only the tokenized action list decides whether the rule blocks: free text in
        // msg/logdata/tag values never does (a `msg:'not blocking'` is not a block action).
        $actions['deny'] = in_array($parsedActions['disruptiveAction'], self::BLOCKING_DISRUPTIVE_ACTIONS, true);

        $severity = null;
        $anomalyScore = 5;
        $severityAction = $actions['severity'] ?? null;
        if (is_int($severityAction) || is_string($severityAction)) {
            $resolved = Severity::tryFromActionValue($severityAction);
            if ($resolved instanceof Severity) {
                $severity = $resolved->value;
                $anomalyScore = $resolved->anomalyScore();
            }
        }

        $paranoiaLevel = 1;
        foreach ($tags as $tag) {
            if (preg_match(self::PARANOIA_LEVEL_TAG_PATTERN, $tag, $matches) === 1) {
                $paranoiaLevel = (int)$matches[1];
            }
        }

        return [
            'rule' => new CoreRule($id, $variables, $op, $arg, $actions, $contextFolder, $anomalyScore, $severity, $paranoiaLevel, $tags, null, $transformations),
            'ctl' => $ctls,
        ];
    }

    /**
     * Split a SecRule line into parts: ["SecRule <vars>", "<op arg>", "<actions>"]
     * Quoted segments act as the delimiters; unquoted runs between them form their own segments.
     *
     * @return list<string>
     */
    private function splitTopLevel(string $line): array
    {
        $segments = [];
        foreach ($this->scanSpans($line) as $span) {
            if ($span['quoted']) {
                // A quoted span is its own segment, surrounding quotes retained.
                $segments[] = $span['text'];
                continue;
            }

            // Unquoted runs are emitted as-is (trimmed) when they carry content.
            $trimmed = trim($span['text']);
            if ($trimmed !== '') {
                $segments[] = $trimmed;
            }
        }

        return $segments;
    }

    /**
     * Walk a string honoring quote state (single or double) and backslash-escapes inside quotes,
     * yielding alternating unquoted and quoted spans. Quoted spans retain their surrounding quote
     * characters and any escape sequences verbatim, exactly as the source text contained them.
     *
     * This is the single low-level scanner shared by {@see splitTopLevel()} and {@see parseActions()};
     * each method applies its own emission rules on top of the produced spans. The final span
     * carries `open: true` when the input ended while still inside an unclosed quote, so callers can
     * keep the unterminated remainder intact (commas and all) for that malformed input.
     *
     * @return list<array{quoted: bool, open: bool, text: string}>
     */
    private function scanSpans(string $input): array
    {
        $spans = [];
        $current = '';
        $inQuote = false;
        $quoteChar = '';
        $length = strlen($input);
        for ($index = 0; $index < $length; ++$index) {
            $character = $input[$index];
            if ($inQuote) {
                if ($character === '\\' && $index + 1 < $length) { // escape: keep both characters
                    $current .= $character . $input[$index + 1];
                    ++$index;
                    continue;
                }

                if ($character === $quoteChar) {
                    $inQuote = false;
                    $current .= $character;
                    $spans[] = ['quoted' => true, 'open' => false, 'text' => $current];
                    $current = '';
                    continue;
                }

                $current .= $character;
                continue;
            }

            if ($character === '"' || $character === "'") {
                if ($current !== '') {
                    $spans[] = ['quoted' => false, 'open' => false, 'text' => $current];
                }

                $current = $character;
                $inQuote = true;
                $quoteChar = $character;
                continue;
            }

            $current .= $character;
        }

        if ($current !== '') {
            // The trailing run. If a quote never closed, flag it `open` so parseActions treats it
            // like a quoted span, keeping the unterminated remainder intact (commas included)
            // instead of splitting it. splitTopLevel ignores the flag and trims the run.
            $spans[] = ['quoted' => false, 'open' => $inQuote, 'text' => $current];
        }

        return $spans;
    }

    /**
     * @return array{0:?string,1:?string}
     */
    private function parseOperator(string $operatorPart): array
    {
        $operatorPart = trim($operatorPart);
        if ($operatorPart === '') {
            return [null, null];
        }

        // First token is operator, rest is argument (may contain spaces)
        $spacePos = strpos($operatorPart, ' ');
        if ($spacePos === false) {
            return [null, null];
        }

        $op = trim(substr($operatorPart, 0, $spacePos));
        $arg = substr($operatorPart, $spacePos + 1);

        // @rx arguments are bare PCRE content per ModSecurity grammar — there is no
        // second quoting layer to strip. Stripping surrounding quotes here corrupts
        // patterns whose first and last bytes are literal quote characters (e.g. CRS
        // rule 942511 wraps its alternation in literal apostrophes), collapsing the
        // regex to its inner body and matching essentially every HTTP value. The outer
        // SecRule-level quoting has already been removed by stripQuotes($parts[1]) in
        // parseLine, so the remaining content is the pattern verbatim.
        if (strtolower($op) === '@rx') {
            return [$op, ltrim($arg)];
        }

        // Remove surrounding quotes if present
        $arg = $this->stripQuotes(trim($arg));
        $arg = trim($this->unescape($arg));

        return [$op, $arg];
    }

    private function unescape(string $value): string
    {
        // For non-regex operators, unescape simple sequences to present clean arguments
        // (e.g., convert \" to ", \\' to ', and \\\\ to \\).
        return str_replace(['\\"', "\\'", '\\\\'], ['"', "'", '\\'], $value);
    }

    /**
     * Parse actions key/value map. Values can be quoted (single or double). Commas separate actions.
     * Boolean actions like "deny" will be set to true. Repeated `tag:` and `ctl:` actions are
     * collected into their own lists (in source order) instead of the last-wins map; so are the
     * `t:` actions, which stay in the map as well.
     *
     * `disruptiveAction` is the last disruptive action name in source order (lowercased), or null.
     * `unterminatedQuote` is set when the list ends inside an unclosed quote.
     *
     * @return array{actions: array<string, int|string|bool>, tags: list<string>, ctls: list<string>, transformations: list<string>, disruptiveAction: ?string, unterminatedQuote: bool}
     */
    private function parseActions(string $actionsPart): array
    {
        $actions = [];
        $buffer = '';
        $parts = [];
        $unterminatedQuote = false;
        foreach ($this->scanSpans($actionsPart) as $span) {
            $unterminatedQuote = $unterminatedQuote || $span['open'];
            if ($span['quoted'] || $span['open']) {
                // Quoted spans (and an unterminated open-quote run) never split a part: any
                // commas within them are literal.
                $buffer .= $span['text'];
                continue;
            }

            // Unquoted runs split into parts on top-level commas.
            $fragments = explode(',', $span['text']);
            $lastIndex = count($fragments) - 1;
            foreach ($fragments as $fragmentIndex => $fragment) {
                $buffer .= $fragment;
                if ($fragmentIndex !== $lastIndex) {
                    $parts[] = trim($buffer);
                    $buffer = '';
                }
            }
        }

        if (trim($buffer) !== '') {
            $parts[] = trim($buffer);
        }

        $tags = [];
        $ctls = [];
        $transformations = [];
        $disruptiveAction = null;
        foreach ($parts as $part) {
            if ($part === '') {
                continue;
            }

            $disruptiveAction = $this->disruptiveActionName($part) ?? $disruptiveAction;

            $kv = explode(':', $part, 2);
            if (count($kv) === 1) {
                $actions[$kv[0]] = true;
            } else {
                $key = trim($kv[0]);
                $value = $this->stripQuotes(trim($kv[1]));
                if ($key === 'tag') {
                    $tags[] = $value;
                    continue;
                }

                if ($key === 'ctl') {
                    $ctls[] = $value;
                    continue;
                }

                if (strtolower($key) === 't') {
                    $transformations[] = $value;
                }

                $actions[$key] = is_numeric($value) ? (int)$value : $value;
            }
        }

        return [
            'actions' => $actions,
            'tags' => $tags,
            'ctls' => $ctls,
            'transformations' => $transformations,
            'disruptiveAction' => $disruptiveAction,
            'unterminatedQuote' => $unterminatedQuote,
        ];
    }

    /**
     * Whether any comma-separated fragment from the first quote character onwards names a
     * disruptive action, ignoring quoting (and quote characters around the name). Only used
     * for an unbalanced action list, whose quoted regions cannot be trusted.
     */
    private function quotedRegionMentionsDisruptiveAction(string $actionsPart): bool
    {
        $quotedRegion = substr($actionsPart, strcspn($actionsPart, '\'"'));
        foreach (explode(',', $quotedRegion) as $fragment) {
            if ($this->disruptiveActionName(trim($fragment, " \t'\"")) !== null) {
                return true;
            }
        }

        return false;
    }

    /**
     * The lowercased disruptive action name of one `name[:value]` action, or null when the
     * action is not disruptive. Action names are matched case-insensitively, like ModSecurity.
     */
    private function disruptiveActionName(string $action): ?string
    {
        $name = strtolower(trim(explode(':', $action, 2)[0]));

        return in_array($name, self::DISRUPTIVE_ACTIONS, true) ? $name : null;
    }

    private function stripQuotes(string $value): string
    {
        $l = strlen($value);
        if ($l >= 2 && (($value[0] === '"' && $value[$l - 1] === '"') || ($value[0] === "'" && $value[$l - 1] === "'"))) {
            return substr($value, 1, -1);
        }

        return $value;
    }
}
