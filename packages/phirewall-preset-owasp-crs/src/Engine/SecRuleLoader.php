<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorEvaluatorFactory;
use Flowd\PhirewallPresetOwaspCrs\Engine\Transformation\Transformation;

final class SecRuleLoader
{
    public const SKIP_REASON_UNPARSEABLE = 'unparseable';

    public const SKIP_REASON_UNSUPPORTED_OPERATOR = 'unsupportedOperator';

    public const SKIP_REASON_UNSUPPORTED_TRANSFORMATION = 'unsupportedTransformation';

    public const SKIP_REASON_CHAINED = 'chained';

    /**
     * Split text into logical SecRule lines, supporting backslash (\\) line continuations.
     * - Joins lines ending with an unquoted trailing backslash.
     * - Trims the trailing backslash and newline, and consumes indentation on the next line.
     * - Preserves content inside quotes (no continuation when inside quote).
     * - Skips empty lines and comment-only lines (starting with #, outside quotes).
     *
     * @return list<string>
     */
    private static function logicalLines(string $text): array
    {
        $len = strlen($text);
        $lines = [];
        $buf = '';
        $inQuote = false;
        $quote = '';
        for ($i = 0; $i < $len; ++$i) {
            $ch = $text[$i];

            if ($inQuote) {
                if ($ch === '\\' && $i + 1 < $len) {
                    // keep escapes as-is inside quoted segments
                    $buf .= $ch . $text[$i + 1];
                    ++$i;
                    continue;
                }

                if ($ch === $quote) {
                    $inQuote = false;
                    $quote = '';
                    $buf .= $ch;
                    continue;
                }

                $buf .= $ch;
                continue;
            }

            // Skip full comment lines starting with # (ignoring leading spaces/tabs)
            if ($ch === '#' && trim($buf) === '') {
                // consume until end of line
                while ($i + 1 < $len && $text[$i + 1] !== "\n") {
                    ++$i;
                }

                // reset buffer for this line (comment ignored)
                $buf = '';
                continue;
            }

            if ($ch === '"' || $ch === "'") {
                $inQuote = true;
                $quote = $ch;
                $buf .= $ch;
                continue;
            }

            if ($ch === "\r") {
                // normalize CRLF to handle at the LF
                continue;
            }

            if ($ch === "\n") {
                // Determine if previous non-space char is a backslash
                $j = strlen($buf) - 1;
                while ($j >= 0 && ($buf[$j] === ' ' || $buf[$j] === "\t")) {
                    --$j;
                }

                $isContinuation = ($j >= 0 && $buf[$j] === '\\');
                if ($isContinuation) {
                    // remove the trailing backslash and any spaces before it
                    $buf = rtrim(substr($buf, 0, $j), " \t");
                    // consume indentation on the following line
                    // skip subsequent spaces/tabs at the start of next line
                    $k = $i + 1;
                    while ($k < $len && ($text[$k] === ' ' || $text[$k] === "\t")) {
                        ++$k;
                    }

                    $i = $k - 1; // loop will ++ to next meaningful char
                    continue; // continue accumulating in same logical line
                }

                // finalize current logical line
                $trimmed = trim($buf);
                if ($trimmed !== '' && !str_starts_with($trimmed, '#')) {
                    $lines[] = $trimmed;
                }

                $buf = '';
                continue;
            }

            $buf .= $ch;
        }

        $trimmed = trim($buf);
        if ($trimmed !== '' && !str_starts_with($trimmed, '#')) {
            $lines[] = $trimmed;
        }

        return $lines;
    }

    /**
     * A rule with a transformation the engine does not have (`t:` action)
     * cannot be evaluated as written and would never match; it is skipped.
     */
    private static function transformationsAreSupported(CoreRule $coreRule): bool
    {
        foreach ($coreRule->transformations as $transformation) {
            if (!Transformation::isSupported($transformation)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether a parsed rule carries the `chain` action (case-insensitive). Reads the actions
     * the parser has already tokenized, so the line is not parsed a second time.
     */
    private static function startsAChain(CoreRule $coreRule): bool
    {
        foreach (array_keys($coreRule->actions) as $actionName) {
            if (strtolower($actionName) === 'chain') {
                return true;
            }
        }

        return false;
    }

    public static function fromString(string $rulesText, ?string $contextFolder = null, ?int $maxValuesPerCrsVariable = null): CoreRuleSet
    {
        return self::load($rulesText, $contextFolder, $maxValuesPerCrsVariable)['rules'];
    }

    /**
     * Load rules and report what was skipped. `skipped` counts every logical line that did not
     * become a rule; `skippedByReason` breaks it down by {@see self::SKIP_REASON_UNPARSEABLE}
     * (not a parseable SecRule with an id - including other directives),
     * {@see self::SKIP_REASON_UNSUPPORTED_OPERATOR} (an operator the engine does not implement),
     * {@see self::SKIP_REASON_UNSUPPORTED_TRANSFORMATION} (a `t:` action the engine does not
     * implement; either would otherwise load as a rule that never matches) and
     * {@see self::SKIP_REASON_CHAINED} (a rule chain, counted once for the starter and all its
     * chained rules).
     *
     * @return array{rules: CoreRuleSet, parsed: int, skipped: int, skippedByReason: array<string, int>}
     */
    public static function fromStringWithReport(string $rulesText, ?int $maxValuesPerCrsVariable = null): array
    {
        return self::load($rulesText, null, $maxValuesPerCrsVariable);
    }

    /**
     * @return array{rules: CoreRuleSet, parsed: int, skipped: int, skippedByReason: array<string, int>}
     */
    private static function load(string $rulesText, ?string $contextFolder, ?int $maxValuesPerCrsVariable): array
    {
        $secRuleParser = new SecRuleParser();
        $rules = [];
        $skippedByReason = [];
        $chainContinuationExpected = false;

        foreach (self::logicalLines($rulesText) as $line) {
            $isSecRule = str_starts_with($line, 'SecRule ');

            // The engine evaluates rules independently, so a chain cannot be evaluated faithfully:
            // its starter alone would match (and block) without the chained conditions. Skip the
            // whole chain - the starter and every following SecRule up to the one without `chain`.
            if ($chainContinuationExpected && $isSecRule) {
                $chainContinuationExpected = $secRuleParser->hasChainAction($line);
                continue;
            }

            $rule = $secRuleParser->parseLine($line, $contextFolder);
            if (!$rule instanceof CoreRule) {
                $skippedByReason[self::SKIP_REASON_UNPARSEABLE] = ($skippedByReason[self::SKIP_REASON_UNPARSEABLE] ?? 0) + 1;
                $chainContinuationExpected = $chainContinuationExpected || ($isSecRule && $secRuleParser->hasChainAction($line));
                continue;
            }

            if (self::startsAChain($rule)) {
                $skippedByReason[self::SKIP_REASON_CHAINED] = ($skippedByReason[self::SKIP_REASON_CHAINED] ?? 0) + 1;
                $chainContinuationExpected = true;
                continue;
            }

            if (!OperatorEvaluatorFactory::isSupported($rule->operator)) {
                $skippedByReason[self::SKIP_REASON_UNSUPPORTED_OPERATOR] = ($skippedByReason[self::SKIP_REASON_UNSUPPORTED_OPERATOR] ?? 0) + 1;
                continue;
            }

            if (!self::transformationsAreSupported($rule)) {
                $skippedByReason[self::SKIP_REASON_UNSUPPORTED_TRANSFORMATION] = ($skippedByReason[self::SKIP_REASON_UNSUPPORTED_TRANSFORMATION] ?? 0) + 1;
                continue;
            }

            $rules[] = $rule;
        }

        return [
            'rules' => new CoreRuleSet($rules, $maxValuesPerCrsVariable),
            'parsed' => count($rules),
            'skipped' => array_sum($skippedByReason),
            'skippedByReason' => $skippedByReason,
        ];
    }

    public static function fromFile(string $filePath, ?int $maxValuesPerCrsVariable = null): CoreRuleSet
    {
        if (!is_file($filePath)) {
            throw new \InvalidArgumentException('Rules file not found: ' . $filePath);
        }

        // Confine @pmFromFile resolution to the rule file's own directory,
        // mirroring fromFiles()/fromDirectory(). Without a context folder an
        // absolute or symlinked @pmFromFile operand would read arbitrary files.
        $resolvedPath = realpath($filePath);
        $contextFolder = dirname($resolvedPath !== false ? $resolvedPath : $filePath);

        $content = (string)file_get_contents($filePath);
        return self::fromString($content, $contextFolder, $maxValuesPerCrsVariable);
    }

    /**
     * Load and concatenate multiple files into a single CoreRuleSet.
     * Files that do not exist will trigger an exception.
     * @param list<string> $paths
     */
    public static function fromFiles(array $paths, ?int $maxValuesPerCrsVariable = null): CoreRuleSet
    {
        $buffer = '';
        $directoryOfFirstFile = null;
        foreach ($paths as $path) {
            $path = realpath($path);

            if ($path === false || !is_file($path)) {
                throw new \InvalidArgumentException('Rules file not found: ' . $path);
            }

            if ($directoryOfFirstFile === null) {
                $directoryOfFirstFile = dirname($path);
            } else {
                $currentDir = dirname($path);
                if ($currentDir !== $directoryOfFirstFile) {
                    throw new \InvalidArgumentException(sprintf("File '%s' of a CoreRuleSet must be in the same folder as other files ('%s').", $path, $directoryOfFirstFile));
                }
            }

            $buffer .= file_get_contents($path) . "\n";
        }

        return self::fromString($buffer, $directoryOfFirstFile, $maxValuesPerCrsVariable);
    }

    /**
     * Load all files from a directory, optionally filtered. Files are processed in sorted order.
     * @param callable(string):bool|null $filter
     */
    public static function fromDirectory(string $dir, ?callable $filter = null, ?int $maxValuesPerCrsVariable = null): CoreRuleSet
    {
        // Ensure path is absolute
        $dir = realpath($dir);

        if ($dir === false || !is_dir($dir)) {
            throw new \InvalidArgumentException('Rules directory not found: ' . $dir);
        }

        $entries = scandir($dir);
        if ($entries === false) {
            $entries = [];
        }

        $files = [];
        foreach ($entries as $entry) {
            if ($entry === '.') {
                continue;
            }

            if ($entry === '..') {
                continue;
            }

            $path = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $entry;
            if (is_file($path) && ($filter === null || $filter($path) === true)) {
                $files[] = $path;
            }
        }

        sort($files, SORT_STRING);
        return self::fromFiles($files, $maxValuesPerCrsVariable);
    }
}
