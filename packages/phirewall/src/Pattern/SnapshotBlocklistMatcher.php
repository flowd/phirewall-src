<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Pattern;

use Flowd\Phirewall\Config\MatchResult;
use Flowd\Phirewall\Config\RequestMatcherInterface;
use Flowd\Phirewall\Http\NormalizedPath;
use Flowd\Phirewall\Http\PathNormalizer;
use Flowd\Phirewall\Http\RequestView;
use Flowd\Phirewall\Matchers\ClientIpResolverAware;
use Flowd\Phirewall\Matchers\FailOpenAware;
use Flowd\Phirewall\Matchers\Support\CidrMatcher;
use Flowd\Phirewall\Matchers\Support\PathMatcher;
use Flowd\Phirewall\Matchers\Support\RegexMatcher;
use Psr\Http\Message\ServerRequestInterface;

final class SnapshotBlocklistMatcher implements RequestMatcherInterface, ClientIpResolverAware, FailOpenAware
{
    private ?PatternSnapshot $patternSnapshot = null;

    /**
     * @var array<string, array<string, mixed>>
     */
    private array $compiled = [];

    /** @var (callable(ServerRequestInterface): ?string)|null */
    private $ipExtractor;

    /** Fail-open default, matching {@see \Flowd\Phirewall\Config::isFailOpen()}. */
    private bool $failOpen = true;

    public function __construct(
        private readonly PatternBackendInterface $patternBackend,
        ?callable $ipResolver = null,
        private readonly string $backendName = '',
    ) {
        $this->ipExtractor = $ipResolver;
    }

    /**
     * Name of the pattern backend this matcher reads from, as registered on the
     * Config. Empty when built from a bare backend instance with no registered
     * name. {@see \Flowd\Phirewall\Config::with()} uses it to re-point the
     * matcher at the winning backend when layers override a backend by name.
     */
    public function backendName(): string
    {
        return $this->backendName;
    }

    /**
     * Return an equivalent matcher reading from a different backend instance,
     * preserving the IP resolver and backend name. Lets composition apply a
     * later layer's backend override to rules carried over from earlier layers.
     * Returns $this unchanged when the backend is already identical.
     */
    public function withBackend(PatternBackendInterface $patternBackend): self
    {
        if ($patternBackend === $this->patternBackend) {
            return $this;
        }

        $rebound = new self($patternBackend, $this->ipExtractor, $this->backendName);
        $rebound->useFailOpen($this->failOpen);
        return $rebound;
    }

    public function useFailOpen(bool $failOpen): void
    {
        $this->failOpen = $failOpen;
    }

    /**
     * Regex match honouring the failure policy: fail-open treats a PCRE engine
     * error as no match, fail-closed treats it as a match so the error cannot
     * be forced to slip past a block rule.
     */
    private function matchesRegex(?string $pattern, string $subject): bool
    {
        return $this->failOpen
            ? RegexMatcher::matches($pattern, $subject)
            : RegexMatcher::matchesFailClosed($pattern, $subject);
    }

    public function match(ServerRequestInterface $serverRequest): MatchResult
    {
        return $this->matchWithResolver($serverRequest, static function (ServerRequestInterface $serverRequest): ?string {
            $remoteAddr = $serverRequest->getServerParams()['REMOTE_ADDR'] ?? null;
            return is_string($remoteAddr) && $remoteAddr !== '' ? $remoteAddr : null;
        });
    }

    public function matchWithResolver(ServerRequestInterface $serverRequest, callable $defaultResolver): MatchResult
    {
        $resolver = $this->ipExtractor ?? $defaultResolver;
        $patternSnapshot = $this->loadSnapshot();
        $ip = $resolver($serverRequest);
        // Path entries match the normalised path or the raw path (PathMatcher's
        // restrictive mode), header entries any value of a header, and each in
        // every reading of the request (RequestView): this matcher only ever blocks.
        $requestView = null;
        $requestPaths = null;
        $requestSubjects = null;

        // Pre-compute binary IP once (used by CIDR matching)
        $ipBinary = ($ip !== null) ? @inet_pton($ip) : false;

        // Collapse IPv4-mapped IPv6 peers (`::ffff:x.x.x.x`) once so a client
        // presented in that form by a dual-stack host still matches IPv4 entries.
        $canonicalIp = ($ip !== null) ? CidrMatcher::canonicalizeIp($ip) : null;

        foreach ($patternSnapshot->entries as $entry) {
            $compiled = $this->compiled[$entry->kind->value][$this->entryKey($entry)] ?? null;
            if ($compiled === null) {
                continue;
            }

            switch ($entry->kind) {
                case PatternKind::IP:
                    // $compiled is the entry's canonical IP, pre-computed in compileEntry().
                    if ($canonicalIp !== null && $canonicalIp === $compiled) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::CIDR:
                    /** @var array{network: string, bits: int}|null $cidrCompiled */
                    $cidrCompiled = is_array($compiled) ? $compiled : null;
                    if ($ipBinary !== false && $cidrCompiled !== null && CidrMatcher::matches($ipBinary, $cidrCompiled)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::PATH_EXACT:
                    $requestPaths ??= ($requestView ??= RequestView::of($serverRequest))->normalizedPaths();
                    if ($compiled instanceof NormalizedPath && PathMatcher::equals($requestPaths, $compiled, false)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::PATH_PREFIX:
                    $requestPaths ??= ($requestView ??= RequestView::of($serverRequest))->normalizedPaths();
                    if ($compiled instanceof NormalizedPath && PathMatcher::startsWith($requestPaths, $compiled, false)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::PATH_REGEX:
                    $pathPattern = is_string($compiled) ? $compiled : null;
                    $matchesPath = fn(string $subject): bool => $this->matchesRegex($pathPattern, $subject);
                    $requestPaths ??= ($requestView ??= RequestView::of($serverRequest))->normalizedPaths();
                    if (PathMatcher::matchesRegex($requestPaths, $matchesPath, false)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                    }

                    break;
                case PatternKind::HEADER_EXACT:
                    $headerName = $entry->target ?? '';
                    if ($headerName !== '' && $this->headerValuesEqual(($requestView ??= RequestView::of($serverRequest))->header($headerName), $entry->value)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value, 'target' => $headerName]);
                    }

                    break;
                case PatternKind::HEADER_REGEX:
                    $headerName = $entry->target ?? '';
                    $headerPattern = is_string($compiled) ? $compiled : null;
                    if ($headerName !== '' && $this->headerValuesMatch(($requestView ??= RequestView::of($serverRequest))->header($headerName), $headerPattern)) {
                        return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value, 'target' => $headerName]);
                    }

                    break;
                case PatternKind::REQUEST_REGEX:
                    // Only REQUEST_REGEX needs the subjects; build them lazily once,
                    // and only when such an entry is actually present.
                    $requestSubjects ??= $this->requestSubjects($serverRequest, $requestView ??= RequestView::of($serverRequest));
                    $requestPattern = is_string($compiled) ? $compiled : null;
                    foreach ($requestSubjects as $requestSubject) {
                        if ($this->matchesRegex($requestPattern, $requestSubject)) {
                            return MatchResult::matched('pattern_backend', ['kind' => $entry->kind->value, 'value' => $entry->value]);
                        }
                    }

                    break;
            }
        }

        return MatchResult::noMatch();
    }

    private function loadSnapshot(): PatternSnapshot
    {
        // consume() runs on every request; version equality gates recompilation so
        // the compiled matchers are only rebuilt when the backend actually changed.
        $freshSnapshot = $this->patternBackend->consume();
        if (!$this->patternSnapshot instanceof PatternSnapshot || $freshSnapshot->version !== $this->patternSnapshot->version) {
            $this->patternSnapshot = $freshSnapshot;
            $this->compiled = $this->compileSnapshot($freshSnapshot);
        }

        return $freshSnapshot;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function compileSnapshot(PatternSnapshot $patternSnapshot): array
    {
        $compiled = [];
        $count = 0;
        foreach ($patternSnapshot->entries as $entry) {
            ++$count;
            if ($count > PatternBackendInterface::MAX_ENTRIES_DEFAULT) {
                break;
            }

            $key = $this->entryKey($entry);
            $compiled[$entry->kind->value][$key] = $this->compileEntry($entry);
        }

        return $compiled;
    }

    private function compileEntry(PatternEntry $patternEntry): mixed
    {
        return match ($patternEntry->kind) {
            PatternKind::CIDR => CidrMatcher::compile($patternEntry->value),
            // Canonicalise IP entries once at compile time so match() compares
            // against a pre-computed key instead of re-running inet_pton/inet_ntop
            // for every entry on every request (mirrors IpMatcher's keying).
            PatternKind::IP => CidrMatcher::canonicalizeIp($patternEntry->value),
            PatternKind::PATH_REGEX, PatternKind::HEADER_REGEX, PatternKind::REQUEST_REGEX => RegexMatcher::compile($patternEntry->value),
            // Literal path entries match in both forms; normalise the value once here.
            PatternKind::PATH_EXACT, PatternKind::PATH_PREFIX => PathMatcher::compileLiteral($patternEntry->value),
            default => $patternEntry->value,
        };
    }

    /**
     * Entry key with case-insensitive target for header matching.
     */
    private function entryKey(PatternEntry $patternEntry): string
    {
        $target = $patternEntry->target !== null ? strtolower($patternEntry->target) : '';
        return $patternEntry->kind->value . ':' . $target . ':' . $patternEntry->value;
    }

    /**
     * @param array<string> $values The values of one header ({@see RequestView::header()}).
     */
    private function headerValuesEqual(array $values, string $expected): bool
    {
        return in_array($expected, $values, true);
    }

    /**
     * @param array<string> $values The values of one header ({@see RequestView::header()}).
     */
    private function headerValuesMatch(array $values, ?string $pattern): bool
    {
        if ($pattern === null) {
            return false;
        }

        foreach ($values as $value) {
            if ($this->matchesRegex($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The subjects of a REQUEST_REGEX entry: one for each address of the
     * request (that of its PSR-7 URI, and those its server parameters name
     * besides) with the normalised path, and one with the raw path where the
     * two differ, as for PATH_REGEX. Each with the headers of the PSR-7
     * request alone, so a pattern that counts on their order or on the end of
     * the subject matches as it did, and once more with every header value
     * the request holds in either reading when those are more.
     *
     * @return list<string>
     */
    private function requestSubjects(ServerRequestInterface $serverRequest, RequestView $requestView): array
    {
        $headerSets = [$this->normalizeHeaders($serverRequest->getHeaders())];
        $inEitherReading = [];
        foreach ($requestView->headers() as $name => $values) {
            $name = strtolower((string) $name);
            $inEitherReading[$name] = [...($inEitherReading[$name] ?? []), ...$values];
        }

        if ($inEitherReading !== $headerSets[0]) {
            $headerSets[] = $inEitherReading;
        }

        $subjects = [];
        foreach ($requestView->addresses() as $address) {
            $requestPath = PathNormalizer::analyze($address['path']);
            foreach ($headerSets as $headerSet) {
                $subjects[] = $this->buildRequestSubject($requestPath->normalized, $address['query'], $headerSet);
                if ($requestPath->raw !== $requestPath->normalized) {
                    $subjects[] = $this->buildRequestSubject($requestPath->raw, $address['query'], $headerSet);
                }
            }
        }

        return array_values(array_unique($subjects));
    }

    /**
     * @param array<array-key, array<array-key, string>> $headers
     * @return array<string, list<string>>
     */
    private function normalizeHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $name => $values) {
            $normalized[strtolower((string) $name)] = array_values($values);
        }

        return $normalized;
    }

    /**
     * @param array<string, list<string>> $headers
     */
    private function buildRequestSubject(string $path, string $query, array $headers): string
    {
        $subject = $query === '' ? $path : $path . '?' . $query;
        $headerParts = [];
        foreach ($headers as $name => $values) {
            foreach ($values as $value) {
                $headerParts[] = $name . ':' . $value;
            }
        }

        if ($headerParts !== []) {
            $subject .= "\n" . implode("\n", $headerParts);
        }

        return $subject;
    }
}
