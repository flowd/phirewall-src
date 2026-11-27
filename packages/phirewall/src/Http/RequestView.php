<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * What a request holds, read from two sides: the PSR-7 request as the
 * application's library built it, and the server parameters it came with
 * (`getServerParams()`: `REQUEST_URI`, `QUERY_STRING`, `HTTP_*`, ...).
 *
 * A PSR-7 implementation may refuse, drop or rewrite what the client sent: a
 * header value it does not accept, the encoding of the path, the first of two
 * parameters of the same name. Code of the application that reads the server
 * parameters still gets it. Every list of this class starts with the values of
 * the PSR-7 request and adds those of the server parameters that are not among
 * them, so a rule that inspects a list sees both and a request on which both
 * sides agree costs it nothing extra.
 *
 * An address that differs only in how it is percent-encoded (a library writes
 * `[` as `%5B`) is the same address and is not added. A server parameter whose
 * value the process environment holds under the same name is not a header of
 * the request (`HTTP_PROXY` in a container) and is left out.
 *
 * Only the server parameters of the request itself are read, never the
 * superglobals: in a long-running worker or a test those belong to another
 * request. A runtime that leaves the server parameters empty gives the PSR-7
 * values alone. The body is read for one thing only: the parameters of a form
 * (`application/x-www-form-urlencoded`, or a body that names no content type)
 * that `getParsedBody()` does not show, see {@see hiddenBodyParameters()}.
 *
 * Every built-in rule reads a request through its view. One that restricts
 * (a blocklist, a throttle scope, a fail2ban filter) matches when any reading
 * matches; one that grants (a safelist) only when every reading does, see
 * {@see \Flowd\Phirewall\Matchers\Support\Readings}. Where one value is needed
 * (a counter key, the forwarding chain) it is that of the PSR-7 request, and
 * that of the server parameters when the PSR-7 request has none.
 */
final class RequestView
{
    /** The parameters read from one query string or cookie header when `max_input_vars` gives no bound. */
    public const DEFAULT_MAX_PARAMETERS = 1000;

    /** The bytes read from the body of a form request when `post_max_size` gives no bound. */
    public const DEFAULT_MAX_BODY_BYTES = 8_388_608;

    /** The characters of a header name that names one server parameter (`X-Token`: `HTTP_X_TOKEN`). */
    private const PLAIN_HEADER_NAME = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-';

    /** With {@see SERVER_PARAMETER_CASE}: what a server parameter makes of a header name in one strtr() (`x-token`: `X_TOKEN`). */
    private const HEADER_NAME_CASE = 'abcdefghijklmnopqrstuvwxyz-';

    private const SERVER_PARAMETER_CASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_';

    /** Headers the server parameters may hold twice (`CONTENT_TYPE` and `HTTP_CONTENT_TYPE`). */
    private const HEADERS_OF_TWO_SERVER_PARAMETERS = ['content-type' => true, 'content-length' => true];

    /** What a PSR-7 library leaves as it is in a path or a query string; it percent-encodes everything else. */
    private const NOT_ENCODED_BY_LIBRARIES = '/[^A-Za-z0-9_\-.~!$&\'()*+,;=%:@\/?]+|%(?![A-Fa-f0-9]{2})/';

    /**
     * The request attribute that, when it is `false`, makes {@see of()} leave
     * the server parameters out; see {@see withServerParameterInspection()}.
     */
    public const INSPECT_SERVER_PARAMETERS_ATTRIBUTE = 'phirewall.inspectServerParameters';

    /** @var \WeakMap<ServerRequestInterface, self>|null */
    private static ?\WeakMap $views = null;

    private readonly string $method;

    private readonly string $path;

    private readonly string $query;

    /** @var array<array-key, array<array-key, string>> */
    private readonly array $requestHeaders;

    /** What the library of the request puts between the lines of one header in `getHeaderLine()`. */
    private readonly string $headerLineSeparator;

    /** @var array<array-key, mixed> */
    private readonly array $queryParameters;

    /** @var array<array-key, mixed> */
    private readonly array $cookies;

    /** @var array<array-key, mixed> */
    private readonly array $serverParameters;

    /** @var array<array-key, list<string>>|null */
    private ?array $headers = null;

    /** @var array<array-key, list<array-key>> Lower-case name with dashes => the names in {@see $headers} that read so. */
    private array $headerNames = [];

    /** Whether one header can be read without {@see headers()}, see {@see readsOneHeaderOnItsOwn()}; null until asked. */
    private ?bool $readsOneHeaderOnItsOwn = null;

    /** @var array<array-key, array<array-key, string>> {@see $requestHeaders} by lower-case name, when {@see $readsOneHeaderOnItsOwn}. */
    private array $requestHeadersByLowerName = [];

    /** Under plain CGI the environment of the process is the request; null until asked. */
    private ?bool $environmentIsTheRequest = null;

    /** @var array<array-key, list<string>> What {@see header()} gave, by the name it was asked for. */
    private array $headerValues = [];

    /** @var array<array-key, list<string>> What the PSR-7 request holds for a header {@see header()} was asked for, by that name. */
    private array $ownHeaderValues = [];

    /** @var array<array-key, non-empty-list<string>> What {@see headerLines()} gave, by the name it was asked for. */
    private array $headerLines = [];

    /** @var array<array-key, string|false> What {@see serverHeader()} gave, by the name it was asked for; false for none. */
    private array $serverHeaders = [];

    /** @var non-empty-list<string>|null */
    private ?array $queryStrings = null;

    /** @var non-empty-list<NormalizedPath>|null */
    private ?array $normalizedPaths = null;

    /** @var list<array{name: string, writtenName: string, value: ?string, nameIsHidden: bool}>|null */
    private ?array $hiddenQueryParameters = null;

    /** @var list<array{name: string, writtenName: string, value: ?string, nameIsHidden: bool}>|null */
    private ?array $hiddenCookies = null;

    /** @var list<array{name: string, writtenName: string, value: ?string, nameIsHidden: bool}>|null */
    private ?array $hiddenBodyParameters = null;

    /** @var list<array{name: string, writtenName: string, value: ?string, nameIsHidden: bool}>|null As {@see $hiddenBodyParameters}, with a body without a content type that is no form. */
    private ?array $hiddenFormBodyParameters = null;

    private bool $queryParametersComplete = true;

    private bool $cookiesComplete = true;

    private bool $bodyParametersComplete = true;

    private bool $formBodyParametersComplete = true;

    /**
     * Takes what it reads out of the request and does not keep the request:
     * a kept view is the value of its request in {@see $views}, and a
     * reference back to that key would keep both alive on PHP 8.2 for as long
     * as a worker runs.
     */
    private function __construct(
        ServerRequestInterface $serverRequest,
        private readonly bool $readsServerParameters,
        private readonly ?int $maxParameters,
        private readonly ?int $maxBodyBytes,
    ) {
        $uri = $serverRequest->getUri();
        $this->method = $serverRequest->getMethod();
        $this->path = $uri->getPath();
        $this->query = $uri->getQuery();
        $this->requestHeaders = $serverRequest->getHeaders();
        $separator = ', ';
        foreach ($this->requestHeaders as $name => $values) {
            $lines = 0;
            // A cast, not a call of lines() for every header; lines() only for one that looks like two.
            foreach ((array) $values as $value) {
                if (++$lines === 2) {
                    $all = $this->lines($values);
                    if (count($all) > 1) {
                        $separator = $serverRequest->getHeaderLine((string) $name) === implode(',', $all) ? ',' : ', ';
                        break 2;
                    }

                    break;
                }
            }
        }

        $this->headerLineSeparator = $separator;
        $this->queryParameters = $serverRequest->getQueryParams();
        $this->cookies = $serverRequest->getCookieParams();
        $this->serverParameters = $readsServerParameters ? $serverRequest->getServerParams() : [];
    }

    /**
     * The view of a request. Asked again for the same request object, it is
     * the same view, so what one rule worked out is there for the next. The
     * view does not keep the request alive.
     *
     * @param int|null $maxParameters How many parameters are read from one query string, cookie
     *                                header or form body; PHP's `max_input_vars` when null.
     * @param int|null $maxBodyBytes How many bytes of a form body are read; PHP's `post_max_size`
     *                               when null. A view with a bound of its own is not kept.
     *
     * @throws \InvalidArgumentException When a bound is not positive.
     */
    public static function of(ServerRequestInterface $serverRequest, ?int $maxParameters = null, ?int $maxBodyBytes = null): self
    {
        if ($maxParameters !== null || $maxBodyBytes !== null) {
            if ($maxParameters !== null && $maxParameters < 1) {
                throw new \InvalidArgumentException(sprintf('$maxParameters must be a positive integer, %d given.', $maxParameters));
            }

            if ($maxBodyBytes !== null && $maxBodyBytes < 1) {
                throw new \InvalidArgumentException(sprintf('$maxBodyBytes must be a positive integer, %d given.', $maxBodyBytes));
            }

            return new self($serverRequest, self::readsServerParametersOf($serverRequest), $maxParameters, $maxBodyBytes);
        }

        if (!self::$views instanceof \WeakMap) {
            /** @var \WeakMap<ServerRequestInterface, self> $empty */
            $empty = new \WeakMap();
            self::$views = $empty;
        }

        $views = self::$views;
        $view = $views[$serverRequest] ?? null;
        if (!$view instanceof self) {
            $view = new self($serverRequest, $serverRequest->getAttribute(self::INSPECT_SERVER_PARAMETERS_ATTRIBUTE, true) !== false, null, null);
            $views[$serverRequest] = $view;
        }

        return $view;
    }

    /**
     * The request, saying whether {@see of()} reads its server parameters: the
     * request itself when it says so already, a copy with the attribute
     * {@see INSPECT_SERVER_PARAMETERS_ATTRIBUTE} otherwise. A request without
     * the attribute has them read. The setting belongs to the request, so it
     * goes along with every copy made of it (`withAttribute()`,
     * `withHeader()`, ...). {@see Firewall} and
     * {@see \Flowd\Phirewall\Middleware} apply
     * {@see \Flowd\Phirewall\Config::inspectServerParameters()} with it.
     */
    public static function withServerParameterInspection(ServerRequestInterface $serverRequest, bool $inspect): ServerRequestInterface
    {
        if (self::readsServerParametersOf($serverRequest) === $inspect) {
            return $serverRequest;
        }

        return $inspect
            ? $serverRequest->withoutAttribute(self::INSPECT_SERVER_PARAMETERS_ATTRIBUTE)
            : $serverRequest->withAttribute(self::INSPECT_SERVER_PARAMETERS_ATTRIBUTE, false);
    }

    /**
     * Only the boolean turns the server parameters off: a framework that copies
     * route parameters into attributes gives strings.
     */
    private static function readsServerParametersOf(ServerRequestInterface $serverRequest): bool
    {
        return $serverRequest->getAttribute(self::INSPECT_SERVER_PARAMETERS_ATTRIBUTE, true) !== false;
    }

    /**
     * The PSR-7 request alone: every list holds what the request object
     * returns and nothing from the server parameters.
     */
    public static function ofPsr7Only(ServerRequestInterface $serverRequest): self
    {
        return new self($serverRequest, false, null, null);
    }

    /**
     * PHP's `max_input_vars`: a query string or cookie header PHP parses in
     * full is read in full here too.
     */
    public static function defaultMaxParameters(): int
    {
        $configured = (int) ini_get('max_input_vars');

        return $configured > 0 ? $configured : self::DEFAULT_MAX_PARAMETERS;
    }

    /**
     * The request method, and `REQUEST_METHOD` when it is another.
     *
     * @return non-empty-list<string>
     */
    public function methods(): array
    {
        $methods = [$this->method];
        $written = $this->serverParameter('REQUEST_METHOD');
        if ($written !== null && $written !== $methods[0]) {
            $methods[] = $written;
        }

        return $methods;
    }

    /**
     * Path and query string of the request, and `REQUEST_URI` when it names
     * another address.
     *
     * @return non-empty-list<string>
     */
    public function targets(): array
    {
        $targets = [$this->path . ($this->query !== '' ? '?' . $this->query : '')];
        $written = $this->serverParameter('REQUEST_URI');
        if ($written !== null && !$this->isSameAddress($this->withoutAuthority($written), $targets[0])) {
            $targets[] = $written;
        }

        return $targets;
    }

    /**
     * The path of the request, and the path of `REQUEST_URI` when it is
     * another. Both as they are, percent-encoding included.
     *
     * @return non-empty-list<string>
     */
    public function paths(): array
    {
        $paths = [$this->path];
        $written = $this->serverParameter('REQUEST_URI');
        if ($written === null) {
            return $paths;
        }

        $written = $this->withoutAuthority($written);
        $queryStart = strpos($written, '?');
        if ($queryStart !== false) {
            $written = substr($written, 0, $queryStart);
        }

        if ($written !== '' && !$this->isSameAddress($written, $paths[0])) {
            $paths[] = $written;
        }

        return $paths;
    }

    /**
     * The query string of the request, then `QUERY_STRING` and the query
     * string of `REQUEST_URI` when they are others. A web server that rewrites
     * the address gives `QUERY_STRING` after the rewrite and `REQUEST_URI`
     * before it.
     *
     * @return non-empty-list<string>
     */
    public function queryStrings(): array
    {
        if ($this->queryStrings !== null) {
            return $this->queryStrings;
        }

        $queryStrings = [$this->query];
        $written = [$this->serverParameter('QUERY_STRING')];
        $target = $this->serverParameter('REQUEST_URI');
        $queryStart = $target === null ? false : strpos($target, '?');
        if ($target !== null && $queryStart !== false) {
            $written[] = substr($target, $queryStart + 1);
        }

        foreach ($written as $queryString) {
            if ($queryString === null) {
                continue;
            }

            foreach ($queryStrings as $known) {
                if ($this->isSameAddress($queryString, $known)) {
                    continue 2;
                }
            }

            $queryStrings[] = $queryString;
        }

        return $this->queryStrings = $queryStrings;
    }

    /**
     * {@see paths()}, each with its normalised form ({@see PathNormalizer}).
     *
     * @return non-empty-list<NormalizedPath>
     */
    public function normalizedPaths(): array
    {
        if ($this->normalizedPaths === null) {
            $normalizedPaths = [];
            foreach ($this->paths() as $path) {
                $normalizedPaths[] = PathNormalizer::analyze($path);
            }

            $this->normalizedPaths = $normalizedPaths;
        }

        return $this->normalizedPaths;
    }

    /**
     * Path and query string of the request, those of `REQUEST_URI` when it
     * names another address, and the path of the request with `QUERY_STRING`
     * when that is a query string of neither.
     *
     * @return non-empty-list<array{path: string, query: string}>
     */
    public function addresses(): array
    {
        $addresses = [['path' => $this->path, 'query' => $this->query]];
        $written = $this->serverParameter('REQUEST_URI');
        if ($written !== null) {
            $written = $this->withoutAuthority($written);
            $queryStart = strpos($written, '?');
            $path = $queryStart === false ? $written : substr($written, 0, $queryStart);
            $query = $queryStart === false ? '' : substr($written, $queryStart + 1);
            if (!$this->isSameAddress($path, $this->path) || !$this->isSameAddress($query, $this->query)) {
                $addresses[] = ['path' => $path, 'query' => $query];
            }
        }

        $queryString = $this->serverParameter('QUERY_STRING');
        if ($queryString !== null) {
            foreach ($addresses as $address) {
                if ($this->isSameAddress($queryString, $address['query'])) {
                    return $addresses;
                }
            }

            $addresses[] = ['path' => $this->path, 'query' => $queryString];
        }

        return $addresses;
    }

    /**
     * The headers of the request by name, with the values of the `HTTP_*`
     * server parameters (and `CONTENT_TYPE`, `CONTENT_LENGTH`) the request
     * does not hold.
     *
     * A value counts as held when it equals one of the header, leading and
     * trailing blanks aside. A server parameter names its header in upper
     * case with underscores, so it cannot tell `X-Token` from `X_Token`: its
     * value is compared with, and added to, every header of the request that
     * reads so, and listed under the name with dashes (`User-Agent`) when the
     * request has no header of that name.
     *
     * @return array<array-key, list<string>> A name of digits is an integer key
     */
    public function headers(): array
    {
        if ($this->headers !== null) {
            return $this->headers;
        }

        $headers = [];
        $names = [];
        foreach ($this->requestHeaders as $name => $values) {
            $held = [];
            foreach ((array) $values === $values ? $values : $this->lines($values) as $value) {
                $held[] = (string) $value;
            }

            $headers[$name] = $held;
            $names[strtr((string) $name, self::SERVER_PARAMETER_CASE, self::HEADER_NAME_CASE)][] = $name;
        }

        // Under plain CGI the environment of the process is the request; everywhere else a
        // variable of the environment that happens to be named like a header is none of its headers.
        $environmentIsTheRequest = $this->environmentIsTheRequest ??= getenv('REQUEST_METHOD', true) !== false;

        foreach ($this->serverParameters as $key => $value) {
            if (!is_string($key)) {
                continue;
            }

            if (str_starts_with($key, 'HTTP_')) {
                $lookup = substr($key, 5);
            } elseif ($key === 'CONTENT_TYPE' || $key === 'CONTENT_LENGTH') {
                $lookup = $key;
            } else {
                continue;
            }

            if ($lookup === '') {
                continue;
            }

            if (!is_string($value)) {
                continue;
            }

            if ($value === '') {
                continue;
            }

            $lookup = strtr($lookup, self::SERVER_PARAMETER_CASE, self::HEADER_NAME_CASE);
            $known = $names[$lookup] ?? [];
            $withDashes = null;
            foreach ($known as $name) {
                if ($this->holds($headers[$name], $value)) {
                    continue 2;
                }

                if (strtolower((string) $name) === $lookup) {
                    $withDashes = $name;
                }
            }

            if (!$environmentIsTheRequest && getenv($key, true) === $value) {
                continue;
            }

            if ($withDashes === null) {
                $withDashes = ucwords($lookup, '-');
                $headers[$withDashes] = [];
                $known[] = $withDashes;
                $names[$lookup] = $known;
            }

            foreach ($known as $name) {
                $headers[$name][] = $value;
            }
        }

        $this->headerNames = $names;

        return $this->headers = $headers;
    }

    /**
     * The values of one header from {@see headers()}; the name in any case,
     * and of every header that differs from it only in dashes and underscores
     * (a server parameter cannot tell them apart; not so in a view that
     * leaves the server parameters out).
     *
     * @return list<string>
     */
    public function header(string $name): array
    {
        if (isset($this->headerValues[$name])) {
            return $this->headerValues[$name];
        }

        $lowerName = strtolower($name);
        if (
            $this->headers === null
            && ($this->readsOneHeaderOnItsOwn ?? $this->readsOneHeaderOnItsOwn())
            && $name !== ''
            && strspn($name, self::PLAIN_HEADER_NAME) === strlen($name)
            && !isset(self::HEADERS_OF_TWO_SERVER_PARAMETERS[$lowerName])
        ) {
            // One header of the request and one server parameter stand for this name, and
            // nobody has asked for all headers yet: read the two and leave the others alone.
            $own = [];
            $held = $this->requestHeadersByLowerName[$lowerName] ?? [];
            foreach ((array) $held === $held ? $held : $this->lines($held) as $value) {
                $own[] = (string) $value;
            }

            $values = $own;
            if (isset($own[1])) {
                $values = [];
                foreach ($own as $value) {
                    if (!in_array($value, $values, true)) {
                        $values[] = $value;
                    }
                }
            }

            if ($this->readsServerParameters) {
                $key = 'HTTP_' . strtr($name, self::HEADER_NAME_CASE, self::SERVER_PARAMETER_CASE);
                $value = $this->serverParameters[$key] ?? null;
                if (
                    is_string($value)
                    && $value !== ''
                    && !in_array($value, $values, true)
                    && !$this->holds($values, $value)
                    && (($this->environmentIsTheRequest ??= getenv('REQUEST_METHOD', true) !== false) || getenv($key, true) !== $value)
                ) {
                    $values[] = $value;
                }
            }

            $this->ownHeaderValues[$name] = $own;

            return $this->headerValues[$name] = $values;
        }

        $headers = $this->headers();
        $own = [];
        $values = [];
        foreach ($this->headerNames[strtr($name, self::SERVER_PARAMETER_CASE, self::HEADER_NAME_CASE)] ?? [] as $known) {
            $isTheName = strtolower((string) $known) === $lowerName;
            if ($isTheName) {
                $held = $this->requestHeaders[$known] ?? [];
                foreach ((array) $held === $held ? $held : $this->lines($held) as $value) {
                    $own[] = (string) $value;
                }
            } elseif (!$this->readsServerParameters) {
                // Without the server parameters a header is the one of that name, as getHeader() gives it.
                continue;
            }

            foreach ($headers[$known] as $value) {
                if (!in_array($value, $values, true)) {
                    $values[] = $value;
                }
            }
        }

        $this->ownHeaderValues[$name] = $own;

        return $this->headerValues[$name] = $values;
    }

    /**
     * One header as a line, in every reading: first the line of the PSR-7
     * request as `getHeaderLine()` gives it (`''` when it has no such
     * header), then each value of {@see header()} that is not on that line:
     * what the server parameters hold besides, and a header of the request
     * that differs from the name only in dashes and underscores.
     *
     * @return non-empty-list<string>
     */
    public function headerLines(string $name): array
    {
        if (isset($this->headerLines[$name])) {
            return $this->headerLines[$name];
        }

        $values = $this->header($name);
        $own = $this->ownHeaderValues[$name];
        $lines = [isset($own[1]) ? implode($this->headerLineSeparator, $own) : $own[0] ?? ''];
        if (!$this->readsServerParameters || $values === $own) {
            return $this->headerLines[$name] = $lines;
        }

        foreach ($values as $value) {
            if (in_array($value, $own, true)) {
                continue;
            }

            if (in_array($value, $lines, true)) {
                continue;
            }

            // The lines of the request, joined by the web server.
            if (isset($own[1]) && $this->withoutBlanksAtCommas($value) === $this->withoutBlanksAtCommas($lines[0])) {
                continue;
            }

            $lines[] = $value;
        }

        return $this->headerLines[$name] = $lines;
    }

    /**
     * What the server parameters hold for one header (`HTTP_X_FORWARDED_FOR`
     * for `X-Forwarded-For`), whether or not the request holds it too; null
     * when they hold nothing, or the view does not read them.
     */
    public function serverHeader(string $name): ?string
    {
        $known = $this->serverHeaders[$name] ?? null;
        if ($known !== null) {
            return $known === false ? null : $known;
        }

        $key = strtr($name, self::HEADER_NAME_CASE, self::SERVER_PARAMETER_CASE);
        if ($key !== 'CONTENT_TYPE' && $key !== 'CONTENT_LENGTH') {
            $key = 'HTTP_' . $key;
        }

        $value = $this->serverParameter($key);
        if ($value !== null && !($this->environmentIsTheRequest ??= getenv('REQUEST_METHOD', true) !== false) && getenv($key, true) === $value) {
            $value = null;
        }

        $this->serverHeaders[$name] = $value ?? false;

        return $value;
    }

    /**
     * `getQueryParams()` of the request, as it was when the view was made.
     *
     * @return array<array-key, mixed>
     */
    public function queryParameters(): array
    {
        return $this->queryParameters;
    }

    /**
     * `getCookieParams()` of the request, as it was when the view was made.
     *
     * @return array<array-key, mixed>
     */
    public function cookies(): array
    {
        return $this->cookies;
    }

    /**
     * What the query strings hold and `getQueryParams()` does not show: the
     * first of two parameters of one name (PHP keeps the last), a name PHP
     * rewrites or drops (`my.field`, `a[`, a name with a NUL byte, no name at
     * all), parameters beyond `max_input_vars`, and every parameter of a
     * request whose query parameters were never filled in.
     *
     * Each entry carries the name of the parameter as the request shows it:
     * the name PHP gives it (`my_field`, `a[b]`, `list[0]`), or the written
     * name when the request shows that one (a runtime that parses the query
     * string itself) or PHP drops such a name. Then the name as written,
     * decoded; the decoded value when the request does not hold it under that
     * name, else null; and whether the written name is one the request does
     * not show. Names and values are decoded once, as PHP decodes them.
     *
     * @return list<array{name: string, writtenName: string, value: ?string, nameIsHidden: bool}>
     */
    public function hiddenQueryParameters(): array
    {
        if ($this->hiddenQueryParameters === null) {
            $separators = (string) ini_get('arg_separator.input');
            [$this->hiddenQueryParameters, $this->queryParametersComplete] = $this->readsServerParameters
                ? $this->hidden($this->queryStrings(), $this->queryParameters, $separators === '' ? '&' : $separators, false)
                : [[], true];
        }

        return $this->hiddenQueryParameters;
    }

    /**
     * False when a query string holds more parameters than are read (see
     * {@see of()}): {@see hiddenQueryParameters()} is then not all there is.
     * As many are read as the request shows, when those are more.
     */
    public function queryParametersComplete(): bool
    {
        $this->hiddenQueryParameters();

        return $this->queryParametersComplete;
    }

    /**
     * What the `Cookie` headers hold and `getCookieParams()` does not show:
     * the second of two cookies of one name (PHP keeps the first), a name
     * PHP rewrites, cookies beyond `max_input_vars`. Entries as in
     * {@see hiddenQueryParameters()}; a cookie name is not decoded, its value
     * is, with `+` left as it is, as PHP reads cookies.
     *
     * @return list<array{name: string, writtenName: string, value: ?string, nameIsHidden: bool}>
     */
    public function hiddenCookies(): array
    {
        if ($this->hiddenCookies === null) {
            [$this->hiddenCookies, $this->cookiesComplete] = $this->readsServerParameters
                ? $this->hidden($this->header('Cookie'), $this->cookies, ';', true)
                : [[], true];
        }

        return $this->hiddenCookies;
    }

    /**
     * False when a `Cookie` header holds more cookies than are read (see
     * {@see of()}): {@see hiddenCookies()} is then not all there is.
     */
    public function cookiesComplete(): bool
    {
        $this->hiddenCookies();

        return $this->cookiesComplete;
    }

    /**
     * What the body of a form request (`application/x-www-form-urlencoded`,
     * or no content type in any reading, which some frameworks parse as a
     * form) holds and `getParsedBody()` does not show: the first of two
     * parameters of one name, a name PHP rewrites or drops, parameters
     * beyond `max_input_vars`, and every parameter of a request whose body
     * was never parsed. Entries as in {@see hiddenQueryParameters()}.
     *
     * The body is read from its start and left at the position it was at. A
     * body of another content type is not read, nor an empty one, nor one
     * that cannot be read again (a stream that is not seekable, a stream of
     * slim/psr7), nor any with a view that leaves the server parameters out.
     * A form body longer than the bound, by its size or its `Content-Length`,
     * is incomplete whether it can be read or not.
     *
     * @param ServerRequestInterface $serverRequest The request this is the view of; the view does not keep it
     * @param bool $bodyWithoutContentTypeIsForm Whether a body for which no reading names a content type
     *                                           is read as a form (the default); with false only a body of
     *                                           type `application/x-www-form-urlencoded` is. The view keeps
     *                                           the answer for each value apart.
     *
     * @return list<array{name: string, writtenName: string, value: ?string, nameIsHidden: bool}>
     */
    public function hiddenBodyParameters(ServerRequestInterface $serverRequest, bool $bodyWithoutContentTypeIsForm = true): array
    {
        $known = $bodyWithoutContentTypeIsForm ? $this->hiddenBodyParameters : $this->hiddenFormBodyParameters;
        if ($known !== null) {
            return $known;
        }

        [$body, $complete] = $this->formBody($serverRequest, $bodyWithoutContentTypeIsForm);
        $hidden = [];
        if ($body !== null) {
            $parsedBody = $serverRequest->getParsedBody();
            [$hidden, $complete] = $this->hidden([$body], is_array($parsedBody) ? $parsedBody : [], '&', false);
        }

        if ($bodyWithoutContentTypeIsForm) {
            $this->bodyParametersComplete = $complete;

            return $this->hiddenBodyParameters = $hidden;
        }

        $this->formBodyParametersComplete = $complete;

        return $this->hiddenFormBodyParameters = $hidden;
    }

    /**
     * False when the body of a form request holds more parameters than are
     * read or more bytes than are read (see {@see of()}):
     * {@see hiddenBodyParameters()} is then not all there is.
     *
     * @param bool $bodyWithoutContentTypeIsForm As for {@see hiddenBodyParameters()}
     */
    public function bodyParametersComplete(ServerRequestInterface $serverRequest, bool $bodyWithoutContentTypeIsForm = true): bool
    {
        $this->hiddenBodyParameters($serverRequest, $bodyWithoutContentTypeIsForm);

        return $bodyWithoutContentTypeIsForm ? $this->bodyParametersComplete : $this->formBodyParametersComplete;
    }

    /**
     * PHP's `post_max_size`: a form body PHP parses is read in full here
     * too. `0` is no bound, as for PHP.
     */
    public static function defaultMaxBodyBytes(): int
    {
        $configured = trim((string) ini_get('post_max_size'));
        if ($configured === '') {
            return self::DEFAULT_MAX_BODY_BYTES;
        }

        $bytes = @ini_parse_quantity($configured);
        if ($bytes === 0) {
            return PHP_INT_MAX;
        }

        return $bytes > 0 ? $bytes : self::DEFAULT_MAX_BODY_BYTES;
    }

    /**
     * The body of a form request and true, or null and whether that is
     * because there is nothing to read (true) or more than is read (false).
     *
     * @return array{0: ?string, 1: bool}
     */
    private function formBody(ServerRequestInterface $serverRequest, bool $bodyWithoutContentTypeIsForm): array
    {
        if (!$this->readsServerParameters) {
            return [null, true];
        }

        // The start of the type decides, as it does for frameworks that parse a form themselves
        // (symfony/http-foundation 7 takes `application/x-www-form-urlencodedX` for a form).
        // A body for which no reading names a type is a form too, whatever the method, unless
        // the caller says otherwise: symfony/http-foundation 7 below PHP 8.4 parses such a body
        // of PUT, PATCH and DELETE as one, yii2 that of every method but POST, and of a POST its
        // X-Http-Method-Override header turns into another method.
        $isForm = false;
        $namesAType = false;
        foreach ($this->header('Content-Type') as $contentType) {
            $contentType = ltrim($contentType);
            if (stripos($contentType, 'application/x-www-form-urlencoded') === 0) {
                $isForm = true;
                break;
            }

            if (rtrim($contentType) !== '') {
                $namesAType = true;
            }
        }

        if (!$isForm && ($namesAType || !$bodyWithoutContentTypeIsForm)) {
            return [null, true];
        }

        $limit = $this->maxBodyBytes ?? self::defaultMaxBodyBytes();
        $stream = null;
        $position = null;
        $content = '';
        try {
            $stream = $serverRequest->getBody();
            // A body longer than the bound is more than is read, also one that is not read at all:
            // the size the stream knows, else the length the request declares (php://input knows none).
            $size = $stream->getSize();
            if ($size === 0) {
                return [null, true];
            }

            if ($size === null) {
                foreach ($this->header('Content-Length') as $declared) {
                    if (ctype_digit($declared) && (int) $declared > $limit) {
                        return [null, false];
                    }
                }
            } elseif ($size > $limit) {
                return [null, false];
            }

            if (!$stream->isSeekable() || !$stream->isReadable()) {
                return [null, true];
            }

            // slim/psr7 keeps a copy of everything read from a body and appends to it on each
            // read: read here and again by the application, the body would be in it twice.
            if (is_a($stream, 'Slim\\Psr7\\Stream')) {
                return [null, true];
            }

            $position = $stream->tell();
            $stream->rewind();
            while (!$stream->eof()) {
                $remaining = $limit - strlen($content);
                if ($remaining < 0) {
                    break;
                }

                // One byte more than the bound tells a body of that size from a longer one.
                $chunk = $stream->read($remaining >= 65_536 ? 65_536 : $remaining + 1);
                if ($chunk === '') {
                    break;
                }

                $content .= $chunk;
            }

            $stream->seek($position);
        } catch (\Throwable) {
            // A body that cannot be read is left to the application; what it parsed of it is inspected.
            try {
                if ($stream instanceof \Psr\Http\Message\StreamInterface && $position !== null) {
                    $stream->seek($position);
                }
            } catch (\Throwable) {
            }

            return [null, true];
        }

        return strlen($content) > $limit ? [null, false] : [$content, true];
    }

    /**
     * Whether one header can be read without sorting out all of them in
     * {@see headers()}: no two headers of the request read alike (in case, or
     * in dashes and underscores), and every server parameter of a header is
     * named as a web server names it (`HTTP_USER_AGENT`), so that one name
     * stands for one header and one server parameter. Nearly every request is
     * like that; for the others {@see headers()} is asked.
     */
    private function readsOneHeaderOnItsOwn(): bool
    {
        if ($this->readsOneHeaderOnItsOwn !== null) {
            return $this->readsOneHeaderOnItsOwn;
        }

        $names = array_keys($this->requestHeaders);
        $byLowerName = array_change_key_case($this->requestHeaders, CASE_LOWER);
        $onItsOwn = count($byLowerName) === count($names)
            && !str_contains(implode("\n", $names), '_')
            && ($this->serverParameters === [] || preg_match('/^HTTP_[A-Z0-9_]*+[^A-Z0-9_\n]/m', implode("\n", array_keys($this->serverParameters))) === 0);

        if ($onItsOwn) {
            $this->requestHeadersByLowerName = $byLowerName;
        }

        return $this->readsOneHeaderOnItsOwn = $onItsOwn;
    }

    /**
     * The lines of a header as the library of the request gives them. One
     * that is not strict may give a single value instead of a list: that is
     * one line, cast to a string where it is read like every other; null is
     * none, as a header that is not there.
     *
     * @return array<array-key, string>
     */
    private function lines(mixed $values): array
    {
        $lines = match (true) {
            is_array($values) => $values,
            $values === null => [],
            $values instanceof \Traversable => iterator_to_array($values, false),
            default => [$values],
        };

        /** @var array<array-key, string> $lines Not always strings: each is cast where it is read. */
        return $lines;
    }

    /** A server parameter that is a non-empty string, else null. */
    private function serverParameter(string $name): ?string
    {
        $value = $this->serverParameters[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * A request line may name the whole URI (absolute form); path and query
     * string follow the host.
     */
    private function withoutAuthority(string $target): string
    {
        if (!str_starts_with($target, '/') && preg_match('~^[a-z][a-z0-9+.-]*://[^/?#]*~i', $target, $match) === 1) {
            return substr($target, strlen($match[0]));
        }

        return $target;
    }

    /**
     * Whether two paths or query strings differ at most in what a PSR-7
     * library percent-encodes: `/photo[1].jpg` is `/photo%5B1%5D.jpg`.
     * Nothing is decoded, so `/%2e%2e/` is not `/../`.
     */
    private function isSameAddress(string $written, string $held): bool
    {
        if ($written === $held) {
            return true;
        }

        $encode = static fn(string $address): string => preg_replace_callback(
            self::NOT_ENCODED_BY_LIBRARIES,
            static fn(array $match): string => rawurlencode($match[0]),
            $address,
        ) ?? $address;

        return $encode($written) === $encode($held);
    }

    private function withoutBlanksAtCommas(string $line): string
    {
        return str_contains($line, ',') ? preg_replace('/[ \t]*,[ \t]*/', ',', trim($line, " \t")) ?? $line : trim($line, " \t");
    }

    /**
     * @param list<string> $held
     */
    private function holds(array $held, string $value): bool
    {
        if (in_array($value, $held, true)) {
            return true;
        }

        $value = trim($value, " \t");
        foreach ($held as $heldValue) {
            if (trim($heldValue, " \t") === $value) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $sources Query strings, or cookie headers
     * @param array<array-key, mixed> $shown What the request shows of them
     * @param non-empty-string $separators Each of its characters ends a parameter
     *
     * @return array{0: list<array{name: string, writtenName: string, value: ?string, nameIsHidden: bool}>, 1: bool}
     */
    private function hidden(array $sources, array $shown, string $separators, bool $cookies): array
    {
        if (implode('', $sources) === '') {
            return [[], true];
        }

        $shownValues = [];
        $shownNames = [];
        $shownCount = 0;
        self::index($shown, '', $shownValues, $shownNames, $shownCount);

        // What the request shows was read, however many: a runtime may not know PHP's bound.
        $limit = max($this->maxParameters ?? self::defaultMaxParameters(), $shownCount);

        $hidden = [];
        $seenValues = [];
        $seenNames = [];
        $complete = true;

        foreach ($sources as $source) {
            $length = strlen($source);
            $offset = 0;
            $named = 0;
            $unnamed = 0;
            while ($offset < $length) {
                $end = $offset + strcspn($source, $separators, $offset);
                $pair = substr($source, $offset, $end - $offset);
                $offset = $end + 1;
                if ($cookies) {
                    $pair = ltrim($pair, " \t\n\r\v\f");
                }

                // PHP skips these without counting them.
                if ($pair === '') {
                    continue;
                }

                $equals = strpos($pair, '=');
                $writtenName = $equals === false ? $pair : substr($pair, 0, $equals);
                $writtenValue = $equals === false ? '' : substr($pair, $equals + 1);
                if ($cookies) {
                    $value = rawurldecode($writtenValue);
                } else {
                    $writtenName = urldecode($writtenName);
                    $value = urldecode($writtenValue);
                }

                if ($writtenName === '') {
                    // PHP drops a value without a name and does not count it; other readers of the header keep it.
                    if (++$unnamed > $limit) {
                        $complete = false;
                        break;
                    }

                    if ($value !== '' && !isset($seenValues["\0" . $value])) {
                        $seenValues["\0" . $value] = true;
                        $hidden[] = ['name' => '', 'writtenName' => '', 'value' => $value, 'nameIsHidden' => false];
                    }

                    continue;
                }

                if (++$named > $limit) {
                    $complete = false;
                    break;
                }

                $name = $this->phpName($writtenName);
                $nameKey = $name === null ? null : self::withoutIndexes($name);
                $writtenKey = self::withoutIndexes($writtenName);
                $nameIsHidden = !isset($shownNames[$writtenKey]);

                // Held under the name PHP gives the parameter, or under the written one. Only the
                // value decoded as PHP decodes it counts: any other form of it is one the client
                // could have put into a second parameter to cover this one.
                $valueIsHidden = $value !== ''
                    && ($nameKey === null || !isset($shownValues[$nameKey . "\0" . $value]))
                    && !isset($shownValues[$writtenKey . "\0" . $value]);

                $entryName = $name !== null && ($nameKey === $writtenKey || $nameIsHidden) ? $name : $writtenName;
                if ($valueIsHidden) {
                    $seenKey = $entryName . "\0" . $value;
                    $valueIsHidden = !isset($seenValues[$seenKey]);
                    $seenValues[$seenKey] = true;
                }

                if ($nameIsHidden) {
                    $nameIsHidden = !isset($seenNames[$writtenName]);
                    $seenNames[$writtenName] = true;
                }

                if ($valueIsHidden || $nameIsHidden) {
                    $hidden[] = [
                        'name' => $entryName,
                        'writtenName' => $writtenName,
                        'value' => $valueIsHidden ? $value : null,
                        'nameIsHidden' => $nameIsHidden,
                    ];
                }
            }
        }

        return [$hidden, $complete];
    }

    /**
     * @param array<array-key, mixed> $parameters
     * @param array<string, true> $values "name NUL value" of every value
     * @param array<string, true> $names The name of every value
     */
    private static function index(array $parameters, string $prefix, array &$values, array &$names, int &$count): void
    {
        foreach ($parameters as $key => $value) {
            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';
            if (is_array($value)) {
                self::index($value, $name, $values, $names, $count);
                continue;
            }

            ++$count;
            $nameKey = self::withoutIndexes($name);
            $names[$nameKey] = true;
            if (is_scalar($value) || $value === null) {
                $values[$nameKey . "\0" . $value] = true;
            }
        }
    }

    /**
     * The name PHP registers a parameter under, with the keys of an array
     * in brackets (`a[b]`, `list[0]`); null when PHP drops the name. PHP
     * strips leading blanks, turns blanks, dots and an unclosed bracket into
     * underscores and cuts the name at a NUL byte.
     */
    private function phpName(string $writtenName): ?string
    {
        if (strpbrk($writtenName, " .[\0") === false) {
            return $writtenName;
        }

        parse_str(rawurlencode($writtenName) . '=', $parsed);
        $name = '';
        while (is_array($parsed) && $parsed !== []) {
            $key = array_key_first($parsed);
            $name = $name === '' ? (string) $key : $name . '[' . $key . ']';
            $parsed = $parsed[$key];
        }

        return $name === '' ? null : $name;
    }

    /**
     * `list[0]`, `list[7]` and `list[]` are entries of one list: the index
     * says where PHP put a value, not which parameter it came from.
     */
    private static function withoutIndexes(string $name): string
    {
        return str_contains($name, '[') ? preg_replace('/\[\d*\]/', '[]', $name) ?? $name : $name;
    }
}
