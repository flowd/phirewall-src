<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\RequestView;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestVariableValues;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The rules inspect the PSR-7 request and what its server parameters hold
 * beyond it, see {@see RequestView}.
 */
final class ServerParametersInspectionTest extends TestCase
{
    private const VARIABLES = [
        'REQUEST_URI', 'REQUEST_METHOD', 'QUERY_STRING', 'ARGS', 'ARGS_NAMES', 'REQUEST_COOKIES',
        'REQUEST_COOKIES_NAMES', 'REQUEST_HEADERS', 'REQUEST_HEADERS_NAMES', 'REQUEST_FILENAME',
    ];

    /**
     * A request as PHP-FPM hands it to an application: the PSR-7 request built
     * from the superglobals, with the server parameters it was built from.
     *
     * @param array<string, string> $headers
     */
    private static function requestFromWebServer(string $method, string $target, array $headers = [], string $cookieHeader = ''): ServerRequestInterface
    {
        $queryString = (string) parse_url('http://example.test' . $target, PHP_URL_QUERY);
        parse_str($queryString, $queryParameters);

        $cookies = [];
        foreach ($cookieHeader === '' ? [] : explode('; ', $cookieHeader) as $cookie) {
            [$name, $value] = explode('=', $cookie, 2);
            $cookies[$name] ??= rawurldecode($value);
        }

        $headers = ['Host' => 'example.test'] + $headers + ($cookieHeader === '' ? [] : ['Cookie' => $cookieHeader]);
        $serverParameters = [
            'REQUEST_METHOD' => $method,
            'REQUEST_URI' => $target,
            'QUERY_STRING' => $queryString,
            'SCRIPT_NAME' => '/index.php',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
            'REMOTE_ADDR' => '203.0.113.7',
            'REQUEST_TIME' => 1_795_000_000,
            'CONTENT_TYPE' => $headers['Content-Type'] ?? '',
            'CONTENT_LENGTH' => $headers['Content-Length'] ?? '',
        ];
        foreach ($headers as $name => $value) {
            $serverParameters['HTTP_' . strtoupper(strtr($name, '-', '_'))] = $value;
        }

        return (new ServerRequest($method, 'https://example.test' . $target, $headers, null, '1.1', $serverParameters))
            ->withQueryParams($queryParameters)
            ->withCookieParams($cookies);
    }

    /**
     * A form as PHP-FPM hands it over: the body as it was sent, and what PHP
     * parsed of it.
     *
     * @param array<array-key, mixed>|null $parsedBody What PHP parsed, when that is not what parse_str() gives
     */
    private static function formFromWebServer(string $body, string $target = '/contact', ?array $parsedBody = null): ServerRequestInterface
    {
        if ($parsedBody === null) {
            parse_str($body, $parsedBody);
        }

        $serverRequest = self::requestFromWebServer('POST', $target, [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Content-Length' => (string) strlen($body),
        ]);
        $serverRequest->getBody()->write($body);
        $serverRequest->getBody()->rewind();

        return $serverRequest->withParsedBody($parsedBody);
    }

    /**
     * @return iterable<string, array{ServerRequestInterface}>
     */
    public static function ordinaryRequests(): iterable
    {
        $browser = [
            'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language' => 'de,en-US;q=0.7,en;q=0.3',
            'Accept-Encoding' => 'gzip, deflate, br, zstd',
            'Referer' => 'https://example.test/products?category=shoes',
            'Sec-Fetch-Dest' => 'document',
            'Sec-Fetch-Mode' => 'navigate',
            'X-Forwarded-For' => '198.51.100.4, 10.0.0.1',
        ];

        yield 'page view' => [self::requestFromWebServer('GET', '/products', $browser, 'PHPSESSID=3d1f0c9a7b; theme=dark')];
        yield 'filters' => [self::requestFromWebServer('GET', '/products?category=shoes&page=2&sort=price', $browser, 'PHPSESSID=3d1f0c9a7b')];
        yield 'lists and encoded values' => [self::requestFromWebServer('GET', '/search?q=caf%C3%A9+au+lait&tags%5B%5D=a&tags%5B%5D=b&filter%5Bprice%5D%5Bmax%5D=20&empty=&flag', $browser, 'consent=a%3D1%26b%3D0; token=ab+cd/ef==')];
        yield 'unencoded brackets in the query' => [self::requestFromWebServer('GET', '/list?ids[]=1&ids[]=2&ids[]=1', $browser)];
        yield 'unencoded brackets in the path' => [self::requestFromWebServer('GET', '/images/photo[1].jpg', $browser)];
        yield 'unencoded characters a library encodes' => [self::requestFromWebServer('GET', '/files/report{2024}|v2^.pdf?q=a|b', $browser)];
        yield 'UTF-8 as it is' => [self::requestFromWebServer('GET', "/caf\u{e9}/men\u{fc}?q=gr\u{fc}n", $browser)];
        yield 'form post' => [self::requestFromWebServer('POST', '/contact', $browser + ['Content-Type' => 'application/x-www-form-urlencoded', 'Content-Length' => '120', 'Origin' => 'https://example.test'], 'PHPSESSID=3d1f0c9a7b')];
        yield 'api call' => [self::requestFromWebServer('PUT', '/api/v1/items/42?expand=owner', ['User-Agent' => 'curl/8.9.1', 'Accept' => '*/*', 'Authorization' => 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc', 'Content-Type' => 'application/json', 'Content-Length' => '2'])];
        yield 'no query, no cookies, no headers' => [self::requestFromWebServer('GET', '/')];
        yield 'delete without a body' => [self::requestFromWebServer('DELETE', '/api/v1/items/42', ['User-Agent' => 'curl/8.9.1', 'Accept' => '*/*'])];
        yield 'form with a body' => [self::formFromWebServer(
            'name=J%C3%B6rg+M%C3%BCller&email=joerg%40example.test&message=Hello%2C+I+have+a+question.%0D%0AThanks%21&topics%5B%5D=sales&topics%5B%5D=support&address%5Bcity%5D=K%C3%B6ln&newsletter=&csrf=9f8a7b6c',
        )];
        yield 'form with a body and a query string' => [self::formFromWebServer('q=shoes&page=2', '/search?lang=de&page=1')];
        yield 'form without a body' => [self::formFromWebServer('')];
    }

    #[DataProvider('ordinaryRequests')]
    public function testAnOrdinaryRequestGivesTheRulesNothingMoreToInspect(ServerRequestInterface $serverRequest): void
    {
        $inspecting = new RequestVariableValues($serverRequest);
        $psr7Only = new RequestVariableValues($serverRequest, inspectServerParameters: false);

        foreach (self::VARIABLES as $variable) {
            $this->assertSame($psr7Only->entriesFor($variable), $inspecting->entriesFor($variable), $variable);
            $this->assertFalse($inspecting->wasCapped($variable), $variable);
        }
    }

    #[DataProvider('ordinaryRequests')]
    public function testAnOrdinaryRequestPassesTheShippedRulesAsBefore(ServerRequestInterface $serverRequest): void
    {
        $evaluation = Presets::coreRuleSet(ParanoiaLevel::Level2)->evaluate($serverRequest, stopWhenThresholdReached: false);
        $psr7Only = Presets::coreRuleSet(ParanoiaLevel::Level2)->inspectServerParameters(false)->evaluate($serverRequest, stopWhenThresholdReached: false);

        $this->assertSame($psr7Only->matchedRuleIds(), $evaluation->matchedRuleIds());
        $this->assertFalse($evaluation->isBlocked());
    }

    public function testTheFirstOfTwoParametersOfOneNameIsInspected(): void
    {
        // PHP keeps the last one; the query string an application may read itself holds both.
        $serverRequest = self::requestFromWebServer('GET', '/guestbook?comment=%3Cscript%3Ealert(1)%3C/script%3E&comment=hello');
        $this->assertSame(['comment' => 'hello'], $serverRequest->getQueryParams());

        $this->assertTrue(Presets::coreRuleSet()->evaluate($serverRequest)->isBlocked());
        $this->assertFalse(Presets::coreRuleSet()->inspectServerParameters(false)->evaluate($serverRequest)->isBlocked());
    }

    public function testAnExclusionOfAParameterCoversItsHiddenValuesToo(): void
    {
        $serverRequest = self::requestFromWebServer('GET', '/guestbook?comment=%3Cscript%3Ealert(1)%3C/script%3E&comment=hello');

        $evaluation = Presets::coreRuleSet()
            ->excludeTarget('ARGS:comment')
            ->excludeTarget('REQUEST_URI')
            ->excludeTarget('QUERY_STRING')
            ->evaluate($serverRequest);

        $this->assertSame([], $evaluation->matchedRuleIds());
    }

    public function testAnExclusionCoversAParameterOfARuntimeThatKeepsTheWrittenName(): void
    {
        // A runtime that parses the query string itself shows "query.sql", not PHP's "query_sql".
        $serverRequest = (new ServerRequest('GET', "https://example.test/report?query.sql=%27%20UNION%20SELECT%20password%20FROM%20users--", [], null, '1.1', [
            'QUERY_STRING' => 'query.sql=%27%20UNION%20SELECT%20password%20FROM%20users--',
        ]))->withQueryParams(['query.sql' => "' UNION SELECT password FROM users--"]);

        $excluding = static fn(): CoreRuleSet => Presets::coreRuleSet()
            ->excludeTarget('ARGS:query.sql')
            ->excludeTarget('REQUEST_URI')
            ->excludeTarget('QUERY_STRING');

        $this->assertSame([], $excluding()->evaluate($serverRequest, stopWhenThresholdReached: false)->matchedRuleIds());
        $this->assertTrue(Presets::coreRuleSet()->evaluate($serverRequest)->isBlocked(), 'Without the exclusion the value is inspected.');
    }

    public function testAValueWithoutANameIsInspected(): void
    {
        // PHP drops "=value"; what else reads the query string or the Cookie header may not.
        $args = SecRuleLoader::fromString('SecRule ARGS "@contains <script" "id:100113,phase:2,deny"');
        $inTheQuery = self::requestFromWebServer('GET', '/?=%3Cscript%3Ealert(1)%3C/script%3E&page=2');
        $this->assertSame(['page' => '2'], $inTheQuery->getQueryParams());
        $this->assertSame([100113], $args->evaluate($inTheQuery)->matchedRuleIds());

        $cookies = SecRuleLoader::fromString('SecRule REQUEST_COOKIES "@contains <script" "id:100114,phase:2,deny"');
        $inACookie = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['HTTP_COOKIE' => 'sid=abc; =%3Cscript%3E']);
        $this->assertSame([100114], $cookies->evaluate($inACookie)->matchedRuleIds());
    }

    public function testACookieCannotHideBehindAnEncodedCopyOfItself(): void
    {
        $payload = '$(cat /etc/passwd)';
        $serverRequest = (new ServerRequest('GET', 'https://example.test/', [], null, '1.1', [
            'HTTP_COOKIE' => 'c=' . rawurlencode(rawurlencode($payload)) . '; c=' . rawurlencode($payload),
        ]))->withCookieParams(['c' => rawurlencode($payload)]);

        $coreRuleSet = SecRuleLoader::fromString('SecRule REQUEST_COOKIES "@contains $(cat" "id:100115,phase:2,deny"');

        $this->assertSame([100115], $coreRuleSet->evaluate($serverRequest)->matchedRuleIds());
    }

    public function testEmptyParametersDoNotFailClosed(): void
    {
        // PHP skips them without counting them, so nothing was dropped.
        $padding = RequestView::defaultMaxParameters() + 10;
        $queryString = 'a=1' . str_repeat('&', $padding) . 'b=2';
        $serverRequest = (new ServerRequest('GET', 'https://example.test/', [], null, '1.1', [
            'QUERY_STRING' => $queryString,
            'REQUEST_URI' => '/?' . $queryString,
            'HTTP_COOKIE' => str_repeat('; ', $padding) . 'sid=abc',
        ]))->withQueryParams(['a' => '1', 'b' => '2'])->withCookieParams(['sid' => 'abc']);

        $coreRuleSet = SecRuleLoader::fromString(implode("\n", [
            'SecRule ARGS "@streq needle" "id:100116,phase:2,deny"',
            'SecRule REQUEST_COOKIES "@streq needle" "id:100117,phase:2,deny"',
        ]));

        $this->assertFalse($coreRuleSet->evaluate($serverRequest)->failClosed);
    }

    public function testANameAsItWasWrittenIsInspected(): void
    {
        // PHP turns the name into "x_y_"; a rule on parameter names has to see what was sent.
        $coreRuleSet = SecRuleLoader::fromString('SecRule ARGS_NAMES "@contains [evil" "id:100101,phase:2,deny"');
        $serverRequest = self::requestFromWebServer('GET', '/?x.y%5Bevil=1');
        $this->assertSame(['x_y_evil' => '1'], $serverRequest->getQueryParams());

        $this->assertSame([100101], $coreRuleSet->evaluate($serverRequest)->matchedRuleIds());
        $this->assertSame([], $coreRuleSet->inspectServerParameters(false)->evaluate($serverRequest)->matchedRuleIds());
    }

    public function testASecondCookieOfOneNameIsInspected(): void
    {
        // PHP keeps the first one.
        $coreRuleSet = SecRuleLoader::fromString('SecRule REQUEST_COOKIES:role "@streq admin" "id:100102,phase:2,deny"');
        $serverRequest = self::requestFromWebServer('GET', '/', [], 'role=user; role=admin');
        $this->assertSame(['role' => 'user'], $serverRequest->getCookieParams());

        $this->assertSame([100102], $coreRuleSet->evaluate($serverRequest)->matchedRuleIds());
        $this->assertSame([], $coreRuleSet->inspectServerParameters(false)->evaluate($serverRequest)->matchedRuleIds());
    }

    public function testAHeaderThePsr7RequestDoesNotHoldIsInspected(): void
    {
        // The Symfony bridge leaves out a header its PSR-7 library refuses; PHP still has it.
        $coreRuleSet = SecRuleLoader::fromString(implode("\n", [
            'SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:100103,phase:2,deny"',
            'SecRule REQUEST_HEADERS_NAMES "@streq X-Debug-Token" "id:100104,phase:2,deny"',
        ]));
        $serverRequest = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', [
            'HTTP_USER_AGENT' => "sqlmap/1.8\x01",
            'HTTP_X_DEBUG_TOKEN' => "a\x7f",
        ]);

        $this->assertSame([100103, 100104], $coreRuleSet->evaluate($serverRequest, stopWhenThresholdReached: false)->matchedRuleIds());
        $this->assertSame([], $coreRuleSet->inspectServerParameters(false)->evaluate($serverRequest)->matchedRuleIds());
    }

    public function testTheAddressAsTheServerReceivedItIsInspected(): void
    {
        // A router or a front controller that rewrote the address before the firewall saw the request.
        $coreRuleSet = SecRuleLoader::fromString(implode("\n", [
            'SecRule REQUEST_FILENAME "@endsWith /.env" "id:100105,phase:2,deny"',
            'SecRule REQUEST_URI "@contains debug=1" "id:100106,phase:2,deny"',
            'SecRule QUERY_STRING "@contains debug=1" "id:100107,phase:2,deny"',
            'SecRule REQUEST_METHOD "@streq TRACE" "id:100108,phase:2,deny"',
        ]));
        $serverRequest = new ServerRequest('POST', 'https://example.test/index.php', [], null, '1.1', [
            'REQUEST_METHOD' => 'TRACE',
            'REQUEST_URI' => '/app/.env?debug=1',
            'QUERY_STRING' => 'debug=1',
        ]);

        $this->assertSame([100105, 100106, 100107, 100108], $coreRuleSet->evaluate($serverRequest, stopWhenThresholdReached: false)->matchedRuleIds());
        $this->assertSame([], $coreRuleSet->inspectServerParameters(false)->evaluate($serverRequest)->matchedRuleIds());
    }

    public function testMoreParametersThanPhpReadsFailClosed(): void
    {
        $limit = RequestView::defaultMaxParameters();
        $pairs = [];
        $queryParameters = [];
        for ($index = 0; $index <= $limit; ++$index) {
            $pairs[] = 'k' . $index . '=v';
            if ($index < $limit) {
                $queryParameters['k' . $index] = 'v'; // what PHP keeps: max_input_vars of them
            }
        }

        $serverRequest = (new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['QUERY_STRING' => implode('&', $pairs)]))
            ->withQueryParams($queryParameters);

        $args = SecRuleLoader::fromString('SecRule ARGS "@streq needle" "id:100109,phase:2,deny"');
        $this->assertTrue($args->evaluate($serverRequest)->failClosed, 'What lies beyond the bound cannot be inspected.');
        $this->assertFalse($args->inspectServerParameters(false)->evaluate($serverRequest)->failClosed);

        $other = SecRuleLoader::fromString('SecRule REQUEST_HEADERS "@streq needle" "id:100110,phase:2,deny"');
        $this->assertFalse($other->evaluate($serverRequest)->failClosed, 'A rule on another variable is not affected.');

        array_pop($pairs);
        $withinTheBound = (new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['QUERY_STRING' => implode('&', $pairs)]))
            ->withQueryParams($queryParameters);
        $this->assertFalse(SecRuleLoader::fromString('SecRule ARGS "@streq needle" "id:100109,phase:2,deny"')->evaluate($withinTheBound)->failClosed);
    }

    public function testMoreCookiesThanPhpReadsFailClosed(): void
    {
        $cookies = [];
        for ($index = 0; $index <= RequestView::defaultMaxParameters(); ++$index) {
            $cookies[] = 'c' . $index . '=v';
        }

        $serverRequest = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['HTTP_COOKIE' => implode('; ', $cookies)]);

        $coreRuleSet = SecRuleLoader::fromString('SecRule REQUEST_COOKIES_NAMES "@streq needle" "id:100111,phase:2,deny"');
        $this->assertTrue($coreRuleSet->evaluate($serverRequest)->failClosed);
        $this->assertFalse($coreRuleSet->inspectServerParameters(false)->evaluate($serverRequest)->failClosed);
    }

    public function testTheMatcherPassesTheSettingOn(): void
    {
        $serverRequest = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['HTTP_USER_AGENT' => "sqlmap\x01"]);
        $rules = 'SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:100112,phase:2,deny,severity:CRITICAL"';

        $inspecting = new CoreRuleSetMatcher(SecRuleLoader::fromString($rules));
        $this->assertTrue($inspecting->match($serverRequest)->isMatch());

        $psr7Only = (new CoreRuleSetMatcher(SecRuleLoader::fromString($rules)))->inspectServerParameters(false);
        $this->assertFalse($psr7Only->match($serverRequest)->isMatch());

        $this->assertInstanceOf(CoreRuleSet::class, (new CoreRuleSet())->inspectServerParameters(true));
    }

    public function testTheSettingOfTheFirewallCoversTheRules(): void
    {
        $serverRequest = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', [
            'REQUEST_URI' => '/?q=%3Cscript%3Ealert(1)%3C/script%3E',
            'REMOTE_ADDR' => '203.0.113.9',
        ]);

        $config = (new Config(new InMemoryCache()))->with(Presets::blocklist(ParanoiaLevel::Level1));
        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isBlocked());

        $config->inspectServerParameters(false);
        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isPass());

        $config->inspectServerParameters(true);
        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isBlocked());
    }

    public function testTheFirstOfTwoBodyParametersOfOneNameIsInspected(): void
    {
        // PHP keeps the last one; the body an application may read itself holds both.
        $serverRequest = self::formFromWebServer('comment=%3Cscript%3Ealert(1)%3C/script%3E&comment=hello');
        $this->assertSame(['comment' => 'hello'], $serverRequest->getParsedBody());

        $this->assertTrue(Presets::coreRuleSet()->evaluate($serverRequest)->isBlocked());
        $this->assertFalse(Presets::coreRuleSet()->inspectServerParameters(false)->evaluate($serverRequest)->isBlocked());
        $this->assertSame(0, $serverRequest->getBody()->tell(), 'The body is where the application expects it.');
    }

    public function testAFormBodyThatWasNeverParsedIsInspected(): void
    {
        $serverRequest = self::formFromWebServer('comment=%3Cscript%3Ealert(1)%3C/script%3E')->withParsedBody(null);

        $this->assertTrue(Presets::coreRuleSet()->evaluate($serverRequest)->isBlocked());
        $this->assertFalse(Presets::coreRuleSet()->inspectServerParameters(false)->evaluate($serverRequest)->isBlocked());

        $names = array_column((new RequestVariableValues($serverRequest))->entriesFor('ARGS_NAMES'), 'value');
        $this->assertSame(['comment'], $names);
    }

    public function testAnExclusionOfAParameterCoversItsHiddenBodyValuesToo(): void
    {
        $serverRequest = self::formFromWebServer('comment=%3Cscript%3Ealert(1)%3C/script%3E&comment=hello');

        $this->assertSame([], Presets::coreRuleSet()->excludeTarget('ARGS:comment')->evaluate($serverRequest)->matchedRuleIds());
    }

    public function testABodyNameAsItWasWrittenIsInspected(): void
    {
        $serverRequest = self::formFromWebServer('user.name=x');
        $this->assertSame(['user_name' => 'x'], $serverRequest->getParsedBody());

        $names = array_column((new RequestVariableValues($serverRequest))->entriesFor('ARGS_NAMES'), 'value');
        $this->assertSame(['user_name', 'user.name'], $names);
    }

    public function testABodyThatIsNoFormIsNotRead(): void
    {
        $serverRequest = self::requestFromWebServer('POST', '/api', ['Content-Type' => 'application/json']);
        $serverRequest->getBody()->write('comment=%3Cscript%3Ealert(1)%3C/script%3E');
        $serverRequest->getBody()->rewind();

        $this->assertSame([], Presets::coreRuleSet()->evaluate($serverRequest)->matchedRuleIds());
    }

    public function testABodyThatNamesNoContentTypeIsInspectedAsAForm(): void
    {
        // symfony/http-foundation 7 below PHP 8.4 and yii2 parse such a body as a form; PHP does not.
        $body = 'comment=%3Cscript%3Ealert(1)%3C/script%3E';
        $serverRequest = self::requestFromWebServer('PUT', '/comments/7', ['Content-Length' => (string) strlen($body)]);
        $serverRequest->getBody()->write($body);
        $serverRequest->getBody()->rewind();

        $this->assertTrue(Presets::coreRuleSet()->evaluate($serverRequest)->isBlocked());
        $this->assertFalse(Presets::coreRuleSet()->inspectServerParameters(false)->evaluate($serverRequest)->isBlocked());
        $this->assertSame(0, $serverRequest->getBody()->tell(), 'The body is where the application expects it.');
    }

    public function testAnOrdinaryFormBodyWithoutAContentTypePassesTheShippedRules(): void
    {
        $body = 'name=J%C3%B6rg+M%C3%BCller&email=joerg%40example.test&tags%5B%5D=sales&quantity=2';
        $serverRequest = self::requestFromWebServer('PATCH', '/api/v1/items/42', ['User-Agent' => 'curl/8.9.1', 'Content-Length' => (string) strlen($body)]);
        $serverRequest->getBody()->write($body);
        $serverRequest->getBody()->rewind();

        $evaluation = Presets::coreRuleSet(ParanoiaLevel::Level2)->evaluate($serverRequest, stopWhenThresholdReached: false);
        $this->assertSame([], $evaluation->matchedRuleIds());
        $this->assertCount(8, (new RequestVariableValues($serverRequest))->entriesFor('ARGS'));
    }

    /**
     * @param string $body Sent without a content type, behind a web server that hands over an empty CONTENT_TYPE
     */
    private function bodyWithoutContentType(string $body, string $method = 'PUT'): ServerRequestInterface
    {
        $serverRequest = self::requestFromWebServer($method, '/upload', ['User-Agent' => 'curl/8.14.1', 'Content-Length' => (string) strlen($body)]);
        $serverRequest->getBody()->write($body);
        $serverRequest->getBody()->rewind();

        return $serverRequest;
    }

    public function testABodyWithoutAContentTypeIsInspectedUnlessThatIsTurnedOff(): void
    {
        $payload = $this->bodyWithoutContentType('comment=%3Cscript%3Ealert(1)%3C/script%3E');
        $this->assertTrue(Presets::coreRuleSet()->evaluate($payload)->isBlocked());
        $this->assertTrue(Presets::coreRuleSet()->inspectBodiesWithoutContentType()->evaluate($payload)->isBlocked());
        $this->assertSame([], Presets::coreRuleSet()->inspectBodiesWithoutContentType(false)->evaluate($payload)->matchedRuleIds());

        $upload = $this->bodyWithoutContentType(str_repeat('QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo', 100));
        $this->assertTrue(Presets::coreRuleSet()->evaluate($upload)->failClosed, 'More than the inspectable length without an & cannot be inspected.');
        $off = Presets::coreRuleSet()->inspectBodiesWithoutContentType(false)->evaluate($upload);
        $this->assertFalse($off->failClosed);
        $this->assertFalse($off->isBlocked());

        $form = self::formFromWebServer('comment=%3Cscript%3Ealert(1)%3C/script%3E&comment=hello');
        $this->assertTrue(Presets::coreRuleSet()->inspectBodiesWithoutContentType(false)->evaluate($form)->isBlocked(), 'A form is read either way.');
    }

    public function testTheMatcherPassesTheSettingForBodiesWithoutAContentTypeOn(): void
    {
        $serverRequest = $this->bodyWithoutContentType('q=needle');
        $rules = 'SecRule ARGS "@streq needle" "id:100114,phase:2,deny,severity:CRITICAL"';

        $this->assertTrue((new CoreRuleSetMatcher(SecRuleLoader::fromString($rules)))->match($serverRequest)->isMatch());
        $this->assertFalse((new CoreRuleSetMatcher(SecRuleLoader::fromString($rules)))->inspectBodiesWithoutContentType(false)->match($serverRequest)->isMatch());
        $this->assertTrue((new CoreRuleSetMatcher(SecRuleLoader::fromString($rules)))->inspectBodiesWithoutContentType(false)->inspectBodiesWithoutContentType()->match($serverRequest)->isMatch());

        $preset = Presets::blocklist(
            ParanoiaLevel::Level1,
            configure: static function (CoreRuleSetMatcher $coreRuleSetMatcher): void {
                $coreRuleSetMatcher->inspectBodiesWithoutContentType(false);
            },
        );
        $this->assertTrue((new Firewall((new Config(new InMemoryCache()))->with($preset)))->decide($this->bodyWithoutContentType('comment=%3Cscript%3Ealert(1)%3C/script%3E'))->isPass());
    }

    public function testWithoutTheServerParametersNoBodyWithoutAContentTypeIsRead(): void
    {
        $serverRequest = $this->bodyWithoutContentType('comment=%3Cscript%3Ealert(1)%3C/script%3E');

        $this->assertFalse(Presets::coreRuleSet()->inspectServerParameters(false)->inspectBodiesWithoutContentType(true)->evaluate($serverRequest)->isBlocked());

        $config = (new Config(new InMemoryCache()))->with(Presets::blocklist(ParanoiaLevel::Level1));
        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isBlocked());
        $config->inspectServerParameters(false);
        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isPass());
    }

    public function testMoreBodyParametersThanPhpReadsFailClosed(): void
    {
        $limit = RequestView::defaultMaxParameters();
        $pairs = [];
        $parsedBody = [];
        for ($index = 0; $index <= $limit; ++$index) {
            $pairs[] = 'k' . $index . '=v';
            if ($index < $limit) {
                $parsedBody['k' . $index] = 'v'; // what PHP keeps: max_input_vars of them
            }
        }

        $overTheBound = self::formFromWebServer(implode('&', $pairs), '/contact', $parsedBody);

        $args = SecRuleLoader::fromString('SecRule ARGS "@streq needle" "id:100113,phase:2,deny"');
        $this->assertTrue($args->evaluate($overTheBound)->failClosed, 'What lies beyond the bound cannot be inspected.');
        $this->assertFalse($args->inspectServerParameters(false)->evaluate($overTheBound)->failClosed);

        array_pop($pairs);
        $withinTheBound = self::formFromWebServer(implode('&', $pairs));
        $this->assertFalse(SecRuleLoader::fromString('SecRule ARGS "@streq needle" "id:100113,phase:2,deny"')->evaluate($withinTheBound)->failClosed);
    }
}
