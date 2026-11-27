<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests;

use Flowd\Phirewall\BanType;
use Flowd\Phirewall\Config;
use Flowd\Phirewall\Context\RequestContext;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Http\RequestView;
use Flowd\Phirewall\Http\TrustedProxyResolver;
use Flowd\Phirewall\KeyExtractors;
use Flowd\Phirewall\Matchers\SuspiciousHeadersMatcher;
use Flowd\Phirewall\Matchers\TrustedBotMatcher;
use Flowd\Phirewall\Middleware;
use Flowd\Phirewall\Pattern\InMemoryPatternBackend;
use Flowd\Phirewall\Pattern\PatternEntry;
use Flowd\Phirewall\Pattern\PatternKind;
use Flowd\Phirewall\Pattern\SnapshotBlocklistMatcher;
use Flowd\Phirewall\Portable\PortableConfig;
use Flowd\Phirewall\Store\InMemoryCache;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Every built-in rule reads a request in both readings: the PSR-7 request and
 * its server parameters. A rule that restricts matches when one of them
 * matches, a safelist only when both do.
 */
final class ServerParametersInRulesTest extends TestCase
{
    /**
     * @param array<string, string> $headers
     * @param array<string, string> $serverParameters
     */
    private function request(string $method, string $uri, array $headers = [], array $serverParameters = []): ServerRequest
    {
        return new ServerRequest($method, $uri, $headers, null, '1.1', $serverParameters + ['REMOTE_ADDR' => '203.0.113.9']);
    }

    /**
     * @param array{type: string} $filter
     */
    private function blocks(array $filter, ServerRequest $serverRequest, bool $inspectServerParameters = true): bool
    {
        $config = (new Config(new InMemoryCache()))->with(PortableConfig::create()->blocklist('rule', $filter));
        $config->inspectServerParameters($inspectServerParameters);

        return (new Firewall($config))->decide($serverRequest)->isBlocked();
    }

    /**
     * @param array{type: string} $filter
     */
    private function safelists(array $filter, ServerRequest $serverRequest, bool $inspectServerParameters = true): bool
    {
        $config = (new Config(new InMemoryCache()))->with(
            PortableConfig::create()->safelist('rule', $filter)->blocklist('everything', PortableConfig::filterAll()),
        );
        $config->inspectServerParameters($inspectServerParameters);

        return (new Firewall($config))->decide($serverRequest)->outcome === Outcome::SAFELISTED;
    }

    /**
     * A request on which the two readings differ in the way named by the key:
     * the filter matches the server parameters and not the PSR-7 request.
     *
     * @return iterable<string, array{array{type: string}, ServerRequest}>
     */
    public static function filtersThatMatchTheServerParametersOnly(): iterable
    {
        $rewritten = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/admin/users', 'REMOTE_ADDR' => '203.0.113.9'];

        yield 'path equals' => [PortableConfig::filterPathEquals('/admin/users'), new ServerRequest('GET', '/health', [], null, '1.1', $rewritten)];
        yield 'path prefix' => [PortableConfig::filterPathPrefix('/admin'), new ServerRequest('GET', '/health', [], null, '1.1', $rewritten)];
        yield 'path prefix, encoded' => [
            PortableConfig::filterPathPrefix('/admin'),
            new ServerRequest('GET', '/health', [], null, '1.1', ['REQUEST_URI' => '/%61dmin/users?x=1', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'path regex' => [PortableConfig::filterPathRegex('#^/admin/#'), new ServerRequest('GET', '/health', [], null, '1.1', $rewritten)];
        yield 'method equals' => [
            PortableConfig::filterMethodEquals('DELETE'),
            new ServerRequest('POST', '/', [], null, '1.1', ['REQUEST_METHOD' => 'DELETE', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'method in' => [
            PortableConfig::filterMethodIn(['PUT', 'DELETE']),
            new ServerRequest('POST', '/', [], null, '1.1', ['REQUEST_METHOD' => 'delete', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'header equals, header dropped' => [
            PortableConfig::filterHeaderEquals('X-Debug', 'on'),
            new ServerRequest('GET', '/', [], null, '1.1', ['HTTP_X_DEBUG' => 'on', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'header equals, value rewritten' => [
            PortableConfig::filterHeaderEquals('X-Debug', 'on'),
            new ServerRequest('GET', '/', ['X-Debug' => 'off'], null, '1.1', ['HTTP_X_DEBUG' => 'on', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'header present' => [
            PortableConfig::filterHeaderPresent('X-Debug'),
            new ServerRequest('GET', '/', [], null, '1.1', ['HTTP_X_DEBUG' => 'on', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'header regex' => [
            PortableConfig::filterHeaderRegex('User-Agent', '/sqlmap/i'),
            new ServerRequest('GET', '/', ['User-Agent' => 'Mozilla/5.0'], null, '1.1', ['HTTP_USER_AGENT' => 'sqlmap/1.8', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
    }

    /**
     * A portable safelist takes no header filter.
     *
     * @param iterable<string, array{array{type: string}, ServerRequest}> $cases
     *
     * @return iterable<string, array{array{type: string}, ServerRequest}>
     */
    private static function withoutHeaderFilters(iterable $cases): iterable
    {
        foreach ($cases as $name => $case) {
            if (!str_starts_with($case[0]['type'], 'header_')) {
                yield $name => $case;
            }
        }
    }

    /**
     * @return iterable<string, array{array{type: string}, ServerRequest}>
     */
    public static function safelistFiltersThatMatchTheServerParametersOnly(): iterable
    {
        return self::withoutHeaderFilters(self::filtersThatMatchTheServerParametersOnly());
    }

    /**
     * @return iterable<string, array{array{type: string}, ServerRequest}>
     */
    public static function safelistFiltersThatMatchThePsr7RequestOnly(): iterable
    {
        return self::withoutHeaderFilters(self::filtersThatMatchThePsr7RequestOnly());
    }

    /**
     * @return iterable<string, array{array{type: string}, ServerRequest}>
     */
    public static function safelistFiltersOnRequestsWhoseReadingsAgree(): iterable
    {
        return self::withoutHeaderFilters(self::filtersOnRequestsWhoseReadingsAgree());
    }

    /**
     * @param array{type: string} $filter
     */
    #[DataProvider('filtersThatMatchTheServerParametersOnly')]
    public function testABlocklistMatchesWhatOnlyTheServerParametersHold(array $filter, ServerRequest $serverRequest): void
    {
        $this->assertTrue($this->blocks($filter, $serverRequest));
        $this->assertFalse($this->blocks($filter, $serverRequest, false), 'Turned off, the rule reads the PSR-7 request alone.');
    }

    /**
     * The same requests the other way round: the filter is written for what
     * the server parameters hold, and the PSR-7 request says something else.
     *
     * @param array{type: string} $filter
     */
    #[DataProvider('safelistFiltersThatMatchTheServerParametersOnly')]
    public function testASafelistDoesNotApplyWhenOnlyOneReadingMatches(array $filter, ServerRequest $serverRequest): void
    {
        $this->assertFalse($this->safelists($filter, $serverRequest));
    }

    /**
     * @return iterable<string, array{array{type: string}, ServerRequest}>
     */
    public static function filtersThatMatchThePsr7RequestOnly(): iterable
    {
        yield 'path equals' => [
            PortableConfig::filterPathEquals('/health'),
            new ServerRequest('GET', '/health', [], null, '1.1', ['REQUEST_URI' => '/admin/users', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'path prefix' => [
            PortableConfig::filterPathPrefix('/public/'),
            new ServerRequest('GET', '/public/logo.png', [], null, '1.1', ['REQUEST_URI' => '/admin/users', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'path regex' => [
            PortableConfig::filterPathRegex('#^/health$#'),
            new ServerRequest('GET', '/health', [], null, '1.1', ['REQUEST_URI' => '/admin/users', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'method equals' => [
            PortableConfig::filterMethodEquals('GET'),
            new ServerRequest('GET', '/', [], null, '1.1', ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'method in' => [
            PortableConfig::filterMethodIn(['GET', 'HEAD']),
            new ServerRequest('GET', '/', [], null, '1.1', ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'header equals' => [
            PortableConfig::filterHeaderEquals('X-Monitor', 'secret'),
            new ServerRequest('GET', '/', ['X-Monitor' => 'secret'], null, '1.1', ['HTTP_X_MONITOR' => 'guess', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'header regex' => [
            PortableConfig::filterHeaderRegex('User-Agent', '/^UptimeCheck/'),
            new ServerRequest('GET', '/', ['User-Agent' => 'UptimeCheck/2'], null, '1.1', ['HTTP_USER_AGENT' => 'sqlmap/1.8', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
    }

    /**
     * @param array{type: string} $filter
     */
    #[DataProvider('safelistFiltersThatMatchThePsr7RequestOnly')]
    public function testASafelistNeedsTheServerParametersToMatchToo(array $filter, ServerRequest $serverRequest): void
    {
        $this->assertFalse($this->safelists($filter, $serverRequest));
        $this->assertTrue($this->safelists($filter, $serverRequest, false), 'Turned off, the rule reads the PSR-7 request alone.');
    }

    /**
     * @param array{type: string} $filter
     */
    #[DataProvider('filtersThatMatchThePsr7RequestOnly')]
    public function testABlocklistStillMatchesWhatThePsr7RequestHolds(array $filter, ServerRequest $serverRequest): void
    {
        $this->assertTrue($this->blocks($filter, $serverRequest));
    }

    /**
     * @return iterable<string, array{array{type: string}, ServerRequest}>
     */
    public static function filtersOnRequestsWhoseReadingsAgree(): iterable
    {
        $server = [
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/health/live?probe=1',
            'QUERY_STRING' => 'probe=1',
            'HTTP_HOST' => 'example.test',
            'HTTP_USER_AGENT' => 'UptimeCheck/2',
            'HTTP_X_MONITOR' => 'secret',
            'REMOTE_ADDR' => '203.0.113.9',
        ];
        $headers = ['Host' => 'example.test', 'User-Agent' => 'UptimeCheck/2', 'X-Monitor' => 'secret'];
        $serverRequest = new ServerRequest('GET', 'https://example.test/health/live?probe=1', $headers, null, '1.1', $server);

        yield 'path equals' => [PortableConfig::filterPathEquals('/health/live'), $serverRequest];
        yield 'path prefix' => [PortableConfig::filterPathPrefix('/health/'), $serverRequest];
        yield 'path regex' => [PortableConfig::filterPathRegex('#^/health/#'), $serverRequest];
        yield 'method equals' => [PortableConfig::filterMethodEquals('get'), $serverRequest];
        yield 'method in' => [PortableConfig::filterMethodIn(['GET', 'HEAD']), $serverRequest];
        yield 'header equals' => [PortableConfig::filterHeaderEquals('X-Monitor', 'secret'), $serverRequest];
        yield 'header present' => [PortableConfig::filterHeaderPresent('x-monitor'), $serverRequest];
        yield 'header regex' => [PortableConfig::filterHeaderRegex('User-Agent', '/^UptimeCheck/'), $serverRequest];
        yield 'path with brackets a library encodes' => [
            PortableConfig::filterPathPrefix('/photos/'),
            new ServerRequest('GET', '/photos/a%5B1%5D.jpg', [], null, '1.1', ['REQUEST_URI' => '/photos/a[1].jpg', 'REMOTE_ADDR' => '203.0.113.9']),
        ];
        yield 'a request without server parameters' => [PortableConfig::filterPathEquals('/health/live'), new ServerRequest('GET', '/health/live')];
        yield 'a header the server parameters do not hold' => [
            PortableConfig::filterHeaderEquals('X-Monitor', 'secret'),
            new ServerRequest('GET', '/', ['X-Monitor' => 'secret'], null, '1.1', ['REMOTE_ADDR' => '203.0.113.9']),
        ];
    }

    /**
     * @param array{type: string} $filter
     */
    #[DataProvider('filtersOnRequestsWhoseReadingsAgree')]
    public function testABlocklistMatchesARequestWhoseReadingsAgreeAsBefore(array $filter, ServerRequest $serverRequest): void
    {
        $this->assertTrue($this->blocks($filter, $serverRequest));
        $this->assertTrue($this->blocks($filter, $serverRequest, false));
    }

    /**
     * @param array{type: string} $filter
     */
    #[DataProvider('safelistFiltersOnRequestsWhoseReadingsAgree')]
    public function testASafelistMatchesARequestWhoseReadingsAgreeAsBefore(array $filter, ServerRequest $serverRequest): void
    {
        $this->assertTrue($this->safelists($filter, $serverRequest));
        $this->assertTrue($this->safelists($filter, $serverRequest, false));
    }

    public function testAHeaderWrittenWithAnUnderscoreIsAReadingOfTheHeader(): void
    {
        $serverRequest = $this->request('GET', '/', ['User-Agent' => 'UptimeCheck/2', 'User_Agent' => 'sqlmap/1.8']);

        $this->assertTrue($this->blocks(PortableConfig::filterHeaderRegex('User-Agent', '/sqlmap/'), $serverRequest));
        $this->assertTrue($this->blocks(PortableConfig::filterHeaderRegex('User-Agent', '/^UptimeCheck/'), $serverRequest));
    }

    public function testThrottleScopeAndFail2BanFilterMatchWhatOnlyTheServerParametersHold(): void
    {
        $portableConfig = PortableConfig::create()
            ->throttle('logins', 1, 60, PortableConfig::keyIp(), false, PortableConfig::filterPathPrefix('/login'))
            ->fail2ban('probes', 1, 60, 600, PortableConfig::filterHeaderPresent('X-Probe'), PortableConfig::keyIp());
        $firewall = new Firewall((new Config(new InMemoryCache()))->with($portableConfig));

        $login = $this->request('POST', '/index.php', [], ['REQUEST_URI' => '/login']);
        $this->assertTrue($firewall->decide($login)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($login)->outcome);

        $firewall->resetAll();
        $probe = $this->request('GET', '/', [], ['HTTP_X_PROBE' => '1']);
        $firewall->decide($probe);
        $this->assertTrue($firewall->decide($this->request('GET', '/'))->isBlocked(), 'The filter counted the request and the ban holds for the next.');
    }

    public function testAPatternBlocklistMatchesWhatOnlyTheServerParametersHold(): void
    {
        $matcher = static fn(PatternEntry ...$patternEntry): SnapshotBlocklistMatcher => new SnapshotBlocklistMatcher(new InMemoryPatternBackend(array_values($patternEntry)));

        $rewritten = $this->request('GET', '/index.php?page=home', [], ['REQUEST_URI' => '/wp-admin/install.php?step=1', 'QUERY_STRING' => 'page=home&debug=1']);
        $this->assertTrue($matcher(new PatternEntry(PatternKind::PATH_EXACT, '/wp-admin/install.php'))->match($rewritten)->isMatch());
        $this->assertTrue($matcher(new PatternEntry(PatternKind::PATH_PREFIX, '/wp-admin'))->match($rewritten)->isMatch());
        $this->assertTrue($matcher(new PatternEntry(PatternKind::PATH_REGEX, '#install\.php$#'))->match($rewritten)->isMatch());
        $this->assertTrue($matcher(new PatternEntry(PatternKind::REQUEST_REGEX, '#^/wp-admin/install\.php\?step=1$#m'))->match($rewritten)->isMatch());
        $this->assertTrue($matcher(new PatternEntry(PatternKind::REQUEST_REGEX, '#^/index\.php\?page=home&debug=1$#m'))->match($rewritten)->isMatch());
        $this->assertTrue($matcher(new PatternEntry(PatternKind::REQUEST_REGEX, '#^/index\.php\?page=home$#m'))->match($rewritten)->isMatch());
        $this->assertFalse($matcher(new PatternEntry(PatternKind::PATH_PREFIX, '/admin'))->match($rewritten)->isMatch());

        $dropped = $this->request('GET', '/', ['X-Client' => 'app'], ['HTTP_X_CLIENT' => 'scanner', 'HTTP_X_EXPLOIT' => '${jndi:ldap://x}']);
        $this->assertTrue($matcher(new PatternEntry(PatternKind::HEADER_EXACT, 'scanner', target: 'X-Client'))->match($dropped)->isMatch());
        $this->assertTrue($matcher(new PatternEntry(PatternKind::HEADER_EXACT, 'app', target: 'X-Client'))->match($dropped)->isMatch());
        $this->assertTrue($matcher(new PatternEntry(PatternKind::HEADER_REGEX, '/jndi:/', target: 'x-exploit'))->match($dropped)->isMatch());
        $this->assertTrue($matcher(new PatternEntry(PatternKind::REQUEST_REGEX, '/^x-exploit:\$\{jndi:/m'))->match($dropped)->isMatch());
        $this->assertFalse($matcher(new PatternEntry(PatternKind::HEADER_EXACT, 'other', target: 'X-Client'))->match($dropped)->isMatch());
    }

    public function testAPatternBlocklistReadsThePsr7RequestAloneWhenTheConfigSaysSo(): void
    {
        $config = new Config(new InMemoryCache());
        $config->blocklists->patternBlocklist('patterns', [new PatternEntry(PatternKind::PATH_PREFIX, '/wp-admin')]);
        $serverRequest = $this->request('GET', '/index.php', [], ['REQUEST_URI' => '/wp-admin/install.php']);

        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isBlocked());

        $config->inspectServerParameters(false);
        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isPass());
    }

    public function testAHeaderOnlyTheServerParametersHoldIsNotMissing(): void
    {
        $suspiciousHeadersMatcher = new SuspiciousHeadersMatcher(['Accept', 'Accept-Language']);

        $this->assertFalse($suspiciousHeadersMatcher->match(
            $this->request('GET', '/', ['Accept' => '*/*'], ['HTTP_ACCEPT' => '*/*', 'HTTP_ACCEPT_LANGUAGE' => "de\x01"]),
        )->isMatch());
        $this->assertTrue($suspiciousHeadersMatcher->match(
            $this->request('GET', '/', ['Accept' => '*/*'], ['HTTP_ACCEPT' => '*/*']),
        )->isMatch());
        $this->assertTrue($suspiciousHeadersMatcher->match(
            $this->request('GET', '/', ['Accept' => '*/*', 'Accept_Language' => 'de']),
        )->isMatch(), 'A header of another name does not stand in for the required one.');
    }

    public function testARequestPatternStillMatchesTheHeadersOfThePsr7RequestAlone(): void
    {
        $matcher = static fn(string $pattern): SnapshotBlocklistMatcher => new SnapshotBlocklistMatcher(
            new InMemoryPatternBackend([new PatternEntry(PatternKind::REQUEST_REGEX, $pattern)]),
        );
        // The server parameters hold one header more, and another Host.
        $serverRequest = $this->request(
            'GET',
            '/',
            ['Host' => 'e.test', 'User-Agent' => 'sqlmap', 'Accept' => '*/*'],
            ['HTTP_HOST' => 'other.test', 'HTTP_USER_AGENT' => 'sqlmap', 'HTTP_ACCEPT' => '*/*', 'HTTP_X_EXTRA' => '1'],
        );

        $this->assertTrue($matcher('#accept:\*/\*$#')->match($serverRequest)->isMatch(), 'The end of the subject.');
        $this->assertTrue($matcher('#host:e\.test\nuser-agent:sqlmap#')->match($serverRequest)->isMatch(), 'Two headers in a row.');
        $this->assertTrue($matcher('#\A/\nhost:e\.test\nuser-agent:sqlmap\naccept:\*/\*\z#')->match($serverRequest)->isMatch(), 'The whole subject.');
        $this->assertTrue($matcher('#^host:other\.test$#m')->match($serverRequest)->isMatch(), 'What the server parameters hold besides.');
        $this->assertTrue($matcher('#^x-extra:1$#m')->match($serverRequest)->isMatch());
    }

    public function testTurnedOffAHeaderOfAnotherNameIsNoReadingOfAHeader(): void
    {
        $serverRequest = $this->request('GET', '/', ['User-Agent' => 'Mozilla/5.0', 'User_Agent' => 'sqlmap/1.8']);

        $config = new Config(new InMemoryCache());
        $config->blocklists->knownScanners();
        $config->blocklists->patternBlocklist('patterns', [new PatternEntry(PatternKind::HEADER_EXACT, 'sqlmap/1.8', target: 'User-Agent')]);

        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isBlocked());

        $config->inspectServerParameters(false);
        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isPass());
    }

    public function testATrustedBotHasToBeNamedInEveryReadingOfTheUserAgent(): void
    {
        $trustedBotMatcher = new TrustedBotMatcher(
            additionalBots: [],
            reverseResolve: static fn(string $ip): string => 'crawl-66-249-66-1.googlebot.com',
            forwardResolve: static fn(string $host): array => ['66.249.66.1'],
        );
        $googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        $request = static fn(array $headers, array $serverParameters): ServerRequest => new ServerRequest(
            'GET',
            '/',
            $headers,
            null,
            '1.1',
            $serverParameters + ['REMOTE_ADDR' => '66.249.66.1'],
        );

        $this->assertTrue($trustedBotMatcher->match($request(['User-Agent' => $googlebot], ['HTTP_USER_AGENT' => $googlebot]))->isMatch());
        $this->assertTrue($trustedBotMatcher->match($request(['User-Agent' => $googlebot], []))->isMatch());
        $this->assertFalse($trustedBotMatcher->match($request(['User-Agent' => $googlebot], ['HTTP_USER_AGENT' => 'sqlmap/1.8']))->isMatch());
        $this->assertFalse($trustedBotMatcher->match($request(['User-Agent' => $googlebot, 'User_Agent' => 'sqlmap/1.8'], []))->isMatch());
        $this->assertFalse($trustedBotMatcher->match($request([], ['HTTP_USER_AGENT' => $googlebot]))->isMatch(), 'As before: the PSR-7 request has to name the bot.');
    }

    public function testAKeyIsTakenFromTheServerParametersWhenThePsr7RequestHasNone(): void
    {
        $header = KeyExtractors::header('X-Api-Key');
        $hashedHeader = KeyExtractors::hashedHeader('X-Api-Key');

        $both = $this->request('GET', '/', ['X-Api-Key' => 'from-request'], ['HTTP_X_API_KEY' => 'from-server']);
        $this->assertSame('from-request', $header($both));
        $this->assertSame(hash('sha256', 'from-request'), $hashedHeader($both));

        $dropped = $this->request('GET', '/', [], ['HTTP_X_API_KEY' => 'from-server']);
        $this->assertSame('from-server', $header($dropped));
        $this->assertSame(hash('sha256', 'from-server'), $hashedHeader($dropped));

        $this->assertNull($header($this->request('GET', '/')));
        $this->assertNull($hashedHeader($this->request('GET', '/')));

        $this->assertSame('POST', KeyExtractors::method()($this->request('post', '/', [], ['REQUEST_METHOD' => 'DELETE'])));
        $this->assertSame('/login', KeyExtractors::path()($this->request('GET', '/login', [], ['REQUEST_URI' => '/other'])));
    }

    public function testAHeaderKeyedThrottleCountsARequestWhoseHeaderTheLibraryDropped(): void
    {
        $config = new Config(new InMemoryCache());
        $config->throttles->add('per-key', 1, 60, KeyExtractors::header('X-Api-Key'));

        $firewall = new Firewall($config);

        $dropped = $this->request('GET', '/', [], ['HTTP_X_API_KEY' => "key\x01"]);
        $this->assertTrue($firewall->decide($dropped)->isPass());
        $this->assertSame(Outcome::THROTTLED, $firewall->decide($dropped)->outcome);
    }

    public function testTheForwardingChainIsReadFromTheServerParametersWhenThePsr7RequestHasNone(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8'], ['X-Forwarded-For', 'Forwarded']);
        $request = static fn(array $headers, array $serverParameters): ServerRequest => new ServerRequest(
            'GET',
            '/',
            $headers,
            null,
            '1.1',
            $serverParameters + ['REMOTE_ADDR' => '10.0.0.1'],
        );

        // What a client put in front of the chain made the library drop the header.
        $this->assertSame('198.51.100.7', $trustedProxyResolver->resolve($request([], ['HTTP_X_FORWARDED_FOR' => "evil\x01, 198.51.100.7"])));
        $this->assertSame('198.51.100.7', $trustedProxyResolver->resolve($request([], ['HTTP_FORWARDED' => 'for=198.51.100.7;proto=https'])));

        // The request holds the header: it is read as before.
        $this->assertSame(
            '198.51.100.7',
            $trustedProxyResolver->resolve($request(['X-Forwarded-For' => '198.51.100.7'], ['HTTP_X_FORWARDED_FOR' => '192.0.2.66'])),
        );

        // A header of another name is none of the chain.
        $this->assertSame('10.0.0.1', $trustedProxyResolver->resolve($request(['X_Forwarded_For' => '192.0.2.66'], [])));

        // A peer that is not trusted is the client, whatever it sends.
        $untrusted = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '192.0.2.66']);
        $this->assertSame('203.0.113.9', $trustedProxyResolver->resolve($untrusted));
    }

    public function testTheForwardingChainOfThePsr7RequestAloneWhenTheConfigSaysSo(): void
    {
        $trustedProxyResolver = new TrustedProxyResolver(['10.0.0.0/8']);
        $config = new Config(new InMemoryCache());
        $config->setIpResolver($trustedProxyResolver->resolve(...));

        $config->blocklists->ip('blocked', '198.51.100.7');

        $serverRequest = new ServerRequest('GET', '/', [], null, '1.1', ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.7']);

        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isBlocked());

        $config->inspectServerParameters(false);
        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isPass());
    }

    public function testTheSettingOfTheFirewallThatDecidesCounts(): void
    {
        $serverRequest = $this->request('GET', '/', ['User-Agent' => 'Mozilla/5.0'], ['HTTP_USER_AGENT' => 'sqlmap/1.8']);

        $inspecting = new Config(new InMemoryCache());
        $inspecting->blocklists->knownScanners();

        $psr7Only = new Config(new InMemoryCache());
        $psr7Only->blocklists->knownScanners();
        $psr7Only->inspectServerParameters(false);

        $this->assertTrue((new Firewall($inspecting))->decide($serverRequest)->isBlocked());
        $this->assertTrue((new Firewall($psr7Only))->decide($serverRequest)->isPass());
        $this->assertTrue((new Firewall($inspecting))->decide($serverRequest)->isBlocked());
    }

    public function testAFirewallBehindAnotherReadsTheRequestByItsOwnSetting(): void
    {
        $serverRequest = $this->request('GET', '/', ['User-Agent' => 'Mozilla/5.0'], ['HTTP_USER_AGENT' => 'sqlmap/1.8']);

        $seen = [];
        $application = $this->handler(static function (ServerRequestInterface $serverRequest) use (&$seen): void {
            $seen[] = RequestView::of($serverRequest)->headerLines('User-Agent');
        });
        $status = function (bool $inspectInFront, bool $inspectBehind) use ($serverRequest, $application): int {
            $inFront = (new Config(new InMemoryCache()))->inspectServerParameters($inspectInFront);
            $behind = (new Config(new InMemoryCache()))->inspectServerParameters($inspectBehind);
            $behind->blocklists->knownScanners();

            $handler = new class (new Middleware($behind, new Psr17Factory()), $application) implements RequestHandlerInterface {
                public function __construct(private readonly Middleware $middleware, private readonly RequestHandlerInterface $requestHandler)
                {
                }

                public function handle(ServerRequestInterface $serverRequest): ResponseInterface
                {
                    return $this->middleware->process($serverRequest, $this->requestHandler);
                }
            };

            return (new Middleware($inFront, new Psr17Factory()))->process($serverRequest, $handler)->getStatusCode();
        };

        $this->assertSame(403, $status(false, true));
        $this->assertSame([], $seen);

        $this->assertSame(200, $status(true, false));
        $this->assertSame([['Mozilla/5.0']], $seen);
    }

    public function testTheHandlerGetsTheRequestAsTheRulesReadIt(): void
    {
        $serverRequest = $this->request('GET', '/', ['User-Agent' => 'Mozilla/5.0'], ['HTTP_USER_AGENT' => 'sqlmap/1.8']);

        $seen = [];
        $handler = $this->handler(static function (ServerRequestInterface $serverRequest) use (&$seen): void {
            $seen[] = RequestView::of($serverRequest)->headerLines('User-Agent');
        });

        $config = new Config(new InMemoryCache());
        (new Middleware($config, new Psr17Factory()))->process($serverRequest, $handler);

        $config->inspectServerParameters(false);
        (new Middleware($config, new Psr17Factory()))->process($serverRequest, $handler);

        $this->assertSame([['Mozilla/5.0', 'sqlmap/1.8'], ['Mozilla/5.0']], $seen);
        $this->assertSame(['Mozilla/5.0', 'sqlmap/1.8'], RequestView::of($serverRequest)->headerLines('User-Agent'), 'The request that came in is left as it was.');
    }

    public function testAClosureOfARuleReadsTheRequestByTheSettingOfItsFirewall(): void
    {
        $serverRequest = $this->request('GET', '/index.php', [], ['REQUEST_URI' => '/wp-admin/install.php']);

        $config = new Config(new InMemoryCache());
        $config->blocklists->add('own', static fn(ServerRequestInterface $serverRequest): bool => in_array('/wp-admin/install.php', RequestView::of($serverRequest)->paths(), true));

        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isBlocked());

        $config->inspectServerParameters(false);
        $this->assertTrue((new Firewall($config))->decide($serverRequest)->isPass());
    }

    public function testASignalRecordedByTheHandlerIsCountedByTheSettingOfTheFirewall(): void
    {
        $serverRequest = $this->request('POST', '/login', [], ['HTTP_X_API_KEY' => 'from-the-server']);
        $handler = $this->handler(static function (ServerRequestInterface $serverRequest): void {
            $context = $serverRequest->getAttribute(RequestContext::ATTRIBUTE_NAME);
            self::assertInstanceOf(RequestContext::class, $context);
            $context->recordFailure('login');
        });

        $banned = static function (bool $inspect) use ($serverRequest, $handler): bool {
            $inMemoryCache = new InMemoryCache();
            $config = (new Config($inMemoryCache))->inspectServerParameters($inspect);
            $config->fail2ban->add('login', 1, 60, 300, static fn(): bool => false, KeyExtractors::header('X-Api-Key'));
            (new Middleware($config, new Psr17Factory()))->process($serverRequest, $handler);

            return (new Firewall($config))->isBanned('login', 'from-the-server', BanType::Fail2Ban);
        };

        $this->assertTrue($banned(true));
        $this->assertFalse($banned(false), 'Without the server parameters the request has no key.');
    }

    /**
     * @param \Closure(ServerRequestInterface): void $inspect
     */
    private function handler(\Closure $inspect): RequestHandlerInterface
    {
        return new class ($inspect) implements RequestHandlerInterface {
            /**
             * @param \Closure(ServerRequestInterface): void $inspect
             */
            public function __construct(private readonly \Closure $inspect)
            {
            }

            public function handle(ServerRequestInterface $serverRequest): ResponseInterface
            {
                ($this->inspect)($serverRequest);

                return new Response(200);
            }
        };
    }

    public function testTheSettingIsPartOfAComposedAndOfAPortableConfig(): void
    {
        $config = new Config(new InMemoryCache());
        $this->assertTrue($config->inspectsServerParameters());

        $off = (new Config(new InMemoryCache()))->inspectServerParameters(false);
        $this->assertFalse($off->inspectsServerParameters());
        $this->assertFalse($config->with($off)->inspectsServerParameters());
        $this->assertFalse($off->with($config)->inspectsServerParameters(), 'A layer that left the default does not turn it back on.');

        $portableConfig = PortableConfig::create()->inspectServerParameters(false);
        $this->assertFalse($portableConfig->toArray()['options']['inspectServerParameters'] ?? null);
        $this->assertFalse($config->with(PortableConfig::fromArray($portableConfig->toArray()))->inspectsServerParameters());
        $this->assertArrayNotHasKey('inspectServerParameters', PortableConfig::create()->toArray()['options'] ?? []);
        $this->assertTrue($config->with(PortableConfig::create())->inspectsServerParameters());
    }

    public function testAPortableSettingThatIsNotABooleanIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/inspectServerParameters.*boolean/');

        PortableConfig::fromArray(['options' => ['inspectServerParameters' => 'false']]);
    }
}
