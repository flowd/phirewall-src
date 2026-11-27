<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Http;

use Flowd\Phirewall\Http\RequestView;
use Flowd\Phirewall\Tests\Support\AppendingCacheStream;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

final class RequestViewTest extends TestCase
{
    public function testARequestWithoutServerParametersGivesThePsr7ValuesAlone(): void
    {
        $serverRequest = (new ServerRequest('POST', 'https://example.test/shop/list?page=2', ['User-Agent' => 'curl/8', 'Cookie' => 'sid=abc']))
            ->withQueryParams(['page' => '2'])
            ->withCookieParams(['sid' => 'abc']);

        $requestView = RequestView::of($serverRequest);

        $this->assertSame(['POST'], $requestView->methods());
        $this->assertSame(['/shop/list?page=2'], $requestView->targets());
        $this->assertSame(['/shop/list'], $requestView->paths());
        $this->assertSame(['page=2'], $requestView->queryStrings());
        $this->assertSame(['Host' => ['example.test'], 'User-Agent' => ['curl/8'], 'Cookie' => ['sid=abc']], $requestView->headers());
        $this->assertSame([], $requestView->hiddenQueryParameters());
        $this->assertSame([], $requestView->hiddenCookies());
        $this->assertTrue($requestView->queryParametersComplete());
        $this->assertTrue($requestView->cookiesComplete());
    }

    public function testServerParametersThatSayTheSameAddNothing(): void
    {
        $serverRequest = (new ServerRequest(
            'GET',
            'https://example.test/shop/list?page=2&sort=price',
            ['Host' => 'example.test', 'User-Agent' => 'curl/8', 'Accept' => 'text/html, application/json', 'Cookie' => 'sid=abc; theme=dark', 'Content-Type' => 'text/plain'],
            null,
            '1.1',
            [
                'REQUEST_METHOD' => 'GET',
                'REQUEST_URI' => '/shop/list?page=2&sort=price',
                'QUERY_STRING' => 'page=2&sort=price',
                'HTTP_HOST' => 'example.test',
                'HTTP_USER_AGENT' => "  curl/8\t",
                'HTTP_ACCEPT' => 'text/html, application/json',
                'HTTP_COOKIE' => 'sid=abc; theme=dark',
                'CONTENT_TYPE' => 'text/plain',
                'HTTP_CONTENT_TYPE' => 'text/plain',
                'CONTENT_LENGTH' => '',
                'REMOTE_ADDR' => '192.0.2.1',
                'argv' => ['not', 'a', 'string'],
                7 => 'numeric key',
            ],
        ))->withQueryParams(['page' => '2', 'sort' => 'price'])->withCookieParams(['sid' => 'abc', 'theme' => 'dark']);

        $requestView = RequestView::of($serverRequest);

        $this->assertSame(['GET'], $requestView->methods());
        $this->assertSame(['/shop/list?page=2&sort=price'], $requestView->targets());
        $this->assertSame(['/shop/list'], $requestView->paths());
        $this->assertSame(['page=2&sort=price'], $requestView->queryStrings());
        $this->assertSame($serverRequest->getHeaders(), $requestView->headers());
        $this->assertSame([], $requestView->hiddenQueryParameters());
        $this->assertSame([], $requestView->hiddenCookies());
    }

    public function testTheSameRequestObjectGivesTheSameView(): void
    {
        $serverRequest = new ServerRequest('GET', '/');

        $this->assertSame(RequestView::of($serverRequest), RequestView::of($serverRequest));
        $this->assertNotSame(RequestView::of($serverRequest), RequestView::of($serverRequest->withMethod('POST')));
        $this->assertNotSame(RequestView::of($serverRequest), RequestView::of($serverRequest, 10), 'A view with a bound of its own is not kept.');
        $this->assertNotSame(RequestView::of($serverRequest), RequestView::ofPsr7Only($serverRequest));
    }

    public function testMethodTargetPathAndQueryStringOfTheServerParametersAreAddedWhenTheyDiffer(): void
    {
        $serverRequest = new ServerRequest('DELETE', 'https://example.test/app/%3Cb%3E?q=%22x%22', [], null, '1.1', [
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/base/app/<b>?q="x"',
            'QUERY_STRING' => 'q="x"&route=app',
        ]);

        $requestView = RequestView::of($serverRequest);

        $this->assertSame(['DELETE', 'POST'], $requestView->methods());
        $this->assertSame(['/app/%3Cb%3E?q=%22x%22', '/base/app/<b>?q="x"'], $requestView->targets());
        $this->assertSame(['/app/%3Cb%3E', '/base/app/<b>'], $requestView->paths());
        $this->assertSame(['q=%22x%22', 'q="x"&route=app'], $requestView->queryStrings(), 'The request and QUERY_STRING after a rewrite; that of REQUEST_URI is the one of the request, written without percent-encoding.');
    }

    public function testThePathOfAnAbsoluteRequestTargetFollowsTheHost(): void
    {
        $view = static fn(string $target): RequestView => RequestView::of(new ServerRequest('GET', '/x', [], null, '1.1', ['REQUEST_URI' => $target]));

        $this->assertSame(['/x', '/admin/.env'], $view('http://example.test:8080/admin/.env?a=1')->paths());
        $this->assertSame(['/x'], $view('http://example.test')->paths(), 'No path after the host: nothing to add.');
        $this->assertSame(['/x', '*'], $view('*')->paths());
        $this->assertSame(['/x'], $view('/x?a=1')->paths());
        $this->assertSame(['/x'], $view('?a=1')->paths());
    }

    public function testAHeaderTheRequestDoesNotHoldIsAdded(): void
    {
        // What the Symfony bridge does with a header a strict library refuses: it is not in the request.
        $serverRequest = new ServerRequest('GET', 'https://example.test/', ['Accept' => 'text/html', 'x_custom' => 'a'], null, '1.1', [
            'HTTP_USER_AGENT' => "sqlmap\x01",
            'HTTP_ACCEPT' => 'text/html',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.9',
            'HTTP_X_CUSTOM' => 'b',
            'CONTENT_TYPE' => 'application/json',
            'CONTENT_LENGTH' => '12',
            'HTTP_' => 'no name',
        ]);

        $requestView = RequestView::of($serverRequest);

        $this->assertSame([
            'Host' => ['example.test'],
            'Accept' => ['text/html'],
            'x_custom' => ['a', 'b'],
            'User-Agent' => ["sqlmap\x01"],
            'X-Forwarded-For' => ['203.0.113.9'],
            'X-Custom' => ['b'],
            'Content-Type' => ['application/json'],
            'Content-Length' => ['12'],
        ], $requestView->headers());
        $this->assertSame(["sqlmap\x01"], $requestView->header('user-agent'));
        $this->assertSame(['a', 'b'], $requestView->header('X-Custom'), 'A server parameter cannot tell a dash from an underscore.');
        $this->assertSame([], $requestView->header('Referer'));
    }

    public function testAHeaderValueThatDiffersIsAddedToTheValuesOfTheRequest(): void
    {
        $serverRequest = new ServerRequest('GET', 'https://example.test/', ['Referer' => 'https://example.test/a', 'X-Dup' => ['one', 'two']], null, '1.1', [
            'HTTP_REFERER' => "https://example.test/a\nX-Injected: 1",
            'HTTP_X_DUP' => 'one,two',
            'HTTP_HOST' => 'EXAMPLE.test',
        ]);

        $requestView = RequestView::of($serverRequest);

        $this->assertSame(['https://example.test/a', "https://example.test/a\nX-Injected: 1"], $requestView->header('Referer'));
        $this->assertSame(['one', 'two', 'one,two'], $requestView->header('X-Dup'), 'What the server made of two lines is a value an application reads, so it is one to inspect.');
        $this->assertSame(['example.test', 'EXAMPLE.test'], $requestView->header('Host'));
    }

    public function testThePsr7OnlyViewReadsNoServerParameters(): void
    {
        $serverRequest = new ServerRequest('GET', 'https://example.test/a?x=1', ['Cookie' => 'a=1; a=2'], null, '1.1', [
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/b?y=2',
            'QUERY_STRING' => 'y=2',
            'HTTP_USER_AGENT' => 'sqlmap',
            'HTTP_COOKIE' => 'c=3',
        ]);

        $requestView = RequestView::ofPsr7Only($serverRequest);

        $this->assertSame(['GET'], $requestView->methods());
        $this->assertSame(['/a?x=1'], $requestView->targets());
        $this->assertSame(['/a'], $requestView->paths());
        $this->assertSame(['x=1'], $requestView->queryStrings());
        $this->assertSame($serverRequest->getHeaders(), $requestView->headers());
        $this->assertSame([], $requestView->hiddenQueryParameters(), 'Not even the query string of the request itself is parsed.');
        $this->assertSame([], $requestView->hiddenCookies());
    }

    /**
     * The query string and what PHP 8.5 made of it, measured with the built-in server.
     */
    public function testWhatPhpDoesNotShowOfAQueryStringIsHidden(): void
    {
        $queryString = 'a=1&a=2&my.field=3&sp%20ace=4&b[]=5&b[]=6&c[x][y]=7&d=8+9%2B&e&=f&g[=h&i%00j=k&%41=l&[m]=n&o[p=q&%20lead=r&&z=%zz';
        $queryParameters = ['a' => '2', 'my_field' => '3', 'sp_ace' => '4', 'b' => ['5', '6'], 'c' => ['x' => ['y' => '7']], 'd' => '8 9+', 'e' => '', 'g_' => 'h', 'i' => 'k', 'A' => 'l', 'o_p' => 'q', 'lead' => 'r', 'z' => '%zz'];
        parse_str($queryString, $parsed);
        $this->assertSame($queryParameters, $parsed, 'PHP still parses the query string as measured.');

        $serverRequest = (new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['QUERY_STRING' => $queryString]))
            ->withQueryParams($queryParameters);

        $this->assertSame([
            ['name' => 'a', 'writtenName' => 'a', 'value' => '1', 'nameIsHidden' => false],
            ['name' => 'my_field', 'writtenName' => 'my.field', 'value' => null, 'nameIsHidden' => true],
            ['name' => 'sp_ace', 'writtenName' => 'sp ace', 'value' => null, 'nameIsHidden' => true],
            ['name' => '', 'writtenName' => '', 'value' => 'f', 'nameIsHidden' => false],
            ['name' => 'g_', 'writtenName' => 'g[', 'value' => null, 'nameIsHidden' => true],
            ['name' => 'i', 'writtenName' => "i\0j", 'value' => null, 'nameIsHidden' => true],
            ['name' => '[m]', 'writtenName' => '[m]', 'value' => 'n', 'nameIsHidden' => true],
            ['name' => 'o_p', 'writtenName' => 'o[p', 'value' => null, 'nameIsHidden' => true],
            ['name' => 'lead', 'writtenName' => ' lead', 'value' => null, 'nameIsHidden' => true],
        ], RequestView::of($serverRequest)->hiddenQueryParameters());
    }

    public function testEveryParameterIsHiddenWhenTheQueryParametersWereNeverFilledIn(): void
    {
        // A request whose query parameters nobody filled in: a library need not parse the query string of the URI.
        $serverRequest = (new ServerRequest('GET', 'https://example.test/?id=1%27+OR+1&list[]=a&list[]=a&list[]=b'))->withQueryParams([]);

        $this->assertSame([], $serverRequest->getQueryParams());
        $this->assertSame([
            ['name' => 'id', 'writtenName' => 'id', 'value' => "1' OR 1", 'nameIsHidden' => true],
            ['name' => 'list[0]', 'writtenName' => 'list[]', 'value' => 'a', 'nameIsHidden' => true],
            ['name' => 'list[0]', 'writtenName' => 'list[]', 'value' => 'b', 'nameIsHidden' => false],
        ], RequestView::of($serverRequest)->hiddenQueryParameters());
    }

    public function testAParameterOnlyOneOfTheQueryStringsHoldsIsHidden(): void
    {
        $serverRequest = (new ServerRequest('GET', 'https://example.test/page?id=7', [], null, '1.1', [
            'REQUEST_URI' => '/page?id=7&id=8',
            'QUERY_STRING' => 'id=7&route=page&debug=1',
        ]))->withQueryParams(['id' => '7', 'route' => 'page']);

        $this->assertSame([
            ['name' => 'debug', 'writtenName' => 'debug', 'value' => '1', 'nameIsHidden' => true],
            ['name' => 'id', 'writtenName' => 'id', 'value' => '8', 'nameIsHidden' => false],
        ], RequestView::of($serverRequest)->hiddenQueryParameters());
    }

    /**
     * The cookie header and what PHP 8.5 made of it, measured with the built-in server.
     */
    public function testWhatPhpDoesNotShowOfACookieHeaderIsHidden(): void
    {
        $cookieHeader = "a=1; a=2; b.c=3; d[x]=4; e=5+6%2B%41; f;  g = h ;i[=j; k=l, m=n; %41b=1;\th=4;i==5";
        $cookies = ['a' => '1', 'b_c' => '3', 'd' => ['x' => '4'], 'e' => '5+6+A', 'f' => '', 'g_' => ' h ', 'i_' => 'j', 'k' => 'l, m=n', '%41b' => '1', 'h' => '4', 'i' => '=5'];

        $serverRequest = (new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['HTTP_COOKIE' => $cookieHeader]))
            ->withCookieParams($cookies);

        $this->assertSame([
            ['name' => 'a', 'writtenName' => 'a', 'value' => '2', 'nameIsHidden' => false],
            ['name' => 'b_c', 'writtenName' => 'b.c', 'value' => null, 'nameIsHidden' => true],
            ['name' => 'g_', 'writtenName' => 'g ', 'value' => null, 'nameIsHidden' => true],
            ['name' => 'i_', 'writtenName' => 'i[', 'value' => null, 'nameIsHidden' => true],
        ], RequestView::of($serverRequest)->hiddenCookies());
    }

    public function testACookieCountsAsShownOnlyWithTheValuePhpDecodesItTo(): void
    {
        // A runtime that reads cookies another way shows other values; the value as PHP decodes it is inspected too.
        $serverRequest = (new ServerRequest('GET', 'https://example.test/', ['Cookie' => 'plus=a+b%20c; raw=a%20b; same=a%20b']))
            ->withCookieParams(['plus' => 'a b c', 'raw' => 'a%20b', 'same' => 'a b']);

        $this->assertSame([
            ['name' => 'plus', 'writtenName' => 'plus', 'value' => 'a+b c', 'nameIsHidden' => false],
            ['name' => 'raw', 'writtenName' => 'raw', 'value' => 'a b', 'nameIsHidden' => false],
        ], RequestView::of($serverRequest)->hiddenCookies());
    }

    public function testASecondCookieCannotHideBehindAnEncodedCopyOfItself(): void
    {
        // PHP keeps the first cookie and shows it decoded once: the text of the second one as it was written.
        $payload = '<script>alert(1)</script>';
        $cookieHeader = 'c=' . rawurlencode(rawurlencode($payload)) . '; c=' . rawurlencode($payload);
        $serverRequest = (new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['HTTP_COOKIE' => $cookieHeader]))
            ->withCookieParams(['c' => rawurlencode($payload)]);

        $this->assertSame([
            ['name' => 'c', 'writtenName' => 'c', 'value' => $payload, 'nameIsHidden' => false],
        ], RequestView::of($serverRequest)->hiddenCookies());
    }

    public function testCookiesOfTheHeaderOfTheRequestAndOfTheServerParameterAreBothRead(): void
    {
        $serverRequest = (new ServerRequest('GET', 'https://example.test/', ['Cookie' => 'sid=abc'], null, '1.1', ['HTTP_COOKIE' => 'sid=abc; sid=evil']))
            ->withCookieParams(['sid' => 'abc']);

        $this->assertSame([
            ['name' => 'sid', 'writtenName' => 'sid', 'value' => 'evil', 'nameIsHidden' => false],
        ], RequestView::of($serverRequest)->hiddenCookies());
    }

    public function testMoreParametersThanTheBoundAreNotReadAndTheViewSaysSo(): void
    {
        $serverRequest = (new ServerRequest('GET', 'https://example.test/?a=1&b=2&c=3&d=4', ['Cookie' => 'a=1; b=2; c=3; d=4']))->withQueryParams([]);

        $complete = RequestView::of($serverRequest, 4);
        $this->assertCount(4, $complete->hiddenQueryParameters());
        $this->assertTrue($complete->queryParametersComplete());
        $this->assertCount(4, $complete->hiddenCookies());
        $this->assertTrue($complete->cookiesComplete());

        $cut = RequestView::of($serverRequest, 3);
        $this->assertFalse($cut->queryParametersComplete());
        $this->assertSame(['a', 'b', 'c'], array_column($cut->hiddenQueryParameters(), 'name'));
        $this->assertFalse($cut->cookiesComplete());
        $this->assertSame(['a', 'b', 'c'], array_column($cut->hiddenCookies(), 'name'));

    }

    public function testEmptyParametersAreNotCountedAsPhpDoesNotCountThem(): void
    {
        $padded = RequestView::of((new ServerRequest('GET', 'https://example.test/?' . str_repeat('&', 50) . 'a=1&&&b=2'))->withQueryParams([]), 2);
        $this->assertTrue($padded->queryParametersComplete());
        $this->assertSame(['a', 'b'], array_column($padded->hiddenQueryParameters(), 'name'));

        $cookies = RequestView::of(new ServerRequest('GET', 'https://example.test/', ['Cookie' => str_repeat('; ', 50) . 'a=1;;; b=2']), 2);
        $this->assertTrue($cookies->cookiesComplete());
        $this->assertSame(['a', 'b'], array_column($cookies->hiddenCookies(), 'name'));
    }

    public function testValuesWithoutANameAreInspectedAndHaveABoundOfTheirOwn(): void
    {
        // PHP drops them without counting them; another reader of the same header keeps them.
        $serverRequest = (new ServerRequest('GET', 'https://example.test/?=one&a=1&=two&=one&='))->withQueryParams(['a' => '1']);

        $this->assertSame([
            ['name' => '', 'writtenName' => '', 'value' => 'one', 'nameIsHidden' => false],
            ['name' => '', 'writtenName' => '', 'value' => 'two', 'nameIsHidden' => false],
        ], RequestView::of($serverRequest)->hiddenQueryParameters());
        $this->assertTrue(RequestView::of($serverRequest, 4)->queryParametersComplete());
        $this->assertFalse(RequestView::of($serverRequest, 3)->queryParametersComplete());

        $cookies = (new ServerRequest('GET', 'https://example.test/', ['Cookie' => '=%3Cx%3E; sid=abc']))->withCookieParams(['sid' => 'abc']);
        $this->assertSame([
            ['name' => '', 'writtenName' => '', 'value' => '<x>', 'nameIsHidden' => false],
        ], RequestView::of($cookies)->hiddenCookies());
    }

    public function testAsManyParametersAreReadAsTheRequestShows(): void
    {
        // A runtime that parses the query string itself is not bound by max_input_vars.
        $serverRequest = (new ServerRequest('GET', 'https://example.test/?a=1&b=2&c=3&d=4&e=5'))
            ->withQueryParams(['a' => '1', 'b' => '2', 'c' => '3', 'd' => '4', 'e' => '5']);

        $requestView = RequestView::of($serverRequest, 3);
        $this->assertTrue($requestView->queryParametersComplete());
        $this->assertSame([], $requestView->hiddenQueryParameters());
    }

    public function testAParameterARuntimeShowsUnderItsWrittenNameIsNotHidden(): void
    {
        // Not PHP: the name keeps its dot. Nothing is hidden, and a second value goes by the name the request shows.
        $serverRequest = (new ServerRequest('GET', 'https://example.test/?user.name=ada&user.name=eve'))
            ->withQueryParams(['user.name' => 'ada']);

        $this->assertSame([
            ['name' => 'user.name', 'writtenName' => 'user.name', 'value' => 'eve', 'nameIsHidden' => false],
        ], RequestView::of($serverRequest)->hiddenQueryParameters());
    }

    public function testTheBoundIsPhpsMaxInputVars(): void
    {
        $configured = (int) ini_get('max_input_vars');

        $this->assertSame($configured > 0 ? $configured : RequestView::DEFAULT_MAX_PARAMETERS, RequestView::defaultMaxParameters());
    }

    public function testABoundThatIsNotPositiveIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RequestView::of(new ServerRequest('GET', '/'), 0);
    }

    public function testQueryParametersThatAreNotStringsAreComparedAsPhpWouldWriteThem(): void
    {
        $serverRequest = (new ServerRequest('GET', 'https://example.test/?n=5&flag=1&empty=&gone=x'))
            ->withQueryParams(['n' => 5, 'flag' => true, 'empty' => null, 'gone' => null]);

        $this->assertSame([
            ['name' => 'gone', 'writtenName' => 'gone', 'value' => 'x', 'nameIsHidden' => false],
        ], RequestView::of($serverRequest)->hiddenQueryParameters());
    }

    public function testAnAddressThatDiffersOnlyInPercentEncodingIsNotAdded(): void
    {
        // Browsers send brackets as they are; a PSR-7 library percent-encodes them.
        $serverRequest = new ServerRequest('GET', 'https://example.test/images/photo[1].jpg?ids[]=1&name=J%C3%BCrgen', [], null, '1.1', [
            'REQUEST_URI' => '/images/photo[1].jpg?ids[]=1&name=J%C3%BCrgen',
            'QUERY_STRING' => 'ids[]=1&name=J%C3%BCrgen',
        ]);
        $this->assertSame('/images/photo%5B1%5D.jpg', $serverRequest->getUri()->getPath());

        $requestView = RequestView::of($serverRequest);

        $this->assertSame(['/images/photo%5B1%5D.jpg?ids%5B%5D=1&name=J%C3%BCrgen'], $requestView->targets());
        $this->assertSame(['/images/photo%5B1%5D.jpg'], $requestView->paths());
        $this->assertSame(['ids%5B%5D=1&name=J%C3%BCrgen'], $requestView->queryStrings());
    }

    public function testAnAddressThatDecodesToTheSameIsStillAnother(): void
    {
        // Nothing is decoded for the comparison: an encoded dot or slash is not the character itself.
        $view = static fn(string $path, string $written): RequestView => RequestView::of(new ServerRequest('GET', 'https://example.test' . $path, [], null, '1.1', ['REQUEST_URI' => $written]));

        $this->assertSame(['/%2Eenv', '/.env'], $view('/%2Eenv', '/.env')->paths());
        $this->assertSame(['/a%2Fb', '/a/b'], $view('/a%2Fb', '/a/b')->paths());
        $this->assertSame(['/%5b', '/%5B'], $view('/%5b', '/%5B')->paths());
        $this->assertSame(['/a', '/a%'], $view('/a', '/a%')->paths());
        $this->assertSame(['/a%25'], $view('/a%25', '/a%')->paths(), 'A percent sign that starts no escape is one a library encodes.');
    }

    public function testAnAbsoluteRequestTargetForTheSameAddressIsNotAdded(): void
    {
        $serverRequest = new ServerRequest('GET', 'https://example.test/shop?page=2', [], null, '1.1', ['REQUEST_URI' => 'http://example.test/shop?page=2']);
        $this->assertSame(['/shop?page=2'], RequestView::of($serverRequest)->targets());

        $other = new ServerRequest('GET', 'https://example.test/shop?page=2', [], null, '1.1', ['REQUEST_URI' => 'http://example.test/admin?page=2']);
        $this->assertSame(['/shop?page=2', 'http://example.test/admin?page=2'], RequestView::of($other)->targets());
    }

    public function testAHeaderWrittenWithAnUnderscoreDoesNotStandInForTheOneWithADash(): void
    {
        $serverRequest = new ServerRequest('GET', 'https://example.test/', ['User_Agent' => 'Mozilla/5.0', 'User-Agent' => 'sqlmap/1.8'], null, '1.1', [
            'HTTP_USER_AGENT' => 'nikto/2.5',
        ]);

        $requestView = RequestView::of($serverRequest);

        $this->assertSame(['Mozilla/5.0', 'nikto/2.5', 'sqlmap/1.8'], $requestView->header('User-Agent'));
        $this->assertSame(['Mozilla/5.0', 'nikto/2.5'], $requestView->headers()['User_Agent'], 'The server parameter could be either header.');
        $this->assertSame(['sqlmap/1.8', 'nikto/2.5'], $requestView->headers()['User-Agent']);
    }

    public function testAVariableOfTheEnvironmentNamedLikeAHeaderIsNotOne(): void
    {
        putenv('HTTP_PHIREWALL_TEST_PROXY=http://proxy.internal:3128');
        try {
            $fromEnvironment = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['HTTP_PHIREWALL_TEST_PROXY' => 'http://proxy.internal:3128']);
            $this->assertSame([], RequestView::of($fromEnvironment)->header('Phirewall-Test-Proxy'));

            $fromTheClient = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['HTTP_PHIREWALL_TEST_PROXY' => 'http://evil.example']);
            $this->assertSame(['http://evil.example'], RequestView::of($fromTheClient)->header('Phirewall-Test-Proxy'));
        } finally {
            putenv('HTTP_PHIREWALL_TEST_PROXY');
        }
    }

    public function testUnderPlainCgiTheEnvironmentIsTheRequest(): void
    {
        // php-cgi run as a CGI program gets the request in its environment, the headers too.
        putenv('REQUEST_METHOD=GET');
        putenv('HTTP_USER_AGENT=sqlmap/1.8');
        try {
            $serverRequest = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['HTTP_USER_AGENT' => 'sqlmap/1.8']);
            $this->assertSame(['sqlmap/1.8'], RequestView::of($serverRequest)->header('User-Agent'));
        } finally {
            putenv('REQUEST_METHOD');
            putenv('HTTP_USER_AGENT');
        }
    }

    public function testAKeptViewDoesNotKeepItsRequestAlive(): void
    {
        $serverRequest = new ServerRequest('GET', 'https://example.test/shop?a=1');
        $request = \WeakReference::create($serverRequest);
        $requestView = RequestView::of($serverRequest);
        $view = \WeakReference::create($requestView);
        unset($requestView);
        $this->assertInstanceOf(RequestView::class, $view->get(), 'Kept for as long as the request is there.');

        // No collection of cycles: on PHP 8.2 one between a request and its view is never collected.
        unset($serverRequest);
        $this->assertNull($request->get(), 'The view must not hold its request.');
        $this->assertNull($view->get(), 'The view goes with its request.');
    }

    public function testAViewOutlivesItsRequest(): void
    {
        $requestView = RequestView::of(new ServerRequest('GET', 'https://example.test/shop?a=1', ['User-Agent' => 'curl/8']));

        $this->assertSame(['/shop?a=1'], $requestView->targets());
        $this->assertSame(['curl/8'], $requestView->header('User-Agent'));
        $this->assertSame(['a' => '1'], $requestView->queryParameters());
    }

    public function testAHeaderNameOfDigitsIsKept(): void
    {
        $serverRequest = new ServerRequest('GET', 'https://example.test/', ['123' => 'a'], null, '1.1', ['HTTP_123' => 'b', 'HTTP_456' => 'c']);

        $requestView = RequestView::of($serverRequest);

        $this->assertSame(['a', 'b'], $requestView->header('123'));
        $this->assertSame(['c'], $requestView->header('456'));
    }

    public function testAHeaderAsALineInEveryReading(): void
    {
        $serverRequest = (new ServerRequest(
            'GET',
            '/',
            ['Accept' => ['text/html', 'application/json'], 'User-Agent' => 'curl/8', 'X-Token' => 'abc', 'X_Token' => 'underscore'],
            null,
            '1.1',
            [
                'HTTP_ACCEPT' => 'text/html,application/json',
                'HTTP_USER_AGENT' => 'sqlmap/1.8',
                'HTTP_X_TOKEN' => 'abc',
                'HTTP_X_DROPPED' => 'only here',
            ],
        ));

        $requestView = RequestView::of($serverRequest);

        // The line of the request first, as getHeaderLine() gives it.
        $this->assertSame($serverRequest->getHeaderLine('Accept'), $requestView->headerLines('accept')[0]);
        // Its lines, joined by the web server, are no other reading.
        $this->assertSame(['text/html, application/json'], $requestView->headerLines('Accept'));
        $this->assertSame(['curl/8', 'sqlmap/1.8'], $requestView->headerLines('User-Agent'));
        $this->assertSame(['abc', 'underscore'], $requestView->headerLines('X-Token'));
        $this->assertSame(['underscore', 'abc'], $requestView->headerLines('X_Token'));
        $this->assertSame(['', 'only here'], $requestView->headerLines('X-Dropped'));
        $this->assertSame([''], $requestView->headerLines('X-Missing'));

        $this->assertSame(['curl/8'], RequestView::ofPsr7Only($serverRequest)->headerLines('User-Agent'));
        $this->assertSame(['abc'], RequestView::ofPsr7Only($serverRequest)->headerLines('X-Token'));
    }

    public function testTheLineOfAHeaderIsJoinedAsTheLibraryOfTheRequestJoinsIt(): void
    {
        $uri = $this->createConfiguredStub(UriInterface::class, ['getPath' => '/', 'getQuery' => '']);
        $serverRequest = $this->createConfiguredStub(ServerRequestInterface::class, [
            'getUri' => $uri,
            'getMethod' => 'GET',
            'getHeaders' => ['Host' => ['example.test'], 'Accept' => ['text/html', 'application/json']],
            'getHeaderLine' => 'text/html,application/json',
            'getQueryParams' => [],
            'getCookieParams' => [],
            'getServerParams' => ['HTTP_ACCEPT' => 'text/html, application/json'],
        ]);

        $this->assertSame(['text/html,application/json'], RequestView::of($serverRequest)->headerLines('Accept'));
        $this->assertSame(['example.test'], RequestView::of($serverRequest)->headerLines('Host'));
    }

    /**
     * A library that is not strict may give a header as one value instead of
     * a list of lines. It is one line, read like every other; null is none.
     */
    public function testAHeaderGivenAsOneValueInsteadOfAListIsOneLine(): void
    {
        $build = fn(array $headers): ServerRequestInterface => $this->createConfiguredStub(ServerRequestInterface::class, [
            'getUri' => $this->createConfiguredStub(UriInterface::class, ['getPath' => '/', 'getQuery' => '']),
            'getMethod' => 'GET',
            'getHeaders' => $headers,
            'getHeaderLine' => 'text/html, application/json',
            'getQueryParams' => [],
            'getCookieParams' => [],
            'getServerParams' => ['HTTP_USER_AGENT' => 'curl/8', 'HTTP_X_TOKEN' => 'xyz'],
        ]);
        $headers = [
            'User-Agent' => 'curl/8',
            'Accept' => ['text/html', 'application/json'],
            'X-Token' => 'abc',
            'X-Count' => 3,
            'X-None' => null,
        ];
        $expected = [
            'User-Agent' => ['curl/8'],
            'Accept' => ['text/html', 'application/json'],
            'X-Token' => ['abc', 'xyz'],
            'X-Count' => ['3'],
            'X-None' => [],
        ];

        // Header by header, after all headers, and with a header that makes every read take the long way.
        $direct = RequestView::of($build($headers));
        $afterAll = RequestView::of($build($headers));
        $afterAll->headers();

        $longWay = RequestView::of($build($headers + ['X_Other' => 'q']));

        foreach (['header by header' => $direct, 'after all headers' => $afterAll, 'the long way' => $longWay] as $label => $requestView) {
            $this->assertSame(['curl/8'], $requestView->header('User-Agent'), $label);
            $this->assertSame(['curl/8'], $requestView->headerLines('User-Agent'), $label);
            $this->assertSame(['abc', 'xyz'], $requestView->header('x-token'), $label);
            $this->assertSame(['abc', 'xyz'], $requestView->headerLines('x-token'), $label);
            $this->assertSame(['3'], $requestView->header('X-Count'), $label);
            $this->assertSame(['3'], $requestView->headerLines('X-Count'), $label);
            $this->assertSame([], $requestView->header('X-None'), $label);
            $this->assertSame([''], $requestView->headerLines('X-None'), $label);
            $this->assertSame(['text/html, application/json'], $requestView->headerLines('Accept'), $label);
        }

        $this->assertSame($expected, $direct->headers());
        $this->assertSame($expected + ['X_Other' => ['q']], $longWay->headers());
        $this->assertSame(['curl/8'], RequestView::ofPsr7Only($build($headers))->headerLines('User-Agent'));
        $this->assertSame(['abc'], RequestView::ofPsr7Only($build($headers))->header('X-Token'));
    }

    public function testWhatTheServerParametersHoldForAHeader(): void
    {
        $serverRequest = new ServerRequest('POST', '/', ['X-Forwarded-For' => '198.51.100.7', 'X_Real_Ip' => '192.0.2.1'], null, '1.1', [
            'HTTP_X_FORWARDED_FOR' => '198.51.100.7',
            'CONTENT_TYPE' => 'text/plain',
            'HTTP_EMPTY' => '',
            'HTTP_LIST' => ['not', 'a', 'string'],
        ]);

        $requestView = RequestView::of($serverRequest);

        $this->assertSame('198.51.100.7', $requestView->serverHeader('X-Forwarded-For'));
        $this->assertSame('198.51.100.7', $requestView->serverHeader('x-forwarded-for'));
        $this->assertSame('text/plain', $requestView->serverHeader('Content-Type'));
        $this->assertNull($requestView->serverHeader('X-Real-Ip'), 'A header of the request is no server parameter.');
        $this->assertNull($requestView->serverHeader('Empty'));
        $this->assertNull($requestView->serverHeader('List'));
        $this->assertNull(RequestView::ofPsr7Only($serverRequest)->serverHeader('X-Forwarded-For'));
    }

    public function testAVariableOfTheEnvironmentIsNotWhatTheServerParametersHoldForAHeader(): void
    {
        putenv('HTTP_X_PHIREWALL_TEST=from the environment');
        try {
            $fromEnvironment = new ServerRequest('GET', '/', [], null, '1.1', ['HTTP_X_PHIREWALL_TEST' => 'from the environment']);
            $fromClient = new ServerRequest('GET', '/', [], null, '1.1', ['HTTP_X_PHIREWALL_TEST' => 'from the client']);

            $this->assertNull(RequestView::of($fromEnvironment)->serverHeader('X-Phirewall-Test'));
            $this->assertSame('from the client', RequestView::of($fromClient)->serverHeader('X-Phirewall-Test'));
        } finally {
            putenv('HTTP_X_PHIREWALL_TEST');
        }
    }

    public function testTheAddressesOfARequest(): void
    {
        $same = new ServerRequest('GET', '/shop/a%5B1%5D?x=1', [], null, '1.1', ['REQUEST_URI' => '/shop/a[1]?x=1', 'QUERY_STRING' => 'x=1']);
        $this->assertSame([['path' => '/shop/a%5B1%5D', 'query' => 'x=1']], RequestView::of($same)->addresses());

        $rewritten = new ServerRequest('GET', '/index.php?page=shop', [], null, '1.1', [
            'REQUEST_URI' => 'http://example.test/shop?debug=1',
            'QUERY_STRING' => 'page=shop&debug=1',
        ]);
        $this->assertSame(
            [
                ['path' => '/index.php', 'query' => 'page=shop'],
                ['path' => '/shop', 'query' => 'debug=1'],
                ['path' => '/index.php', 'query' => 'page=shop&debug=1'],
            ],
            RequestView::of($rewritten)->addresses(),
        );

        $withoutQuery = new ServerRequest('GET', '/a', [], null, '1.1', ['REQUEST_URI' => '/b']);
        $this->assertSame([['path' => '/a', 'query' => ''], ['path' => '/b', 'query' => '']], RequestView::of($withoutQuery)->addresses());

        $this->assertSame([['path' => '/a', 'query' => '']], RequestView::ofPsr7Only($withoutQuery)->addresses());
    }

    public function testThePathsOfARequestInTheirNormalisedForm(): void
    {
        $serverRequest = new ServerRequest('GET', '/health', [], null, '1.1', ['REQUEST_URI' => '/x/../%61dmin?y=1']);

        $normalizedPaths = RequestView::of($serverRequest)->normalizedPaths();

        $this->assertCount(2, $normalizedPaths);
        $this->assertSame(['/health', '/health', false], [$normalizedPaths[0]->raw, $normalizedPaths[0]->normalized, $normalizedPaths[0]->ambiguous]);
        $this->assertSame(['/x/../%61dmin', '/admin', true], [$normalizedPaths[1]->raw, $normalizedPaths[1]->normalized, $normalizedPaths[1]->ambiguous]);
        $this->assertSame($normalizedPaths, RequestView::of($serverRequest)->normalizedPaths());
        $this->assertCount(1, RequestView::ofPsr7Only($serverRequest)->normalizedPaths());
    }

    /**
     * @return iterable<string, array{array<string, string|list<string>>, array<string, mixed>}>
     */
    public static function requestsReadHeaderByHeader(): iterable
    {
        $own = [
            'none' => [],
            'one line' => ['X-Token' => 'abc'],
            'blanks around' => ['X-Token' => ' abc '],
            'two lines' => ['X-Token' => ['abc', 'def']],
            'the same line twice' => ['X-Token' => ['abc', 'abc']],
            'an empty line' => ['X-Token' => ''],
            'lower case' => ['x-token' => 'abc'],
        ];
        $server = [
            'none' => [],
            'the same' => ['HTTP_X_TOKEN' => 'abc'],
            'the same with blanks' => ['HTTP_X_TOKEN' => ' abc'],
            'another' => ['HTTP_X_TOKEN' => 'xyz'],
            'the lines joined' => ['HTTP_X_TOKEN' => 'abc, def'],
            'empty' => ['HTTP_X_TOKEN' => ''],
            'not a string' => ['HTTP_X_TOKEN' => ['abc']],
            'of another header' => ['HTTP_X_TOKENS' => 'xyz', 'HTTP_X' => 'xyz'],
            'named in lower case' => ['HTTP_x_token' => 'xyz'],
            'named with a dash' => ['HTTP_X-TOKEN' => 'xyz'],
        ];

        foreach ($own as $ownName => $headers) {
            foreach ($server as $serverName => $serverParameters) {
                yield sprintf('request: %s, server parameters: %s', $ownName, $serverName) => [$headers, $serverParameters];
            }
        }
    }

    /**
     * One header is read without sorting out all of them where one name
     * stands for one header and one server parameter. A header with an
     * underscore in its name ends that, so the same request with such a
     * header, of another name, is read the long way and has to give the same.
     *
     * @param array<string, string|list<string>> $headers
     * @param array<string, mixed> $serverParameters
     */
    #[DataProvider('requestsReadHeaderByHeader')]
    public function testOneHeaderReadOnItsOwnIsWhatAllHeadersGive(array $headers, array $serverParameters): void
    {
        $build = static fn(array $headers): ServerRequest => new ServerRequest('GET', '/', $headers, null, '1.1', $serverParameters);

        foreach ([false, true] as $psr7Only) {
            foreach (['X-Token', 'x-token', 'X-TOKEN', 'X-Tokens', 'X', 'Host'] as $name) {
                $view = static fn(ServerRequest $serverRequest): RequestView => $psr7Only ? RequestView::ofPsr7Only($serverRequest) : RequestView::of($serverRequest);

                $direct = $view($build($headers));
                $sorted = $view($build($headers + ['Zz_Unrelated' => 'y']));
                $afterAll = $view($build($headers));
                $afterAll->headers();

                $label = sprintf('%s, %s', $name, $psr7Only ? 'PSR-7 only' : 'both readings');
                $this->assertSame($sorted->header($name), $direct->header($name), $label);
                $this->assertSame($sorted->headerLines($name), $direct->headerLines($name), $label);
                $this->assertSame($sorted->header($name), $afterAll->header($name), $label);
                $this->assertSame($sorted->headerLines($name), $afterAll->headerLines($name), $label);
                $this->assertSame($direct->header($name), $direct->header($name), 'Asked again.');
                $listed = array_values(array_filter(
                    $direct->headers(),
                    static fn(int|string $known): bool => strtolower((string) $known) === strtolower($name),
                    ARRAY_FILTER_USE_KEY,
                ))[0] ?? [];
                $this->assertSame($direct->header($name), array_values(array_unique($listed)), $label . ': each value headers() lists, once.');
            }
        }
    }

    /**
     * A server parameter named longer than PCRE backtracks through
     * (`pcre.backtrack_limit`) does not hide one named in lower case after it.
     */
    public function testAServerParameterOfAnyLengthLeavesHeadersReadInFull(): void
    {
        $serverParameters = ['HTTP_' . str_repeat('A', 1_100_000) => 'x', 'HTTP_x_token' => 'xyz'];
        $serverRequest = new ServerRequest('GET', '/', ['X-Token' => 'abc'], null, '1.1', $serverParameters);

        $this->assertSame(['abc', 'xyz'], RequestView::of($serverRequest)->header('X-Token'));
    }

    public function testARequestCanBeReadWithoutItsServerParameters(): void
    {
        $serverRequest = new ServerRequest('GET', '/a', [], null, '1.1', ['REQUEST_URI' => '/b', 'HTTP_X_DEBUG' => 'on']);

        $this->assertSame($serverRequest, RequestView::withServerParameterInspection($serverRequest, true), 'A request has them read unless it says otherwise.');
        $this->assertSame(['/a', '/b'], RequestView::of($serverRequest)->paths());

        $psr7Only = RequestView::withServerParameterInspection($serverRequest, false);
        $this->assertNotSame($serverRequest, $psr7Only);
        $this->assertFalse($psr7Only->getAttribute(RequestView::INSPECT_SERVER_PARAMETERS_ATTRIBUTE));
        $this->assertSame(['/a'], RequestView::of($psr7Only)->paths());
        $this->assertSame([], RequestView::of($psr7Only)->header('X-Debug'));
        $this->assertSame(['/a'], RequestView::of($psr7Only, 10)->paths());
        $this->assertSame($psr7Only, RequestView::withServerParameterInspection($psr7Only, false));
        $this->assertSame(['/a', '/b'], RequestView::of($serverRequest)->paths(), 'The request it was made from is read as before.');

        $inspected = RequestView::withServerParameterInspection($psr7Only, true);
        $this->assertArrayNotHasKey(RequestView::INSPECT_SERVER_PARAMETERS_ATTRIBUTE, $inspected->getAttributes());
        $this->assertSame(['/a', '/b'], RequestView::of($inspected)->paths());
        $this->assertSame(['on'], RequestView::of($inspected)->header('X-Debug'));
    }

    public function testTheSettingGoesAlongWithEveryCopyOfTheRequest(): void
    {
        $serverRequest = new ServerRequest('GET', '/a', [], null, '1.1', ['REQUEST_URI' => '/b']);
        $psr7Only = RequestView::withServerParameterInspection($serverRequest, false);

        $this->assertSame(['/a'], RequestView::of($psr7Only->withAttribute('route', 'a'))->paths());
        $this->assertSame(['/a'], RequestView::of($psr7Only->withHeader('X-Trace', '1'))->paths());
    }

    public function testOnlyTheBooleanTurnsTheServerParametersOff(): void
    {
        $serverRequest = new ServerRequest('GET', '/a', [], null, '1.1', ['REQUEST_URI' => '/b']);

        foreach (['false', '0', 0, '', null] as $value) {
            $withAttribute = $serverRequest->withAttribute(RequestView::INSPECT_SERVER_PARAMETERS_ATTRIBUTE, $value);
            $this->assertSame(['/a', '/b'], RequestView::of($withAttribute)->paths(), var_export($value, true));
        }
    }

    /**
     * @param array<array-key, mixed>|null $parsedBody
     */
    private function formRequest(string $body, ?array $parsedBody, string $contentType = 'application/x-www-form-urlencoded'): ServerRequestInterface
    {
        return (new ServerRequest('POST', '/form', ['Content-Type' => $contentType], $body, '1.1', ['CONTENT_TYPE' => $contentType]))
            ->withParsedBody($parsedBody);
    }

    public function testWhatPhpDoesNotShowOfAFormBodyIsHidden(): void
    {
        parse_str('comment=first&comment=second&my.field=x&name=J%C3%B6rg+M&list[]=a&list[]=b', $parsedBody);
        $serverRequest = $this->formRequest('comment=first&comment=second&my.field=x&name=J%C3%B6rg+M&list[]=a&list[]=b', $parsedBody);

        $requestView = RequestView::of($serverRequest);

        $this->assertSame(
            [
                ['name' => 'comment', 'writtenName' => 'comment', 'value' => 'first', 'nameIsHidden' => false],
                ['name' => 'my_field', 'writtenName' => 'my.field', 'value' => null, 'nameIsHidden' => true],
            ],
            $requestView->hiddenBodyParameters($serverRequest),
        );
        $this->assertTrue($requestView->bodyParametersComplete($serverRequest));
        $this->assertSame([], $requestView->hiddenQueryParameters());
    }

    public function testEveryParameterOfAFormBodyIsHiddenWhenTheBodyWasNeverParsed(): void
    {
        $serverRequest = $this->formRequest('user=admin&pass=a%27+or+1', null);

        $this->assertSame(
            [
                ['name' => 'user', 'writtenName' => 'user', 'value' => 'admin', 'nameIsHidden' => true],
                ['name' => 'pass', 'writtenName' => 'pass', 'value' => "a' or 1", 'nameIsHidden' => true],
            ],
            RequestView::of($serverRequest)->hiddenBodyParameters($serverRequest),
        );
    }

    public function testTheBodyIsLeftAtThePositionItWasAt(): void
    {
        $serverRequest = $this->formRequest('a=1&a=2', ['a' => '2']);
        $serverRequest->getBody()->seek(3);

        $this->assertCount(1, RequestView::of($serverRequest)->hiddenBodyParameters($serverRequest));
        $this->assertSame(3, $serverRequest->getBody()->tell());
        $this->assertSame('&a=2', $serverRequest->getBody()->getContents());
    }

    public function testABodyThatIsNoFormIsNotRead(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->never())->method('read');
        $stream->expects($this->never())->method('rewind');
        $stream->expects($this->never())->method('getContents');
        $stream->expects($this->never())->method('__toString');

        foreach (['application/json', 'multipart/form-data; boundary=x', 'text/plain'] as $contentType) {
            $serverRequest = (new ServerRequest('POST', '/api', ['Content-Type' => $contentType]))->withBody($stream);

            $requestView = RequestView::of($serverRequest);
            $this->assertSame([], $requestView->hiddenBodyParameters($serverRequest));
            $this->assertTrue($requestView->bodyParametersComplete($serverRequest));
        }
    }

    public function testABodyThatNamesNoContentTypeIsReadAsAForm(): void
    {
        foreach (['PUT', 'PATCH', 'DELETE', 'GET', 'POST'] as $method) {
            $withoutHeader = new ServerRequest($method, '/item', [], 'user=admin&pass=a%27+or+1');
            $this->assertSame(
                [
                    ['name' => 'user', 'writtenName' => 'user', 'value' => 'admin', 'nameIsHidden' => true],
                    ['name' => 'pass', 'writtenName' => 'pass', 'value' => "a' or 1", 'nameIsHidden' => true],
                ],
                RequestView::of($withoutHeader)->hiddenBodyParameters($withoutHeader),
                $method,
            );
        }

        $empty = new ServerRequest('PUT', '/item', ['Content-Type' => ' '], 'a=1', '1.1', ['CONTENT_TYPE' => '', 'HTTP_CONTENT_TYPE' => '']);
        $this->assertCount(1, RequestView::of($empty)->hiddenBodyParameters($empty));

        parse_str('a=1&a=2', $parsedBody);
        $parsed = (new ServerRequest('PUT', '/item', [], 'a=1&a=2'))->withParsedBody($parsedBody);
        $this->assertSame(
            [['name' => 'a', 'writtenName' => 'a', 'value' => '1', 'nameIsHidden' => false]],
            RequestView::of($parsed)->hiddenBodyParameters($parsed),
        );
    }

    public function testABodyIsNotReadAsAFormWhenOneReadingNamesAnotherType(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->never())->method('read');
        $stream->expects($this->never())->method('getSize');

        $inServerParameters = (new ServerRequest('PUT', '/item', [], null, '1.1', ['CONTENT_TYPE' => 'application/json']))->withBody($stream);
        $inTheRequest = (new ServerRequest('PUT', '/item', ['Content-Type' => 'application/json'], null, '1.1', ['CONTENT_TYPE' => '']))->withBody($stream);
        foreach ([$inServerParameters, $inTheRequest] as $serverRequest) {
            $requestView = RequestView::of($serverRequest);
            $this->assertSame([], $requestView->hiddenBodyParameters($serverRequest));
            $this->assertTrue($requestView->bodyParametersComplete($serverRequest));
        }
    }

    public function testAnEmptyBodyIsNotRead(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getSize')->willReturn(0);
        $stream->expects($this->never())->method('isSeekable');
        $stream->expects($this->never())->method('tell');
        $stream->expects($this->never())->method('rewind');
        $stream->expects($this->never())->method('read');

        foreach ([[], ['Content-Type' => 'application/x-www-form-urlencoded']] as $headers) {
            $serverRequest = (new ServerRequest('GET', '/', $headers))->withBody($stream);
            $requestView = RequestView::of($serverRequest);
            $this->assertSame([], $requestView->hiddenBodyParameters($serverRequest));
            $this->assertTrue($requestView->bodyParametersComplete($serverRequest));
        }
    }

    public function testABodyWithoutAContentTypeIsLeftAtThePositionItWasAt(): void
    {
        $serverRequest = new ServerRequest('PUT', '/item', [], 'a=1&a=2');
        $serverRequest->getBody()->seek(3);

        $this->assertCount(2, RequestView::of($serverRequest)->hiddenBodyParameters($serverRequest));
        $this->assertSame(3, $serverRequest->getBody()->tell());
        $this->assertSame('&a=2', $serverRequest->getBody()->getContents());
    }

    public function testABodyWithoutAContentTypeHasTheBoundsOfAForm(): void
    {
        $longer = new ServerRequest('PUT', '/item', [], 'a=1&b=' . str_repeat('x', 100));
        $this->assertFalse(RequestView::of($longer, null, 64)->bodyParametersComplete($longer));
        $this->assertSame(0, $longer->getBody()->tell());

        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isSeekable')->willReturn(false);
        $stream->method('isReadable')->willReturn(true);
        $stream->method('getSize')->willReturn(null);
        $stream->expects($this->never())->method('read');
        $declared = (new ServerRequest('PUT', '/item', [], null, '1.1', ['CONTENT_LENGTH' => '2006']))->withBody($stream);
        $this->assertFalse(RequestView::of($declared, null, 1024)->bodyParametersComplete($declared));

        $moreParameters = new ServerRequest('PUT', '/item', [], 'a=1&b=2&c=3');
        $this->assertFalse(RequestView::of($moreParameters, 2)->bodyParametersComplete($moreParameters));
    }

    public function testABodyWithoutAContentTypeIsNotReadWithoutTheServerParametersOrWhenItCannotBeReadAgain(): void
    {
        $serverRequest = new ServerRequest('PUT', '/item', [], 'a=1');
        $this->assertSame([], RequestView::ofPsr7Only($serverRequest)->hiddenBodyParameters($serverRequest));

        $turnedOff = RequestView::withServerParameterInspection($serverRequest, false);
        $this->assertSame([], RequestView::of($turnedOff)->hiddenBodyParameters($turnedOff));

        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isSeekable')->willReturn(false);
        $stream->method('isReadable')->willReturn(true);
        $stream->method('getSize')->willReturn(3);
        $stream->expects($this->never())->method('read');
        $notSeekable = $serverRequest->withBody($stream);
        $this->assertSame([], RequestView::of($notSeekable)->hiddenBodyParameters($notSeekable));
        $this->assertTrue(RequestView::of($notSeekable)->bodyParametersComplete($notSeekable));
    }

    public function testWhetherABodyWithoutAContentTypeIsAFormIsTheCallersChoice(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->never())->method('getSize');
        $stream->expects($this->never())->method('read');
        $serverRequest = (new ServerRequest('PUT', '/item', [], null, '1.1', ['CONTENT_TYPE' => '']))->withBody($stream);

        $requestView = RequestView::of($serverRequest);
        $this->assertSame([], $requestView->hiddenBodyParameters($serverRequest, false));
        $this->assertTrue($requestView->bodyParametersComplete($serverRequest, false));

        $form = $this->formRequest('a=1&a=2', ['a' => '2']);
        $this->assertCount(1, RequestView::of($form)->hiddenBodyParameters($form, false), 'A form is read either way.');
    }

    public function testTheTwoAnswersAboutABodyWithoutAContentTypeDoNotMixOnOneView(): void
    {
        $serverRequest = new ServerRequest('PUT', '/item', [], 'a=1&b=' . str_repeat('x', 100));
        $requestView = RequestView::of($serverRequest, null, 64);

        $this->assertTrue($requestView->bodyParametersComplete($serverRequest, false));
        $this->assertFalse($requestView->bodyParametersComplete($serverRequest, true));
        $this->assertTrue($requestView->bodyParametersComplete($serverRequest, false));

        $small = new ServerRequest('PUT', '/item', [], 'a=1');
        $view = RequestView::of($small);
        $this->assertSame([], $view->hiddenBodyParameters($small, false));
        $this->assertCount(1, $view->hiddenBodyParameters($small));
        $this->assertSame([], $view->hiddenBodyParameters($small, false));
        $this->assertCount(1, $view->hiddenBodyParameters($small, true));
    }

    public function testTheContentTypeOfAFormIsReadInBothReadings(): void
    {
        $withParameter = $this->formRequest('a=1', null, 'Application/X-WWW-Form-Urlencoded; charset=UTF-8');
        $this->assertCount(1, RequestView::of($withParameter)->hiddenBodyParameters($withParameter));

        $onlyInServerParameters = (new ServerRequest('POST', '/form', [], 'a=1', '1.1', ['CONTENT_TYPE' => 'application/x-www-form-urlencoded']));
        $this->assertCount(1, RequestView::of($onlyInServerParameters)->hiddenBodyParameters($onlyInServerParameters));
    }

    public function testABodyThatCannotBeReadAgainIsNotRead(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isSeekable')->willReturn(false);
        $stream->method('isReadable')->willReturn(true);
        $stream->expects($this->never())->method('read');

        $serverRequest = $this->formRequest('', null)->withBody($stream);
        $requestView = RequestView::of($serverRequest);

        $this->assertSame([], $requestView->hiddenBodyParameters($serverRequest));
        $this->assertTrue($requestView->bodyParametersComplete($serverRequest));
    }

    public function testABodyThatFailsWhileItIsReadIsPutBackAndLeftToTheApplication(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isSeekable')->willReturn(true);
        $stream->method('isReadable')->willReturn(true);
        $stream->method('getSize')->willReturn(null);
        $stream->method('tell')->willReturn(5);
        $stream->method('eof')->willReturn(false);
        $stream->method('read')->willThrowException(new \RuntimeException('gone'));
        $stream->expects($this->once())->method('seek')->with(5);

        $serverRequest = $this->formRequest('', null)->withBody($stream);
        $requestView = RequestView::of($serverRequest);

        $this->assertSame([], $requestView->hiddenBodyParameters($serverRequest));
        $this->assertTrue($requestView->bodyParametersComplete($serverRequest));
    }

    public function testAFormBodyWithMoreBytesThanTheBoundIsNotReadAndTheViewSaysSo(): void
    {
        $serverRequest = $this->formRequest('a=1&a=2&b=' . str_repeat('x', 100), ['a' => '2', 'b' => str_repeat('x', 100)]);

        $bounded = RequestView::of($serverRequest, null, 64);
        $this->assertSame([], $bounded->hiddenBodyParameters($serverRequest));
        $this->assertFalse($bounded->bodyParametersComplete($serverRequest));
        $this->assertSame(0, $serverRequest->getBody()->tell());

        $wide = RequestView::of($serverRequest, null, 110);
        $this->assertCount(1, $wide->hiddenBodyParameters($serverRequest));
        $this->assertTrue($wide->bodyParametersComplete($serverRequest));
    }

    public function testAStreamThatDoesNotKnowItsSizeIsReadUpToTheBound(): void
    {
        $content = 'a=1&a=2&b=' . str_repeat('x', 100);
        $position = 0;
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isSeekable')->willReturn(true);
        $stream->method('isReadable')->willReturn(true);
        $stream->method('getSize')->willReturn(null);
        $stream->method('tell')->willReturnCallback(static function () use (&$position): int {
            return $position;
        });
        $stream->method('eof')->willReturnCallback(static function () use (&$position, $content): bool {
            return $position >= strlen($content);
        });
        $stream->method('read')->willReturnCallback(static function (int $length) use (&$position, $content): string {
            $chunk = substr($content, $position, min($length, 16));
            $position += strlen($chunk);

            return $chunk;
        });
        $stream->method('rewind')->willReturnCallback(static function () use (&$position): void {
            $position = 0;
        });
        $stream->method('seek')->willReturnCallback(static function (int $offset) use (&$position): void {
            $position = $offset;
        });

        $serverRequest = $this->formRequest('', ['a' => '2', 'b' => str_repeat('x', 100)])->withBody($stream);

        $bounded = RequestView::of($serverRequest, null, 64);
        $this->assertFalse($bounded->bodyParametersComplete($serverRequest));
        $this->assertSame(0, $position);

        $wide = RequestView::of($serverRequest, null, 4096);
        $this->assertSame(
            [['name' => 'a', 'writtenName' => 'a', 'value' => '1', 'nameIsHidden' => false]],
            $wide->hiddenBodyParameters($serverRequest),
        );
        $this->assertTrue($wide->bodyParametersComplete($serverRequest));
    }

    public function testAFormBodyLongerThanTheBoundIsIncompleteEvenWhenItIsNotRead(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isSeekable')->willReturn(false);
        $stream->method('isReadable')->willReturn(true);
        $stream->method('getSize')->willReturn(110);
        $stream->expects($this->never())->method('read');

        $serverRequest = $this->formRequest('', ['a' => '2'])->withBody($stream);

        $this->assertFalse(RequestView::of($serverRequest, null, 64)->bodyParametersComplete($serverRequest));
        $this->assertTrue(RequestView::of($serverRequest, null, 110)->bodyParametersComplete($serverRequest));
    }

    public function testAFormBodyThatDeclaresMoreBytesThanTheBoundIsIncompleteWhenItsStreamKnowsNoSize(): void
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('isSeekable')->willReturn(false);
        $stream->method('isReadable')->willReturn(true);
        $stream->method('getSize')->willReturn(null);
        $stream->expects($this->never())->method('read');

        $declaredInHeader = $this->formRequest('', [])->withBody($stream)->withHeader('Content-Length', '2006');
        $this->assertFalse(RequestView::of($declaredInHeader, null, 1024)->bodyParametersComplete($declaredInHeader));

        $declaredInServerParameter = new ServerRequest('POST', '/form', ['Content-Type' => 'application/x-www-form-urlencoded'], null, '1.1', ['CONTENT_TYPE' => 'application/x-www-form-urlencoded', 'CONTENT_LENGTH' => '2006']);
        $declaredInServerParameter = $declaredInServerParameter->withBody($stream);
        $this->assertFalse(RequestView::of($declaredInServerParameter, null, 1024)->bodyParametersComplete($declaredInServerParameter));

        $withinTheBound = $this->formRequest('', [])->withBody($stream)->withHeader('Content-Length', '1024');
        $this->assertTrue(RequestView::of($withinTheBound, null, 1024)->bodyParametersComplete($withinTheBound));
    }

    public function testAFormBodyWithMoreParametersThanTheBoundIsIncomplete(): void
    {
        $serverRequest = $this->formRequest('a=1&b=2&c=3', null);

        $requestView = RequestView::of($serverRequest, 2);

        $this->assertCount(2, $requestView->hiddenBodyParameters($serverRequest));
        $this->assertFalse($requestView->bodyParametersComplete($serverRequest));
    }

    public function testThePsr7OnlyViewDoesNotReadTheBody(): void
    {
        $serverRequest = $this->formRequest('a=1&a=2', ['a' => '2']);

        $requestView = RequestView::ofPsr7Only($serverRequest);

        $this->assertSame([], $requestView->hiddenBodyParameters($serverRequest));
        $this->assertTrue($requestView->bodyParametersComplete($serverRequest));
    }

    public function testTheBoundOfTheBodyIsPhpsPostMaxSize(): void
    {
        $configured = ini_parse_quantity((string) ini_get('post_max_size'));

        $this->assertSame($configured > 0 ? $configured : RequestView::DEFAULT_MAX_BODY_BYTES, RequestView::defaultMaxBodyBytes());
    }

    public function testABoundOfTheBodyThatIsNotPositiveIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        RequestView::of(new ServerRequest('GET', '/'), null, 0);
    }

    public function testABodyOfSlimPsr7IsNotRead(): void
    {
        if (!class_exists('Slim\\Psr7\\Stream')) {
            class_alias(AppendingCacheStream::class, 'Slim\\Psr7\\Stream');
        }

        if (!is_a(AppendingCacheStream::class, 'Slim\\Psr7\\Stream', true)) {
            $this->markTestSkipped('slim/psr7 is installed; its stream is tested where it is built from php://input.');
        }

        // Read twice, such a body is in its own copy twice.
        $readTwice = new AppendingCacheStream('a=1&a=2');
        $readTwice->read(100);
        $readTwice->rewind();
        $readTwice->read(100);
        $this->assertSame('a=1&a=2a=1&a=2', (string) $readTwice);

        $stream = new AppendingCacheStream('a=1&a=2');
        $serverRequest = $this->formRequest('', ['a' => '2'])->withBody($stream);
        $requestView = RequestView::of($serverRequest);

        $this->assertSame([], $requestView->hiddenBodyParameters($serverRequest));
        $this->assertTrue($requestView->bodyParametersComplete($serverRequest));

        // The application reads it in pieces and then as a whole.
        $read = '';
        while (!$stream->eof()) {
            $read .= $stream->read(3);
        }

        $this->assertSame('a=1&a=2', $read);
        $this->assertSame('a=1&a=2', (string) $stream);
    }

    public function testWithoutTheServerParametersAHeaderIsTheOneOfItsName(): void
    {
        $serverRequest = new ServerRequest('GET', '/', ['User-Agent' => 'curl/8', 'User_Agent' => 'sqlmap/1.8'], null, '1.1', ['HTTP_USER_AGENT' => 'other']);

        $this->assertSame(['curl/8', 'other', 'sqlmap/1.8'], RequestView::of($serverRequest)->header('User-Agent'));
        $this->assertSame(['curl/8'], RequestView::ofPsr7Only($serverRequest)->header('user-agent'));
        $this->assertSame(['sqlmap/1.8'], RequestView::ofPsr7Only($serverRequest)->header('User_Agent'));
        $this->assertSame($serverRequest->getHeader('User-Agent'), RequestView::ofPsr7Only($serverRequest)->header('User-Agent'));
    }
}
