<?php

declare(strict_types=1);

namespace Flowd\PhirewallBenchmarks\Support;

use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The requests the benchmarks send. They never change: a different request is a
 * different benchmark.
 */
final class Requests
{
    /** TEST-NET-3: an address no list contains. */
    public const CLIENT_IP = '203.0.113.7';

    private const BROWSER_HEADERS = [
        'Host' => 'www.example.org',
        'User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language' => 'de,en-US;q=0.7,en;q=0.3',
        'Accept-Encoding' => 'gzip, deflate, br, zstd',
        'Connection' => 'keep-alive',
        'Referer' => 'https://www.example.org/blog',
    ];

    private const COOKIES = [
        'session' => '7f3a9c2e5b1d4f60a8e2c7b9d4f1a3e5',
        'consent' => 'essential',
    ];

    private function __construct()
    {
    }

    /** A page view with a few query parameters and cookies. */
    public static function pageView(string $clientIp = self::CLIENT_IP): ServerRequestInterface
    {
        return self::get($clientIp, [
            'page' => '2',
            'category' => 'release-notes',
            'utm_source' => 'newsletter',
            'utm_campaign' => 'autumn-2026',
        ]);
    }

    /** The same page view, with an SQL injection attempt in one parameter. */
    public static function sqlInjection(string $clientIp = self::CLIENT_IP): ServerRequestInterface
    {
        return self::get($clientIp, [
            'page' => '2',
            'category' => "release-notes' UNION SELECT username, password FROM users--",
        ]);
    }

    /** A contact form with a longer free-text field. */
    public static function formPost(string $clientIp = self::CLIENT_IP): ServerRequestInterface
    {
        $fields = [
            'name' => 'Erika Mustermann',
            'email' => 'erika.mustermann@example.org',
            'subject' => 'Question about the autumn release',
            'message' => str_repeat('We would like to know when the release is planned and what it contains. ', 12),
            'newsletter' => '1',
        ];

        $serverRequest = new ServerRequest(
            'POST',
            'https://www.example.org/contact',
            self::BROWSER_HEADERS + [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Cookie' => self::cookieHeader(),
                'Origin' => 'https://www.example.org',
            ],
            http_build_query($fields),
            '1.1',
            ['REMOTE_ADDR' => $clientIp],
        );

        return $serverRequest->withCookieParams(self::COOKIES)->withParsedBody($fields);
    }

    /**
     * @param array<string, string> $query
     */
    private static function get(string $clientIp, array $query): ServerRequestInterface
    {
        $serverRequest = new ServerRequest(
            'GET',
            'https://www.example.org/blog/2026/a-quiet-page?' . http_build_query($query),
            self::BROWSER_HEADERS + ['Cookie' => self::cookieHeader()],
            null,
            '1.1',
            ['REMOTE_ADDR' => $clientIp],
        );

        return $serverRequest->withCookieParams(self::COOKIES)->withQueryParams($query);
    }

    private static function cookieHeader(): string
    {
        return http_build_query(self::COOKIES, '', '; ');
    }
}
