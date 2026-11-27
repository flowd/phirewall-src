<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\ShippedRules;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Every payload of the fixtures once more, this time only in the server
 * parameters of the request: the PSR-7 request itself is an empty GET of "/",
 * as if its library had dropped or never parsed what the client sent. The rule
 * has to fire all the same, and must not when the server parameters are not
 * inspected.
 */
final class ServerParametersPayloadTest extends TestCase
{
    /**
     * @return iterable<string, array{int, string, string}>
     */
    public static function payloadProvider(): iterable
    {
        $path = __DIR__ . '/../Fixtures/rule-payloads.php';
        if (!is_file($path)) {
            return;
        }

        /** @var array{payloads: array<int, array{vector: string, payload_base64: string}>} $fixtures */
        $fixtures = require $path;
        foreach ($fixtures['payloads'] as $id => $entry) {
            yield 'rule ' . $id => [$id, $entry['vector'], (string) base64_decode($entry['payload_base64'], true)];
        }
    }

    #[DataProvider('payloadProvider')]
    public function testThePayloadFiresItsRuleFromTheServerParametersAlone(int $id, string $vector, string $payload): void
    {
        $rule = Presets::coreRuleSet(ParanoiaLevel::Level4)->getRule($id);
        $this->assertInstanceOf(CoreRule::class, $rule);

        $serverRequest = $this->requestWithServerParameters($vector, $payload);
        $this->assertSame('/', $serverRequest->getUri()->getPath());
        $this->assertSame('', $serverRequest->getUri()->getQuery());
        $this->assertSame([], $serverRequest->getQueryParams());
        $this->assertSame([], $serverRequest->getCookieParams());
        $this->assertSame(['Host' => ['example.test']], $serverRequest->getHeaders());

        $this->assertSame(
            [$id],
            (new CoreRuleSet([$rule]))->evaluate($serverRequest, anomalyThreshold: 1)->matchedRuleIds(),
            sprintf('Rule %d did not fire on a payload only the server parameters hold (vector %s).', $id, $vector),
        );
        $this->assertSame(
            [],
            (new CoreRuleSet([$rule]))->inspectServerParameters(false)->evaluate($serverRequest, anomalyThreshold: 1)->matchedRuleIds(),
            sprintf('Rule %d fired although the server parameters are not inspected.', $id),
        );
    }

    /**
     * The server parameters a web server would hand PHP for the request
     * {@see EveryRulePayloadTest::buildRequest()} builds for the vector.
     */
    private function requestWithServerParameters(string $vector, string $payload): ServerRequestInterface
    {
        $header = match (true) {
            str_starts_with($vector, 'raw-header:') => substr($vector, strlen('raw-header:')),
            str_starts_with($vector, 'header:') => substr($vector, strlen('header:')),
            $vector === 'header_referer' => 'Referer',
            $vector === 'header_ua' => 'User-Agent',
            $vector === 'header_content_type' => 'Content-Type',
            default => null,
        };

        $serverParameters = match (true) {
            $header !== null => ['HTTP_' . strtoupper(strtr($header, '-', '_')) => $payload],
            $vector === 'args' => ['QUERY_STRING' => 'p=' . rawurlencode($payload)],
            $vector === 'args_names' => ['QUERY_STRING' => rawurlencode($payload) . '=1'],
            $vector === 'query_string' => ['QUERY_STRING' => $payload],
            $vector === 'uri' => ['REQUEST_URI' => '/' . ltrim($payload, '/')],
            $vector === 'filename' => ['REQUEST_URI' => '/' . ltrim(str_replace('?', '', $payload), '/')],
            $vector === 'cookie' => ['HTTP_COOKIE' => 'c=' . rawurlencode($payload)],
            str_starts_with($vector, 'cookie:') => ['HTTP_COOKIE' => substr($vector, strlen('cookie:')) . '=' . rawurlencode($payload)],
            $vector === 'method', $vector === 'raw-method' => ['REQUEST_METHOD' => $payload],
            default => self::fail(sprintf('No server parameter is known for vector "%s".', $vector)),
        };

        return new ServerRequest('GET', 'https://example.test/', [], null, '1.1', $serverParameters);
    }
}
