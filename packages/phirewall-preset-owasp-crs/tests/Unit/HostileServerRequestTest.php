<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Unit;

use Flowd\PhirewallPresetOwaspCrs\Tests\HostileServerRequest;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class HostileServerRequestTest extends TestCase
{
    public function testWithAddedHeaderAppendsToARawHeader(): void
    {
        $serverRequest = HostileServerRequest::from(
            (new ServerRequest('GET', 'https://example.test/'))->withHeader('X-Test', 'shadowed'),
        )->withRawHeader('X-Test', "evil\r\n");

        $added = $serverRequest->withAddedHeader('x-test', [' second ', 'third']);

        $this->assertSame(["evil\r\n", 'second', 'third'], $added->getHeader('X-Test'));
        $this->assertSame(["evil\r\n", 'second', 'third'], $added->getHeaders()['X-Test']);
        $this->assertSame(["evil\r\n"], $serverRequest->getHeader('X-Test'));
    }
}
