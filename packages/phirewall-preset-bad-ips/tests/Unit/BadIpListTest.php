<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\Unit;

use Flowd\PhirewallPresetBadIps\BadIpList;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

final class BadIpListTest extends TestCase
{
    public function testLoadsAddressesSkippingHeaderCommentsAndBlanks(): void
    {
        $root = vfsStream::setup('resources', null, [
            'bad-ips.data' => "# header\n# more\n192.0.2.1\n\n203.0.113.7\n",
        ]);

        $this->assertSame(['192.0.2.1', '203.0.113.7'], BadIpList::load($root->url() . '/bad-ips.data'));
    }

    public function testCommentOnlyFileYieldsAnEmptyList(): void
    {
        $root = vfsStream::setup('resources', null, [
            'bad-ips.data' => "# header only\n# no addresses\n\n",
        ]);

        $this->assertSame([], BadIpList::load($root->url() . '/bad-ips.data'));
    }

    public function testMissingFileThrows(): void
    {
        $root = vfsStream::setup('resources');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not found');

        BadIpList::load($root->url() . '/missing.data');
    }

    public function testAMissingFileRaisesNoWarning(): void
    {
        $root = vfsStream::setup('resources');

        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });
        try {
            BadIpList::load($root->url() . '/missing.data');
            $this->fail('A missing data file must be reported.');
        } catch (\RuntimeException $runtimeException) {
            $this->assertStringContainsString('not found', $runtimeException->getMessage());
        } finally {
            restore_error_handler();
        }
    }

    public function testParsesContentLikeAFile(): void
    {
        $content = "# header\r\n 192.0.2.1 \r\n\r\n#203.0.113.1\n203.0.113.7\n198.51.100.0/24";

        $this->assertSame(['192.0.2.1', '203.0.113.7', '198.51.100.0/24'], BadIpList::parse($content));
        $this->assertSame([], BadIpList::parse(''));

        $root = vfsStream::setup('resources', null, ['bad-ips.data' => $content]);
        $this->assertSame(BadIpList::parse($content), BadIpList::load($root->url() . '/bad-ips.data'));
        $this->assertSame($content, BadIpList::read($root->url() . '/bad-ips.data'));
    }
}
