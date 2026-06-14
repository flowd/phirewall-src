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
}
