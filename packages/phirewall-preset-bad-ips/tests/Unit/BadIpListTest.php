<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\Unit;

use Flowd\PhirewallPresetBadIps\BadIpList;
use Flowd\PhirewallPresetBadIps\Tests\TemporaryFiles;
use PHPUnit\Framework\TestCase;

final class BadIpListTest extends TestCase
{
    use TemporaryFiles;

    public function testLoadsAddressesSkippingHeaderCommentsAndBlanks(): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "# header\n# more\n192.0.2.1\n\n203.0.113.7\n");

        $this->assertSame(['192.0.2.1', '203.0.113.7'], BadIpList::load($dataFile));
    }

    public function testCommentOnlyFileYieldsAnEmptyList(): void
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "# header only\n# no addresses\n\n");

        $this->assertSame([], BadIpList::load($dataFile));
    }

    public function testAnUnreadableFileIsReportedAsTheSameException(): void
    {
        $dataFile = $this->unreadableFile();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('cannot be read');

        @BadIpList::load($dataFile);
    }

    public function testAnUnreadableFileIsTheSameExceptionUnderAStrictErrorHandler(): void
    {
        $dataFile = $this->unreadableFile();

        // Also called for warnings silenced with `@`, as every error handler is.
        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });
        try {
            BadIpList::load($dataFile);
            $this->fail('An unreadable data file must be reported.');
        } catch (\RuntimeException $runtimeException) {
            $this->assertStringContainsString('cannot be read', $runtimeException->getMessage());
            // What the handler threw says why, so it must not get lost.
            $this->assertInstanceOf(\ErrorException::class, $runtimeException->getPrevious());
        } finally {
            restore_error_handler();
        }
    }

    public function testMissingFileThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not found');

        BadIpList::load($this->temporaryPath('missing.data'));
    }

    public function testAMissingFileRaisesNoWarning(): void
    {
        $missing = $this->temporaryPath('missing.data');

        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });
        try {
            BadIpList::load($missing);
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

        $dataFile = $this->temporaryFile('bad-ips.data', $content);
        $this->assertSame(BadIpList::parse($content), BadIpList::load($dataFile));
        $this->assertSame($content, BadIpList::read($dataFile));
    }

    /**
     * A data file that is there but may not be read.
     */
    private function unreadableFile(): string
    {
        $dataFile = $this->temporaryFile('bad-ips.data', "192.0.2.1\n");
        chmod($dataFile, 0);
        if (is_readable($dataFile)) {
            $this->markTestSkipped('This user reads every file, whatever its permissions (root).');
        }

        return $dataFile;
    }
}
