<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\Unit;

use Flowd\PhirewallPresetBadIps\Manifest;
use Flowd\PhirewallPresetBadIps\Tests\TemporaryFiles;
use PHPUnit\Framework\TestCase;

final class ManifestTest extends TestCase
{
    use TemporaryFiles;

    public function testReadsAValidManifest(): void
    {
        $this->temporaryFile('manifest.json', (string) json_encode([
                'feedName' => 'stamparm/ipsum',
                'feedUrl' => 'https://github.com/stamparm/ipsum',
                'feedLevel' => '3',
                'license' => 'The Unlicense (public domain)',
                'ipCount' => 19246,
                'importedAt' => '2026-06-13T10:00:00+00:00',
        ], JSON_THROW_ON_ERROR));

        $manifest = Manifest::read($this->temporaryPath());

        $this->assertSame('stamparm/ipsum', $manifest->feedName);
        $this->assertSame('3', $manifest->feedLevel);
        $this->assertSame(19246, $manifest->ipCount);
    }

    public function testMissingFileThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not found');

        Manifest::read($this->temporaryPath());
    }

    public function testInvalidJsonThrows(): void
    {
        $this->temporaryFile('manifest.json', '{not json');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not valid JSON');

        Manifest::read($this->temporaryPath());
    }

    public function testMissingRequiredFieldThrows(): void
    {
        $this->temporaryFile('manifest.json', '{"feedName":"x"}');

        $this->expectException(\RuntimeException::class);

        Manifest::read($this->temporaryPath());
    }
}
