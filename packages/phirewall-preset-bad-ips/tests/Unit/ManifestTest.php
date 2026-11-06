<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\Unit;

use Flowd\PhirewallPresetBadIps\Manifest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

final class ManifestTest extends TestCase
{
    public function testReadsAValidManifest(): void
    {
        $root = vfsStream::setup('resources', null, [
            'manifest.json' => json_encode([
                'feedName' => 'stamparm/ipsum',
                'feedUrl' => 'https://github.com/stamparm/ipsum',
                'feedLevel' => '3',
                'license' => 'The Unlicense (public domain)',
                'ipCount' => 19246,
                'importedAt' => '2026-06-13T10:00:00+00:00',
            ], JSON_THROW_ON_ERROR),
        ]);

        $manifest = Manifest::read($root->url());

        $this->assertSame('stamparm/ipsum', $manifest->feedName);
        $this->assertSame('3', $manifest->feedLevel);
        $this->assertSame(19246, $manifest->ipCount);
    }

    public function testMissingFileThrows(): void
    {
        $root = vfsStream::setup('resources');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not found');

        Manifest::read($root->url());
    }

    public function testInvalidJsonThrows(): void
    {
        $root = vfsStream::setup('resources', null, ['manifest.json' => '{not json']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not valid JSON');

        Manifest::read($root->url());
    }

    public function testMissingRequiredFieldThrows(): void
    {
        $root = vfsStream::setup('resources', null, ['manifest.json' => '{"feedName":"x"}']);

        $this->expectException(\RuntimeException::class);

        Manifest::read($root->url());
    }
}
