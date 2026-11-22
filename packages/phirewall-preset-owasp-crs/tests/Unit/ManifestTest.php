<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Unit;

use Flowd\PhirewallPresetOwaspCrs\Manifest;
use Flowd\PhirewallPresetOwaspCrs\Tests\TemporaryFiles;
use PHPUnit\Framework\TestCase;

final class ManifestTest extends TestCase
{
    use TemporaryFiles;

    public function testReadsManifestFromRulesDirectory(): void
    {
        $this->temporaryFile('manifest.json', (string) json_encode([
            'crsVersion' => 'v4.16.0',
            'importedAt' => '2026-06-12T00:00:00+00:00',
            'ruleCountsByParanoiaLevel' => [1 => 100, 2 => 40, 3 => 20, 4 => 10],
            'droppedRuleCounts' => ['chained' => 50],
            'sourceFiles' => ['REQUEST-942-APPLICATION-ATTACK-SQLI.conf'],
            'dataFiles' => ['restricted-files.data'],
        ], JSON_THROW_ON_ERROR));

        $manifest = Manifest::read($this->temporaryPath());

        $this->assertSame('v4.16.0', $manifest->crsVersion);
        $this->assertSame('2026-06-12T00:00:00+00:00', $manifest->importedAt);
        $this->assertSame([1 => 100, 2 => 40, 3 => 20, 4 => 10], $manifest->ruleCountsByParanoiaLevel);
        $this->assertSame(['chained' => 50], $manifest->droppedRuleCounts);
        $this->assertSame(['REQUEST-942-APPLICATION-ATTACK-SQLI.conf'], $manifest->sourceFiles);
        $this->assertSame(['restricted-files.data'], $manifest->dataFiles);
    }

    public function testFailsWhenManifestIsMissing(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('manifest.json');

        Manifest::read($this->temporaryPath());
    }

    public function testFailsOnInvalidJson(): void
    {
        $this->temporaryFile('manifest.json', '{not json');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not valid JSON');

        Manifest::read($this->temporaryPath());
    }

    public function testFailsWhenRequiredFieldsAreMissing(): void
    {
        $this->temporaryFile('manifest.json', '{"importedAt":"2026-06-12T00:00:00+00:00"}');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('crsVersion');

        Manifest::read($this->temporaryPath());
    }
}
