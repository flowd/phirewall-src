<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\Unit;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Http\Outcome;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetBadIps\Presets;
use Nyholm\Psr7\ServerRequest;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class PresetsTest extends TestCase
{
    private function dataFileWith(string $contents): string
    {
        $root = vfsStream::setup('resources', null, ['bad-ips.data' => $contents]);

        return $root->url() . '/bad-ips.data';
    }

    public function testBlocklistBlocksAListedIpAndPassesOthers(): void
    {
        $dataFile = $this->dataFileWith("192.0.2.1\n203.0.113.7\n");
        $config = (new Config(new InMemoryCache()))->with(Presets::blocklist($dataFile));
        $firewall = new Firewall($config);

        $this->assertTrue($firewall->decide($this->requestFrom('192.0.2.1'))->isBlocked());
        $this->assertTrue($firewall->decide($this->requestFrom('203.0.113.7'))->isBlocked());
        $this->assertTrue($firewall->decide($this->requestFrom('8.8.8.8'))->isPass());
    }

    public function testTrackCountsWithoutBlocking(): void
    {
        $dataFile = $this->dataFileWith("192.0.2.1\n");
        $config = (new Config(new InMemoryCache()))->with(Presets::track(3600, $dataFile));
        $firewall = new Firewall($config);

        $result = $firewall->decide($this->requestFrom('192.0.2.1'));
        $this->assertNotSame(Outcome::BLOCKED, $result->outcome);
    }

    public function testBlocklistRegistersTheNamedRule(): void
    {
        $dataFile = $this->dataFileWith("192.0.2.1\n");
        $blocklistNames = array_column(Presets::blocklist($dataFile)->toArray()['blocklists'], 'name');

        $this->assertContains(Presets::BLOCKLIST_RULE, $blocklistNames);
    }

    public function testSnapshotImportedAtReadsTheManifest(): void
    {
        $root = vfsStream::setup('resources', null, [
            'manifest.json' => json_encode([
                'feedName' => 'stamparm/ipsum',
                'feedUrl' => 'https://github.com/stamparm/ipsum',
                'feedLevel' => '3',
                'license' => 'The Unlicense (public domain)',
                'ipCount' => 1,
                'importedAt' => '2026-06-13T12:00:00+00:00',
            ], JSON_THROW_ON_ERROR),
        ]);

        $this->assertSame('2026-06-13T12:00:00+00:00', Presets::snapshotImportedAt($root->url()));
    }

    private function requestFrom(string $ip): ServerRequestInterface
    {
        return new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    }
}
