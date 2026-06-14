<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetBadIps\Tests\ShippedList;

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetBadIps\BadIpList;
use Flowd\PhirewallPresetBadIps\Manifest;
use Flowd\PhirewallPresetBadIps\Presets;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

/**
 * Validates the committed resources/ snapshot so a broken import cannot ship unnoticed.
 */
final class ShippedListTest extends TestCase
{
    public function testManifestCountMatchesTheDataFile(): void
    {
        $manifest = Manifest::read();
        $addresses = BadIpList::load();

        $this->assertCount($manifest->ipCount, $addresses);
        $this->assertNotSame([], $addresses);
    }

    public function testEveryShippedAddressIsValidIpv4(): void
    {
        foreach (BadIpList::load() as $address) {
            $this->assertNotFalse(filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4), "Invalid address: {$address}");
        }
    }

    public function testShippedBlocklistBlocksAListedAddress(): void
    {
        $addresses = BadIpList::load();
        $config = (new Config(new InMemoryCache()))->with(Presets::blocklist());
        $firewall = new Firewall($config);

        $listed = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['REMOTE_ADDR' => $addresses[0]]);
        $this->assertTrue($firewall->decide($listed)->isBlocked());
    }
}
