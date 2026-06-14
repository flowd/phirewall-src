<?php

/**
 * Example 01: Block requests from known bad IP addresses.
 *
 * Run: php examples/01-block-bad-ips.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetBadIps\BadIpList;
use Flowd\PhirewallPresetBadIps\Manifest;
use Flowd\PhirewallPresetBadIps\Presets;
use Nyholm\Psr7\ServerRequest;

echo "=== Block Bad IPs ===\n\n";

$manifest = Manifest::read();
printf("Snapshot: %s level %s, %d addresses (imported %s)\n\n", $manifest->feedName, $manifest->feedLevel, $manifest->ipCount, $manifest->importedAt);

$config = (new Config(new InMemoryCache()))->with(Presets::blocklist());
$firewall = new Firewall($config);

$listed = BadIpList::load()[0];
$cases = [$listed => true, '8.8.8.8' => false];
$failures = 0;

foreach ($cases as $ip => $expectedBlocked) {
    $request = new ServerRequest('GET', 'https://example.test/', [], null, '1.1', ['REMOTE_ADDR' => $ip]);
    $blocked = $firewall->decide($request)->isBlocked();
    $marker = $blocked === $expectedBlocked ? 'OK ' : 'FAIL';
    printf("[%s] %-16s %s\n", $marker, $ip, $blocked ? 'blocked' : 'passed');
    if ($blocked !== $expectedBlocked) {
        ++$failures;
    }
}

if ($failures > 0) {
    echo "\nUnexpected decisions: {$failures}\n";
    exit(1);
}

echo "\nAll decisions as expected.\n";
