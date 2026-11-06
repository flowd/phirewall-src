<?php

/**
 * Example 02: Rate-limit AI and SEO crawlers instead of blocking them.
 *
 * Run: php examples/02-throttle-crawlers.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetBots\Presets;
use Nyholm\Psr7\ServerRequest;

echo "=== Throttle Crawlers ===\n\n";

// Stay indexable but cap each crawler IP at 3 requests / 60s.
$config = (new Config(new InMemoryCache()))->with(
    Presets::throttleAiCrawlers(limit: 3, period: 60),
    Presets::throttleSeoCrawlers(limit: 3, period: 60),
);
$firewall = new Firewall($config);

$request = new ServerRequest(
    'GET',
    'https://example.test/products',
    ['User-Agent' => 'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)'],
    null,
    '1.1',
    ['REMOTE_ADDR' => '203.0.113.55'],
);

$blockedAt = null;
for ($attempt = 1; $attempt <= 5; ++$attempt) {
    $result = $firewall->decide($request);
    $state = $result->isPass() ? 'passed' : 'throttled';
    printf("AhrefsBot request %d: %s\n", $attempt, $state);
    if ($blockedAt === null && !$result->isPass()) {
        $blockedAt = $attempt;
    }
}

if ($blockedAt !== 4) {
    echo "\nExpected throttling to start on request 4, got {$blockedAt}.\n";
    exit(1);
}

echo "\nCrawler throttled after the configured limit.\n";
