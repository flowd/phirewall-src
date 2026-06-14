<?php

/**
 * Example 01: Block AI crawlers by User-Agent.
 *
 * Run: php examples/01-block-ai-crawlers.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Http\Firewall;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetBots\Presets;
use Nyholm\Psr7\ServerRequest;

echo "=== Block AI Crawlers ===\n\n";

$config = (new Config(new InMemoryCache()))->with(Presets::blockAiCrawlers());
$firewall = new Firewall($config);

$requests = [
    'GPTBot' => 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)',
    'ClaudeBot' => 'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)',
    'Chrome browser' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36',
    'Googlebot' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
];

$expectedBlocked = ['GPTBot' => true, 'ClaudeBot' => true, 'Chrome browser' => false, 'Googlebot' => false];
$failures = 0;

foreach ($requests as $label => $userAgent) {
    $request = new ServerRequest('GET', 'https://example.test/articles', ['User-Agent' => $userAgent]);
    $blocked = $firewall->decide($request)->isBlocked();
    $marker = $blocked === $expectedBlocked[$label] ? 'OK ' : 'FAIL';
    printf("[%s] %-15s %s\n", $marker, $label, $blocked ? 'blocked' : 'passed');
    if ($blocked !== $expectedBlocked[$label]) {
        ++$failures;
    }
}

if ($failures > 0) {
    echo "\nUnexpected decisions: {$failures}\n";
    exit(1);
}

echo "\nAll decisions as expected.\n";
