--TEST--
Bots preset: an AI crawler User-Agent is blocked with 403 while a browser passes
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetBots\Presets;

$config = (new Config(new InMemoryCache()))->with(Presets::blockAiCrawlers());
$middleware = phpt_middleware($config);
$handler = phpt_handler();

$crawler = $middleware->process(
    phpt_request('GET', '/articles', [], ['User-Agent' => 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)']),
    $handler,
);
$browser = $middleware->process(
    phpt_request('GET', '/articles', [], ['User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36']),
    $handler,
);

echo 'crawler=' . $crawler->getStatusCode() . "\n";
echo 'browser=' . $browser->getStatusCode() . "\n";
?>
--EXPECT--
crawler=403
browser=200
