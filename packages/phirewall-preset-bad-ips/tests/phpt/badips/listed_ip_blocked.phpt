--TEST--
Bad-IP preset: a request from a listed address is blocked with 403 while others pass
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Config;
use Flowd\Phirewall\Store\InMemoryCache;
use Flowd\PhirewallPresetBadIps\BadIpList;
use Flowd\PhirewallPresetBadIps\Presets;

$config = (new Config(new InMemoryCache()))->with(Presets::blocklist());
$middleware = phpt_middleware($config);
$handler = phpt_handler();

$listedIp = BadIpList::load()[0];

$blocked = $middleware->process(phpt_request('GET', '/', ['REMOTE_ADDR' => $listedIp]), $handler);
$allowed = $middleware->process(phpt_request('GET', '/', ['REMOTE_ADDR' => '8.8.8.8']), $handler);

echo 'listed=' . $blocked->getStatusCode() . "\n";
echo 'other=' . $allowed->getStatusCode() . "\n";
?>
--EXPECT--
listed=403
other=200
