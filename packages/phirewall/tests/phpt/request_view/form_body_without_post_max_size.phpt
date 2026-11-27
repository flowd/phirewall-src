--TEST--
Phirewall: a form body is read in full when post_max_size is 0 (no limit)
--INI--
post_max_size=0
memory_limit=256M
--FILE--
<?php
declare(strict_types=1);

require __DIR__ . '/../_bootstrap.inc';

use Flowd\Phirewall\Http\RequestView;
use Nyholm\Psr7\ServerRequest;

$body = 'a=1&a=2&b=' . str_repeat('x', 9 * 1024 * 1024);
$request = (new ServerRequest('POST', '/form', ['Content-Type' => 'application/x-www-form-urlencoded'], $body))
    ->withParsedBody(['a' => '2', 'b' => str_repeat('x', 9 * 1024 * 1024)]);

$view = RequestView::of($request);
echo 'unbounded=' . var_export(RequestView::defaultMaxBodyBytes() === PHP_INT_MAX, true) . "\n";
echo 'hidden=' . count($view->hiddenBodyParameters($request)) . "\n";
echo 'complete=' . var_export($view->bodyParametersComplete($request), true) . "\n";
echo 'position=' . $request->getBody()->tell() . "\n";
?>
--EXPECT--
unbounded=true
hidden=1
complete=true
position=0
