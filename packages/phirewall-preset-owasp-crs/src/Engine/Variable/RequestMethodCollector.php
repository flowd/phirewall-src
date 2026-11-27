<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Flowd\Phirewall\Http\RequestView;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects the HTTP request method (GET, POST, etc.), and `REQUEST_METHOD`
 * of the server parameters when it is another.
 */
final readonly class RequestMethodCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest, ?RequestView $requestView = null): array
    {
        $collected = [];
        foreach (($requestView ?? RequestView::of($serverRequest))->methods() as $method) {
            $collected[] = ['name' => null, 'value' => $method];
        }

        return $collected;
    }
}
