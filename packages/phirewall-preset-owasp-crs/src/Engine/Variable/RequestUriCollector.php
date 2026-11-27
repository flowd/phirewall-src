<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Flowd\Phirewall\Http\RequestView;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects the full request URI (path + optional query string), and
 * `REQUEST_URI` of the server parameters when it is written differently.
 */
final readonly class RequestUriCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest, ?RequestView $requestView = null): array
    {
        $collected = [];
        foreach (($requestView ?? RequestView::of($serverRequest))->targets() as $target) {
            $collected[] = ['name' => null, 'value' => $target];
        }

        return $collected;
    }
}
