<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Flowd\Phirewall\Http\RequestView;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects the query string of the request URI, and those of the server
 * parameters (`QUERY_STRING`, `REQUEST_URI`) when they are written differently.
 */
final readonly class QueryStringCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest, ?RequestView $requestView = null): array
    {
        $collected = [];
        foreach (($requestView ?? RequestView::of($serverRequest))->queryStrings() as $queryString) {
            $collected[] = ['name' => null, 'value' => $queryString];
        }

        return $collected;
    }
}
