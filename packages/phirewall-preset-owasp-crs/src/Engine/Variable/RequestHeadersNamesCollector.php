<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Flowd\Phirewall\Http\RequestView;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all header names from the request, and those of the `HTTP_*`
 * server parameters the request does not hold.
 */
final readonly class RequestHeadersNamesCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest, ?RequestView $requestView = null): array
    {
        /** @var list<array{name: ?string, value: string}> $collected */
        $collected = [];

        foreach (array_keys(($requestView ?? RequestView::of($serverRequest))->headers()) as $name) {
            $collected[] = ['name' => (string) $name, 'value' => (string) $name];
        }

        return $collected;
    }
}
