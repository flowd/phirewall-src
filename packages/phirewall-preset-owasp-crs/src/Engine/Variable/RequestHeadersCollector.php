<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Flowd\Phirewall\Http\RequestView;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all header values from the request, and the values of the `HTTP_*`
 * server parameters the request does not hold.
 */
final readonly class RequestHeadersCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest, ?RequestView $requestView = null): array
    {
        /** @var list<array{name: ?string, value: string}> $collected */
        $collected = [];

        foreach (($requestView ?? RequestView::of($serverRequest))->headers() as $name => $values) {
            foreach ($values as $value) {
                $collected[] = ['name' => (string) $name, 'value' => $value];
            }
        }

        return $collected;
    }
}
