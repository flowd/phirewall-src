<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Flowd\Phirewall\Http\RequestView;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects all cookie names from the request, and the names the `Cookie` headers hold
 * as PHP does not show them ({@see RequestView::hiddenCookies()}).
 */
final readonly class RequestCookiesNamesCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest, ?RequestView $requestView = null): array
    {
        /** @var list<array{name: ?string, value: string}> $collected */
        $collected = [];

        $requestView ??= RequestView::of($serverRequest);
        foreach (array_keys($requestView->cookies()) as $key) {
            $collected[] = ['name' => (string) $key, 'value' => (string) $key];
        }

        foreach ($requestView->hiddenCookies() as $hidden) {
            if ($hidden['nameIsHidden']) {
                $collected[] = ['name' => $hidden['writtenName'], 'value' => $hidden['writtenName']];
            }
        }

        return $collected;
    }
}
