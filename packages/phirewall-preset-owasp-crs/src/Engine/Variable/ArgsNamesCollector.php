<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Flowd\Phirewall\Http\RequestView;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects argument names (keys) from both query parameters and parsed body, and the names
 * the query strings and the body of a form request hold as PHP does not show them
 * ({@see RequestView::hiddenQueryParameters()}, {@see RequestView::hiddenBodyParameters()}).
 */
final readonly class ArgsNamesCollector implements VariableCollectorInterface
{
    /**
     * @param bool $inspectBodiesWithoutContentType Whether a body for which no reading names a content type
     *                                              is read as a form; see
     *                                              {@see \Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSet::inspectBodiesWithoutContentType()}.
     */
    public function __construct(
        private bool $inspectBodiesWithoutContentType = true,
    ) {
    }

    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest, ?RequestView $requestView = null): array
    {
        /** @var list<array{name: ?string, value: string}> $collected */
        $collected = [];

        $requestView ??= RequestView::of($serverRequest);
        foreach (array_keys($requestView->queryParameters()) as $key) {
            $collected[] = ['name' => (string) $key, 'value' => (string) $key];
        }

        $parsed = $serverRequest->getParsedBody();
        if (is_array($parsed)) {
            foreach (array_keys($parsed) as $key) {
                $collected[] = ['name' => (string) $key, 'value' => (string) $key];
            }
        }

        foreach ([...$requestView->hiddenQueryParameters(), ...$requestView->hiddenBodyParameters($serverRequest, $this->inspectBodiesWithoutContentType)] as $hidden) {
            if ($hidden['nameIsHidden']) {
                $collected[] = ['name' => $hidden['writtenName'], 'value' => $hidden['writtenName']];
            }
        }

        return $collected;
    }
}
