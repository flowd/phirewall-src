<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Flowd\Phirewall\Http\RequestView;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects target values from a request for a specific OWASP CRS variable type.
 *
 * A collector reads the request through its {@see RequestView}: the values of
 * the PSR-7 request first, then those of the server parameters the request
 * does not hold.
 */
interface VariableCollectorInterface
{
    /**
     * Collect entries for this variable from the given request, in collection order.
     * Each entry carries the member name it belongs to (parameter, cookie or header
     * name) so selectors like `ARGS:utm_source` can include or exclude it; entries
     * of unnamed variables (e.g. QUERY_STRING) carry a null name. An entry whose
     * value IS a member name injected for inspection (the ARGS hardening entries)
     * is flagged with `isNameEntry`.
     *
     * @param RequestView|null $requestView The view to collect from; the view of $serverRequest when null.
     *
     * @return list<array{name: ?string, value: string, isNameEntry?: bool}>
     */
    public function collect(ServerRequestInterface $serverRequest, ?RequestView $requestView = null): array;
}
