<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Variable;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Collects the request path without the query string, matching ModSecurity's
 * REQUEST_FILENAME.
 *
 * This previously returned only basename($path), which is actually the distinct
 * REQUEST_BASENAME variable: a basename can never contain a slash, so every
 * slash-bearing @pmFromFile token (directory prefixes like `.git/`, leading-slash
 * secret-file names like `/auth.json`) could never match, silently disabling the
 * bulk of the restricted-files/AI-artifact rules (930130/930140). Returning the
 * full path restores upstream semantics; the value is the PSR-7 path as it is,
 * percent-encoding included. Decoding it is up to the rule (`t:urlDecodeUni`).
 */
final readonly class RequestFilenameCollector implements VariableCollectorInterface
{
    /** @return list<array{name: ?string, value: string}> */
    public function collect(ServerRequestInterface $serverRequest): array
    {
        $path = $serverRequest->getUri()->getPath();

        return $path !== '' ? [['name' => null, 'value' => $path]] : [];
    }
}
