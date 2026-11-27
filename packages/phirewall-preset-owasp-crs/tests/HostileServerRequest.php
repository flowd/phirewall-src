<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

/**
 * Test double for requests a strict PSR-7 implementation refuses to build: a
 * method that is not an HTTP token, or a header value with a line break or
 * another control character (RFC 7230 field-value).
 *
 * The engine has to cope with such requests, because a lenient PSR-7
 * implementation (nyholm/psr7 before 1.8.3 let a trailing line break through)
 * or a framework bridge can still hand them over. This double decorates a
 * request built through the library and returns the hostile method or header
 * values on top of it, so a test does not depend on the leniency of one library
 * version. The mutators delegate to the decorated request and keep the hostile
 * values, unless they replace exactly the method or header in question.
 */
final readonly class HostileServerRequest implements ServerRequestInterface
{
    /** An HTTP method token (RFC 7230, section 3.2.6). */
    private const METHOD_TOKEN = "@^[!#$%&'*+.^_`|~0-9A-Za-z-]+$@D";

    /** An HTTP field value as strict PSR-7 implementations check it: no control character but tab. */
    private const HEADER_VALUE = "@^[ \t\x21-\x7E\x80-\xFF]*$@D";

    /**
     * @param array<string, array{string, list<string>}> $rawHeaders lowercase name => [name, values]
     */
    private function __construct(
        private ServerRequestInterface $inner,
        private ?string $rawMethod = null,
        private array $rawHeaders = [],
    ) {
    }

    public static function from(ServerRequestInterface $serverRequest): self
    {
        return new self($serverRequest);
    }

    /** Whether a strict PSR-7 implementation accepts $method as the request method. */
    public static function isMethodToken(string $method): bool
    {
        return preg_match(self::METHOD_TOKEN, $method) === 1;
    }

    /** Whether a strict PSR-7 implementation accepts $value as a header value. */
    public static function isHeaderValue(string $value): bool
    {
        return preg_match(self::HEADER_VALUE, $value) === 1;
    }

    public function withRawMethod(string $method): self
    {
        return new self($this->inner, $method, $this->rawHeaders);
    }

    public function withRawHeader(string $name, string $value): self
    {
        $rawHeaders = $this->rawHeaders;
        $rawHeaders[strtolower($name)] = [$name, [$value]];

        return new self($this->inner, $this->rawMethod, $rawHeaders);
    }

    public function getMethod(): string
    {
        return $this->rawMethod ?? $this->inner->getMethod();
    }

    public function withMethod(string $method): static
    {
        return new self($this->inner->withMethod($method), null, $this->rawHeaders);
    }

    /** @return array<string, array<int, string>> */
    public function getHeaders(): array
    {
        $headers = [];
        foreach ($this->inner->getHeaders() as $name => $values) {
            if (!isset($this->rawHeaders[strtolower((string) $name)])) {
                $headers[(string) $name] = $values;
            }
        }

        foreach ($this->rawHeaders as [$name, $values]) {
            $headers[$name] = $values;
        }

        return $headers;
    }

    public function hasHeader(string $name): bool
    {
        return isset($this->rawHeaders[strtolower($name)]) || $this->inner->hasHeader($name);
    }

    /** @return array<int, string> */
    public function getHeader(string $name): array
    {
        return $this->rawHeaders[strtolower($name)][1] ?? $this->inner->getHeader($name);
    }

    public function getHeaderLine(string $name): string
    {
        return implode(', ', $this->getHeader($name));
    }

    public function withHeader(string $name, $value): static
    {
        return new self($this->inner->withHeader($name, $value), $this->rawMethod, $this->withoutRawHeader($name));
    }

    public function withAddedHeader(string $name, $value): static
    {
        $inner = $this->inner->withAddedHeader($name, $value);
        $rawHeaders = $this->rawHeaders;
        $key = strtolower($name);
        if (isset($rawHeaders[$key])) {
            // Append the values as the decorated request normalised them.
            $added = array_values(array_slice($inner->getHeader($name), count($this->inner->getHeader($name))));
            $rawHeaders[$key][1] = [...$rawHeaders[$key][1], ...$added];
        }

        return new self($inner, $this->rawMethod, $rawHeaders);
    }

    public function withoutHeader(string $name): static
    {
        return new self($this->inner->withoutHeader($name), $this->rawMethod, $this->withoutRawHeader($name));
    }

    public function getProtocolVersion(): string
    {
        return $this->inner->getProtocolVersion();
    }

    public function withProtocolVersion(string $version): static
    {
        return $this->decorate($this->inner->withProtocolVersion($version));
    }

    public function getBody(): StreamInterface
    {
        return $this->inner->getBody();
    }

    public function withBody(StreamInterface $stream): static
    {
        return $this->decorate($this->inner->withBody($stream));
    }

    public function getRequestTarget(): string
    {
        return $this->inner->getRequestTarget();
    }

    public function withRequestTarget(string $requestTarget): static
    {
        return $this->decorate($this->inner->withRequestTarget($requestTarget));
    }

    public function getUri(): UriInterface
    {
        return $this->inner->getUri();
    }

    public function withUri(UriInterface $uri, bool $preserveHost = false): static
    {
        return $this->decorate($this->inner->withUri($uri, $preserveHost));
    }

    /** @return array<array-key, mixed> */
    public function getServerParams(): array
    {
        return $this->inner->getServerParams();
    }

    /** @return array<array-key, mixed> */
    public function getCookieParams(): array
    {
        return $this->inner->getCookieParams();
    }

    /** @param array<array-key, mixed> $cookies */
    public function withCookieParams(array $cookies): static
    {
        return $this->decorate($this->inner->withCookieParams($cookies));
    }

    /** @return array<array-key, mixed> */
    public function getQueryParams(): array
    {
        return $this->inner->getQueryParams();
    }

    /** @param array<array-key, mixed> $query */
    public function withQueryParams(array $query): static
    {
        return $this->decorate($this->inner->withQueryParams($query));
    }

    /** @return array<array-key, mixed> */
    public function getUploadedFiles(): array
    {
        return $this->inner->getUploadedFiles();
    }

    /** @param array<array-key, mixed> $uploadedFiles */
    public function withUploadedFiles(array $uploadedFiles): static
    {
        return $this->decorate($this->inner->withUploadedFiles($uploadedFiles));
    }

    /** @return array<array-key, mixed>|object|null */
    public function getParsedBody()
    {
        return $this->inner->getParsedBody();
    }

    /** @param array<array-key, mixed>|object|null $data */
    public function withParsedBody($data): static
    {
        return $this->decorate($this->inner->withParsedBody($data));
    }

    /** @return array<array-key, mixed> */
    public function getAttributes(): array
    {
        return $this->inner->getAttributes();
    }

    public function getAttribute(string $name, $default = null): mixed
    {
        return $this->inner->getAttribute($name, $default);
    }

    public function withAttribute(string $name, $value): static
    {
        return $this->decorate($this->inner->withAttribute($name, $value));
    }

    public function withoutAttribute(string $name): static
    {
        return $this->decorate($this->inner->withoutAttribute($name));
    }

    private function decorate(ServerRequestInterface $serverRequest): self
    {
        return new self($serverRequest, $this->rawMethod, $this->rawHeaders);
    }

    /** @return array<string, array{string, list<string>}> */
    private function withoutRawHeader(string $name): array
    {
        $rawHeaders = $this->rawHeaders;
        unset($rawHeaders[strtolower($name)]);

        return $rawHeaders;
    }
}
