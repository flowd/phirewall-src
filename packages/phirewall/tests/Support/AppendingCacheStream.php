<?php

declare(strict_types=1);

namespace Flowd\Phirewall\Tests\Support;

use Psr\Http\Message\StreamInterface;

/**
 * A body as slim/psr7 builds it from `php://input`: seekable, with a copy of
 * everything that was read from it, to which each read appends. Read twice,
 * the copy holds the body twice, and that copy is what a cast to string gives
 * once the end was reached.
 */
final class AppendingCacheStream implements StreamInterface
{
    private string $cache = '';

    private int $position = 0;

    private bool $finished = false;

    public function __construct(private readonly string $content)
    {
    }

    public function __toString(): string
    {
        if ($this->finished) {
            return $this->cache;
        }

        $this->rewind();

        return $this->getContents();
    }

    public function close(): void
    {
    }

    public function detach()
    {
        return null;
    }

    public function getSize(): int
    {
        return strlen($this->content);
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->position >= strlen($this->content);
    }

    public function isSeekable(): bool
    {
        return true;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        $this->position = $offset;
    }

    public function rewind(): void
    {
        $this->position = 0;
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new \RuntimeException('Not writable.');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        $chunk = substr($this->content, $this->position, $length);
        $this->position += strlen($chunk);
        $this->cache .= $chunk;
        if ($this->eof()) {
            $this->finished = true;
        }

        return $chunk;
    }

    public function getContents(): string
    {
        if ($this->finished) {
            return $this->cache;
        }

        return $this->read(strlen($this->content));
    }

    public function getMetadata(?string $key = null)
    {
        return $key === null ? [] : null;
    }
}
