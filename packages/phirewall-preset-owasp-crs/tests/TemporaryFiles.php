<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests;

use PHPUnit\Framework\Attributes\After;
use Spatie\TemporaryDirectory\TemporaryDirectory;

/**
 * Real files for a test, in a directory of its own that is removed afterwards.
 */
trait TemporaryFiles
{
    private ?TemporaryDirectory $temporaryDirectory = null;

    #[After]
    protected function removeTemporaryFiles(): void
    {
        $this->temporaryDirectory?->delete();
        $this->temporaryDirectory = null;
    }

    /**
     * A path below the directory of this test. The directory exists; nothing
     * is created at the path itself.
     */
    private function temporaryPath(string $path = ''): string
    {
        $this->temporaryDirectory ??= TemporaryDirectory::make();
        $directory = $this->temporaryDirectory->path();

        return $path === '' ? $directory : $directory . '/' . $path;
    }

    /**
     * Write a file below the directory of this test, replacing what is there.
     *
     * @param int|null $modified Modification time to give the file, to control what a change of the file looks like.
     * @return string The path of the file.
     */
    private function temporaryFile(string $path, string $content, ?int $modified = null): string
    {
        $this->temporaryDirectory(dirname($path));
        $file = $this->temporaryPath($path);
        file_put_contents($file, $content);
        if ($modified !== null) {
            touch($file, $modified);
        }

        clearstatcache();

        return $file;
    }

    /**
     * @return string The path of the directory, which now exists.
     */
    private function temporaryDirectory(string $path): string
    {
        $directory = $this->temporaryPath($path);
        if (!is_dir($directory)) {
            mkdir($directory, 0o777, true);
        }

        return $directory;
    }

    /**
     * @return list<string> Paths of the files and directories in a directory, sorted.
     */
    private function entriesIn(string $directory): array
    {
        clearstatcache();
        $entries = glob($directory . '/*') ?: [];
        sort($entries);

        return $entries;
    }

    /**
     * Replace a file the way an update from cron or a deployment does: from
     * another process.
     *
     * PHP remembers time and size of the file it was asked about last and
     * forgets them whenever the process itself writes, also when it starts a
     * command. A change made by this process therefore never shows what a
     * long-running worker sees. The other process is told over a socket when
     * to write, which leaves what PHP remembers untouched.
     *
     * @param int|null $modified Modification time to give the file.
     */
    private function replaceFromAnotherProcess(string $file, string $content, ?int $modified = null): void
    {
        $script = 'fgets(STDIN); file_put_contents($argv[1], base64_decode($argv[2]));'
            . ' if ($argv[3] !== "") { touch($argv[1], (int) $argv[3]); } echo "done\n";';
        $process = proc_open(
            [PHP_BINARY, '-r', $script, $file, base64_encode($content), (string) $modified],
            [0 => ['socket'], 1 => ['socket']],
            $sockets,
        );
        // Nothing below may load a class: that makes PHP look at another file
        // and forget this one, which is what the caller wants to keep.
        if (!is_resource($process)) {
            throw new \RuntimeException('Cannot start another process.');
        }

        fwrite($sockets[0], "go\n");
        $answer = fgets($sockets[1]);
        fclose($sockets[0]);
        fclose($sockets[1]);
        proc_close($process);

        if ($answer !== "done\n") {
            throw new \RuntimeException('The other process did not replace the file: ' . $file);
        }
    }
}
