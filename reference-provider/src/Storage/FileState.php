<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Storage;

use RuntimeException;

final readonly class FileState
{
    public function __construct(private string $path)
    {
        $directory = dirname($path);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException(sprintf('Unable to create storage directory: %s', $directory));
        }
    }

    /** @return array<string, mixed> */
    public function read(): array
    {
        $handle = fopen($this->path, 'c+b');
        if ($handle === false) {
            throw new RuntimeException('Unable to open reference-provider storage.');
        }
        try {
            if (!flock($handle, LOCK_SH)) {
                throw new RuntimeException('Unable to lock reference-provider storage for reading.');
            }
            rewind($handle);
            $contents = stream_get_contents($handle);
            $decoded = $contents === false || $contents === '' ? [] : json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($decoded)) {
                throw new RuntimeException('Reference-provider storage has an invalid format.');
            }
            /** @var array<string, mixed> $decoded */

            return $decoded;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * @template TResult
     * @param callable(array<string, mixed>&): TResult $callback
     * @return TResult
     */
    public function update(callable $callback): mixed
    {
        $handle = fopen($this->path, 'c+b');
        if ($handle === false) {
            throw new RuntimeException('Unable to open reference-provider storage.');
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Unable to lock reference-provider storage for writing.');
            }
            rewind($handle);
            $contents = stream_get_contents($handle);
            $state = $contents === false || $contents === '' ? [] : json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($state)) {
                throw new RuntimeException('Reference-provider storage has an invalid format.');
            }
            /** @var array<string, mixed> $state */
            $result = $callback($state);
            $encoded = json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            rewind($handle);
            if (!ftruncate($handle, 0) || fwrite($handle, $encoded) !== strlen($encoded)) {
                throw new RuntimeException('Unable to persist reference-provider storage.');
            }
            fflush($handle);

            return $result;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
