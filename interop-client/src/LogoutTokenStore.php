<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient;

use RuntimeException;

final readonly class LogoutTokenStore
{
    public function __construct(private string $path)
    {
        $directory = dirname($path);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Unable to create RP logout state directory.');
        }
    }

    public function claim(string $issuer, string $clientId, string $tokenId, int $expiresAt): bool
    {
        return $this->update(static function (array &$state) use ($issuer, $clientId, $tokenId, $expiresAt): bool {
            $now = time();
            $tokens = is_array($state['tokens'] ?? null) ? $state['tokens'] : [];
            foreach ($tokens as $key => $expiry) {
                if (!is_int($expiry) || $expiry < $now) {
                    unset($tokens[$key]);
                }
            }
            $key = hash('sha256', $issuer . "\0" . $clientId . "\0" . $tokenId);
            if (isset($tokens[$key])) {
                $state['tokens'] = $tokens;
                return false;
            }
            $tokens[$key] = $expiresAt;
            $state['tokens'] = $tokens;
            return true;
        }) === true;
    }

    public function revokeSession(?string $subject, ?string $sessionId): void
    {
        $this->update(static function (array &$state) use ($subject, $sessionId): void {
            $revoked = is_array($state['revoked'] ?? null) ? $state['revoked'] : [];
            $kind = $sessionId !== null ? 'sid' : 'sub';
            $value = $sessionId ?? $subject;
            if ($value !== null && $value !== '') {
                $revoked[$kind . ':' . hash('sha256', $value)] = true;
            }
            $state['revoked'] = $revoked;
        });
    }

    public function isSessionRevoked(?string $subject, ?string $sessionId): bool
    {
        $state = $this->read();
        $revoked = is_array($state['revoked'] ?? null) ? $state['revoked'] : [];
        if ($sessionId !== null && $sessionId !== '' && ($revoked['sid:' . hash('sha256', $sessionId)] ?? false) === true) {
            return true;
        }
        return $subject !== null && $subject !== '' && ($revoked['sub:' . hash('sha256', $subject)] ?? false) === true;
    }

    /** @return array<string, mixed> */
    private function read(): array
    {
        $handle = fopen($this->path, 'c+b');
        if ($handle === false) {
            throw new RuntimeException('Unable to open RP logout state.');
        }
        try {
            if (!flock($handle, LOCK_SH)) {
                throw new RuntimeException('Unable to lock RP logout state.');
            }
            rewind($handle);
            $contents = stream_get_contents($handle);
            $state = $contents === false || $contents === '' ? [] : json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($state)) {
                throw new RuntimeException('RP logout state is malformed.');
            }
            return $state;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /** @param callable(array<string, mixed>&): mixed $callback */
    private function update(callable $callback): mixed
    {
        $handle = fopen($this->path, 'c+b');
        if ($handle === false) {
            throw new RuntimeException('Unable to open RP logout state.');
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Unable to lock RP logout state.');
            }
            rewind($handle);
            $contents = stream_get_contents($handle);
            $state = $contents === false || $contents === '' ? [] : json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($state)) {
                throw new RuntimeException('RP logout state is malformed.');
            }
            $result = $callback($state);
            $encoded = json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            rewind($handle);
            if (!ftruncate($handle, 0) || fwrite($handle, $encoded) !== strlen($encoded)) {
                throw new RuntimeException('Unable to persist RP logout state.');
            }
            fflush($handle);
            return $result;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
