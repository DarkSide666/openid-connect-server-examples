<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient;

use RuntimeException;

final class RsaJwkConverter
{
    /** @param array<string, mixed> $jwk */
    public static function toPem(array $jwk): string
    {
        if (($jwk['kty'] ?? null) !== 'RSA' || !is_string($jwk['n'] ?? null) || !is_string($jwk['e'] ?? null)) {
            throw new RuntimeException('Provider JWKS contains an invalid RSA key.');
        }
        $decode = static function (string $part): string {
            $decoded = base64_decode(strtr($part, '-_', '+/') . str_repeat('=', (4 - strlen($part) % 4) % 4), true);
            if (!is_string($decoded) || $decoded === '') {
                throw new RuntimeException('Provider JWKS contains an invalid RSA parameter.');
            }
            return $decoded;
        };
        $integer = static function (string $value): string {
            $value = ltrim($value, "\0");
            if ($value === '' || (ord($value[0]) & 0x80) !== 0) {
                $value = "\0" . $value;
            }
            return "\x02" . self::asnLength(strlen($value)) . $value;
        };
        $rsa = "\x30" . self::asnLength(strlen($integer($decode($jwk['n'])) . $integer($decode($jwk['e']))))
            . $integer($decode($jwk['n'])) . $integer($decode($jwk['e']));
        $algorithm = hex2bin('300d06092a864886f70d0101010500');
        $bitString = "\x03" . self::asnLength(strlen($rsa) + 1) . "\0" . $rsa;
        $der = "\x30" . self::asnLength(strlen($algorithm . $bitString)) . $algorithm . $bitString;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function asnLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }
        $encoded = ltrim(pack('N', $length), "\0");
        return chr(0x80 | strlen($encoded)) . $encoded;
    }
}
