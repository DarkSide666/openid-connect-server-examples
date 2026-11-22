<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient\Tests;

use DarkSide\OidcInteropClient\RsaJwkConverter;
use PHPUnit\Framework\TestCase;

final class RsaJwkConverterTest extends TestCase
{
    public function testConvertsPublicRsaJwkIntoVerifiablePem(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsArray($details['rsa'] ?? null);
        $encode = static fn (string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
        $pem = RsaJwkConverter::toPem([
            'kty' => 'RSA',
            'n' => $encode($details['rsa']['n']),
            'e' => $encode($details['rsa']['e']),
        ]);
        self::assertNotFalse(openssl_pkey_get_public($pem));
        self::assertSame($details['rsa']['n'], openssl_pkey_get_details(openssl_pkey_get_public($pem))['rsa']['n']);
    }
}
