<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient\Tests;

use DarkSide\OidcInteropClient\LogoutTokenStore;
use DarkSide\OidcInteropClient\LogoutTokenValidator;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class LogoutTokenValidatorTest extends TestCase
{
    private string $path;
    private string $publicKey;
    private string $privateKey;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/darkside-logout-jti-' . bin2hex(random_bytes(8)) . '.json';
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($key);
        self::assertTrue(openssl_pkey_export($key, $privateKey));
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsString($details['key'] ?? null);
        $this->privateKey = $privateKey;
        $this->publicKey = $details['key'];
    }

    protected function tearDown(): void
    {
        if (is_file($this->path)) {
            unlink($this->path);
        }
    }

    public function testValidatesAndConsumesLogoutTokenExactlyOnce(): void
    {
        $token = $this->token();
        $validator = new LogoutTokenValidator('https://op.example', 'rp-client', ['key-1' => $this->publicKey], new LogoutTokenStore($this->path));

        self::assertSame(['sub' => 'subject-1', 'sid' => 'session-1'], $validator->validate($token));
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('replay');
        $validator->validate($token);
    }

    public function testRejectsMissingLogoutEventAndNonce(): void
    {
        $validator = new LogoutTokenValidator('https://op.example', 'rp-client', ['key-1' => $this->publicKey], new LogoutTokenStore($this->path));

        $this->expectException(RuntimeException::class);
        $validator->validate($this->token(['events' => null, 'nonce' => 'forbidden']));
    }

    public function testAcceptsFractionalNumericDateClaims(): void
    {
        $validator = new LogoutTokenValidator('https://op.example', 'rp-client', ['key-1' => $this->publicKey], new LogoutTokenStore($this->path));
        $now = time();

        self::assertSame(
            ['sub' => 'subject-1', 'sid' => 'session-1'],
            $validator->validate($this->token(['iat' => $now + 0.25, 'exp' => $now + 120.75]))
        );
    }

    public function testAcceptsUserWideLogoutWithoutSessionIdentifier(): void
    {
        $validator = new LogoutTokenValidator('https://op.example', 'rp-client', ['key-1' => $this->publicKey], new LogoutTokenStore($this->path));

        self::assertSame(['sub' => 'subject-1'], $validator->validate($this->token(['sid' => null])));
    }

    public function testAcceptsSingleSessionLogoutWithoutSubject(): void
    {
        $validator = new LogoutTokenValidator('https://op.example', 'rp-client', ['key-1' => $this->publicKey], new LogoutTokenStore($this->path));

        self::assertSame(['sid' => 'session-1'], $validator->validate($this->token(['sub' => null])));
    }

    public function testRejectsIncorrectAudience(): void
    {
        $validator = new LogoutTokenValidator('https://op.example', 'rp-client', ['key-1' => $this->publicKey], new LogoutTokenStore($this->path));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('claims are invalid');
        $validator->validate($this->token(['aud' => 'another-client']));
    }

    public function testRejectsInvalidSignature(): void
    {
        $validator = new LogoutTokenValidator('https://op.example', 'rp-client', ['key-1' => $this->publicKey], new LogoutTokenStore($this->path));
        $token = $this->token();
        $parts = explode('.', $token);
        $parts[1] = rtrim(strtr(base64_encode(json_encode(['iss' => 'https://op.example'], JSON_THROW_ON_ERROR)), '+/', '-_'), '=');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('signature');
        $validator->validate(implode('.', $parts));
    }

    /** @param array<string, mixed> $overrides */
    private function token(array $overrides = []): string
    {
        $now = time();
        $header = ['alg' => 'RS256', 'typ' => 'logout+jwt', 'kid' => 'key-1'];
        $claims = array_replace([
            'iss' => 'https://op.example',
            'aud' => 'rp-client',
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => bin2hex(random_bytes(16)),
            'sub' => 'subject-1',
            'sid' => 'session-1',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass()],
        ], $overrides);
        $base64Url = static fn (string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
        $payload = $base64Url(json_encode($header, JSON_THROW_ON_ERROR)) . '.' . $base64Url(json_encode($claims, JSON_THROW_ON_ERROR));
        self::assertTrue(openssl_sign($payload, $signature, $this->privateKey, OPENSSL_ALGO_SHA256));
        return $payload . '.' . $base64Url($signature);
    }
}
