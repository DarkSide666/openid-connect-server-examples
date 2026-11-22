<?php

declare(strict_types=1);

namespace DarkSide\OidcInteropClient;

use InvalidArgumentException;

final readonly class Config
{
    public function __construct(
        public string $providerIssuer,
        public string $clientId,
        public string $clientSecret,
        public string $redirectUri,
        public ?string $caBundle = null,
    ) {
        $allowInsecureHttpForCi = getenv('OIDC_INTEROP_ALLOW_INSECURE_HTTP_FOR_CI') === '1';
        self::assertOrigin($providerIssuer, 'OIDC_INTEROP_PROVIDER_ISSUER', $allowInsecureHttpForCi);
        self::assertUrl($redirectUri, 'OIDC_INTEROP_REDIRECT_URI', $allowInsecureHttpForCi);

        if ($clientId === '' || $clientSecret === '') {
            throw new InvalidArgumentException('OIDC_INTEROP_CLIENT_ID and OIDC_INTEROP_CLIENT_SECRET must not be empty.');
        }

        if ($caBundle !== null && !is_file($caBundle)) {
            throw new InvalidArgumentException('OIDC_INTEROP_CA_BUNDLE does not point to an existing file.');
        }
    }

    public static function fromEnvironment(): self
    {
        $issuer = trim((string) getenv('OIDC_INTEROP_PROVIDER_ISSUER'));
        $clientId = trim((string) getenv('OIDC_INTEROP_CLIENT_ID'));
        $clientSecret = trim((string) getenv('OIDC_INTEROP_CLIENT_SECRET'));
        $redirectUri = trim((string) getenv('OIDC_INTEROP_REDIRECT_URI'));
        $caBundle = trim((string) getenv('OIDC_INTEROP_CA_BUNDLE'));

        if ($issuer === '' || $clientId === '' || $clientSecret === '' || $redirectUri === '') {
            throw new InvalidArgumentException('Copy .env.example to .env and configure all required OIDC_INTEROP_* values.');
        }

        return new self($issuer, $clientId, $clientSecret, $redirectUri, $caBundle !== '' ? $caBundle : null);
    }

    private static function assertOrigin(string $url, string $name, bool $allowInsecureHttpForCi): void
    {
        self::assertUrl($url, $name, $allowInsecureHttpForCi);
        $parts = parse_url($url);
        if (!is_array($parts)
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || isset($parts['path']) && $parts['path'] !== '') {
            throw new InvalidArgumentException($name . ' must be an HTTPS origin without credentials, path, query or fragment.');
        }
    }

    private static function assertUrl(string $url, string $name, bool $allowInsecureHttpForCi): void
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            throw new InvalidArgumentException($name . ' must be an absolute HTTPS URL.');
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $allowedScheme = $scheme === 'https' || ($allowInsecureHttpForCi && $scheme === 'http');
        if (!$allowedScheme
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])) {
            throw new InvalidArgumentException($name . ' must be an absolute HTTPS URL.');
        }
    }
}
