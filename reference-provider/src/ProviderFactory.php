<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider;

use DateInterval;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\ResourceServer;
use DarkSide\OpenIdConnectServer\Discovery\DiscoveryDocumentGenerator;
use DarkSide\OpenIdConnectServer\Discovery\ProviderMetadata;
use DarkSide\OpenIdConnectServer\Endpoint\UserInfoEndpoint;
use DarkSide\OpenIdConnectServer\Jwks\JwksGenerator;
use DarkSide\OpenIdConnectServer\Key\SigningKey;
use DarkSide\OpenIdConnectServer\Key\SigningKeySet;
use DarkSide\OpenIdConnectServer\Key\VerificationKey;
use DarkSide\OpenIdConnectServer\League\OidcAuthCodeGrant;
use DarkSide\OpenIdConnectServer\League\OidcAuthCodeRepository;
use DarkSide\OpenIdConnectServer\League\OidcBearerTokenResponse;
use DarkSide\OpenIdConnectServer\League\OidcRefreshTokenGrant;
use DarkSide\OpenIdConnectServer\Transaction\OidcSessionIdProviderInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use DarkSide\OpenIdConnectServer\Token\IdTokenIssuer;
use DarkSide\OpenIdConnectServer\Transaction\OidcRequestContext;
use DarkSide\OpenIdConnectServer\Transaction\RequestScopedOidcContextProvider;
use DarkSide\OidcReferenceProvider\Repository\AccessTokenRepository;
use DarkSide\OidcReferenceProvider\Repository\AuthCodeRepository;
use DarkSide\OidcReferenceProvider\Repository\ClientRepository;
use DarkSide\OidcReferenceProvider\Repository\RefreshTokenRepository;
use DarkSide\OidcReferenceProvider\Repository\ScopeRepository;
use DarkSide\OidcReferenceProvider\Storage\AuthenticationTimeStore;
use DarkSide\OidcReferenceProvider\Storage\FileAuthorizationCodeMetadataStore;
use DarkSide\OidcReferenceProvider\Storage\RevocationStore;

final readonly class ProviderFactory
{
    public function __construct(private string $rootDirectory)
    {
    }

    /** @return array{authorization: AuthorizationServer, userinfo: UserInfoEndpoint, discovery: DiscoveryDocumentGenerator, jwks: JwksGenerator, clientId: string, username: string, password: string, authenticationTimeStore: AuthenticationTimeStore, revocationStore: RevocationStore} */
    public function create(): array
    {
        $baseUrl = rtrim((string) getenv('OIDC_REFERENCE_BASE_URL'), '/');
        if ($baseUrl === '' || !str_starts_with($baseUrl, 'https://')) {
            throw new \RuntimeException('OIDC_REFERENCE_BASE_URL must be an externally reachable HTTPS URL.');
        }
        $baseUrlParts = parse_url($baseUrl);
        if (!is_array($baseUrlParts) || isset($baseUrlParts['query']) || isset($baseUrlParts['fragment']) || isset($baseUrlParts['user']) || isset($baseUrlParts['pass']) || in_array($baseUrlParts['path'] ?? '', ['', '/'], true) === false) {
            throw new \RuntimeException('OIDC_REFERENCE_BASE_URL must be an HTTPS origin without credentials, path, query or fragment.');
        }
        $dataDirectory = (string) (getenv('OIDC_REFERENCE_DATA_DIR') ?: $this->rootDirectory . '/var');
        if (!str_starts_with($dataDirectory, DIRECTORY_SEPARATOR) && !preg_match('/^[A-Za-z]:[\\\\\/]/', $dataDirectory)) {
            $dataDirectory = $this->rootDirectory . '/' . $dataDirectory;
        }
        $keysDirectory = $dataDirectory . '/keys';
        $oauthPrivatePath = $keysDirectory . '/oauth-private.pem';
        $oauthPublicPath = $keysDirectory . '/oauth-public.pem';
        $oidcPrivatePath = $keysDirectory . '/oidc-private.pem';
        $oidcPublicPath = $keysDirectory . '/oidc-public.pem';
        $encryptionKeyPath = $keysDirectory . '/oauth-encryption.key';
        foreach ([$oauthPrivatePath, $oauthPublicPath, $oidcPrivatePath, $oidcPublicPath, $encryptionKeyPath] as $path) {
            if (!is_file($path)) {
                throw new \RuntimeException('Reference-provider keys are missing. Run: php bin/setup.php');
            }
        }

        $oauthPrivate = file_get_contents($oauthPrivatePath);
        $oauthPublic = file_get_contents($oauthPublicPath);
        $oidcPrivate = file_get_contents($oidcPrivatePath);
        $oidcPublic = file_get_contents($oidcPublicPath);
        $encryptionKey = file_get_contents($encryptionKeyPath);
        if (!is_string($oauthPrivate) || !is_string($oauthPublic) || !is_string($oidcPrivate) || !is_string($oidcPublic) || !is_string($encryptionKey)) {
            throw new \RuntimeException('Unable to read reference-provider key material.');
        }

        $clientId = (string) (getenv('OIDC_REFERENCE_CLIENT_ID') ?: 'oidc-test-client');
        $clientSecret = (string) getenv('OIDC_REFERENCE_CLIENT_SECRET');
        $redirectUri = (string) (getenv('OIDC_REFERENCE_REDIRECT_URI') ?: 'https://client.example.test/callback');
        if ($clientSecret === '') {
            throw new \RuntimeException('Set OIDC_REFERENCE_CLIENT_SECRET before starting the reference provider.');
        }

        $contextProvider = new RequestScopedOidcContextProvider(new OidcRequestContext());
        $clientRepository = new ClientRepository($clientId, $clientSecret, $redirectUri);
        $scopeRepository = new ScopeRepository();
        $revocationStore = new RevocationStore($dataDirectory . '/revoked-access-tokens.json');
        $refreshTokenRepository = new RefreshTokenRepository(new \DarkSide\OidcReferenceProvider\Storage\RefreshTokenState($dataDirectory . '/refresh-tokens.json'));
        $accessTokenRepository = new AccessTokenRepository($revocationStore);
        $authCodeRepository = new OidcAuthCodeRepository(
            new AuthCodeRepository(new RevocationStore($dataDirectory . '/revoked-authorization-codes.json')),
            new FileAuthorizationCodeMetadataStore($dataDirectory . '/authorization-code-metadata.json'),
            $contextProvider,
        );
        $authenticationTimeStore = new AuthenticationTimeStore($dataDirectory . '/authentication-time.json');
        $identityResolver = new IdentityResolver($authenticationTimeStore);
        $activeKeyId = (string) (getenv('OIDC_REFERENCE_OIDC_KEY_ID') ?: 'reference-rs256-2026');
        $activePrivatePath = (string) (getenv('OIDC_REFERENCE_OIDC_PRIVATE_KEY_PATH') ?: $oidcPrivatePath);
        $activePublicPath = (string) (getenv('OIDC_REFERENCE_OIDC_PUBLIC_KEY_PATH') ?: $oidcPublicPath);
        foreach (['activePrivatePath', 'activePublicPath'] as $pathVariable) {
            if (!str_starts_with($$pathVariable, DIRECTORY_SEPARATOR) && !preg_match('/^[A-Za-z]:[\\\\\/]/', $$pathVariable)) {
                $$pathVariable = $this->rootDirectory . '/' . $$pathVariable;
            }
        }
        $activePrivate = file_get_contents($activePrivatePath);
        $activePublic = file_get_contents($activePublicPath);
        if (!is_string($activePrivate) || !is_string($activePublic)) {
            throw new \RuntimeException('Unable to read the configured active OIDC signing key.');
        }
        $signingKey = new SigningKey($activeKeyId, $activePrivate, $activePublic);
        $retiredKeys = [];
        $retiredConfiguration = trim((string) getenv('OIDC_REFERENCE_RETIRED_OIDC_KEYS'));
        if ($retiredConfiguration !== '') {
            foreach (explode(';', $retiredConfiguration) as $entry) {
                [$retiredId, $retiredPath] = array_pad(explode('=', $entry, 2), 2, '');
                $retiredId = trim($retiredId);
                $retiredPath = trim($retiredPath);
                if ($retiredId === '' || $retiredPath === '') {
                    throw new \RuntimeException('OIDC_REFERENCE_RETIRED_OIDC_KEYS entries must use kid=public-key-path syntax.');
                }
                if (!str_starts_with($retiredPath, DIRECTORY_SEPARATOR) && !preg_match('/^[A-Za-z]:[\\\\\/]/', $retiredPath)) {
                    $retiredPath = $this->rootDirectory . '/' . $retiredPath;
                }
                $retiredPem = file_get_contents($retiredPath);
                if (!is_string($retiredPem)) {
                    throw new \RuntimeException('Unable to read a configured retired OIDC public key: ' . $retiredPath);
                }
                $retiredKeys[] = new VerificationKey($retiredId, $retiredPem);
            }
        }
        $signingKeySet = new SigningKeySet($signingKey, $retiredKeys);
        $idTokenLifetime = max(1, min(3600, (int) (getenv('OIDC_REFERENCE_ID_TOKEN_TTL_SECONDS') ?: 300)));
        $idTokenIssuer = new IdTokenIssuer($baseUrl, $signingKey, $idTokenLifetime);
        $tokenResponse = new OidcBearerTokenResponse($idTokenIssuer, $identityResolver, $contextProvider);

        $authorization = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $oauthPrivatePath,
            trim($encryptionKey),
            $tokenResponse,
        );
        $authorization->enableGrantType(
            new OidcAuthCodeGrant(
                $authCodeRepository,
                $refreshTokenRepository,
                new DateInterval('PT5M'),
                $contextProvider,
                true,
                new class () implements OidcSessionIdProviderInterface {
                    public function sessionId(AuthorizationRequestInterface $authorizationRequest): ?string
                    {
                        $sessionId = session_id();
                        return is_string($sessionId) && $sessionId !== '' ? $sessionId : null;
                    }
                },
            ),
            $accessTokenTtl = new DateInterval('PT' . max(1, (int) (getenv('OIDC_REFERENCE_ACCESS_TOKEN_TTL_SECONDS') ?: 600)) . 'S'),
        );
        $authorization->enableGrantType(
            new OidcRefreshTokenGrant($refreshTokenRepository, $contextProvider, new DateInterval('P30D')),
            $accessTokenTtl,
        );

        $resourceServer = new ResourceServer($accessTokenRepository, $oauthPublicPath);
        $metadata = new ProviderMetadata(
            issuer: $baseUrl,
            authorizationEndpoint: $baseUrl . '/authorize',
            tokenEndpoint: $baseUrl . '/token',
            jwksUri: $baseUrl . '/jwks',
            userinfoEndpoint: $baseUrl . '/userinfo',
            scopes: ['openid', 'profile', 'email', 'offline_access'],
            claims: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'sid', 'name', 'preferred_username', 'email', 'email_verified'],
            grantTypes: ['authorization_code', 'refresh_token'],
            offlineAccessSupported: true,
            tokenEndpointAuthMethods: ['client_secret_basic'],
        );

        return [
            'authorization' => $authorization,
            'userinfo' => new UserInfoEndpoint($resourceServer, $identityResolver),
            'discovery' => new DiscoveryDocumentGenerator($metadata),
            'jwks' => new JwksGenerator($signingKeySet),
            'clientId' => $clientId,
            'username' => (string) (getenv('OIDC_REFERENCE_TEST_USERNAME') ?: 'alice'),
            'password' => (string) getenv('OIDC_REFERENCE_TEST_PASSWORD'),
            'authenticationTimeStore' => $authenticationTimeStore,
            'revocationStore' => $revocationStore,
        ];
    }
}
