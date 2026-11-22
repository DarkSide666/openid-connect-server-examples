<?php

declare(strict_types=1);

use League\OAuth2\Server\Exception\OAuthServerException;
use Slim\Factory\AppFactory;
use DarkSide\OidcReferenceProvider\Entity\User;
use DarkSide\OidcReferenceProvider\ProviderFactory;
use DarkSide\OpenIdConnectServer\Logout\RpInitiatedLogoutRequest;

require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/bootstrap.php';

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_name('DARKSIDE_OIDC_REFERENCE');
$allowInsecureHttpForCi = getenv('OIDC_REFERENCE_ALLOW_INSECURE_HTTP_FOR_CI') === '1';
session_set_cookie_params([
    'httponly' => true,
    'secure' => !$allowInsecureHttpForCi,
    'samesite' => 'Lax',
    'path' => '/',
]);
session_start();

$app = AppFactory::create();
$app->addBodyParsingMiddleware();
$app->addRoutingMiddleware();
$app->addErrorMiddleware(false, true, false);

$factory = new ProviderFactory(dirname(__DIR__));
$services = $factory->create();

$sendJson = static function ($response, array $payload, int $status = 200) {
    $response->getBody()->write(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

    return $response
        ->withStatus($status)
        ->withHeader('Content-Type', 'application/json; charset=utf-8')
        ->withHeader('Cache-Control', 'no-store')
        ->withHeader('Pragma', 'no-cache');
};

$csrfToken = static function (): string {
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
};

$postLogoutUrisForClient = static function (?string $clientId) use ($services): array {
    if ($clientId === null || hash_equals($services['clientId'], $clientId)) {
        return [$services['postLogoutRedirectUri']];
    }
    $state = $services['dynamicClientState'];
    $metadata = $state instanceof \DarkSide\OidcReferenceProvider\Storage\DynamicClientState ? $state->get($clientId) : null;
    $uris = is_array($metadata) ? ($metadata['post_logout_redirect_uris'] ?? []) : [];
    return is_array($uris) ? array_values(array_filter($uris, 'is_string')) : [];
};

$app->get('/health', static function ($request, $response) use ($sendJson) {
    return $sendJson($response, ['status' => 'ok', 'purpose' => 'oidc-reference-provider-test-only']);
});

// Disabled unless an explicit test-control secret is configured. Never enable this route in a real provider.
$app->post('/__test/revoke-access-token', static function ($request, $response) use ($services, $sendJson) {
    $secret = (string) getenv('OIDC_REFERENCE_TEST_CONTROL_SECRET');
    $provided = $request->getHeaderLine('X-Reference-Test-Control');
    if ($secret === '' || !hash_equals($secret, $provided)) {
        return $sendJson($response, ['error' => 'not_found'], 404);
    }
    $body = $request->getParsedBody();
    $token = is_array($body) ? ($body['access_token'] ?? null) : null;
    if (!is_string($token)) {
        return $sendJson($response, ['error' => 'invalid_request'], 400);
    }
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return $sendJson($response, ['error' => 'invalid_token'], 400);
    }
    $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/') . str_repeat('=', (4 - strlen($parts[1]) % 4) % 4)), true);
    $identifier = is_array($payload) ? ($payload['jti'] ?? null) : null;
    if (!is_string($identifier) || $identifier === '') {
        return $sendJson($response, ['error' => 'invalid_token'], 400);
    }
    $services['revocationStore']->revoke($identifier);

    return $sendJson($response, ['status' => 'revoked']);
});

$app->get('/.well-known/openid-configuration', static function ($request, $response) use ($services, $sendJson) {
    return $sendJson($response, $services['discovery']->generate());
});

$app->get('/jwks', static function ($request, $response) use ($services, $sendJson) {
    return $sendJson($response, $services['jwks']->generate());
});

$app->get('/authorize', static function ($request, $response) use ($services, $csrfToken) {
    try {
        $authorizationRequest = $services['authorization']->validateAuthorizationRequest($request);
        $_SESSION['oidc_authorization_request'] = $authorizationRequest;
        $token = htmlspecialchars($csrfToken(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $clientName = htmlspecialchars($authorizationRequest->getClient()->getName(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $scopes = [];
        foreach ($authorizationRequest->getScopes() as $scope) {
            $scopes[] = htmlspecialchars($scope->getIdentifier(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }
        $scopeText = htmlspecialchars(implode(' ', $scopes), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $html = <<<HTML
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>OIDC Reference Provider Login</title></head>
<body><h1>Test OpenID Provider</h1><p><strong>Test-only reference provider.</strong></p>
<p>Client: {$clientName}</p><p>Requested scopes: {$scopeText}</p>
<p>The offline_access scope grants this test client a rotating refresh token after explicit approval.</p>
<form method="post" action="/authorize">
<input type="hidden" name="csrf_token" value="{$token}">
<label>Username <input name="username" autocomplete="username" required></label><br>
<label>Password <input type="password" name="password" autocomplete="current-password" required></label><br>
<label><input type="checkbox" name="approve" value="1"> Approve this test authorization</label><br>
<button type="submit">Continue</button></form></body></html>
HTML;
        $response->getBody()->write($html);

        return $response->withHeader('Content-Type', 'text/html; charset=utf-8')->withHeader('Cache-Control', 'no-store');
    } catch (OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
    }
});

$app->post('/authorize', static function ($request, $response) use ($services, $csrfToken) {
    $body = $request->getParsedBody();
    if (!is_array($body)) {
        return $response->withStatus(400);
    }
    $submittedCsrf = $body['csrf_token'] ?? null;
    if (!is_string($submittedCsrf) || !hash_equals($csrfToken(), $submittedCsrf)) {
        return $response->withStatus(400);
    }
    $authorizationRequest = $_SESSION['oidc_authorization_request'] ?? null;
    unset($_SESSION['oidc_authorization_request']);
    if (!$authorizationRequest instanceof \DarkSide\OpenIdConnectServer\League\OidcAuthorizationRequest) {
        return $response->withStatus(400);
    }

    $expectedUsername = $services['username'];
    $expectedPassword = $services['password'];
    $username = $body['username'] ?? null;
    $password = $body['password'] ?? null;
    if (!is_string($username) || !is_string($password)
        || !hash_equals($expectedUsername, $username)
        || $expectedPassword === ''
        || !hash_equals($expectedPassword, $password)) {
        $response->getBody()->write('Invalid test credentials. Restart the authorization request and try again.');

        return $response->withStatus(401)->withHeader('Content-Type', 'text/plain; charset=utf-8');
    }

    session_regenerate_id(true);
    $_SESSION['oidc_sid'] = session_id();
    $_SESSION['oidc_subject'] = 'reference-user-subject-001';
    $services['authenticationTimeStore']->recordSuccessfulLogin();
    $authorizationRequest->setUser(new User('reference-user-001'));
    $authorizationRequest->setAuthorizationApproved(($body['approve'] ?? null) === '1');

    try {
        return $services['authorization']->completeAuthorizationRequest($authorizationRequest, $response);
    } catch (OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
    }
});

$app->post('/token', static function ($request, $response) use ($services) {
    try {
        return $services['authorization']->respondToAccessTokenRequest($request, $response);
    } catch (OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
    }
});

$app->post('/register', static function ($request, $response) use ($services, $sendJson) {
    $registration = $services['registration'];
    if (!$registration instanceof \DarkSide\OpenIdConnectServer\Registration\ClientRegistrationService) {
        return $sendJson($response, ['error' => 'not_found'], 404);
    }
    $body = $request->getParsedBody();
    if (!is_array($body)) {
        return $sendJson($response, ['error' => 'invalid_client_metadata'], 400);
    }
    $authorization = $request->getHeaderLine('Authorization');
    $initialAccessToken = preg_match('/^Bearer\s+([^\s]+)$/i', $authorization, $matches) === 1 ? $matches[1] : null;
    try {
        $client = $registration->register($body, $initialAccessToken);
        $payload = $client->metadata + ['client_id' => $client->clientId];
        if ($client->clientSecret !== null) {
            $payload['client_secret'] = $client->clientSecret;
        }
        $payload['client_id_issued_at'] = time();
        $payload['client_secret_expires_at'] = 0;
        return $sendJson($response, $payload, 201);
    } catch (\InvalidArgumentException $exception) {
        return $sendJson($response, ['error' => 'invalid_client_metadata'], 400);
    } catch (\RuntimeException $exception) {
        return $sendJson($response, ['error' => 'registration_not_permitted'], 403);
    }
});

$app->map(['GET', 'POST'], '/userinfo', static function ($request, $response) use ($services) {
    return $services['userinfo']->handle($request, $response);
});

$app->get('/logout', static function ($request, $response) use ($services, $csrfToken, $sendJson, $postLogoutUrisForClient) {
    try {
        $logoutRequest = RpInitiatedLogoutRequest::fromQuery($request->getQueryParams());
        $services['logout']->validate($logoutRequest, $postLogoutUrisForClient($logoutRequest->clientId));
    } catch (\Throwable $exception) {
        return $sendJson($response, ['error' => 'invalid_request', 'error_description' => $exception->getMessage()], 400);
    }

    $escape = static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $csrf = $escape($csrfToken());
    $hidden = '';
    $parameters = [
        'id_token_hint' => $logoutRequest->idTokenHint,
        'client_id' => $logoutRequest->clientId,
        'post_logout_redirect_uri' => $logoutRequest->postLogoutRedirectUri,
        'state' => $logoutRequest->state,
    ];
    foreach ($parameters as $name => $value) {
        if ($value !== null) {
            $hidden .= '<input type="hidden" name="' . $name . '" value="' . $escape($value) . '">';
        }
    }
    $response->getBody()->write('<!doctype html><html lang="en"><meta charset="utf-8"><title>Sign out</title><h1>Sign out</h1>'
        . '<p>Confirm ending this test provider session.</p><form method="post" action="/logout">'
        . '<input type="hidden" name="csrf_token" value="' . $csrf . '">' . $hidden
        . '<button type="submit">Sign out</button></form></html>');
    return $response->withHeader('Content-Type', 'text/html; charset=utf-8')->withHeader('Cache-Control', 'no-store');
});

$app->post('/logout', static function ($request, $response) use ($services, $csrfToken, $sendJson, $postLogoutUrisForClient) {
    $body = $request->getParsedBody();
    if (!is_array($body) || !is_string($body['csrf_token'] ?? null)
        || !hash_equals($csrfToken(), $body['csrf_token'])) {
        return $sendJson($response, ['error' => 'invalid_request'], 400);
    }
    try {
        $logoutRequest = RpInitiatedLogoutRequest::fromQuery($body);
        $result = $services['logout']->validate($logoutRequest, $postLogoutUrisForClient($logoutRequest->clientId));
    } catch (\Throwable $exception) {
        return $sendJson($response, ['error' => 'invalid_request', 'error_description' => $exception->getMessage()], 400);
    }
    if ($result['sub'] !== null
        && (!is_string($_SESSION['oidc_subject'] ?? null) || !hash_equals($result['sub'], $_SESSION['oidc_subject'])
            || !is_string($_SESSION['oidc_sid'] ?? null) || !is_string($result['sid'])
            || !hash_equals($result['sid'], $_SESSION['oidc_sid']))) {
        return $sendJson($response, ['error' => 'login_required', 'error_description' => 'The ID Token hint does not identify this browser session.'], 400);
    }
    if ($result['sub'] !== null && $services['backchannelLogout'] instanceof \DarkSide\OpenIdConnectServer\Logout\BackChannelLogoutService) {
        try {
            $services['backchannelLogout']->notify($result['sub'], $result['sid']);
        } catch (\Throwable $exception) {
            return $sendJson($response, ['error' => 'server_error', 'error_description' => 'Back-channel notification failed; session was not terminated.'], 502);
        }
    }

    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $cookie = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $cookie['path'], $cookie['domain'], $cookie['secure'], $cookie['httponly']);
    }
    session_destroy();
    $target = $result['post_logout_redirect_uri'] ?? '/';
    if ($target !== '/' && $result['state'] !== null) {
        $target .= (str_contains($target, '?') ? '&' : '?') . http_build_query(['state' => $result['state']], '', '&', PHP_QUERY_RFC3986);
    }
    return $response->withStatus(302)->withHeader('Location', $target)->withHeader('Cache-Control', 'no-store');
});

$app->run();
