<?php

declare(strict_types=1);

use DarkSide\OidcInteropClient\Config;
use DarkSide\OidcInteropClient\DiagnosticOpenIDConnectClient;
use DarkSide\OidcInteropClient\LogoutTokenStore;
use DarkSide\OidcInteropClient\LogoutTokenValidator;
use DarkSide\OidcInteropClient\RsaJwkConverter;

require dirname(__DIR__) . '/bootstrap.php';
require dirname(__DIR__) . '/vendor/autoload.php';

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_name('DARKSIDE_OIDC_INTEROP_RP');
session_set_cookie_params([
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Lax',
    'path' => '/',
]);
session_start();

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');

$escape = static fn (string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$oidc = null;
$respond = static function (string $title, string $content, int $status = 200) use ($escape): never {
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'
        . $escape($title)
        . '</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:850px;margin:3rem auto;padding:0 1rem;color:#222}code,pre{background:#f3f4f6;padding:.2rem .35rem;border-radius:4px}pre{padding:1rem;overflow:auto}a.button{display:inline-block;padding:.7rem 1rem;background:#174ea6;color:white;text-decoration:none;border-radius:5px}</style></head><body><h1>'
        . $escape($title)
        . '</h1>' . $content . '</body></html>';
    exit;
};

try {
    $config = Config::fromEnvironment();
    $path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);

    if ($path === '/health') {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['status' => 'ok', 'client' => 'jumbojett/openid-connect-php'], JSON_THROW_ON_ERROR);
        exit;
    }

    if ($path === '/backchannel-logout') {
        $body = file_get_contents('php://input');
        parse_str(is_string($body) ? $body : '', $form);
        $logoutToken = $form['logout_token'] ?? null;
        if (!is_string($logoutToken) || $logoutToken === '') {
            $respond('Invalid logout request', '<p>logout_token is required.</p>', 400);
        }
        $fetchJson = static function (string $url) use ($config): array {
            $handle = curl_init($url);
            if ($handle === false) {
                throw new RuntimeException('Unable to initialize JWKS request.');
            }
            $curlOptions = [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_HTTPHEADER => ['Accept: application/json'],
            ];
            if ($config->caBundle !== null) {
                $curlOptions[CURLOPT_CAINFO] = $config->caBundle;
            }
            curl_setopt_array($handle, $curlOptions);
            $body = curl_exec($handle);
            $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
            curl_close($handle);
            $decoded = is_string($body) ? json_decode($body, true) : null;
            if ($status !== 200 || !is_array($decoded)) {
                throw new RuntimeException('Unable to retrieve provider signing keys.');
            }
            return $decoded;
        };
        try {
            $metadata = $fetchJson($config->providerIssuer . '/.well-known/openid-configuration');
            if (($metadata['issuer'] ?? null) !== $config->providerIssuer
                || ($metadata['jwks_uri'] ?? null) !== $config->providerIssuer . '/jwks') {
                throw new RuntimeException('Provider discovery does not match the configured issuer.');
            }
            $jwks = $fetchJson($metadata['jwks_uri']);
            $keys = [];
            foreach ($jwks['keys'] ?? [] as $jwk) {
                if (is_array($jwk) && ($jwk['alg'] ?? null) === 'RS256' && is_string($jwk['kid'] ?? null)) {
                    $keys[$jwk['kid']] = RsaJwkConverter::toPem($jwk);
                }
            }
            $store = new LogoutTokenStore(dirname(__DIR__) . '/var/logout-state.json');
            $claims = (new LogoutTokenValidator($config->providerIssuer, $config->clientId, $keys, $store))->validate($logoutToken);
            $store->revokeSession($claims['sub'] ?? null, $claims['sid'] ?? null);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['status' => 'accepted'], JSON_THROW_ON_ERROR);
            exit;
        } catch (Throwable) {
            $respond('Invalid logout token', '<p>The Back-Channel Logout Token failed validation.</p>', 400);
        }
    }

    if ($path === '/logout') {
        $idToken = $_SESSION['oidc_id_token'] ?? null;
        if (!is_string($idToken) || $idToken === '') {
            $respond('Already signed out', '<p>No OpenID Provider session is stored in this RP session.</p><p><a href="/">Return to the test client</a></p>');
        }
        $logoutClient = new DiagnosticOpenIDConnectClient($config->providerIssuer, $config->clientId, $config->clientSecret);
        if ($config->caBundle !== null) {
            $logoutClient->setCertPath($config->caBundle);
        }
        $endpoint = $logoutClient->endSessionEndpoint();
        if ($endpoint === null) {
            throw new RuntimeException('Provider discovery does not advertise end_session_endpoint.');
        }
        $state = bin2hex(random_bytes(32));
        $_SESSION['oidc_logout_state'] = $state;
        $query = http_build_query([
            'id_token_hint' => $idToken,
            'client_id' => $config->clientId,
            'post_logout_redirect_uri' => $config->postLogoutRedirectUri,
            'state' => $state,
        ], '', '&', PHP_QUERY_RFC3986);
        header('Location: ' . $endpoint . (str_contains($endpoint, '?') ? '&' : '?') . $query, true, 302);
        exit;
    }

    if ($path === '/signed-out') {
        $expectedState = $_SESSION['oidc_logout_state'] ?? null;
        $returnedState = $_GET['state'] ?? null;
        if (!is_string($expectedState) || !is_string($returnedState) || !hash_equals($expectedState, $returnedState)) {
            $respond('Logout state error', '<p>The post-logout state is missing or invalid.</p><p><a href="/">Return</a></p>', 400);
        }
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
        $respond('Signed out', '<p>The OpenID Provider and relying-party test sessions have been cleared.</p><p><a href="/">Return to the test client</a></p>');
    }

    if ($path === '/login' || $path === '/callback') {
        $oidc = new DiagnosticOpenIDConnectClient($config->providerIssuer, $config->clientId, $config->clientSecret);
        $oidc->setRedirectURL($config->redirectUri);
        $oidc->setCodeChallengeMethod('S256');
        $oidc->addScope(['profile', 'email']);
        if ($config->caBundle !== null) {
            $oidc->setCertPath($config->caBundle);
        }

        $authenticated = $oidc->authenticate();
        if (!$authenticated) {
            $respond('Redirecting', '<p>Redirecting to the OpenID Provider...</p>');
        }

        $claims = $oidc->getVerifiedClaims();
        $header = $oidc->getIdTokenHeader();
        if (!is_object($claims)
            || !isset($claims->iss, $claims->sub, $claims->aud, $claims->exp, $claims->nonce)
            || !is_string($claims->iss)
            || !hash_equals($config->providerIssuer, $claims->iss)
            || !is_string($claims->sub)
            || $claims->sub === ''
            || !is_string($claims->nonce)
            || $claims->nonce === '') {
            throw new RuntimeException('The independently validated ID Token is missing required OIDC claims, including nonce.');
        }
        if (!is_object($header) || ($header->alg ?? null) !== 'RS256' || !is_string($header->kid ?? null)) {
            throw new RuntimeException('The ID Token did not use the expected RS256 algorithm and key identifier.');
        }
        $audienceIsValid = is_string($claims->aud)
            ? hash_equals($config->clientId, $claims->aud)
            : is_array($claims->aud) && in_array($config->clientId, $claims->aud, true)
                && (count($claims->aud) === 1 || ($claims->azp ?? null) === $config->clientId);
        if (!$audienceIsValid) {
            throw new RuntimeException('The ID Token audience or authorized-party claim is invalid.');
        }

        $userInfo = $oidc->requestUserInfo();
        if (!is_object($userInfo) || !is_string($userInfo->sub ?? null) || !hash_equals($claims->sub, $userInfo->sub)) {
            throw new RuntimeException('UserInfo sub does not match the ID Token sub.');
        }
        $idToken = $oidc->getIdToken();
        if (!is_string($idToken) || $idToken === '') {
            throw new RuntimeException('The RP library did not retain the verified ID Token for logout.');
        }

        $result = [
            'result' => 'success',
            'client_library' => 'jumbojett/openid-connect-php',
            'issuer' => $claims->iss,
            'subject' => $claims->sub,
            'audience' => $claims->aud,
            'id_token_algorithm' => $header->alg,
            'key_id' => $header->kid,
            'nonce_present_and_validated_by_client_library' => true,
            'pkce_method_requested' => 'S256',
            'userinfo_subject_matches_id_token' => true,
            'userinfo' => get_object_vars($userInfo),
        ];
        $_SESSION['oidc_interop_success'] = true;
        $_SESSION['oidc_id_token'] = $idToken;
        $_SESSION['oidc_subject'] = $claims->sub;
        $_SESSION['oidc_sid'] = is_string($claims->sid ?? null) ? $claims->sid : null;
        $json = json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $respond('OIDC interoperability successful', '<p>The independent relying-party library completed the Authorization Code flow, validated the ID Token signature and claims, and retrieved matching UserInfo.</p><pre>' . $escape($json) . '</pre><p><a href="/logout">Clear client session</a></p>');
    }

    if ($path !== '/') {
        $respond('Not found', '<p>Unknown route.</p>', 404);
    }

    $issuer = $escape($config->providerIssuer);
    $redirect = $escape($config->redirectUri);
    $store = new LogoutTokenStore(dirname(__DIR__) . '/var/logout-state.json');
    $subject = is_string($_SESSION['oidc_subject'] ?? null) ? $_SESSION['oidc_subject'] : null;
    $sessionId = is_string($_SESSION['oidc_sid'] ?? null) ? $_SESSION['oidc_sid'] : null;
    $remotelySignedOut = $store->isSessionRevoked($subject, $sessionId);
    if ($remotelySignedOut) {
        $_SESSION = [];
    }
    $status = $remotelySignedOut
        ? '<p>The provider ended this RP session through Back-Channel Logout.</p>'
        : (isset($_SESSION['oidc_interop_success']) ? '<p>Previous login completed successfully in this browser session.</p>' : '');
    $respond('Independent OIDC relying-party test client', $status
        . '<p>This application uses <code>jumbojett/openid-connect-php</code>, independently of the DarkSide OIDC Provider library.</p>'
        . '<ul><li>Provider issuer: <code>' . $issuer . '</code></li><li>Registered redirect URI: <code>' . $redirect . '</code></li>'
        . '<li>Flow: Authorization Code</li><li>PKCE: S256</li><li>Scopes: openid profile email</li><li>Client authentication: client_secret_basic</li></ul>'
        . '<p><a class="button" href="/login">Start OIDC login</a></p><p><a href="/health">Client health check</a></p>');
} catch (Throwable $exception) {
    $details = '';
    if ($oidc instanceof DiagnosticOpenIDConnectClient) {
        $diagnostics = $oidc->claimValidationDiagnostics();
        if ($diagnostics !== []) {
            $diagnosticJson = json_encode($diagnostics, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
            $details = '<p>Non-sensitive ID Token claim checks:</p><pre>' . $escape($diagnosticJson) . '</pre>';
        }
    }

    $respond('OIDC interoperability failed', '<p>The relying-party test did not complete.</p><pre>' . $escape($exception->getMessage()) . '</pre>' . $details . '<p>These diagnostics show which standard claim check failed; they do not display the ID Token, nonce, client secret or other credentials.</p><p><a href="/">Return</a></p>', 500);
}
