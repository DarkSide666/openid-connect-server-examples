<?php

declare(strict_types=1);

use DarkSide\OidcInteropClient\Config;

require dirname(__DIR__) . '/bootstrap.php';
require dirname(__DIR__) . '/vendor/autoload.php';

$config = Config::fromEnvironment();
$username = trim((string) getenv('OIDC_INTEROP_TEST_USERNAME'));
$password = (string) getenv('OIDC_INTEROP_TEST_PASSWORD');
if ($username === '' || $password === '') {
    fwrite(STDERR, "Set OIDC_INTEROP_TEST_USERNAME and OIDC_INTEROP_TEST_PASSWORD in interop-client/.env.\n");
    exit(2);
}

/**
 * @param list<string> $headers
 *
 * @return array{status: int, headers: array<string, string>, body: string}
 */
$http = static function (string $method, string $url, array $headers = [], ?string $body = null) use ($config): array {
    $handle = curl_init($url);
    if ($handle === false) {
        throw new RuntimeException('Unable to initialize cURL.');
    }

    $responseHeaders = [];
    $options = [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$responseHeaders): int {
            $length = strlen($line);
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) {
                $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
            }

            return $length;
        },
    ];
    if ($body !== null) {
        $options[CURLOPT_POSTFIELDS] = $body;
    }
    if ($config->caBundle !== null) {
        $options[CURLOPT_CAINFO] = $config->caBundle;
    }

    curl_setopt_array($handle, $options);
    $responseBody = curl_exec($handle);
    if (!is_string($responseBody)) {
        $message = curl_error($handle);
        curl_close($handle);
        throw new RuntimeException('HTTPS request failed: ' . $message);
    }

    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    curl_close($handle);

    return ['status' => $status, 'headers' => $responseHeaders, 'body' => $responseBody];
};

$base64Url = static fn (string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
$verifier = static fn (): string => $base64Url(random_bytes(32));
$basicAuthorization = 'Authorization: Basic ' . base64_encode($config->clientId . ':' . $config->clientSecret);
$formHeaders = ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded', $basicAuthorization];
$discoveryResponse = $http('GET', $config->providerIssuer . '/.well-known/openid-configuration', ['Accept: application/json']);
$discovery = json_decode($discoveryResponse['body'], true);
if ($discoveryResponse['status'] !== 200 || !is_array($discovery)
    || ($discovery['issuer'] ?? null) !== $config->providerIssuer
    || !is_string($discovery['authorization_endpoint'] ?? null)
    || !is_string($discovery['token_endpoint'] ?? null)) {
    fwrite(STDERR, "Unable to load valid provider discovery metadata over HTTPS.\n");
    exit(2);
}
$authorizationEndpoint = $discovery['authorization_endpoint'];
$tokenEndpoint = $discovery['token_endpoint'];

/** @return array{code: string, verifier: string} */
$createAuthorizationCode = static function (bool $offlineAccess = false) use ($http, $config, $username, $password, $base64Url, $verifier, $authorizationEndpoint): array {
    $codeVerifier = $verifier();
    $codeChallenge = $base64Url(hash('sha256', $codeVerifier, true));
    $query = http_build_query([
        'client_id' => $config->clientId,
        'response_type' => 'code',
        'redirect_uri' => $config->redirectUri,
        'scope' => 'openid profile email' . ($offlineAccess ? ' offline_access' : ''),
        'state' => bin2hex(random_bytes(16)),
        'nonce' => bin2hex(random_bytes(16)),
        'code_challenge' => $codeChallenge,
        'code_challenge_method' => 'S256',
        ...($offlineAccess ? ['prompt' => 'consent'] : []),
    ], '', '&', PHP_QUERY_RFC3986);

    $authorizationPage = $http('GET', $authorizationEndpoint . '?' . $query, ['Accept: text/html']);
    if ($authorizationPage['status'] !== 200
        || !preg_match('/name="csrf_token"\s+value="([a-f0-9]+)"/i', $authorizationPage['body'], $csrfMatch)
        || !isset($authorizationPage['headers']['set-cookie'])) {
        throw new RuntimeException('Could not initialize the provider login form for a test authorization transaction.');
    }

    $cookie = explode(';', $authorizationPage['headers']['set-cookie'], 2)[0];
    $loginResponse = $http('POST', $authorizationEndpoint, [
        'Accept: text/html',
        'Content-Type: application/x-www-form-urlencoded',
        'Cookie: ' . $cookie,
    ], http_build_query([
        'csrf_token' => $csrfMatch[1],
        'username' => $username,
        'password' => $password,
        'approve' => '1',
    ], '', '&', PHP_QUERY_RFC3986));

    $location = $loginResponse['headers']['location'] ?? null;
    $locationParts = is_string($location) ? parse_url($location) : false;
    parse_str(is_array($locationParts) ? (string) ($locationParts['query'] ?? '') : '', $redirectQuery);
    $authorizationCode = $redirectQuery['code'] ?? null;
    if ($loginResponse['status'] !== 302 || !is_string($authorizationCode) || $authorizationCode === '') {
        throw new RuntimeException('Provider did not return an authorization code. Check the test login credentials and provider logs.');
    }

    return ['code' => $authorizationCode, 'verifier' => $codeVerifier];
};

$redeem = static function (string $code, string $codeVerifier) use ($http, $tokenEndpoint, $formHeaders, $config): array {
    $response = $http('POST', $tokenEndpoint, $formHeaders, http_build_query([
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $config->redirectUri,
        'code_verifier' => $codeVerifier,
    ], '', '&', PHP_QUERY_RFC3986));
    $payload = json_decode($response['body'], true);
    if (!is_array($payload)) {
        $payload = [];
    }
    /** @var array<string, mixed> $payload */

    return ['status' => $response['status'], 'payload' => $payload];
};

$checks = [];
$record = static function (string $name, bool $passed, string $detail) use (&$checks): void {
    $checks[] = ['name' => $name, 'passed' => $passed, 'detail' => $detail];
};

try {
    $pkceTransaction = $createAuthorizationCode();
    $incorrectVerifier = $verifier();
    while (hash_equals($pkceTransaction['verifier'], $incorrectVerifier)) {
        $incorrectVerifier = $verifier();
    }
    $pkceFailure = $redeem($pkceTransaction['code'], $incorrectVerifier);
    $pkceError = $pkceFailure['payload']['error'] ?? null;
    $record(
        'Token endpoint rejects an incorrect PKCE verifier',
        $pkceFailure['status'] === 400 && $pkceError === 'invalid_grant'
            && !isset($pkceFailure['payload']['access_token'])
            && !isset($pkceFailure['payload']['id_token']),
        'HTTP ' . $pkceFailure['status'] . '; OAuth error: ' . (is_string($pkceError) ? $pkceError : 'missing')
            . '; tokens issued: ' . (isset($pkceFailure['payload']['access_token']) || isset($pkceFailure['payload']['id_token']) ? 'yes' : 'no'),
    );

    $replayTransaction = $createAuthorizationCode();
    $firstRedemption = $redeem($replayTransaction['code'], $replayTransaction['verifier']);
    $firstRedemptionSucceeded = $firstRedemption['status'] === 200
        && is_string($firstRedemption['payload']['access_token'] ?? null)
        && is_string($firstRedemption['payload']['id_token'] ?? null)
        && !isset($firstRedemption['payload']['refresh_token']);
    $record(
        'A valid authorization code and PKCE verifier are accepted once',
        $firstRedemptionSucceeded,
        'HTTP ' . $firstRedemption['status'] . '; access token and ID Token issued without an unrequested refresh token: ' . ($firstRedemptionSucceeded ? 'yes' : 'no'),
    );

    if ($firstRedemptionSucceeded) {
        $replay = $redeem($replayTransaction['code'], $replayTransaction['verifier']);
        $replayError = $replay['payload']['error'] ?? null;
        $record(
            'Token endpoint rejects reuse of a redeemed authorization code',
            $replay['status'] === 400 && $replayError === 'invalid_grant'
                && !isset($replay['payload']['access_token'])
                && !isset($replay['payload']['id_token']),
            'HTTP ' . $replay['status'] . '; OAuth error: ' . (is_string($replayError) ? $replayError : 'missing')
                . '; tokens issued: ' . (isset($replay['payload']['access_token']) || isset($replay['payload']['id_token']) ? 'yes' : 'no'),
        );
    } else {
        $record('Token endpoint rejects reuse of a redeemed authorization code', false, 'Skipped because initial valid redemption failed.');
    }

    $offlineTransaction = $createAuthorizationCode(true);
    $offlineTokens = $redeem($offlineTransaction['code'], $offlineTransaction['verifier']);
    $initialRefreshToken = $offlineTokens['payload']['refresh_token'] ?? null;
    $offlineSucceeded = $offlineTokens['status'] === 200
        && is_string($offlineTokens['payload']['access_token'] ?? null)
        && is_string($initialRefreshToken)
        && $initialRefreshToken !== '';
    $record(
        'Explicitly consented offline_access authorization issues a refresh token',
        $offlineSucceeded,
        'HTTP ' . $offlineTokens['status'] . '; refresh token issued: ' . ($offlineSucceeded ? 'yes' : 'no'),
    );

    if ($offlineSucceeded) {
        $refresh = static function (string $token) use ($http, $tokenEndpoint, $formHeaders): array {
            $response = $http('POST', $tokenEndpoint, $formHeaders, http_build_query([
                'grant_type' => 'refresh_token',
                'refresh_token' => $token,
            ], '', '&', PHP_QUERY_RFC3986));
            $payload = json_decode($response['body'], true);
            return ['status' => $response['status'], 'payload' => is_array($payload) ? $payload : []];
        };
        $rotated = $refresh($initialRefreshToken);
        $replacement = $rotated['payload']['refresh_token'] ?? null;
        $rotationSucceeded = $rotated['status'] === 200 && is_string($replacement)
            && $replacement !== '' && !hash_equals($initialRefreshToken, $replacement);
        $record(
            'Refresh-token grant rotates the token after successful client authentication',
            $rotationSucceeded,
            'HTTP ' . $rotated['status'] . '; replacement token issued: ' . ($rotationSucceeded ? 'yes' : 'no'),
        );

        $replay = $refresh($initialRefreshToken);
        $replayRejected = $replay['status'] === 400 && ($replay['payload']['error'] ?? null) === 'invalid_grant';
        $record(
            'Refresh-token reuse is rejected',
            $replayRejected,
            'HTTP ' . $replay['status'] . '; OAuth error: ' . (is_string($replay['payload']['error'] ?? null) ? $replay['payload']['error'] : 'missing'),
        );

        if ($rotationSucceeded) {
            $familyCheck = $refresh($replacement);
            $familyRevoked = $familyCheck['status'] === 400 && ($familyCheck['payload']['error'] ?? null) === 'invalid_grant';
            $record(
                'Reusing a spent refresh token revokes its replacement token family',
                $familyRevoked,
                'Replacement token after replay: HTTP ' . $familyCheck['status'] . '; OAuth error: ' . (is_string($familyCheck['payload']['error'] ?? null) ? $familyCheck['payload']['error'] : 'missing'),
            );
        } else {
            $record('Reusing a spent refresh token revokes its replacement token family', false, 'Skipped because initial rotation failed.');
        }
    } else {
        $record('Refresh-token grant rotates the token after successful client authentication', false, 'Skipped because offline access did not issue a refresh token.');
        $record('Refresh-token reuse is rejected', false, 'Skipped because offline access did not issue a refresh token.');
        $record('Reusing a spent refresh token revokes its replacement token family', false, 'Skipped because offline access did not issue a refresh token.');
    }
} catch (Throwable $exception) {
    fwrite(STDERR, 'Authorization-flow security checks could not complete: ' . $exception->getMessage() . "\n");
    exit(2);
}

$passed = count(array_filter($checks, static fn (array $check): bool => $check['passed']));
foreach ($checks as $check) {
    printf("%s %s — %s\n", $check['passed'] ? 'PASS' : 'FAIL', $check['name'], $check['detail']);
}
printf("\n%d/%d authorization-flow security checks passed.\n", $passed, count($checks));

exit($passed === count($checks) ? 0 : 1);
