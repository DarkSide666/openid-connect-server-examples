<?php

declare(strict_types=1);

use Defuse\Crypto\Key;

require dirname(__DIR__) . '/vendor/autoload.php';

$root = dirname(__DIR__);
$keysDirectory = $root . '/var/keys';
if (!is_dir($keysDirectory) && !mkdir($keysDirectory, 0700, true) && !is_dir($keysDirectory)) {
    throw new RuntimeException('Unable to create the key directory.');
}

$generatePair = static function (string $prefix) use ($keysDirectory): void {
    $privatePath = $keysDirectory . '/' . $prefix . '-private.pem';
    $publicPath = $keysDirectory . '/' . $prefix . '-public.pem';
    if (is_file($privatePath) || is_file($publicPath)) {
        if (!is_file($privatePath) || !is_file($publicPath)) {
            throw new RuntimeException(sprintf('Incomplete %s key pair exists; inspect and repair it manually.', $prefix));
        }
        return;
    }
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    if ($key === false || !openssl_pkey_export($key, $privatePem)) {
        throw new RuntimeException(sprintf('Unable to generate %s private key.', $prefix));
    }
    $details = openssl_pkey_get_details($key);
    if ($details === false || !isset($details['key'])) {
        throw new RuntimeException(sprintf('Unable to export %s public key.', $prefix));
    }
    file_put_contents($privatePath, $privatePem, LOCK_EX);
    file_put_contents($publicPath, $details['key'], LOCK_EX);
    @chmod($privatePath, 0600);
    @chmod($publicPath, 0644);
};

$generatePair('oauth');
$generatePair('oidc');
$encryptionPath = $keysDirectory . '/oauth-encryption.key';
if (!is_file($encryptionPath)) {
    file_put_contents($encryptionPath, Key::createNewRandomKey()->saveToAsciiSafeString(), LOCK_EX);
    @chmod($encryptionPath, 0600);
}

$envPath = $root . '/.env';
if (!is_file($envPath)) {
    $clientSecret = bin2hex(random_bytes(24));
    $testPassword = bin2hex(random_bytes(12));
    $contents = implode("\n", [
        'OIDC_REFERENCE_BASE_URL=https://oidc-reference.loc',
        'OIDC_REFERENCE_CLIENT_ID=oidc-test-client',
        'OIDC_REFERENCE_CLIENT_SECRET=' . $clientSecret,
        'OIDC_REFERENCE_REDIRECT_URI=https://oidc-client.loc/callback',
        'OIDC_REFERENCE_TEST_USERNAME=alice',
        'OIDC_REFERENCE_TEST_PASSWORD=' . $testPassword,
        'OIDC_REFERENCE_DATA_DIR=var',
        '',
    ]);
    file_put_contents($envPath, $contents, LOCK_EX);
    @chmod($envPath, 0600);
    echo "Created .env with one-time test credentials:\n";
    echo "Client ID: oidc-test-client\nClient secret: {$clientSecret}\nTest username: alice\nTest password: {$testPassword}\n";
} else {
    echo ".env already exists; it was not overwritten.\n";
}

echo "Reference-provider keys are ready. Keep var/ and .env out of version control.\n";
