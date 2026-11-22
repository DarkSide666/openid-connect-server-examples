<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$keyId = $argv[1] ?? '';
if ($keyId === '' || preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $keyId) !== 1) {
    fwrite(STDERR, "Usage: php bin/generate-oidc-rotation-key.php <new-key-id>\n");
    exit(2);
}
$directory = $root . '/var/keys';
if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
    fwrite(STDERR, "Unable to create var/keys directory.\n");
    exit(1);
}
$privatePath = $directory . '/oidc-private-' . $keyId . '.pem';
$publicPath = $directory . '/oidc-public-' . $keyId . '.pem';
if (file_exists($privatePath) || file_exists($publicPath)) {
    fwrite(STDERR, "A key file with this key ID already exists; refusing to overwrite it.\n");
    exit(1);
}
$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
if ($key === false || !openssl_pkey_export($key, $privatePem)) {
    fwrite(STDERR, "Unable to generate/export RSA private key. Check OpenSSL configuration.\n");
    exit(1);
}
$details = openssl_pkey_get_details($key);
if ($details === false || !is_string($details['key'] ?? null)) {
    fwrite(STDERR, "Unable to export RSA public key.\n");
    exit(1);
}
if (file_put_contents($privatePath, $privatePem, LOCK_EX) === false
    || file_put_contents($publicPath, $details['key'], LOCK_EX) === false) {
    @unlink($privatePath);
    @unlink($publicPath);
    fwrite(STDERR, "Unable to write generated key files.\n");
    exit(1);
}
@chmod($privatePath, 0600);
@chmod($publicPath, 0644);
printf("Generated OIDC RS256 key pair:\nPrivate: %s\nPublic:  %s\nKey ID:  %s\n", $privatePath, $publicPath, $keyId);
