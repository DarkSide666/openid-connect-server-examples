<?php

declare(strict_types=1);

namespace DarkSide\OidcReferenceProvider\Logout;

use DarkSide\OpenIdConnectServer\Logout\BackChannelLogoutDeliveryInterface;
use RuntimeException;

final readonly class HttpBackChannelLogoutDelivery implements BackChannelLogoutDeliveryInterface
{
    public function __construct(private ?string $caBundle = null)
    {
    }

    public function deliver(string $clientId, string $logoutUri, string $logoutToken): void
    {
        $ssl = ['verify_peer' => true, 'verify_peer_name' => true];
        if ($this->caBundle !== null && $this->caBundle !== '') {
            $ssl['cafile'] = $this->caBundle;
        }
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n",
                'content' => http_build_query(['logout_token' => $logoutToken], '', '&', PHP_QUERY_RFC3986),
                'timeout' => 5,
                'ignore_errors' => true,
            ],
            'ssl' => $ssl,
        ]);
        $response = @file_get_contents($logoutUri, false, $context);
        $statusLine = $http_response_header[0] ?? '';
        if ($response === false || preg_match('/\s2[0-9]{2}\s/', $statusLine) !== 1) {
            throw new RuntimeException('The RP did not accept the Back-Channel Logout Token.');
        }
    }
}
