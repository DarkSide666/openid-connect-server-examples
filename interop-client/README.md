# Independent OIDC Relying-Party Test Client

This is a separate, test-only OpenID Connect Relying Party (RP) application. It uses
[`jumbojett/openid-connect-php`](https://github.com/jumbojett/OpenID-Connect-PHP) to discover and
authenticate against the reference provider.

It is deliberately a separate Composer project and is not a runtime dependency of
`darkside/openid-connect-server` or `reference-provider`.

> Test fixture only. Use only the generated reference-provider test client and test user. Do not
> configure real accounts or production credentials.

## What the interoperability run covers

1. Fetches and checks the provider discovery document over HTTPS.
2. Checks the advertised Authorization Code and refresh-token grants, `offline_access`, `S256`,
   RS256 and `client_secret_basic` profile.
3. Fetches JWKS over HTTPS and checks that it contains an RS256 public signing key without private
   RSA parameters.
4. Starts an Authorization Code flow using the independent RP library.
5. Requests PKCE `S256`, `openid profile email`, state and nonce. The live security probes also
   request `offline_access` with `prompt=consent`.
6. Lets the RP library exchange the code, verify the ID Token signature using the provider JWKS,
   and validate issuer, audience, expiration, not-before and nonce when present.
7. Additionally requires a nonce claim to be present and checks that the UserInfo `sub` exactly
   matches the verified ID Token `sub`.
8. Uses the ID Token hint to start RP-Initiated Logout and validates the returned state at the exact
   registered post-logout URI.
9. Accepts Back-Channel Logout only after validating the signed Logout Token, its issuer/audience,
   expiry, event claim and one-time `jti`; session-targeted logout is scoped by `sid`.
10. When the provider enables protected registration, checks client creation, initial-access-token
    enforcement and rejection of insecure redirect URIs.

The client does not display or persist the access token or ID Token. It displays selected verified
claims and the UserInfo response after a successful flow.

The selected client library's v1.0.2 release is used as an independent interoperability tool, not
as a recommendation for application production use. Its documented PKCE example uses
`setCodeChallengeMethod('S256')`. The harness adds explicit nonce-presence and UserInfo subject
consistency checks around that library.

## Requirements

- PHP 8.2+.
- Composer.
- PHP `curl` and `json` extensions.
- Apache with `mod_rewrite` and HTTPS enabled for the browser-based flow.
- A TLS certificate trusted by the browser for `oidc-client.loc`. A locally self-signed certificate is
  acceptable for development when its issuing certificate is explicitly trusted by the browser and
  PHP cURL for `oidc-reference.loc`.

## Install

From this directory:

```cmd
copy .env.example .env
composer install
```

Edit `.env` and copy the client ID and client secret from `reference-provider/.env`:

```ini
OIDC_INTEROP_PROVIDER_ISSUER=https://oidc-reference.loc
OIDC_INTEROP_CLIENT_ID=oidc-test-client
OIDC_INTEROP_CLIENT_SECRET=the-generated-secret-from-reference-provider-env
OIDC_INTEROP_REDIRECT_URI=https://oidc-client.loc/callback
OIDC_INTEROP_CA_BUNDLE=C:/path/to/local-ca-bundle.pem
OIDC_INTEROP_TEST_USERNAME=alice
OIDC_INTEROP_TEST_PASSWORD=the-test-password-from-reference-provider-env
```

`OIDC_INTEROP_CA_BUNDLE` is optional. If PHP cURL already trusts the provider certificate or its
issuing local CA, leave it empty. For a self-signed development certificate, you can point this
setting at the PEM file containing that certificate (provided it has the correct hostname in its
Subject Alternative Name), or preferably at the local CA certificate that issued the server
certificate. Import the local CA into the Windows/browser trust store as well so the browser accepts
the RP and provider HTTPS URLs. Do not disable TLS peer or hostname verification to work around
certificate errors; configure trust explicitly instead.

## Configure the reference provider

Edit `reference-provider/.env` and set the redirect URI to exactly the same value:

```ini
OIDC_REFERENCE_BASE_URL=https://oidc-reference.loc
OIDC_REFERENCE_REDIRECT_URI=https://oidc-client.loc/callback
```

Keep the existing generated client ID and secret. The reference provider supports one static test
client, so its registered redirect URI must exactly match the RP callback URL.

## Configure Windows hosts

Run Notepad as Administrator and edit:

`C:\Windows\System32\drivers\etc\hosts`

Add both entries if they are not already present:

```text
127.0.0.1 oidc-reference.loc
127.0.0.1 oidc-client.loc
```

## Configure WAMP Apache

Create a second HTTPS VirtualHost for the RP. Its `DocumentRoot` must point to this project's
`public` directory, not the project root:

```apache
<VirtualHost *:443>
    ServerName oidc-client.loc
    DocumentRoot "C:/path/to/openid-connect-server-examples/interop-client/public"

    SSLEngine on
    SSLCertificateFile "C:/path/to/certificate-with-oidc-client.loc-SAN.crt"
    SSLCertificateKeyFile "C:/path/to/certificate.key"

    <Directory "C:/path/to/openid-connect-server-examples/interop-client/public">
        Options FollowSymLinks
        AllowOverride All
        Require local
    </Directory>

    ErrorLog "logs/oidc-client-error.log"
    CustomLog "logs/oidc-client-access.log" combined
</VirtualHost>
```

Use the actual certificate paths from your WAMP setup. The certificate presented for
`oidc-client.loc` must contain that hostname in its Subject Alternative Names (SAN). If the same
certificate is used for both local hosts, it must contain both `oidc-reference.loc` and
`oidc-client.loc`.

Ensure `ssl_module` and `rewrite_module` are enabled. The included `public/.htaccess` routes
requests to `public/index.php`. Restart Apache after changing the VirtualHost configuration.

## Run the checks

From this directory:

```cmd
php bin/check-provider.php
```

This makes HTTPS requests with certificate verification enabled. It should report successful
checks for discovery metadata and JWKS. A self-signed certificate does not prevent local testing: configure
`OIDC_INTEROP_CA_BUNDLE` to point to the PEM certificate (or, preferably, the local CA certificate)
that should be trusted for the provider hostname. The certificate must include `oidc-reference.loc`
in its Subject Alternative Names. Keep peer and hostname verification enabled.

Then open:

`https://oidc-client.loc/`

Click **Start OIDC login**. The browser should redirect to the reference provider at
`https://oidc-reference.loc/authorize`. Sign in using the test username and password from
`reference-provider/.env`, approve the test authorization, and the browser should return to
`https://oidc-client.loc/callback`.

A successful result page confirms that the independent RP completed the authorization-code flow,
validated the RS256 ID Token against JWKS and checked the UserInfo subject against the ID Token
subject.

## ID Token claim-validation diagnostics

If the independent client rejects an ID Token with `Unable to verify JWT claims`, the
callback page displays non-sensitive boolean diagnostics for issuer, audience, subject,
nonce, expiration and not-before checks. It does not display the ID Token, nonce, access
token, client secret or other credential values. The diagnostic client delegates the final
accept/reject decision to the upstream `jumbojett/openid-connect-php` implementation; it does
not bypass or relax validation.

## Routes

- `/` — test client home page.
- `/login` — begin OIDC authentication.
- `/callback` — fixed registered callback.
- `/health` — client health check.
- `/logout` — clear the local RP session.

## Automated local checks

```cmd
vendor\bin\phpunit
vendor\bin\phpstan analyse
vendor\bin\php-cs-fixer fix --dry-run --diff
```

The PHPUnit suite tests the independent profile/JWKS response validator. The browser-based
interoperability login remains available for interactive testing. The security-check script also
performs its own test-only authorization transactions over HTTPS using the configured test account.
The `bin/check-provider.php` command tests live discovery and JWKS endpoints.

## Important limitations

- This is one independent client implementation, not an OIDC certification result.
- The independent client's own validation behavior is not treated as a normative substitute for
  the OpenID Connect specifications. The harness adds checks for nonce presence and UserInfo `sub`
  consistency; negative probes cover only the scenarios listed in the Phase 6D guide.
- This is a local test harness only. Do not expose it publicly or use real user credentials.

## Negative protocol checks

With the reference provider running, execute this from `interop-client/`:

```cmd
composer security-checks
```

It performs live HTTPS checks for invalid client credentials, unknown/missing authorization codes,
unsupported grant types, unauthenticated/invalid UserInfo requests, incorrect PKCE verifiers, and
authorization-code reuse, refresh-token issuance, rotation, replay rejection and family revocation,
RP-Initiated Logout, and protected Dynamic Client Registration when enabled by the provider. The
authorization-flow checks require the test-only account credentials
from `reference-provider/.env` to be copied into `interop-client/.env`. See
[`../docs/PHASE-6D-NEGATIVE-INTEROP-TESTING.md`](../docs/PHASE-6D-NEGATIVE-INTEROP-TESTING.md)
for exact coverage and remaining limitations.


## Phase 6D.2 — Token and ID Token security checks

The combined command now also runs `bin/token-id-token-security-checks.php`.

### Required local reference-provider configuration

In `reference-provider/.env`, set these test-only values (use a long random secret and copy the same value to the interop client):

```ini
OIDC_REFERENCE_ACCESS_TOKEN_TTL_SECONDS=5
OIDC_REFERENCE_TEST_CONTROL_SECRET=your-long-random-test-only-secret
```

In `interop-client/.env`, add:

```ini
OIDC_INTEROP_TEST_CONTROL_SECRET=your-long-random-test-only-secret
```

Also keep `OIDC_INTEROP_TEST_USERNAME` and `OIDC_INTEROP_TEST_PASSWORD` configured as in Phase 6D.1. Restart Apache after changing the reference-provider `.env`; the five-second access-token lifetime is intentionally short and is only suitable for this local test harness.

The provider exposes a test-only access-token revocation route only when `OIDC_REFERENCE_TEST_CONTROL_SECRET` is set. The route requires the matching `X-Reference-Test-Control` header and returns 404 when the secret is absent or incorrect. Do not enable this test-control secret or route in a deployed provider.

Run from `interop-client/`:

```cmd
composer security-checks
```

The additional checks exercise access-token revocation and expiry through UserInfo, verify a genuine RS256 ID Token signature against the provider's published JWKS, reject a modified signature, check key-ID resolution, and validate issuer/audience claim matching. The issuer/audience negative cases are claim-policy probes in the test harness; they are not forged, provider-signed ID Tokens or a formal OpenID Foundation conformance test.

### Signing-key rotation

The simple active/retired-key configuration is described in the reference-provider README. For the
full two-stage interoperability test—including a token issued before rotation, verification of that
token against the post-rotation JWKS, a new token signed by the new key, and a browser RP login—use
the dedicated [Phase 6D.3 procedure](../docs/PHASE-6D3-KEY-ROTATION.md) below.

## Phase 6D.3 — Signing-key rotation

The two-stage live HTTPS test is documented in [`../docs/PHASE-6D3-KEY-ROTATION.md`](../docs/PHASE-6D3-KEY-ROTATION.md).

1. Configure a longer temporary ID Token lifetime and the old/new key IDs.
2. Run `composer security-checks:rotation:prepare` while the old key is active.
3. Generate a new provider key pair, retain the old **public** key, switch the active key, and restart Apache.
4. Run `composer security-checks:rotation:verify`.
5. Complete a new browser login at `https://oidc-client.loc/` and confirm the result reports the new `kid`.

The preparation command stores a short-lived ID Token in the ignored `interop-client/var/` directory
so the verification command can prove that the old signature remains valid after rotation. The state
file is deleted after successful verification. Do not commit or share it.
