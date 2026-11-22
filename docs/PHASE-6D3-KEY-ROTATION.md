# Phase 6D.3 — Signing-key rotation verification

This procedure exercises signing-key rotation against the live, test-only reference provider over
verified HTTPS. It is not a production key-management procedure.

The test has two commands because the provider must issue one ID Token before rotation and another
after rotation:

1. `prepare` obtains an ID Token signed by the current key, verifies it against the current JWKS,
   and saves that short-lived test token in a private local state file.
2. The operator rotates the provider to a new key while retaining the old **public** key in JWKS.
3. `verify` checks the retained old key, verifies the previously issued ID Token against the new
   JWKS, obtains a new authorization code/token transaction, and verifies that the new ID Token is
   signed by the new active key.

The test-only state file is `interop-client/var/key-rotation-state.json`. It contains a temporary
ID Token and is automatically deleted after a successful verification. The directory is ignored by
Git. Do not copy or commit this file.

## 1. Configure the test

In `reference-provider/.env`, add or set:

```ini
OIDC_REFERENCE_ID_TOKEN_TTL_SECONDS=1800
```

The reference provider clamps this value to 1–3600 seconds. The longer lifetime gives enough time to
complete the manual key switch while the pre-rotation ID Token remains valid. This setting affects
only the test reference provider; the core library's default ID Token lifetime remains unchanged.

In `interop-client/.env`, add:

```ini
OIDC_INTEROP_ROTATION_OLD_KID=reference-rs256-2026
OIDC_INTEROP_ROTATION_NEW_KID=reference-rs256-2027
```

Keep the existing issuer, client credentials, redirect URI, CA bundle and test-user credentials.
The old key ID must match the provider's currently active key ID. With the untouched reference
provider configuration, that ID is `reference-rs256-2026`.

Restart Apache after changing the provider `.env` so the new lifetime setting is loaded.

## 2. Prepare before rotation

From `interop-client/` run:

```cmd
composer security-checks:rotation:prepare
```

Expected checks:

- the old key is currently the active key;
- a fresh authorization transaction produces an ID Token signed by that key;
- the ID Token signature, issuer, audience and expiration validate against the current JWKS;
- the temporary local state file is saved.

Do not rotate if preparation fails.

## 3. Preserve the old public key and generate the new pair

From `reference-provider/`, copy the current public key to a key-ID-specific filename, then generate
the new key pair:

```cmd
copy var\keys\oidc-public.pem var\keys\oidc-public-reference-rs256-2026.pem
php bin\generate-oidc-rotation-key.php reference-rs256-2027
```

The helper creates:

- `var/keys/oidc-private-reference-rs256-2027.pem`
- `var/keys/oidc-public-reference-rs256-2027.pem`

It refuses to overwrite existing files. The old private key remains private and is not configured as a
retired key.

## 4. Switch the active key and retain the old public key

Update `reference-provider/.env` with:

```ini
OIDC_REFERENCE_OIDC_KEY_ID=reference-rs256-2027
OIDC_REFERENCE_OIDC_PRIVATE_KEY_PATH=var/keys/oidc-private-reference-rs256-2027.pem
OIDC_REFERENCE_OIDC_PUBLIC_KEY_PATH=var/keys/oidc-public-reference-rs256-2027.pem
OIDC_REFERENCE_RETIRED_OIDC_KEYS=reference-rs256-2026=var/keys/oidc-public-reference-rs256-2026.pem
```

Restart Apache. Confirm the provider is reachable before continuing:

```cmd
curl.exe --fail https://oidc-reference.loc/.well-known/openid-configuration
curl.exe --fail https://oidc-reference.loc/jwks
```

Use your normal trusted CA configuration if Windows `curl.exe` does not trust the local mkcert CA.
Do not disable TLS verification.

## 5. Verify rotation

From `interop-client/` run:

```cmd
composer security-checks:rotation:verify
```

Expected checks:

- the new key is first in JWKS and is the active key;
- the old public key remains published;
- the new public key is published;
- no private RSA parameters are published;
- the pre-rotation ID Token remains unexpired and its signature validates against the rotated JWKS
  using the retained old public key;
- a new authorization transaction produces an ID Token signed by the new key and its signature,
  issuer, audience and expiration validate against the new JWKS.

The temporary state file is deleted after successful verification. If the old token expires before
verification, restore the old active-key configuration, restart Apache, run `prepare` again, then
repeat the rotation steps. Do not weaken expiration checks.

## 6. Verify with the independent browser RP

After the automated checks pass, open:

`https://oidc-client.loc/`

Start a new login. The independent `jumbojett/openid-connect-php` RP should complete the flow and
display `key_id: reference-rs256-2027`. This is an additional real browser-based check that the
independent RP can refresh/use the rotated JWKS and validate a newly issued ID Token.

## 7. Retire the old public key after the overlap period

Keep the old public key in JWKS for at least the maximum lifetime of all ID Tokens signed with it,
plus a safety margin for clock skew and RP/JWKS caching. For this test the configured ID Token
lifetime is 1800 seconds. After the overlap period, remove the old key from
`OIDC_REFERENCE_RETIRED_OIDC_KEYS` and restart Apache. Never publish a private key.

## What this test proves — and does not prove

It verifies a controlled two-key overlap and that the old and new ID Token signatures can both be
validated against the JWKS published during the overlap. It also checks a new authorization flow
and a separate browser RP after rotation.

It does not implement or validate an automated production key-management service, distributed key
rollout, JWKS cache invalidation behavior across arbitrary RPs, emergency compromise response, or
formal OpenID Foundation certification. The reference provider remains a local test fixture.
