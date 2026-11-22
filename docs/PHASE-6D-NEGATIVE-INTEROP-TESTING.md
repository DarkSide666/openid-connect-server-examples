# Phase 6D — Negative interoperability and security checks

This phase adds an executable negative-protocol probe to the independent
`jumbojett/openid-connect-php` interoperability project. It sends real HTTPS requests to the
separately running reference provider. It does not use the provider's internal PHP classes.

## Run the automated negative checks

Start the reference provider under HTTPS and make sure its discovery endpoint is reachable. From
`interop-client/`, run:

```cmd
composer security-checks
```

The probe checks:

1. Discovery is reachable over certificate-verified HTTPS and reports the configured issuer.
2. The token endpoint rejects deliberately incorrect client credentials.
3. The token endpoint rejects an unknown authorization code.
4. The token endpoint rejects a missing authorization code.
5. The token endpoint rejects the unsupported refresh-token grant.
6. UserInfo rejects a request without a Bearer token.
7. UserInfo rejects a malformed/unknown Bearer token.

The combined command also runs `bin/authorization-flow-security-checks.php`. This second probe
creates real authorization transactions through the provider's interactive login form and checks:

8. A real authorization code cannot be redeemed with an incorrect PKCE verifier.
9. A valid authorization code and its correct PKCE verifier are accepted.
10. The same authorization code cannot be redeemed a second time.

For these flow checks, configure `OIDC_INTEROP_TEST_USERNAME` and
`OIDC_INTEROP_TEST_PASSWORD` in `interop-client/.env` using the test-only account values from
`reference-provider/.env`. The script performs the login form POST over verified HTTPS, carries the
provider session cookie, and does not follow redirects automatically.

The scripts print status codes, OAuth error identifiers and non-secret check details. They never
print credentials, access tokens, ID Tokens, authorization codes, or response bodies.

The combined command also runs `bin/token-id-token-security-checks.php`. It obtains authorization
codes and checks that the provider echoes state correctly and includes the exact requested nonce in
the ID Token. It also checks UserInfo behavior for revoked and expired access tokens, verifies a real
RS256 ID Token signature against the published JWKS, confirms a modified signature does not verify,
and checks issuer/audience claim policies in the harness.

A passing result is evidence only for the listed checks; it is not a complete OIDC conformance or
security certification.

## Limits of the current checks

- The tampered-signature check independently verifies that the altered signature fails cryptographic
  verification. It does not feed a forged token through the browser RP library.
- The unknown-`kid` check confirms the test identifier is not published in provider JWKS; it does not
  test the RP library's behavior when a token refers to an unknown key.
- Wrong-issuer and wrong-audience checks exercise the harness's claim-policy predicate. They are not
  provider-signed tokens passed through the independent RP's validator.

The live browser flow does exercise the independent RP's validation of a genuine ID Token, including
signature, issuer, audience, expiry, not-before and nonce, plus UserInfo subject consistency. It does
not currently run forged-token rejection cases through that RP. Existing library-level regression
tests cover provider-side ID Token claim validation and UserInfo scope/token-validation behavior,
but do not substitute for the live HTTP scenarios above.

## Test boundary

The reference provider is a local test fixture with a single client, test identity, and file-backed
storage. Run these checks only against that fixture. Never use production credentials or expose the
fixture publicly. Do not include `.env`, private keys, tokens, authorization codes, or `var/` data in
bug reports or source control.
