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

The scripts print only HTTP status codes, OAuth error identifiers and whether token fields were
returned. They never print credentials, access tokens, ID Tokens, authorization codes, or response
bodies.

A passing result is evidence for these exact negative cases only; it is not a complete OIDC
conformance or security certification.

## Remaining scenarios

The following scenarios remain outside the automated checks in this phase:

- Confirm that the independent RP rejects a token whose signature is modified, whose signing key is
  unknown, or whose issuer/audience is wrong. These are RP-side validation tests; do not weaken the
  real provider's validation to manufacture a pass.
- Confirm the provider rejects an expired or revoked access token at UserInfo. An unknown token is
  covered automatically; expiration/revocation requires a token that was once valid.

Existing library-level regression tests cover the provider's ID Token claim validation and UserInfo
scope/token-validation behavior, but do not substitute for the live HTTP scenarios above.

## Test boundary

The reference provider is a local test fixture with a single client, test identity, and file-backed
storage. Run these checks only against that fixture. Never use production credentials or expose the
fixture publicly. Do not include `.env`, private keys, tokens, authorization codes, or `var/` data in
bug reports or source control.
