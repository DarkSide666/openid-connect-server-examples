# Phase 7E — Independent integration example

## Objective

Provide a complete example of integrating the library into a PHP HTTP application without making
the example depend on the `reference-provider/` application or its PHP namespace.

## Delivered

- Added `standalone-provider/` as a separate Composer project consuming the sibling
  `openid-connect-server` checkout through a local path repository.
- Added its own Slim HTTP entry point, provider wiring, League repository/entity adapters, identity
  resolver, file-backed test stores, setup/key-generation scripts, environment configuration, and
  fixture tests.
- Gave the example its own `DarkSide\\OidcStandaloneExample` namespace and `OIDC_STANDALONE_*`
  environment-variable prefix.
- Demonstrated the complete current Authorization Code + PKCE S256 + nonce profile, discovery,
  JWKS, ID Token, and UserInfo wiring.
- Linked the example from the library README and integration guide.

## Boundaries

This is a runnable integration example, not a production deployment template. It intentionally
uses a single static client and test identity plus local file-backed storage. Those adapters are
owned by the example and do not become part of the library's public API. Real applications must
replace them with durable, concurrency-safe application storage and their own authentication,
consent, client management, and operational controls.

No OIDC protocol capabilities or library runtime features were added in this phase.

## Verification

- Run the example's own `composer install`, `composer test`, `composer analyse`, and
  `composer format:check`. The examples CI also runs these checks against the library's `main`
  branch, while library pull requests run live interoperability checks against the candidate source.
