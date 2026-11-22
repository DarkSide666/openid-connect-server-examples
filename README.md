# DarkSide OpenID Connect Server examples

Test-only applications for [darkside/openid-connect-server](https://github.com/darkside666/openid-connect-server).

| Project | Purpose |
| --- | --- |
| `reference-provider/` | Protocol fixture used by the live interoperability harness. |
| `interop-client/` | Independent relying-party client and negative/security probes. |

These projects are not production identity providers or relying parties. They use static identities,
test credentials, and file-backed storage. Generated `.env` files and `var/` directories are ignored.

## Development layout

For local development, place both repositories next to each other:

```text
workspace/
├── openid-connect-server/
│   └── openid-connect-server/
└── openid-connect-server-examples/
```

The provider projects use a Composer path repository at `../../openid-connect-server`, so they test the
current library checkout. For normal consumer use, replace `dev-main` with an appropriate released
library constraint before distributing an application derived from an example.

On Windows, call `_set_openssl_conf.cmd` before Composer or PHPUnit commands when the local OpenSSL
installation requires `OPENSSL_CONF` to be set.

## Checks

Run each project’s `composer test`, `composer analyse`, and `composer format:check`. The library
repository additionally owns the required live interoperability workflow, which checks out this
repository and runs the reference provider plus independent RP checks against the candidate library.
If the library repository is private, configure `LIBRARY_REPOSITORY_TOKEN` in this repository with
read access so Examples CI can check it out.

The `OIDC_*_ALLOW_INSECURE_HTTP_FOR_CI=1` settings are reserved for the ephemeral CI harness. They
must never be used in local, staging, or production deployments; ordinary interop configuration
requires HTTPS and certificate verification.
