# DarkSide OpenID Connect Server examples

Test-only applications for [darkside/openid-connect-server](https://github.com/darkside666/openid-connect-server).

| Project | Purpose |
| --- | --- |
| `reference-provider/` | Test-only provider that exercises the library through OIDC endpoints over HTTPS. |
| `interop-client/` | Independent relying-party client and live protocol/security probes. |

Neither project is a production identity provider or relying party. The reference provider uses a
static identity, test credentials and file-backed storage. Generated `.env` files and `var/`
directories are ignored.

## Composer dependency

Each project has its own Composer configuration and should be installed from its own directory. The
reference provider consumes [`darkside/openid-connect-server` from Packagist](https://packagist.org/packages/darkside/openid-connect-server); it does not require a
sibling library checkout or a local path repository. Its development constraint accepts the
`main` and `develop` branches for cross-repository testing. The committed lockfile pins the exact
package commit used by a normal `composer install`.

The GitHub Actions workflows update that dependency to the corresponding `main` or `develop` branch
before running provider checks. For an application derived from the reference provider, use a
released library version from Packagist rather than a development branch.

Install and check each project independently:

```sh
cd reference-provider
composer install
composer test
composer analyse
composer format:check
```

Run the same commands from `interop-client/` for that project's checks. If Windows PHP needs an
OpenSSL configuration, set `OPENSSL_CONF` in the command prompt before running Composer or PHP. For
example:

```cmd
set OPENSSL_CONF=C:\path\to\php\extras\ssl\openssl.cnf
```

The library repository owns the live interoperability workflow. It checks out this examples
repository, resolves the matching library branch through Packagist, starts the reference provider
behind a local HTTPS proxy, and runs the independent RP's live security probes. Examples CI runs each
project's unit tests, PHPStan and formatting checks.
