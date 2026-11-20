# Compatibility

## Runtimes

| Language | Supported | Tested in CI |
| - | - | - |
| TypeScript | Node.js ≥ 22.12, ESM and CommonJS | Node 22, 24 |
| Rust | MSRV 1.88, edition 2021, tokio | stable, 1.88 |
| Go | Go ≥ 1.26 | 1.26, 1.27 |
| Python | ≥ 3.10 | 3.10, 3.13, 3.14 |
| Java | ≥ 17 (Java 17 bytecode) | Temurin 17, 21, 25 |

## OIDC versions

The integration suite runs against `casbin/casdoor:v4.27.1`. Other versions that expose the same API are
expected to work; report problems as an issue.

## Functions the service or a language cannot serve

Every public function is called against the real service in the Docker suite. Functions that the
service, its emulator or a deployment type cannot serve are listed here with the reason; they are
covered by unit tests and raise `UNSUPPORTED` where the capability is missing.

| Function | Languages | Reason |
| - | - | - |
| — | — | none so far |

## Skipped conformance scenarios

| Scenario | Reason |
| - | - |
| — | none so far |

## Language differences

The API is the same in every language; only the conventions differ (naming, durations, async
model). Java cannot change the process environment, so `loadEnv` sets **system properties**
instead and returns the names it set.

## Token verification differences

- Rust ships no public fake IdP (ring cannot generate RSA keys); its tests use wiremock + a test-only
  RSA fixture. The other languages export one (`FakeIdp`, `oidctest`, `FakeIdP`, `oidctest.FakeIdp`).
- Python's `averify` does not deduplicate concurrent JWKS fetches (the sync `verify` does).
- Java's `verifyAsync` runs `verify` on the common pool.
- The Docker suite runs Casdoor v4.27.1 + PostgreSQL (`docker/compose.service.yml`).
  `docker/bootstrap/mint.py` creates organization `oidc-it`, application `oidc-it-app` (JWT
  tokens, password grant), role `oidc-it-admin` and user `oidc-it-user`, mints a real access token
  and writes `GROW_OIDC_TOKEN`, `GROW_AUTH_ISSUER` (the token `iss`, `http://service:8000`),
  `GROW_AUTH_AUDIENCE`/`GROW_AUTH_CLIENT_ID` and the expected `sub`/`email`/role. Every language
  verifies that token with `Verifier.fromEnv` (discovery + JWKS).
- `serverVersion` is always `UNSUPPORTED`: OpenID Connect has no version endpoint, so the core
  conformance step `serverVersion` (capability `version`) is skipped in every language.
- `OidcClient.health` reads `<url>/.well-known/openid-configuration`; `ping` calls the
  provider's `userinfo_endpoint` with `GROW_OIDC_TOKEN` (an access token), so a wrong token is
  `AUTHENTICATION`.

