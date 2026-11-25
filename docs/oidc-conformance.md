# OIDC conformance cases

Every language runs these cases as unit tests against a local fake IdP (TypeScript
`test/oidc/*.test.ts` with `FakeIdp`, Go `verifier_test.go`/`middleware_test.go` with `oidctest`,
Python `tests/test_oidc_*.py` with `grow_oidc.oidctest.FakeIdP`, Java `VerifierTest`/`OidcFilterTest`
with `oidctest.FakeIdp`, Rust `tests/oidc.rs`/`tests/oidc_tower.rs` with wiremock + ring). Test names
carry the case id.

| Id | Case | Expected |
| - | - | - |
| OIDC-01 | RS256 token, keys via discovery | `AuthUser` with `sub`, `email`, `name`, Casdoor role objects → names; discovery fetched once |
| OIDC-02 | ES256, ES384, ES512, RS384, RS512, PS256, PS384, PS512 tokens (Rust: no ES512); ES384 key without `alg` (Logto) | verified; `name` from `preferred_username` |
| OIDC-03 | EdDSA (Ed25519) token | verified |
| OIDC-04 | wrong `iss` | `AUTHENTICATION` naming `iss` |
| OIDC-05 | wrong `aud`; `aud` array containing the audience | rejected; accepted |
| OIDC-06 | `exp` 120 s ago / 30 s ago / 30 s ago with skew 0 | rejected / accepted (60 s skew) / rejected |
| OIDC-07 | `nbf` 120 s / 30 s in the future | rejected / accepted |
| OIDC-08 | missing or non-numeric `exp`, missing `sub` | rejected |
| OIDC-09 | `alg: none`, HS256/HS384/HS512, alg outside the allow-list, malformed token/header/payload | rejected, never fetched as a key |
| OIDC-10 | signature from another key with the same `kid` | `AUTHENTICATION` (signature) |
| OIDC-11 | key rotation: new `kid` after the cooldown | JWKS refetched once, token accepted |
| OIDC-12 | unknown `kid` within the 30 s cooldown | rejected without refetch |
| OIDC-13 | concurrent verifications, TTL expiry, `clearCache`, token without `kid` | one fetch; refetch after 10 min; refetch after clear; all compatible keys tried |
| OIDC-14 | explicit JWKS URL | discovery never called |
| OIDC-15 | IdP returns 500 / non-JSON / no `jwks_uri` / no `keys` / connection refused | `UNAVAILABLE` |
| OIDC-16 | roles claim: dotted path, space-separated string, missing, mixed array | `editor`; `a`,`b`; none; strings + `name`/`code`/`role`/`value` objects, deduplicated |
| OIDC-17 | `fromEnv`: `GROW_AUTH_*`, audience fallback to client id, invalid skew, missing issuer/audience | values applied; `CONFIG` errors name the variable |
| OIDC-18 | framework adapters (Express, NestJS guards, net/http, FastAPI, ASGI, Django, servlet, tower) | 401 without/invalid token (`WWW-Authenticate: Bearer`), 403 without role, 200 with role (case-insensitive), optional mode, public paths, 503 when the IdP is down |
| OIDC-19 | header `alg` that does not match the key: P-256 key + ES384, P-384 key + ES256, RSA key with `alg: RS256` + PS256, EC key + RS256, RSA key + ES256; PKCS#1 signature under a PS256 header | `AUTHENTICATION` (no key matches / signature); the key's `kty`, EC `crv` and `alg` decide, never the header alone |
| OIDC-20 | `iss` and configured issuer that differ only by trailing slashes (token `iss` with `/`, configured without — Authentik — and vice versa); discovery document `issuer` with or without `/` | accepted; discovery URL has no double slash; a different scheme, host, port or path (or a missing `iss`) is still rejected naming `iss` |
