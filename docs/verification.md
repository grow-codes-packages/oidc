# Token verification (`oidc`)

Provider-neutral bearer-token verification for resource servers (Casdoor, Keycloak, Zitadel,
Authentik, FusionAuth, Cognito, any OpenID Connect provider). Same behaviour in every language.
This file ships inside every package (npm, Go module, wheel, jar `META-INF/grow/oidc/AGENTS.md`, crate).

## What it checks

- Signature with keys from `GROW_AUTH_JWKS_URL`, else OIDC discovery
  (`<issuer>/.well-known/openid-configuration` → `jwks_uri`). Algorithms: **RS256, ES256, EdDSA**
  only (`none`/HMAC always rejected; RSA keys ≥ 2048 bit).
- `iss` == issuer (exact), `aud` == or contains audience, `exp` required, `nbf`, `sub` required;
  clock skew **60 s**.
- JWKS cache 10 min; a token with an unknown `kid` triggers one refetch (key rotation), at most once
  per 30 s.
- Roles from `GROW_AUTH_ROLES_CLAIM` (default `roles`; dotted paths like `realm_access.roles`).
  Claim may be a string (split on commas/whitespace) or an array of strings or objects
  (Casdoor `{"name": "admin", …}` → `admin`; also `code`/`role`/`value`). Role checks are
  case-insensitive and mean "has at least one of".
- Errors: `AUTHENTICATION` for every bad token (message names the failed check, never the token),
  `UNAVAILABLE` when discovery/JWKS cannot be fetched, `CONFIG` for bad settings. HTTP adapters
  answer **401** (missing/invalid token, `WWW-Authenticate: Bearer`), **403** (role missing),
  **503** (IdP unreachable) with a JSON body `{"error": "unauthorized" | "forbidden" | "auth_unavailable"}`.

## Environment (`fromEnv`)

| Variable | Meaning |
| - | - |
| `GROW_AUTH_ISSUER` | required; must equal the token's `iss` (Casdoor in-stack: `http://casdoor:8000`) |
| `GROW_AUTH_AUDIENCE` | expected `aud`; default `GROW_AUTH_CLIENT_ID` |
| `GROW_AUTH_JWKS_URL` | optional; skips discovery |
| `GROW_AUTH_ROLES_CLAIM` | default `roles` |
| `GROW_AUTH_CLOCK_SKEW` | optional duration (`60s`, `1500` ms) |

## TypeScript — `npm i @grow-codes/oidc`

```ts
import { Verifier, expressAuth, requireRoles, NestAuthGuard, RolesGuard, Roles, Public, bearerToken } from "@grow-codes/oidc";
const verifier = Verifier.fromEnv();                       // or new Verifier({ issuer, audience, jwksUrl?, rolesClaim? })
const user = await verifier.verify(token);                 // AuthUser { sub, email?, name?, roles: string[], claims }
await verifier.verifyRequest(request);                     // Fetch Request / Node req / Headers (Next.js, TanStack Start)
app.use("/api", expressAuth(verifier));                    // sets req.user; expressAuth(verifier, { optional: true })
app.get("/api/admin", requireRoles("admin"), handler);     // 401 without user, 403 without role
// NestJS (main.ts): app.useGlobalGuards(new NestAuthGuard(verifier), new RolesGuard());
// controllers: @Public() on health/docs routes, @Roles("admin") on protected ones; request.user is the AuthUser
```
Options: `algorithms`, `clockSkewMs`, `jwksCacheTtlMs`, `jwksRefreshCooldownMs`, `httpTimeoutMs`, `fetch`, `now`.
Tests: `import { FakeIdp } from "@grow-codes/oidc/testing"` → `await new FakeIdp("aud").start()`, `idp.issuer`, `await idp.mint({ claims: { roles: ["admin"] } })`, `idp.rotate("ES256")`.

## Go — `go get github.com/grow-codes-packages/oidc/go`

```go
import oidc "github.com/grow-codes-packages/oidc/go"
v, err := oidc.FromEnv(ctx)                  // or oidc.New(oidc.Options{Issuer, Audience, JWKSURL, RolesClaim})
user, err := v.Verify(ctx, token)            // *oidc.User{Sub, Email, Name, Roles, Claims}
mux.Handle("/api/", v.Middleware(api))       // v.OptionalMiddleware(h) lets anonymous requests through
mux.Handle("/api/admin", v.Middleware(oidc.RequireRoles("admin")(admin)))
u, ok := oidc.UserFrom(r.Context())          // errors.Is(err, oidc.ErrAuthentication / oidc.ErrUnavailable)
```
Also `oidc.BearerToken(r)`, `oidc.ExtractRoles(claims, path)`, `oidc.HasAnyRole`, `oidc.WithUser`, `oidc.FromEnvWith(ctx, opts, getenv)`.
Tests: `import "github.com/grow-codes-packages/oidc/go/oidctest"` → `idp := oidctest.New("aud", "RS256")`, `idp.Issuer`, `idp.Mint(map[string]any{"roles": []any{"admin"}}, oidctest.MintOptions{})`.

## Python — `pip install grow-oidc` (`[fastapi]`, `[django]` extras)

```python
from grow_oidc import (
    AuthUser,
    DjangoOidcMiddleware,
    OidcMiddleware,
    Verifier,
    django_require_roles,
    require_user,
)

# or Verifier(issuer, audience, jwks_url=None, roles_claim="roles")
verifier = Verifier.from_env()
# AuthUser(sub, roles, claims, email, name); async: await verifier.averify(token)
user = verifier.verify(token)


# FastAPI; the verifier defaults to Verifier.from_env()
@app.get("/admin")
async def admin(user: AuthUser = Depends(require_user(roles=["admin"]))): ...


# pure ASGI; public_paths default /health*, /docs, /openapi.json
app.add_middleware(OidcMiddleware, verifier=verifier)
# Django: MIDDLEWARE += ["grow_oidc.integrations.DjangoOidcMiddleware"]
# and @django_require_roles("admin") on views
```
Tests: `from grow_oidc.oidctest import FakeIdP` → `with FakeIdP(audience="api") as idp: idp.mint({"roles": ["admin"]})`.

## Java — `codes.grow.packages:oidc`

```java
Verifier verifier = Verifier.fromEnv();     // or Verifier.builder().issuer(..).audience(..).jwksUrl(..).rolesClaim(..).build()
AuthUser user = verifier.verify(token);     // record AuthUser(sub, email, name, roles, claims); verifyAsync(token)
// Servlet (Spring Boot: FilterRegistrationBean): new OidcFilter(verifier) then new RequireRolesFilter("admin")
// request.getUserPrincipal() / isUserInRole("admin") / OidcFilter.user(request)
```
Packages: `codes.grow.packages.oidc` (`Verifier`, `AuthUser`, `Roles`), `.servlet` (`OidcFilter`, `RequireRolesFilter`; needs `jakarta.servlet-api` 5+ from the container), `.oidctest` (`FakeIdp.start("aud", "RS256")`).

## Rust — `cargo add grow-oidc --features tower`

```rust
let verifier = grow_oidc::Verifier::from_env()?;   // or Verifier::new(VerifierOptions { issuer, audience, ..Default::default() })
let user = verifier.verify(token).await?;           // AuthUser { sub, email, name, roles, claims }
let app = Router::new()
    .route("/admin", get(admin).layer(RequireRolesLayer::new(["admin"])))
    .layer(OidcLayer::new(verifier));               // handlers: Extension(user): Extension<AuthUser>
```
Also `bearer_token`, `extract_roles`, `has_any_role`, `claim_at`. `OidcLayer::new(v).optional()`.

## Pitfalls

- `GROW_AUTH_ISSUER` must equal the `iss` of a real token minted the way your frontend/BFF gets
  it (Casdoor sets `iss` from the request origin: in-stack tokens carry `http://casdoor:8000`).
- Roles missing → the IdP app must issue JWT access tokens with roles (Casdoor `tokenFormat: "JWT"`
  and the user added to the role).
- Never log tokens; never skip issuer/audience checks; keep health/docs routes public explicitly.
