# Grow Codes SDK for OIDC

[![CI](https://github.com/grow-codes-packages/oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/oidc/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/grow-codes-packages/oidc?sort=semver)](https://github.com/grow-codes-packages/oidc/releases)
[![Docs](https://img.shields.io/badge/docs-grow--codes--packages.github.io-blue)](https://grow-codes-packages.github.io/oidc/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [![npm](https://img.shields.io/npm/v/@grow-codes/oidc)](https://www.npmjs.com/package/@grow-codes/oidc) | [![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-typescript.json)](https://github.com/grow-codes-packages/oidc/actions/workflows/ci.yml) |
| Rust | [![crates.io](https://img.shields.io/crates/v/grow-oidc)](https://crates.io/crates/grow-oidc) [![docs.rs](https://img.shields.io/docsrs/grow-oidc)](https://docs.rs/grow-oidc) | [![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-rust.json)](https://github.com/grow-codes-packages/oidc/actions/workflows/ci.yml) |
| Go | [![Go Reference](https://pkg.go.dev/badge/github.com/grow-codes-packages/oidc/go.svg)](https://pkg.go.dev/github.com/grow-codes-packages/oidc/go) | [![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-go.json)](https://github.com/grow-codes-packages/oidc/actions/workflows/ci.yml) |
| Python | [![PyPI](https://img.shields.io/pypi/v/grow-oidc)](https://pypi.org/project/grow-oidc/) | [![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-python.json)](https://github.com/grow-codes-packages/oidc/actions/workflows/ci.yml) |
| Java | [![Maven Central](https://img.shields.io/maven-central/v/codes.grow.packages/oidc)](https://central.sonatype.com/artifact/codes.grow.packages/oidc) | [![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-java.json)](https://github.com/grow-codes-packages/oidc/actions/workflows/ci.yml) |

Provider-neutral **OpenID Connect access-token verification** in **TypeScript, Rust, Go, Python and
Java** — one API, five idiomatic packages: JWKS discovery, caching and key rotation,
RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA (Rust: no ES512; Logto's ES384 default works),
`iss`/`aud`/`exp`/`nbf` checks with 60 s clock skew, roles from a configurable claim (Casdoor role
objects included) and framework adapters (Express, NestJS, net/http, FastAPI, ASGI, Django, Jakarta
Servlet, tower/axum). Configured from `GROW_AUTH_*`. See [docs/verification.md](docs/verification.md).

- **Typed client** with timeouts, retries with jitter, `Retry-After`, cancellation and one error
  model (`OidcError` with canonical codes) in every language.
- **Secrets stay secret**: credentials are redacted in `toString`, logs, hooks and error messages.

## Contents

- [Supported service version](#supported-service-version)
- [Install](#install)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Function overview](#function-overview)
- [Testing with Docker](#testing-with-docker)
- [Compatibility](#compatibility)
- [Contributing](#contributing)
- [Security](#security)
- [Licence](#licence)
- [Trademarks and disclaimer](#trademarks-and-disclaimer)
- [About Grow Codes](#about-grow-codes)

## Supported service version

Tested in CI against **`casbin/casdoor:v4.27.1`** (the version pinned in the Grow Codes stack catalog). Other
versions with the same API usually work; see [Compatibility](#compatibility) and
[docs/compatibility.md](docs/compatibility.md).

## Install

| Language | Package | Install |
| - | - | - |
| TypeScript (Node.js ≥ 22.12) | `@grow-codes/oidc` | `npm install @grow-codes/oidc` |
| Rust (MSRV 1.88) | `grow-oidc` | `cargo add grow-oidc` |
| Go (1.26+) | `github.com/grow-codes-packages/oidc/go` | `go get github.com/grow-codes-packages/oidc/go` |
| Python (≥ 3.10) | `grow-oidc` | `pip install grow-oidc` |
| Java (17+) | `codes.grow.packages:oidc` | see below |

Maven:

```xml
<dependency>
  <groupId>codes.grow.packages</groupId>
  <artifactId>oidc</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
implementation("codes.grow.packages:oidc:0.1.0")
```

## Quickstart

Every package reads its configuration from the environment (`GROW_OIDC_URL`,
`GROW_OIDC_TOKEN`, …, see [Configuration](#configuration)) or from an explicit config
object. The examples check the service health and make one authenticated call.

### TypeScript

```ts
import { OidcClient } from "@grow-codes/oidc";

const client = OidcClient.fromEnv();
try {
  const health = await client.health();
  console.log(health.healthy, health.status);
  console.log("latency ms:", await client.ping());
} finally {
  await client.close();
}
```

### Rust

```rust
use grow_oidc::OidcClient;

#[tokio::main]
async fn main() -> Result<(), grow_oidc::Error> {
    let client = OidcClient::from_env()?;
    let health = client.health().await?;
    println!("{} {}", health.healthy, health.status);
    println!("latency: {:?}", client.ping().await?);
    client.close().await;
    Ok(())
}
```

### Go

```go
package main

import (
	"context"
	"fmt"
	"log"

	oidc "github.com/grow-codes-packages/oidc/go"
)

func main() {
	ctx := context.Background()
	client, err := oidc.NewClientFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	health, err := client.Health(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(health.Healthy, health.Status)
}
```

### Python

```python
from grow_oidc import OidcClient

with OidcClient.from_env() as client:
    health = client.health()
    print(health.healthy, health.status)
    print("latency ms:", client.ping())
```

Async code uses `AsyncOidcClient` with the same methods (`async with`, `await client.health()`).

### Java

```java
import codes.grow.packages.oidc.OidcClient;

try (OidcClient client = OidcClient.fromEnv()) {
    var health = client.health();
    System.out.println(health.healthy() + " " + health.status());
    System.out.println("latency ms: " + client.ping());
}
```

More complete programs live in [examples/](examples/) — one folder per language.

## Configuration

All settings can be passed in code or through environment variables. Precedence: **explicit value >
`GROW_OIDC_*` variable > vendor variable > default.** A present but invalid value raises a
`ConfigError` that names the variable (never its value).

| Setting | Environment variable | Default |
| - | - | - |
| `url` | `GROW_OIDC_URL` | service default |
| `token` | `GROW_OIDC_TOKEN` | none |
| `connectTimeout` | `GROW_OIDC_CONNECT_TIMEOUT` | 10 s |
| `requestTimeout` (per attempt) | `GROW_OIDC_REQUEST_TIMEOUT` | 30 s |
| `totalTimeout` (including retries) | `GROW_OIDC_TOTAL_TIMEOUT` | 120 s |
| `retry.maxRetries` | `GROW_OIDC_MAX_RETRIES` | 3 |
| `tls.caCertPath` | `GROW_OIDC_CA_CERT` | system roots |
| `tls.clientCertPath` / `tls.clientKeyPath` | `GROW_OIDC_CLIENT_CERT` / `GROW_OIDC_CLIENT_KEY` | none |
| `tls.insecureSkipVerify` (tests only) | `GROW_OIDC_INSECURE_SKIP_VERIFY` | `false` |
| `proxy` | `GROW_OIDC_PROXY` | none (environment proxies are ignored) |
| `headers`, `userAgentSuffix`, `hooks`, `logger` | — | none |

Vendor variables that are also read: `GROW_AUTH_ISSUER`, `GROW_AUTH_AUDIENCE`, `GROW_AUTH_JWKS_URL`, `GROW_AUTH_ROLES_CLAIM`, `GROW_AUTH_CLIENT_ID`, `GROW_OIDC_*`.

Durations accept milliseconds (`1500`) or units (`500ms`, `10s`, `1m30s`); booleans accept
`true/false/1/0/yes/no/on/off`. Field names follow each language's convention
(`request_timeout` in Python and Rust, `RequestTimeout` in Go). The full reference is in the
[documentation](https://grow-codes-packages.github.io/oidc/).

## Function overview

<!-- service:function-overview — the service fills this section; keep the heading. -->

The same functions exist in every language, named per language convention (`fromEnv` in
TypeScript and Java, `from_env` in Python and Rust, `FromEnv` in Go).

| Area | Functions | Description |
| - | - | - |
| Verifier | `Verifier.fromEnv`, `new Verifier({issuer, audience, jwksUrl?, rolesClaim?})`, `verify(token)`, `clearCache` | verify an access token → `AuthUser {sub, email?, name?, roles, claims}` |
| Helpers | `bearerToken`, `extractRoles`, `hasAnyRole`, `claimAt` | header parsing, roles from a claim (string, array, Casdoor objects, dotted paths) |
| TypeScript | `expressAuth`, `requireRoles`, `NestAuthGuard`, `RolesGuard`, `@Roles`, `@Public`, `verifyRequest` | Express middleware, NestJS guards, Fetch `Request` (Next.js, TanStack Start) |
| Go | `(*Verifier).Middleware`, `OptionalMiddleware`, `RequireRoles`, `UserFrom` | `net/http` middleware |
| Python | `require_user`, `OidcMiddleware`, `DjangoOidcMiddleware`, `django_require_roles`, `averify` | FastAPI dependency, ASGI and Django middleware |
| Java | `OidcFilter`, `RequireRolesFilter`, `verifyAsync` | Jakarta Servlet filters |
| Rust | `OidcLayer`, `RequireRolesLayer` (feature `tower`) | tower layers for axum/tonic/hyper |
| Testing | `FakeIdp` / `oidctest` / `FakeIdP` | local fake OpenID provider (discovery, JWKS, minting, rotation) |
| Client | `health`, `ping`, `serverVersion`, `close` | provider client: `health` reads discovery, `ping` calls `userinfo_endpoint` with `GROW_OIDC_TOKEN`, `serverVersion` is `UNSUPPORTED` (OIDC has no version) |

<!-- /service:function-overview -->

## Testing with Docker

The integration suite runs every public function against a real OIDC (`casbin/casdoor:v4.27.1`) in Docker.
Each language package is packed and installed into a separate consumer project first, so the tests
use the package exactly as you would.

```sh
make test-docker                     # all five languages
make test-docker LANGS="go python"   # a subset
```

No host ports are published and every run uses its own Compose project, so runs never collide; the
stack is always removed afterwards (`docker compose down -v`). Unit tests need no Docker:
`make test` or `make coverage`.

## Compatibility

| | TypeScript | Rust | Go | Python | Java |
| - | - | - | - | - | - |
| Runtime | Node.js ≥ 22.12, ESM + CJS | stable, MSRV 1.88 | 1.26, 1.27 | 3.10 – 3.14 | 17, 21, 25 |
| Async | `Promise` + `AbortSignal` | `async` (tokio), `blocking` feature | `context.Context` | sync + `asyncio` | sync + `CompletableFuture` |
| OIDC | `casbin/casdoor:v4.27.1` | `casbin/casdoor:v4.27.1` | `casbin/casdoor:v4.27.1` | `casbin/casdoor:v4.27.1` | `casbin/casdoor:v4.27.1` |

Functions that OIDC (or its emulator) cannot serve are listed with the reason in
[docs/compatibility.md](docs/compatibility.md).

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md) first. All five languages keep the same API; a change lands in all of them
together. Parts of this repository are generated by
[sdk-kit](https://github.com/grow-codes-packages/sdk-kit) and changed there.

## Security

Please report vulnerabilities privately to [opensource@grow.codes](mailto:opensource@grow.codes).
See [SECURITY.md](SECURITY.md).

## Licence

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for attributions.

## Trademarks and disclaimer

This is an independent, community-maintained project. It is **not affiliated with, endorsed or
sponsored by its owner (OpenID Foundation (specification); any OpenID Connect provider)**. OIDC is a trademark of OpenID Foundation (specification); any OpenID Connect provider; it is used here only to name the
service this SDK connects to. The OIDC server is licensed separately by its owner
(OpenID Connect Core 1.0 (OpenID Foundation specification); tested against Casdoor (Apache-2.0)).

The software is provided "AS IS", without warranties or conditions of any kind. Grow Codes is not
responsible for any damage, data loss, security incident, outage or cost that results from using it.
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## About Grow Codes

This SDK is built and maintained by [Grow Codes](https://grow.codes). Grow Codes publishes the
client libraries it builds as open source in the
[grow-codes-packages](https://github.com/grow-codes-packages) organisation, generated from one
shared kit so that every service and every language behaves the same way. Learn more at
[grow.codes](https://grow.codes).
