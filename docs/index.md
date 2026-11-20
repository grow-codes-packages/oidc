# OIDC SDK

[![Grow Codes](https://img.shields.io/badge/Grow%20Codes-grow.codes-2ea44f)](https://grow.codes)
[![CI](https://github.com/grow-codes-packages/oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/grow-codes-packages/oidc/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](license.md)

One API for **OIDC** in five languages: TypeScript, Rust, Go, Python and Java. Every package
has the same functions, options, defaults, error codes and behaviour, tested against a real
`casbin/casdoor:v4.27.1` in Docker.

| Language | Package | Coverage |
| - | - | - |
| TypeScript | [`@grow-codes/oidc`](https://www.npmjs.com/package/@grow-codes/oidc) | ![TypeScript coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-typescript.json) |
| Rust | [`grow-oidc`](https://crates.io/crates/grow-oidc) | ![Rust coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-rust.json) |
| Go | [`github.com/grow-codes-packages/oidc/go`](https://pkg.go.dev/github.com/grow-codes-packages/oidc/go) | ![Go coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-go.json) |
| Python | [`grow-oidc`](https://pypi.org/project/grow-oidc/) | ![Python coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-python.json) |
| Java | [`codes.grow.packages:oidc`](https://central.sonatype.com/artifact/codes.grow.packages/oidc) | ![Java coverage](https://img.shields.io/endpoint?url=https://grow-codes-packages.github.io/oidc/badges/coverage-java.json) |

## What you get

- **Client** with health, authenticated ping and server version ([Client](client.md)).
- **Configuration** from code or `GROW_OIDC_*` / vendor environment variables, immutable
  and validated ([Configuration](configuration.md)).
- **Retries** with full-jitter backoff and `Retry-After`, connect/request/total timeouts and
  cancellation in every language.
- **Typed errors** with one set of codes across languages ([Error handling](errors.md)).
- **Redaction everywhere**: credentials never appear in errors, logs, hooks or `toString`
  ([Redaction](redaction.md)).
- **Service functions** for the OIDC API ([Functions](functions.md)).

Start with [Install](install.md) and the [Quickstart](quickstart.md).

!!! note "Independent project"
    This SDK is made by [Grow Codes](https://grow.codes). OIDC is a trademark of
    its owner (OpenID Foundation (specification); any OpenID Connect provider); this project is not affiliated with or endorsed by it. See
    [License & disclaimer](license.md).
