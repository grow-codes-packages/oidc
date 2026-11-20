# Functions

The OIDC API of this SDK. Every function exists in all five languages with the same
behaviour; this page shows each one with an example per language.

!!! info "Work in progress"
    The service functions are being added. Until then the client offers the shared surface:
    [`health()`, `ping()`, `serverVersion()`, `close()`](client.md).

## Overview

| Function | Description | Integration test |
| - | - | - |
| `health()` | unauthenticated liveness | `core.health` |
| `ping()` | authenticated round trip | `core.health` |
| `serverVersion()` | server version | `core.health` |

## Service configuration

| Setting | Default | Environment variables (precedence order) |
| - | - | - |
| `url` | `http://127.0.0.1:8000` | `GROW_OIDC_URL` |
| `token` | none | `GROW_OIDC_TOKEN` |

Environment variables recognised by this SDK (explicit config values always win; `GROW_*` names
come before vendor names): `GROW_AUTH_ISSUER`, `GROW_AUTH_AUDIENCE`, `GROW_AUTH_JWKS_URL`, `GROW_AUTH_ROLES_CLAIM`, `GROW_AUTH_CLIENT_ID`, `GROW_OIDC_*`.
