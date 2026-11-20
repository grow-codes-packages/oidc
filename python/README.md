# grow-oidc (Python)

Python SDK for [OIDC](https://grow-codes-packages.github.io/oidc/) by Grow Codes.
Unofficial and community maintained; "OIDC" is a trademark of its owner (OpenID Foundation (specification); any OpenID Connect provider).

```bash
pip install grow-oidc
```

```python
from grow_oidc import OidcClient, OidcConfig

# Reads GROW_OIDC_URL, GROW_OIDC_TOKEN, ... from the environment.
with OidcClient.from_env() as client:
    print(client.health())
    print(client.server_version())
```

The async client has the same methods:

```python
import asyncio
from grow_oidc import AsyncOidcClient

async def main() -> None:
    async with AsyncOidcClient.from_env() as client:
        print(await client.health())

asyncio.run(main())
```

- Python 3.10 or newer, typed (`py.typed`), `httpx` based, environment proxies ignored unless
  configured.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation, hooks and a silent-by-default `logging` logger named `grow_oidc`.
- Credentials are wrapped in `Secret` and never appear in `repr()`, logs or error messages.
- `grow_oidc.testing` ships in-memory fakes and the conformance runner.

Documentation: https://grow-codes-packages.github.io/oidc/ ·
Source: https://github.com/grow-codes-packages/oidc · Licence: Apache-2.0
