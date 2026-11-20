# @grow-codes/oidc

TypeScript SDK for [OIDC](https://grow-codes-packages.github.io/oidc/) by Grow Codes.
Node.js 22.12 or newer, ESM and CommonJS, full type definitions.

```sh
npm install @grow-codes/oidc
```

```ts
import { OidcClient } from "@grow-codes/oidc";

// Reads GROW_OIDC_URL, GROW_OIDC_TOKEN, timeouts, TLS and proxy settings.
const client = OidcClient.fromEnv();
try {
  console.log(await client.health()); // { healthy: true, status: "ok", details: {} }
  console.log(`ping: ${(await client.ping()).toFixed(1)} ms`);
} finally {
  await client.close();
}
```

Every error is a `OidcError` subclass with a canonical `code` (`NOT_FOUND`,
`AUTHENTICATION`, `RATE_LIMITED`, …), `httpStatus`, `requestId` and `retryable`. Credentials
never appear in messages, logs, hook data or `toString()` output.

Test helpers (in-memory fakes and the conformance runner) live in
`@grow-codes/oidc/testing`.

Documentation: https://grow-codes-packages.github.io/oidc/ · Licence: Apache-2.0.
OIDC is a trademark of OpenID Foundation (specification); any OpenID Connect provider; this package is not affiliated with or endorsed by it.
