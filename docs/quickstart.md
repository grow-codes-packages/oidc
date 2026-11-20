# Quickstart

Connect to OIDC, check that it is healthy, make an authenticated call and close the client.
The client reads `GROW_OIDC_URL` and `GROW_OIDC_TOKEN` (and the vendor variables
listed in [Configuration](configuration.md)), or takes the values in code.

```sh
export GROW_OIDC_URL=http://127.0.0.1:8000
export GROW_OIDC_TOKEN=...   # never commit real tokens
```

=== "TypeScript"

    ```ts
    import { OidcClient } from "@grow-codes/oidc";

    const client = OidcClient.fromEnv();
    try {
      const health = await client.health();
      console.log("healthy:", health.healthy, health.status);
      console.log("ping:", await client.ping(), "ms");
      console.log("server version:", await client.serverVersion());
    } finally {
      await client.close();
    }
    ```

=== "Rust"

    ```rust
    use grow_oidc::OidcClient;

    #[tokio::main]
    async fn main() -> grow_oidc::Result<()> {
        let client = OidcClient::from_env()?;
        let health = client.health().await?;
        println!("healthy: {} {}", health.healthy, health.status);
        println!("ping: {:?}", client.ping().await?);
        println!("server version: {}", client.server_version().await?);
        client.close().await;
        Ok(())
    }
    ```

=== "Go"

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
        fmt.Println("healthy:", health.Healthy, health.Status)

        latency, err := client.Ping(ctx)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("ping:", latency)

        version, err := client.ServerVersion(ctx)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("server version:", version)
    }
    ```

=== "Python"

    ```python
    from grow_oidc import OidcClient

    with OidcClient.from_env() as client:
        health = client.health()
        print("healthy:", health.healthy, health.status)
        print("ping:", client.ping(), "ms")
        print("server version:", client.server_version())
    ```

    Async code uses `AsyncOidcClient` with the same methods:

    ```python
    import asyncio
    from grow_oidc import AsyncOidcClient

    async def main() -> None:
        async with AsyncOidcClient.from_env() as client:
            print(await client.health())

    asyncio.run(main())
    ```

=== "Java"

    ```java
    import codes.grow.packages.oidc.OidcClient;
    import codes.grow.packages.oidc.core.HealthStatus;

    public final class Quickstart {
      public static void main(String[] args) {
        try (OidcClient client = OidcClient.fromEnv()) {
          HealthStatus health = client.health();
          System.out.println("healthy: " + health.healthy() + " " + health.status());
          System.out.println("ping: " + client.ping().toMillis() + " ms");
          System.out.println("server version: " + client.serverVersion());
        }
      }
    }
    ```

## Next steps

- [Configuration](configuration.md): timeouts, retries, TLS, proxy, environment variables.
- [Functions](functions.md): the OIDC API of this SDK.
- [Error handling](errors.md): error codes and retries.
