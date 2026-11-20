# grow-oidc (Rust)

Rust SDK for OIDC by [Grow Codes](https://grow.codes). Async on tokio, with an optional
blocking client.

```toml
[dependencies]
grow-oidc = "0.1.0"
# blocking client:   features = ["blocking"]
# test fakes/runner: features = ["testing"] (dev-dependency)
```

```rust,no_run
use grow_oidc::{OidcClient, OidcConfig};

#[tokio::main]
async fn main() -> grow_oidc::Result<()> {
    // explicit > GROW_OIDC_* > vendor variables > defaults
    let client = OidcClient::new(OidcConfig::from_env()?)?;
    println!("{:?}", client.health().await?);
    client.close().await;
    Ok(())
}
```

- Errors: one `Error` enum with `code()`, `http_status()`, `request_id()`, `is_retryable()`,
  `retry_after()`; messages never contain credentials.
- Retries with full-jitter backoff and `Retry-After`, connect/request/total timeouts,
  cancellation (drop the future or pass a `CancellationToken`), request hooks, `tracing` debug
  events.
- MSRV 1.88. Licence Apache-2.0. Documentation: https://grow-codes-packages.github.io/oidc/

Development: `make deps build lint test coverage license pack docs` (see `Makefile`).
`make lint` also runs `cargo clippy --lib --no-default-features`: code that needs an optional
feature (for example tonic TLS types behind `otlp-tls`) must sit behind
`#[cfg(feature = "...")]`.
