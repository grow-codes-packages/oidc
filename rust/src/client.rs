// Skeleton created by sdk-kit 0.3.0; owned by this repository (edit freely).
//! `OidcClient`: entry point of the SDK (SPEC §2.4).

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use serde::Deserialize;

use crate::config::OidcConfig;
use crate::core::lifecycle::CloseGroup;
use crate::core::{Error, HealthStatus, HttpTransport, Result};

/// Async client for OIDC. Cheap to clone (clones share one connection pool).
#[derive(Debug, Clone)]
pub struct OidcClient {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: OidcConfig,
    transport: HttpTransport,
    on_close: CloseGroup,
}

/// Discovery document path, relative to the provider URL (realm prefixes such as Keycloak's kept).
pub const DISCOVERY_PATH: &str = ".well-known/openid-configuration";

#[derive(Deserialize)]
struct Discovery {
    issuer: Option<String>,
    userinfo_endpoint: Option<String>,
}

/// Path of `endpoint` relative to the provider URL `base`: the part after `base` when the endpoint
/// starts with it (keeps realm prefixes out), else the endpoint's own path and query.
pub fn relative_endpoint(base: &str, endpoint: &str) -> String {
    let root = base.trim_end_matches('/');
    if let Some(rest) = endpoint.strip_prefix(root).filter(|r| r.starts_with('/')) {
        return rest.to_owned();
    }
    match url::Url::parse(endpoint) {
        Ok(u) => match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_owned(),
        },
        Err(_) => endpoint.to_owned(),
    }
}

impl OidcClient {
    /// Creates a client from a configuration.
    pub fn new(config: OidcConfig) -> Result<Self> {
        config.validate()?;
        let transport = HttpTransport::new(config.common())?;
        if let Some(token) = config.token() {
            transport.add_known_secret(token);
        }
        Ok(OidcClient {
            inner: Arc::new(Inner {
                config,
                transport,
                on_close: CloseGroup::new(),
            }),
        })
    }

    /// Creates a client from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::new(OidcConfig::from_env()?)
    }

    /// The configuration in use.
    pub fn config(&self) -> &OidcConfig {
        &self.inner.config
    }

    /// The HTTP transport (for service modules).
    pub fn transport(&self) -> &HttpTransport {
        &self.inner.transport
    }

    /// Registers work that [`OidcClient::close`] runs (flush, stop watchers, …).
    pub fn on_close<F>(&self, f: F)
    where
        F: FnOnce() -> BoxFuture<'static, ()> + Send + 'static,
    {
        self.inner.on_close.register(f);
    }

    /// Unauthenticated liveness check: `GET <url>/.well-known/openid-configuration`. Never fails
    /// for an unhealthy or unreachable provider; only `CANCELLED` and `CONFIG` are returned.
    pub async fn health(&self) -> Result<HealthStatus> {
        let resp = self
            .transport()
            .get(DISCOVERY_PATH)
            .operation("health")
            .ok_status(500)
            .ok_status(503)
            .send()
            .await;
        let resp = match resp {
            Ok(resp) => resp,
            Err(err) => return HealthStatus::from_error(err),
        };
        if resp.status() >= 300 {
            return Ok(HealthStatus::unhealthy("unhealthy")
                .with_detail("httpStatus", resp.status().to_string()));
        }
        let mut status = HealthStatus::healthy("ok");
        if let Some(issuer) = resp.json::<Discovery>().ok().and_then(|d| d.issuer) {
            status = status.with_detail("issuer", issuer);
        }
        Ok(status)
    }

    /// Authenticated round trip with the configured access token: `GET` the provider's
    /// `userinfo_endpoint` from discovery. `AUTHENTICATION` for a rejected token, `UNSUPPORTED`
    /// when the provider has no userinfo endpoint.
    pub async fn ping(&self) -> Result<Duration> {
        let started = Instant::now();
        let doc = self
            .transport()
            .get(DISCOVERY_PATH)
            .operation("ping")
            .send()
            .await?;
        let endpoint = doc
            .json::<Discovery>()?
            .userinfo_endpoint
            .filter(|e| !e.is_empty())
            .ok_or_else(|| Error::unsupported("ping: the provider has no userinfo endpoint"))?;
        let path = relative_endpoint(self.config().url().as_str(), &endpoint);
        let mut req = self.transport().get(&path).operation("ping");
        if let Some(token) = self.config().token() {
            req = req.bearer(token);
        }
        req.send().await?;
        Ok(started.elapsed())
    }

    /// `UNSUPPORTED`: OpenID Connect providers expose no version (`CANCELLED` once closed).
    pub async fn server_version(&self) -> Result<String> {
        self.transport().ensure_open("serverVersion")?;
        Err(Error::unsupported(
            "serverVersion: OpenID Connect providers expose no version",
        ))
    }

    /// Flushes and stops background work, then closes the transport. Idempotent.
    pub async fn close(&self) {
        self.inner.on_close.close().await;
        self.inner.transport.close();
    }

    /// Whether [`OidcClient::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.inner.transport.is_closed()
    }
}
