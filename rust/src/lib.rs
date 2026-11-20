// Skeleton created by sdk-kit 0.3.0; owned by this repository (edit freely).
//! # grow-oidc
//!
//! Rust SDK for [OIDC](https://grow-codes-packages.github.io/oidc/) by Grow Codes.
//!
//! ```no_run
//! # async fn demo() -> grow_oidc::Result<()> {
//! use grow_oidc::{OidcClient, OidcConfig};
//!
//! let client = OidcClient::new(OidcConfig::from_env()?)?;
//! let health = client.health().await?;
//! println!("healthy: {}", health.healthy);
//! client.close().await;
//! # Ok(())
//! # }
//! ```
//!
//! Features: `blocking` (a blocking client), `testing` (in-memory fakes and the conformance
//! runner)
//! .
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod core;

mod client;
mod config;
mod oidc;

#[cfg(feature = "tower")]
#[cfg_attr(docsrs, doc(cfg(feature = "tower")))]
mod oidc_tower;

pub use crate::oidc::{
    bearer_token, claim_at, extract_roles, has_any_role, AuthUser, ClockFn, Verifier,
    VerifierOptions, DEFAULT_ALGORITHMS, DEFAULT_CLOCK_SKEW, DEFAULT_HTTP_TIMEOUT,
    DEFAULT_JWKS_CACHE_TTL, DEFAULT_JWKS_REFRESH_COOLDOWN,
};
#[cfg(feature = "tower")]
pub use crate::oidc_tower::{OidcLayer, OidcService, RequireRolesLayer, RequireRolesService};

#[cfg(feature = "blocking")]
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

#[cfg(feature = "testing")]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub mod testing;

pub use crate::core::{Error, ErrorCode, HealthStatus, Result, RetryPolicy, Secret};

pub use crate::config::DEFAULT_URL;

pub use crate::client::OidcClient;

pub use crate::config::OidcConfig;

pub use crate::config::OidcConfigBuilder;

/// Service-prefixed alias of [`Error`].
pub type OidcError = Error;
