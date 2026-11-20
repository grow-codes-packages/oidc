//! `tower` layers (axum, tonic, hyper): bearer-token verification and role checks (feature
//! `tower`, service-owned).
//!
//! ```ignore
//! let verifier = grow_oidc::Verifier::from_env()?;
//! let app = axum::Router::new()
//!     .route("/admin", get(admin).layer(RequireRolesLayer::new(["admin"])))
//!     .route("/me", get(|Extension(user): Extension<AuthUser>| async move { user.sub }))
//!     .layer(OidcLayer::new(verifier));
//! ```

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{header, Request, Response, StatusCode};
use tower_layer::Layer;
use tower_service::Service;

use crate::core::ErrorCode;
use crate::oidc::{bearer_token, has_any_role, AuthUser, Verifier};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

fn deny<B: From<String>>(status: StatusCode, error: &str) -> Response<B> {
    let mut res = Response::new(B::from(format!("{{\"error\":\"{error}\"}}")));
    *res.status_mut() = status;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    if status == StatusCode::UNAUTHORIZED {
        headers.insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer error=\"invalid_token\""),
        );
    }
    res
}

/// Layer that verifies the bearer token of every request and inserts the [`AuthUser`] into the
/// request extensions (`Extension<AuthUser>` in axum). Missing or invalid token → 401, IdP
/// unreachable → 503. The response never says why a token was rejected.
#[derive(Clone, Debug)]
pub struct OidcLayer {
    verifier: Verifier,
    optional: bool,
}

impl OidcLayer {
    /// A layer that requires a valid token.
    pub fn new(verifier: Verifier) -> Self {
        Self {
            verifier,
            optional: false,
        }
    }

    /// Lets requests without a token through anonymously (an invalid token is still 401).
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

impl<S> Layer<S> for OidcLayer {
    type Service = OidcService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OidcService {
            inner,
            verifier: self.verifier.clone(),
            optional: self.optional,
        }
    }
}

/// The service of [`OidcLayer`].
#[derive(Clone, Debug)]
pub struct OidcService<S> {
    inner: S,
    verifier: Verifier,
    optional: bool,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for OidcService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: From<String> + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        // Take the service that was driven to readiness; leave a clone in its place.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let verifier = self.verifier.clone();
        let optional = self.optional;
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(bearer_token)
            .map(str::to_owned);
        Box::pin(async move {
            let Some(token) = token else {
                if optional {
                    return inner.call(req).await;
                }
                return Ok(deny(StatusCode::UNAUTHORIZED, "unauthorized"));
            };
            match verifier.verify(&token).await {
                Ok(user) => {
                    req.extensions_mut().insert(user);
                    inner.call(req).await
                }
                Err(e) if matches!(e.code(), ErrorCode::Unavailable | ErrorCode::Timeout) => {
                    Ok(deny(StatusCode::SERVICE_UNAVAILABLE, "auth_unavailable"))
                }
                Err(_) => Ok(deny(StatusCode::UNAUTHORIZED, "unauthorized")),
            }
        })
    }
}

/// Layer placed inside [`OidcLayer`]: 401 without an [`AuthUser`], 403 unless the user has at
/// least one of the roles (case-insensitive). No roles = any authenticated user.
#[derive(Clone, Debug)]
pub struct RequireRolesLayer {
    roles: Vec<String>,
}

impl RequireRolesLayer {
    /// Creates the layer.
    pub fn new<I, R>(roles: I) -> Self
    where
        I: IntoIterator<Item = R>,
        R: Into<String>,
    {
        Self {
            roles: roles.into_iter().map(Into::into).collect(),
        }
    }
}

impl<S> Layer<S> for RequireRolesLayer {
    type Service = RequireRolesService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireRolesService {
            inner,
            roles: self.roles.clone(),
        }
    }
}

/// The service of [`RequireRolesLayer`].
#[derive(Clone, Debug)]
pub struct RequireRolesService<S> {
    inner: S,
    roles: Vec<String>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RequireRolesService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: From<String> + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let verdict = match req.extensions().get::<AuthUser>() {
            None => Some(deny(StatusCode::UNAUTHORIZED, "unauthorized")),
            Some(user) => {
                let wanted: Vec<&str> = self.roles.iter().map(String::as_str).collect();
                (!has_any_role(&user.roles, &wanted))
                    .then(|| deny(StatusCode::FORBIDDEN, "forbidden"))
            }
        };
        if let Some(res) = verdict {
            return Box::pin(async move { Ok(res) });
        }
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { inner.call(req).await })
    }
}
