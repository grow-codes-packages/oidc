//! Conformance case OIDC-18 (middleware) for the tower layers.
#![cfg(feature = "tower")]

mod oidc_fake_idp;

use std::convert::Infallible;

use grow_oidc::{AuthUser, OidcLayer, RequireRolesLayer, Verifier, VerifierOptions};
use http::{Request, Response, StatusCode};
use oidc_fake_idp::FakeIdp;
use serde_json::json;
use tower::{service_fn, ServiceBuilder, ServiceExt};

async fn handler(req: Request<()>) -> Result<Response<String>, Infallible> {
    let sub = req
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.sub.clone())
        .unwrap_or_else(|| "anon".into());
    Ok(Response::new(sub))
}

async fn call<S>(svc: S, auth: Option<String>) -> (StatusCode, String, Option<String>)
where
    S: tower::Service<Request<()>, Response = Response<String>, Error = Infallible>,
{
    let mut req = Request::builder().uri("/x");
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let res = svc.oneshot(req.body(()).unwrap()).await.unwrap();
    let www = res
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_owned());
    (res.status(), res.into_body(), www)
}

#[tokio::test]
async fn oidc_18_tower_layers() {
    let idp = FakeIdp::start("api", "RS256").await;
    let v = Verifier::new(VerifierOptions {
        issuer: idp.issuer.clone(),
        audience: "api".into(),
        ..Default::default()
    })
    .unwrap();
    let svc = || {
        ServiceBuilder::new()
            .layer(OidcLayer::new(v.clone()))
            .service(service_fn(handler))
    };
    let (status, _, www) = call(svc(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(www.unwrap().starts_with("Bearer"));
    assert_eq!(
        call(svc(), Some("Bearer x.y.z".into())).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, body, _) = call(svc(), Some(format!("Bearer {}", idp.mint(json!({}))))).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "user-1"));
    let optional = ServiceBuilder::new()
        .layer(OidcLayer::new(v.clone()).optional())
        .service(service_fn(handler));
    assert_eq!(call(optional, None).await.1, "anon");

    let admin = || {
        ServiceBuilder::new()
            .layer(OidcLayer::new(v.clone()))
            .layer(RequireRolesLayer::new(["admin"]))
            .service(service_fn(handler))
    };
    let user = idp.mint(json!({"roles": ["user"]}));
    assert_eq!(
        call(admin(), Some(format!("Bearer {user}"))).await.0,
        StatusCode::FORBIDDEN
    );
    let adm = idp.mint(json!({"roles": [{"name": "Admin"}]}));
    assert_eq!(
        call(admin(), Some(format!("Bearer {adm}"))).await.0,
        StatusCode::OK
    );
    let roles_only = ServiceBuilder::new()
        .layer(RequireRolesLayer::new(Vec::<String>::new()))
        .service(service_fn(handler));
    assert_eq!(call(roles_only, None).await.0, StatusCode::UNAUTHORIZED);

    let down = Verifier::new(VerifierOptions {
        issuer: idp.issuer.clone(),
        audience: "api".into(),
        jwks_url: Some("http://127.0.0.1:1/jwks".into()),
        ..Default::default()
    })
    .unwrap();
    let svc = ServiceBuilder::new()
        .layer(OidcLayer::new(down))
        .service(service_fn(handler));
    assert_eq!(
        call(svc, Some(format!("Bearer {}", idp.mint(json!({})))))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
