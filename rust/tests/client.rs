// Skeleton created by sdk-kit 0.3.0; owned by this repository (edit freely).
//! Skeleton client and config against a mock of the demo service. Adapt the routes, the
//! credentials and the config tests when the client changes.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::{closed_port, fast_retry};
use grow_oidc as sdk;
use sdk::core::env::ENV_PREFIX;
use sdk::core::{EnvReader, ErrorCode, Hooks, RetryPolicy, TlsConfig};
use sdk::DEFAULT_URL;
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use sdk::OidcClient as Client;
use sdk::OidcConfig as Config;

fn client(url: &str, token: Option<&str>) -> Client {
    let mut b = Config::builder().url(url).retry(fast_retry(0.0));
    if let Some(t) = token {
        b = b.token(t);
    }
    Client::new(b.build().unwrap()).unwrap()
}

async fn demo_server() -> MockServer {
    let server = MockServer::start().await;
    let userinfo = format!("{}/api/userinfo?schema=openid", server.uri());
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"issuer": "http://idp.test", "userinfo_endpoint": userinfo})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/api/userinfo"))
        .and(query_param("schema", "openid"))
        .and(header("authorization", "Bearer demo-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sub": "u"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/userinfo"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "unauthorized"})))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn client_surface() {
    let server = demo_server().await;
    let c = client(&server.uri(), Some("demo-token"));
    let h = c.health().await.unwrap();
    assert!(h.healthy);
    assert_eq!(h.status, "ok");
    assert_eq!(h.details["issuer"], "http://idp.test");
    assert!(c.ping().await.unwrap() < Duration::from_secs(5));
    assert_eq!(
        c.server_version().await.unwrap_err().code(),
        ErrorCode::Unsupported
    );
    assert_eq!(c.config().token().unwrap().expose_secret(), "demo-token");
    assert!(format!("{c:?}").contains("[REDACTED]"));
    assert!(!format!("{c:?}").contains("demo-token"));

    let bad = client(&server.uri(), Some("wrong-token"));
    let err = bad.ping().await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Authentication);
    assert!(!err.message().contains("wrong-token"));
    let none = client(&server.uri(), None);
    assert_eq!(
        none.ping().await.unwrap_err().code(),
        ErrorCode::Authentication
    );
}

#[tokio::test]
async fn client_health_variants() {
    let server = MockServer::start().await;
    for (prefix, status) in [("a", 503), ("b", 500), ("c", 404), ("d", 204)] {
        Mock::given(path(format!("/{prefix}/.well-known/openid-configuration")))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
    }
    for (prefix, healthy, word) in [
        ("a", false, "unhealthy"),
        ("b", false, "unhealthy"),
        ("c", false, "unhealthy"),
        ("d", true, "ok"),
    ] {
        let h = client(&format!("{}/{prefix}", server.uri()), None)
            .health()
            .await
            .unwrap();
        assert_eq!((h.healthy, h.status.as_str()), (healthy, word), "{prefix}");
    }
}

#[test]
fn relative_endpoints() {
    assert_eq!(
        sdk::relative_endpoint("http://kc/realms/x/", "http://kc/realms/x/protocol/ui"),
        "/protocol/ui"
    );
    assert_eq!(
        sdk::relative_endpoint("http://a", "http://b/api/userinfo?x=1"),
        "/api/userinfo?x=1"
    );
    assert_eq!(
        sdk::relative_endpoint("http://a", "http://b/api/userinfo"),
        "/api/userinfo"
    );
    assert_eq!(sdk::relative_endpoint("http://a", "/userinfo"), "/userinfo");
    assert_eq!(sdk::DISCOVERY_PATH, ".well-known/openid-configuration");
}

#[tokio::test]
async fn core_health_unreachable() {
    let c = client(&format!("http://127.0.0.1:{}", closed_port()), None);
    let h = c.health().await.unwrap();
    assert!(!h.healthy);
    assert_eq!(h.status, "unreachable");
    assert!(h.details.contains_key("error"));
    // closed clients report CANCELLED, which health() returns as an error
    c.close().await;
    assert_eq!(c.health().await.unwrap_err().code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn client_ping_and_version_errors() {
    let server = MockServer::start().await;
    Mock::given(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"issuer": "x"})))
        .mount(&server)
        .await;
    let c = client(&server.uri(), None);
    assert_eq!(c.ping().await.unwrap_err().code(), ErrorCode::Unsupported);
    c.close().await;
    assert_eq!(
        c.server_version().await.unwrap_err().code(),
        ErrorCode::Cancelled
    );
}

#[tokio::test]
async fn core_close_idempotent() {
    let server = demo_server().await;
    let c = client(&server.uri(), Some("demo-token"));
    let closed = Arc::new(AtomicU32::new(0));
    let counter = closed.clone();
    c.on_close(move || {
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
        })
    });
    assert!(!c.is_closed());
    c.close().await;
    c.close().await;
    assert!(c.is_closed());
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert_eq!(c.ping().await.unwrap_err().code(), ErrorCode::Cancelled);
    assert!(c.transport().is_closed());
}

#[tokio::test]
async fn client_config_errors() {
    let err = Config::builder().url("mailto:x").build().unwrap_err();
    assert_eq!(err.code(), ErrorCode::Config);
    let cfg = Config::builder()
        .ca_cert_path("/nonexistent/ca.pem")
        .build()
        .unwrap();
    assert_eq!(Client::new(cfg).unwrap_err().code(), ErrorCode::Config);
    let _ = Client::from_env();
}

fn var(name: &str) -> String {
    format!("{ENV_PREFIX}{name}")
}

#[test]
fn config_from_env() {
    let env = EnvReader::from_map([
        (var("URL"), "https://svc.example:8443"),
        (var("TOKEN"), "tok-from-env"),
    ]);
    let c = Config::builder().build_with_env(&env).unwrap();
    assert_eq!(c.url().as_str(), "https://svc.example:8443/");
    assert_eq!(c.token().unwrap().expose_secret(), "tok-from-env");
    let c = Config::builder()
        .token("explicit")
        .build_with_env(&env)
        .unwrap();
    assert_eq!(c.token().unwrap().expose_secret(), "explicit");
    let c = Config::builder().build().unwrap();
    assert_eq!(c.url().as_str(), format!("{DEFAULT_URL}/"));
    assert!(c.token().is_none());
    assert!(c.validate().is_ok());
    // the process-environment entry points work (values depend on the environment)
    let _ = Config::from_env();
    let _ = Config::builder().build_from_env();
}

#[test]
fn config_builder_setters() {
    struct NoHooks;
    impl Hooks for NoHooks {}
    let c = Config::builder()
        .url("http://h:1/base")
        .connect_timeout(Duration::from_secs(1))
        .request_timeout(Duration::from_secs(2))
        .total_timeout(Duration::from_secs(3))
        .retry(RetryPolicy::none())
        .max_retries(2)
        .tls(TlsConfig {
            insecure_skip_verify: true,
            ..TlsConfig::default()
        })
        .ca_cert_path("/ca.pem")
        .insecure_skip_verify(true)
        .proxy("http://p:1")
        .header("x-a", "b")
        .user_agent_suffix("app/1")
        .hooks(Arc::new(NoHooks))
        .common(|b| b.ca_cert_pem("pem"))
        .build()
        .unwrap();
    let common = c.common();
    assert_eq!(common.connect_timeout(), Duration::from_secs(1));
    assert_eq!(common.request_timeout(), Duration::from_secs(2));
    assert_eq!(common.total_timeout(), Duration::from_secs(3));
    assert_eq!(common.retry().max_retries, 2);
    assert!(common.tls().insecure_skip_verify);
    assert_eq!(common.tls().ca_cert_pem.as_deref(), Some("pem"));
    assert_eq!(common.headers(), &[("x-a".to_owned(), "b".to_owned())]);
    assert_eq!(common.user_agent_suffix(), Some("app/1"));
    assert!(common.hooks().is_some());
}

#[test]
fn config_redaction() {
    let c = Config::builder()
        .url("https://user:url-password-1@svc.example/?token=query-token-1&x=1")
        .token("config-token-secret-1")
        .header("Authorization", "Bearer header-token-1")
        .build()
        .unwrap();
    let text = format!("{c:?}");
    for secret in [
        "url-password-1",
        "query-token-1",
        "config-token-secret-1",
        "header-token-1",
    ] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
    assert!(format!("{:?}", Config::builder().token("t-builder-1")).contains("[REDACTED]"));
}

/// `core` conformance scenarios against the real client and a mock of its routes.
#[cfg(feature = "testing")]
#[tokio::test]
async fn conformance_core_with_client() {
    use sdk::testing::{scenarios_dir, ConformanceRunner, CoreHandler};
    let server = demo_server().await;
    let url = server.uri();
    let factory = move || {
        Client::new(
            Config::builder()
                .url(url.clone())
                .token("demo-token")
                .retry(fast_retry(0.0))
                .build()?,
        )
    };
    let report = ConformanceRunner::new(scenarios_dir(env!("CARGO_MANIFEST_DIR")))
        .capabilities(Vec::<String>::new())
        .handler(CoreHandler::new(factory))
        .run()
        .await
        .unwrap();
    report.assert_success();
    assert_eq!(report.passed(), 1);
}
