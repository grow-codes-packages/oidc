//! Conformance cases OIDC-01…OIDC-18 (docs/oidc-conformance.md) against a local fake IdP.

mod oidc_fake_idp;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use grow_oidc::{
    bearer_token, claim_at, extract_roles, has_any_role, ErrorCode, Verifier, VerifierOptions,
};
use oidc_fake_idp::FakeIdp;
use serde_json::{json, Value};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn opts(idp: &FakeIdp) -> VerifierOptions {
    VerifierOptions {
        issuer: idp.issuer.clone(),
        audience: "app-client".into(),
        ..Default::default()
    }
}

fn verifier(idp: &FakeIdp) -> Verifier {
    Verifier::new(opts(idp)).unwrap()
}

async fn auth_err(v: &Verifier, token: &str, contains: &str) {
    let err = v.verify(token).await.expect_err("token must be rejected");
    assert_eq!(err.code(), ErrorCode::Authentication, "{err}");
    assert!(
        err.to_string().contains(contains),
        "{err} does not contain {contains}"
    );
}

fn now_s() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[derive(Clone)]
struct Clock(Arc<Mutex<SystemTime>>);
impl Clock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(SystemTime::now())))
    }
    fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
    fn func(&self) -> grow_oidc::ClockFn {
        let c = self.0.clone();
        Arc::new(move || *c.lock().unwrap())
    }
}

#[tokio::test]
async fn oidc_01_rs256_via_discovery() {
    let idp = FakeIdp::start("app-client", "RS256").await;
    let token = idp.mint(json!({"email": "a@b.test", "name": "Ann", "roles": [{"name": "admin", "owner": "o"}, {"name": "user"}]}));
    let user = verifier(&idp).verify(&token).await.unwrap();
    assert_eq!(user.sub, "user-1");
    assert_eq!(user.email.as_deref(), Some("a@b.test"));
    assert_eq!(user.name.as_deref(), Some("Ann"));
    assert_eq!(user.roles, vec!["admin", "user"]);
    assert!(user.has_role(&["ADMIN"]) && !user.has_role(&["x"]));
    assert_eq!(idp.hits("/.well-known/openid-configuration").await, 1);
}

#[tokio::test]
async fn oidc_02_03_other_algorithms() {
    for alg in ["ES256", "EdDSA"] {
        let idp = FakeIdp::start("app-client", alg).await;
        let user = verifier(&idp)
            .verify(&idp.mint(json!({"preferred_username": "bob"})))
            .await
            .unwrap();
        assert_eq!(user.name.as_deref(), Some("bob"), "{alg}");
        assert!(user.email.is_none());
    }
}

#[tokio::test]
async fn oidc_04_to_08_claims() {
    let idp = FakeIdp::start("app-client", "ES256").await;
    let v = verifier(&idp);
    let now = now_s();
    auth_err(&v, &idp.mint(json!({"iss": "http://evil.test"})), "iss").await;
    auth_err(&v, &idp.mint(json!({"aud": "other"})), "aud").await;
    auth_err(&v, &idp.mint(json!({"aud": 5})), "aud").await;
    v.verify(&idp.mint(json!({"aud": ["other", "app-client"]})))
        .await
        .unwrap();
    auth_err(&v, &idp.mint(json!({"exp": now - 120})), "expired").await;
    v.verify(&idp.mint(json!({"exp": now - 30}))).await.unwrap();
    let strict = Verifier::new(VerifierOptions {
        clock_skew: Duration::ZERO,
        ..opts(&idp)
    })
    .unwrap();
    auth_err(&strict, &idp.mint(json!({"exp": now - 30})), "expired").await;
    auth_err(&v, &idp.mint(json!({"nbf": now + 120})), "nbf").await;
    v.verify(&idp.mint(json!({"nbf": now + 30}))).await.unwrap();
    auth_err(&v, &idp.mint(json!({"exp": null})), "exp").await;
    auth_err(&v, &idp.mint(json!({"exp": "soon"})), "exp").await;
    auth_err(&v, &idp.mint(json!({"sub": null})), "sub").await;
    auth_err(&v, &idp.mint(json!({"sub": ""})), "sub").await;
}

fn enc(v: Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap())
}

#[tokio::test]
async fn oidc_09_algorithms() {
    let idp = FakeIdp::start("app-client", "RS256").await;
    let v = verifier(&idp);
    auth_err(
        &v,
        &format!("{}.{}.", enc(json!({"alg": "none"})), enc(json!({}))),
        "none is not allowed",
    )
    .await;
    auth_err(
        &v,
        &format!("{}.e30.c2ln", enc(json!({"alg": "HS256"}))),
        "HS256 is not allowed",
    )
    .await;
    auth_err(
        &v,
        &format!("{}.e30.c2ln", enc(json!({}))),
        "(none) is not allowed",
    )
    .await;
    auth_err(
        &v,
        &format!("{}.e30.c2ln", enc(json!({"alg": "A".repeat(40)}))),
        "not allowed",
    )
    .await;
    idp.rotate("ES256");
    let rs = Verifier::new(VerifierOptions {
        algorithms: vec!["RS256".into()],
        ..opts(&idp)
    })
    .unwrap();
    auth_err(&rs, &idp.mint(json!({})), "not allowed").await;
    auth_err(&v, "nope", "malformed token").await;
    auth_err(&v, "!!.e30.c2ln", "malformed token header").await;
    auth_err(
        &v,
        &format!("{}.!!.c2ln", enc(json!({"alg": "RS256"}))),
        "malformed token payload",
    )
    .await;
    auth_err(
        &v,
        &format!("{}.e30.!!", enc(json!({"alg": "RS256"}))),
        "malformed token signature",
    )
    .await;
}

#[tokio::test]
async fn oidc_10_bad_signature() {
    let idp = FakeIdp::start("app-client", "EdDSA").await;
    let other = FakeIdp::start("app-client", "EdDSA").await;
    let token = idp.mint(json!({}));
    let forged = other.mint(json!({"iss": idp.issuer}));
    let p: Vec<&str> = token.split('.').collect();
    let f: Vec<&str> = forged.split('.').collect();
    auth_err(
        &verifier(&idp),
        &format!("{}.{}.{}", p[0], p[1], f[2]),
        "signature",
    )
    .await;
}

#[tokio::test]
async fn oidc_11_12_rotation() {
    let idp = FakeIdp::start("app-client", "RS256").await;
    let clock = Clock::new();
    let v = Verifier::new(VerifierOptions {
        now: Some(clock.func()),
        ..opts(&idp)
    })
    .unwrap();
    v.verify(&idp.mint(json!({}))).await.unwrap();
    idp.rotate("EdDSA");
    auth_err(&v, &idp.mint(json!({})), "no key matches kid key-2").await;
    assert_eq!(idp.hits("/jwks").await, 1);
    clock.advance(Duration::from_secs(31));
    v.verify(&idp.mint(json!({}))).await.unwrap();
    assert_eq!(idp.hits("/jwks").await, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_13_cache_and_no_kid() {
    let idp = FakeIdp::start("app-client", "RS256").await;
    let clock = Clock::new();
    let v = Verifier::new(VerifierOptions {
        now: Some(clock.func()),
        ..opts(&idp)
    })
    .unwrap();
    let token = idp.mint_with(json!({}), None, json!({}), 3600);
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let (v, t) = (v.clone(), token.clone());
            tokio::spawn(async move { v.verify(&t).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(idp.hits("/jwks").await, 1);
    clock.advance(Duration::from_secs(601));
    v.verify(&token).await.unwrap();
    v.clear_cache();
    v.verify(&token).await.unwrap();
    assert_eq!(idp.hits("/jwks").await, 3);
    v.verify(&idp.mint_with(json!({}), None, json!({"kid": null}), 3600))
        .await
        .unwrap();
    auth_err(
        &v,
        &idp.mint_with(json!({}), None, json!({"kid": null, "alg": "ES256"}), 3600),
        "no key matches kid (none)",
    )
    .await;
}

#[tokio::test]
async fn oidc_14_jwks_url_skips_discovery() {
    let idp = FakeIdp::start("app-client", "RS256").await;
    let v = Verifier::new(VerifierOptions {
        jwks_url: Some(format!("{}/jwks", idp.issuer)),
        ..opts(&idp)
    })
    .unwrap();
    v.verify(&idp.mint(json!({}))).await.unwrap();
    assert_eq!(idp.hits("/.well-known/openid-configuration").await, 0);
}

async fn serve(body: &str) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&s)
        .await;
    s
}

#[tokio::test]
async fn oidc_15_unavailable() {
    let idp = FakeIdp::start("app-client", "RS256").await;
    let token = idp.mint(json!({}));
    idp.fail(Some(500));
    let err = verifier(&idp).verify(&token).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.to_string().contains("HTTP 500"));
    for (body, msg) in [
        ("nope", "not JSON"),
        (r#"{"issuer":"x"}"#, "no jwks_uri"),
        (r#"{"jwks_uri":"http://127.0.0.1:1/j"}"#, "request failed"),
    ] {
        let s = serve(body).await;
        let v = Verifier::new(VerifierOptions {
            issuer: s.uri(),
            audience: "a".into(),
            ..Default::default()
        })
        .unwrap();
        let err = v.verify(&token).await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert!(err.to_string().contains(msg), "{err}");
    }
    let s = serve("{}").await;
    let v = Verifier::new(VerifierOptions {
        jwks_url: Some(s.uri()),
        ..opts(&idp)
    })
    .unwrap();
    assert!(v
        .verify(&token)
        .await
        .unwrap_err()
        .to_string()
        .contains("no keys array"));
}

#[tokio::test]
async fn oidc_16_roles_claim() {
    let idp = FakeIdp::start("app-client", "RS256").await;
    let token = idp.mint(json!({"realm_access": {"roles": ["editor"]}, "scope": "a b"}));
    let with = |claim: &str| {
        Verifier::new(VerifierOptions {
            roles_claim: Some(claim.into()),
            ..opts(&idp)
        })
        .unwrap()
    };
    assert_eq!(
        with("realm_access.roles")
            .verify(&token)
            .await
            .unwrap()
            .roles,
        vec!["editor"]
    );
    assert_eq!(
        with("scope").verify(&token).await.unwrap().roles,
        vec!["a", "b"]
    );
    assert!(verifier(&idp)
        .verify(&token)
        .await
        .unwrap()
        .roles
        .is_empty());
    let claims = json!({"roles": [{"code": "b"}, {"role": "c"}, {"value": "d"}, {"x": 1}, {"name": " "}, 3, " ", "b"], "https://x/roles": ["r"], "a": {"b": [1]}, "l": [1]});
    let claims = claims.as_object().unwrap();
    assert_eq!(extract_roles(claims, ""), vec!["b", "c", "d"]);
    assert_eq!(extract_roles(claims, "https://x/roles"), vec!["r"]);
    assert!(extract_roles(claims, "a").is_empty());
    assert_eq!(claim_at(claims, "a.b"), Some(&json!([1])));
    assert!(
        claim_at(claims, "l.b").is_none()
            && claim_at(claims, "a.c").is_none()
            && claim_at(claims, "zz.b").is_none()
    );
    assert!(has_any_role::<String>(&[], &[]) && !has_any_role(&["x"], &["y"]));
}

#[tokio::test]
async fn oidc_17_from_env() {
    let mut env: HashMap<String, String> = [
        ("GROW_AUTH_ISSUER", "http://idp:8000"),
        ("GROW_AUTH_CLIENT_ID", "app"),
        ("GROW_AUTH_ROLES_CLAIM", "groups"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let v = Verifier::from_env_map(&env).unwrap();
    assert_eq!(
        (v.issuer(), v.audience(), v.roles_claim(), v.clock_skew()),
        ("http://idp:8000", "app", "groups", Duration::from_secs(60))
    );
    assert!(format!("{v:?}").contains("idp:8000"));
    env.insert("GROW_AUTH_AUDIENCE".into(), "api".into());
    env.insert("GROW_AUTH_JWKS_URL".into(), "http://idp:8000/jwks".into());
    env.insert("GROW_AUTH_CLOCK_SKEW".into(), "5s".into());
    let v = Verifier::from_env_map(&env).unwrap();
    assert_eq!(
        (v.audience(), v.clock_skew()),
        ("api", Duration::from_secs(5))
    );
    env.insert("GROW_AUTH_CLOCK_SKEW".into(), "soon".into());
    assert_eq!(
        Verifier::from_env_map(&env).unwrap_err().code(),
        ErrorCode::Config
    );
    assert!(Verifier::from_env_map(&HashMap::new())
        .unwrap_err()
        .to_string()
        .contains("GROW_AUTH_ISSUER"));
    let only_issuer: HashMap<String, String> =
        [("GROW_AUTH_ISSUER".to_string(), "http://x".to_string())].into();
    assert!(Verifier::from_env_map(&only_issuer)
        .unwrap_err()
        .to_string()
        .contains("GROW_AUTH_AUDIENCE"));
    let _ = Verifier::from_env();
    let base = VerifierOptions {
        issuer: "http://x".into(),
        audience: "a".into(),
        ..Default::default()
    };
    assert!(format!("{base:?}").contains("http://x"));
    for bad in [
        VerifierOptions {
            issuer: String::new(),
            ..base.clone()
        },
        VerifierOptions {
            audience: " ".into(),
            ..base.clone()
        },
        VerifierOptions {
            issuer: "nope".into(),
            ..base.clone()
        },
        VerifierOptions {
            jwks_url: Some("ftp://x".into()),
            ..base.clone()
        },
        VerifierOptions {
            algorithms: vec!["HS256".into()],
            ..base.clone()
        },
    ] {
        assert_eq!(Verifier::new(bad).unwrap_err().code(), ErrorCode::Config);
    }
    Verifier::new(VerifierOptions {
        http_client: Some(reqwest::Client::new()),
        ..base
    })
    .unwrap();
}

#[tokio::test]
async fn jwks_ignores_unusable_keys() {
    let idp = FakeIdp::start("app-client", "RS256").await;
    let good = idp.jwks()[0].clone();
    let mut enc_key = good.clone();
    enc_key["use"] = json!("enc");
    let mut wrong_alg = good.clone();
    wrong_alg["alg"] = json!("ES256");
    let junk = json!({"keys": ["x", {"kty": "RSA", "n": "AQAB", "e": "AQAB"}, {"kty": "RSA"},
        {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}, {"kty": "OKP", "crv": "Ed25519", "x": "AA"},
        {"kty": "oct", "k": "AA"}, enc_key, wrong_alg]});
    let s = serve(&junk.to_string()).await;
    let v = Verifier::new(VerifierOptions {
        jwks_url: Some(s.uri()),
        ..opts(&idp)
    })
    .unwrap();
    auth_err(&v, &idp.mint(json!({})), "no key matches kid key-1").await;
}

#[test]
fn bearer_tokens() {
    assert_eq!(bearer_token("Bearer abc"), Some("abc"));
    assert_eq!(bearer_token(" bearer  xyz "), Some("xyz"));
    assert_eq!(bearer_token("Basic abc"), None);
    assert_eq!(bearer_token("Bearer a b"), None);
    assert_eq!(bearer_token(""), None);
}
