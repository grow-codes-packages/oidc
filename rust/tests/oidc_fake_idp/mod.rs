//! A local fake OpenID provider for the OIDC tests: wiremock serves discovery + JWKS, `ring`
//! signs tokens. The RSA key is a test-only fixture (ring cannot generate RSA keys).
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};
use serde_json::{json, Map, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const RSA_DER: &[u8] = include_bytes!("../fixtures/oidc-test-only-rsa.der");

pub enum Signer {
    Rsa(RsaKeyPair),
    Ec(EcdsaKeyPair),
    Ed(Ed25519KeyPair),
}

pub struct Key {
    pub kid: String,
    pub alg: String,
    pub signer: Signer,
    pub jwk: Value,
}

#[derive(Default)]
struct State {
    keys: Vec<Arc<Key>>,
    current: String,
    counter: u32,
    fail: Option<u16>,
}

pub struct FakeIdp {
    pub server: MockServer,
    pub issuer: String,
    pub audience: String,
    state: Arc<Mutex<State>>,
}

struct Jwks(Arc<Mutex<State>>);
impl Respond for Jwks {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let st = self.0.lock().unwrap();
        if let Some(code) = st.fail {
            return ResponseTemplate::new(code);
        }
        let keys: Vec<Value> = st.keys.iter().map(|k| k.jwk.clone()).collect();
        ResponseTemplate::new(200).set_body_json(json!({ "keys": keys }))
    }
}

struct Discovery(Arc<Mutex<State>>, String);
impl Respond for Discovery {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        if let Some(code) = self.0.lock().unwrap().fail {
            return ResponseTemplate::new(code);
        }
        ResponseTemplate::new(200)
            .set_body_json(json!({ "issuer": self.1, "jwks_uri": format!("{}/jwks", self.1) }))
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

impl FakeIdp {
    pub async fn start(audience: &str, alg: &str) -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let state = Arc::new(Mutex::new(State::default()));
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(Discovery(state.clone(), issuer.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(Jwks(state.clone()))
            .mount(&server)
            .await;
        let idp = Self {
            server,
            issuer,
            audience: audience.into(),
            state,
        };
        idp.rotate(alg);
        idp
    }

    pub fn rotate(&self, alg: &str) -> String {
        let rng = SystemRandom::new();
        let mut st = self.state.lock().unwrap();
        st.counter += 1;
        let kid = format!("key-{}", st.counter);
        let (signer, mut jwk, alg) = match alg {
            "ES256" => {
                let pk8 =
                    EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                        .unwrap();
                let kp = EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    pk8.as_ref(),
                    &rng,
                )
                .unwrap();
                let p = kp.public_key().as_ref().to_vec();
                (
                    Signer::Ec(kp),
                    json!({"kty": "EC", "crv": "P-256", "x": b64(&p[1..33]), "y": b64(&p[33..])}),
                    "ES256",
                )
            }
            "EdDSA" => {
                let pk8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
                let kp = Ed25519KeyPair::from_pkcs8(pk8.as_ref()).unwrap();
                let x = b64(kp.public_key().as_ref());
                (
                    Signer::Ed(kp),
                    json!({"kty": "OKP", "crv": "Ed25519", "x": x}),
                    "EdDSA",
                )
            }
            _ => {
                let kp = RsaKeyPair::from_der(RSA_DER).unwrap();
                let parts = signature::RsaPublicKeyComponents::<Vec<u8>>::from(kp.public());
                let (n, e) = (parts.n, parts.e);
                (
                    Signer::Rsa(kp),
                    json!({"kty": "RSA", "n": b64(&n), "e": b64(&e)}),
                    "RS256",
                )
            }
        };
        jwk["kid"] = json!(kid);
        jwk["alg"] = json!(alg);
        jwk["use"] = json!("sig");
        st.keys.push(Arc::new(Key {
            kid: kid.clone(),
            alg: alg.into(),
            signer,
            jwk,
        }));
        st.current = kid.clone();
        kid
    }

    pub fn jwks(&self) -> Vec<Value> {
        self.state
            .lock()
            .unwrap()
            .keys
            .iter()
            .map(|k| k.jwk.clone())
            .collect()
    }

    pub fn fail(&self, status: Option<u16>) {
        self.state.lock().unwrap().fail = status;
    }

    pub async fn hits(&self, p: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == p)
            .count()
    }

    /// Mints a token: `claims` merged over iss/aud/sub/iat/exp (null removes a claim),
    /// `header` merged over alg/typ/kid (null removes a field).
    pub fn mint_with(&self, claims: Value, kid: Option<&str>, header: Value, ttl: u64) -> String {
        let st = self.state.lock().unwrap();
        let use_kid = kid.map(str::to_owned).unwrap_or_else(|| st.current.clone());
        let key = st
            .keys
            .iter()
            .find(|k| k.kid == use_kid)
            .expect("unknown kid")
            .clone();
        drop(st);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut payload: Map<String, Value> = json!({
            "iss": self.issuer, "aud": self.audience, "sub": "user-1", "iat": now, "exp": now + ttl
        })
        .as_object()
        .unwrap()
        .clone();
        merge(&mut payload, claims);
        let mut head: Map<String, Value> = json!({"alg": key.alg, "typ": "JWT", "kid": key.kid})
            .as_object()
            .unwrap()
            .clone();
        merge(&mut head, header);
        let signed = format!(
            "{}.{}",
            b64(&serde_json::to_vec(&head).unwrap()),
            b64(&serde_json::to_vec(&payload).unwrap())
        );
        format!("{signed}.{}", b64(&sign(&key, signed.as_bytes())))
    }

    pub fn mint(&self, claims: Value) -> String {
        self.mint_with(claims, None, json!({}), 300)
    }
}

fn merge(into: &mut Map<String, Value>, extra: Value) {
    if let Value::Object(extra) = extra {
        for (k, v) in extra {
            if v.is_null() {
                into.remove(&k);
            } else {
                into.insert(k, v);
            }
        }
    }
}

pub fn sign(key: &Key, data: &[u8]) -> Vec<u8> {
    let rng = SystemRandom::new();
    match &key.signer {
        Signer::Rsa(kp) => {
            let mut sig = vec![0u8; kp.public().modulus_len()];
            kp.sign(&signature::RSA_PKCS1_SHA256, &rng, data, &mut sig)
                .unwrap();
            sig
        }
        Signer::Ec(kp) => kp.sign(&rng, data).unwrap().as_ref().to_vec(),
        Signer::Ed(kp) => kp.sign(data).as_ref().to_vec(),
    }
}
