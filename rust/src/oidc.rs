//! Provider-neutral OIDC access-token verification (service-owned).
//!
//! JWKS discovery, caching and rotation; RS256/384/512, PS256/384/512, ES256, ES384 and EdDSA (via
//! `ring`, which has no P-521, so ES512 is not supported); `iss`/`aud`/`exp`/`nbf` checks with a
//! clock skew (default 60 s); roles from a configurable claim.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{self, UnparsedPublicKey};
use serde_json::{Map, Value};

use crate::core::{Error, ErrorCode, Result};

/// Accepted algorithms by default: every supported one (asymmetric only; `none` and HMAC are never
/// accepted). ES512 is not supported (`ring` has no P-521).
pub const DEFAULT_ALGORITHMS: [&str; 9] = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];
/// Default tolerance applied to `exp` and `nbf`.
pub const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(60);
/// Default JWKS cache lifetime.
pub const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(600);
/// Default minimum interval between two unknown-`kid` refetches.
pub const DEFAULT_JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
/// Default timeout of discovery and JWKS requests.
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The authenticated user of a verified access token.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthUser {
    /// `sub` claim.
    pub sub: String,
    /// `email` claim when present.
    pub email: Option<String>,
    /// `name` claim, else `preferred_username`, when present.
    pub name: Option<String>,
    /// Role names from the roles claim (strings, or Casdoor-style `{name}` objects).
    pub roles: Vec<String>,
    /// Every claim of the token.
    pub claims: Map<String, Value>,
}

impl AuthUser {
    /// True when the user has at least one of `roles` (case-insensitive).
    pub fn has_role(&self, roles: &[&str]) -> bool {
        has_any_role(&self.roles, roles)
    }
}

/// A clock returning the current time (tests inject a fake one).
pub type ClockFn = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// Options of a [`Verifier`]. `Default` gives the documented defaults (issuer/audience empty).
#[derive(Clone)]
pub struct VerifierOptions {
    /// Expected `iss` (exact); discovery uses `<issuer>/.well-known/openid-configuration`.
    pub issuer: String,
    /// Expected `aud` (the token's `aud` must contain it).
    pub audience: String,
    /// JWKS URL; skips discovery when set.
    pub jwks_url: Option<String>,
    /// Claim (or dotted path such as `realm_access.roles`) with the roles; default `roles`.
    pub roles_claim: Option<String>,
    /// Allow-list, a subset of [`DEFAULT_ALGORITHMS`]; empty = all of them.
    pub algorithms: Vec<String>,
    /// `exp`/`nbf` tolerance (default 60 s).
    pub clock_skew: Duration,
    /// JWKS cache lifetime (default 10 min).
    pub jwks_cache_ttl: Duration,
    /// Minimum interval between unknown-`kid` refetches (default 30 s).
    pub jwks_refresh_cooldown: Duration,
    /// Timeout of discovery/JWKS requests (default 10 s).
    pub http_timeout: Duration,
    /// HTTP client (proxies, TLS); default a new client with `http_timeout`.
    pub http_client: Option<reqwest::Client>,
    /// Clock (tests); default `SystemTime::now`.
    pub now: Option<ClockFn>,
}

impl Default for VerifierOptions {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: String::new(),
            jwks_url: None,
            roles_claim: None,
            algorithms: Vec::new(),
            clock_skew: DEFAULT_CLOCK_SKEW,
            jwks_cache_ttl: DEFAULT_JWKS_CACHE_TTL,
            jwks_refresh_cooldown: DEFAULT_JWKS_REFRESH_COOLDOWN,
            http_timeout: DEFAULT_HTTP_TIMEOUT,
            http_client: None,
            now: None,
        }
    }
}

impl fmt::Debug for VerifierOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierOptions")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwks_url", &self.jwks_url)
            .field("roles_claim", &self.roles_claim)
            .field("algorithms", &self.algorithms)
            .field("clock_skew", &self.clock_skew)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct Key {
    kid: Option<String>,
    alg: Option<String>,
    usage: Option<String>,
    kind: KeyKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Curve {
    P256,
    P384,
}

#[derive(Clone)]
enum KeyKind {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ec { curve: Curve, point: Vec<u8> },
    Ed(Vec<u8>),
}

/// How `ring` verifies one algorithm.
enum Verification {
    Rsa(&'static signature::RsaParameters),
    Raw(&'static dyn signature::VerificationAlgorithm),
}

/// The `ring` verification for `alg` with a key of `kind`, or `None` when the key type (and the
/// curve of an EC key) does not match `alg`: the token header never picks a mismatching algorithm.
fn verification(kind: &KeyKind, alg: &str) -> Option<Verification> {
    use Verification::{Raw, Rsa};
    Some(match (kind, alg) {
        (KeyKind::Rsa { .. }, "RS256") => Rsa(&signature::RSA_PKCS1_2048_8192_SHA256),
        (KeyKind::Rsa { .. }, "RS384") => Rsa(&signature::RSA_PKCS1_2048_8192_SHA384),
        (KeyKind::Rsa { .. }, "RS512") => Rsa(&signature::RSA_PKCS1_2048_8192_SHA512),
        (KeyKind::Rsa { .. }, "PS256") => Rsa(&signature::RSA_PSS_2048_8192_SHA256),
        (KeyKind::Rsa { .. }, "PS384") => Rsa(&signature::RSA_PSS_2048_8192_SHA384),
        (KeyKind::Rsa { .. }, "PS512") => Rsa(&signature::RSA_PSS_2048_8192_SHA512),
        (
            KeyKind::Ec {
                curve: Curve::P256, ..
            },
            "ES256",
        ) => Raw(&signature::ECDSA_P256_SHA256_FIXED),
        (
            KeyKind::Ec {
                curve: Curve::P384, ..
            },
            "ES384",
        ) => Raw(&signature::ECDSA_P384_SHA384_FIXED),
        (KeyKind::Ed(_), "EdDSA") => Raw(&signature::ED25519),
        _ => return None,
    })
}

impl Key {
    fn compatible(&self, alg: &str) -> bool {
        if self.usage.as_deref() == Some("enc") || self.alg.as_deref().is_some_and(|a| a != alg) {
            return false;
        }
        verification(&self.kind, alg).is_some()
    }

    fn verify(&self, alg: &str, signed: &[u8], sig: &[u8]) -> bool {
        match (verification(&self.kind, alg), &self.kind) {
            (Some(Verification::Rsa(params)), KeyKind::Rsa { n, e }) => {
                signature::RsaPublicKeyComponents { n, e }
                    .verify(params, signed, sig)
                    .is_ok()
            }
            (
                Some(Verification::Raw(algorithm)),
                KeyKind::Ec { point: bytes, .. } | KeyKind::Ed(bytes),
            ) => UnparsedPublicKey::new(algorithm, bytes)
                .verify(signed, sig)
                .is_ok(),
            _ => false,
        }
    }
}

fn b64(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

fn parse_key(raw: &Value) -> Option<Key> {
    let obj = raw.as_object()?;
    let text = |name: &str| obj.get(name).and_then(Value::as_str).map(str::to_owned);
    let field = |name: &str| text(name).as_deref().and_then(b64);
    let kind = match (text("kty").as_deref(), text("crv").as_deref()) {
        (Some("RSA"), _) => {
            let (n, e) = (field("n")?, field("e")?);
            (n.len() >= 256 && !e.is_empty()).then_some(KeyKind::Rsa { n, e })?
        }
        (Some("EC"), Some(crv @ ("P-256" | "P-384"))) => {
            let (curve, size) = if crv == "P-256" {
                (Curve::P256, 32)
            } else {
                (Curve::P384, 48)
            };
            let (x, y) = (field("x")?, field("y")?);
            if x.len() != size || y.len() != size {
                return None;
            }
            let mut point = vec![4u8];
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            KeyKind::Ec { curve, point }
        }
        (Some("OKP"), Some("Ed25519")) => {
            let x = field("x")?;
            (x.len() == 32).then_some(KeyKind::Ed(x))?
        }
        _ => return None,
    };
    Some(Key {
        kid: text("kid"),
        alg: text("alg"),
        usage: text("use"),
        kind,
    })
}

struct KeySet {
    keys: Vec<Key>,
    fetched_at: SystemTime,
}

struct Inner {
    issuer: String,
    audience: String,
    roles_claim: String,
    jwks_url: Option<String>,
    algorithms: Vec<String>,
    skew: Duration,
    ttl: Duration,
    cooldown: Duration,
    http: reqwest::Client,
    now: ClockFn,
    resolved: RwLock<Option<String>>,
    keys: RwLock<Option<Arc<KeySet>>>,
    fetch: tokio::sync::Mutex<()>,
}

/// Verifies OIDC access tokens (JWT) against the issuer's JWKS. Cheap to clone; thread-safe.
///
/// Errors: [`Error::Authentication`] for every invalid token (the message names the failed check,
/// never the token), [`Error::Unavailable`] when discovery or the JWKS cannot be fetched and
/// [`Error::Config`] for invalid options.
#[derive(Clone)]
pub struct Verifier {
    inner: Arc<Inner>,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("issuer", &self.inner.issuer)
            .field("audience", &self.inner.audience)
            .finish_non_exhaustive()
    }
}

fn check_url(name: &str, value: &str) -> Result<()> {
    match url::Url::parse(value) {
        Ok(u) if (u.scheme() == "http" || u.scheme() == "https") && u.has_host() => Ok(()),
        _ => Err(Error::config(format!(
            "oidc: {name} must be an http or https URL"
        ))),
    }
}

fn auth(reason: impl fmt::Display) -> Error {
    Error::new(ErrorCode::Authentication, format!("verify: {reason}"))
}

fn non_empty(value: Option<&String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

impl Verifier {
    /// Validates `options` and builds a verifier (no network call).
    pub fn new(options: VerifierOptions) -> Result<Self> {
        let issuer = options.issuer.trim().to_owned();
        let audience = options.audience.trim().to_owned();
        if issuer.is_empty() {
            return Err(Error::config("oidc: issuer is required"));
        }
        if audience.is_empty() {
            return Err(Error::config("oidc: audience is required"));
        }
        check_url("issuer", &issuer)?;
        let jwks_url = non_empty(options.jwks_url.as_ref());
        if let Some(url) = &jwks_url {
            check_url("jwks_url", url)?;
        }
        let algorithms = if options.algorithms.is_empty() {
            DEFAULT_ALGORITHMS.iter().map(|a| (*a).to_owned()).collect()
        } else {
            options.algorithms.clone()
        };
        if algorithms
            .iter()
            .any(|a| !DEFAULT_ALGORITHMS.contains(&a.as_str()))
        {
            return Err(Error::config(
                "oidc: algorithms must be a subset of RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA",
            ));
        }
        let http = match options.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .timeout(options.http_timeout)
                .build()
                .map_err(|e| Error::config("oidc: cannot build the HTTP client").with_source(e))?,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                issuer,
                audience,
                roles_claim: non_empty(options.roles_claim.as_ref())
                    .unwrap_or_else(|| "roles".into()),
                jwks_url,
                algorithms,
                skew: options.clock_skew,
                ttl: options.jwks_cache_ttl,
                cooldown: options.jwks_refresh_cooldown,
                http,
                now: options.now.unwrap_or_else(|| Arc::new(SystemTime::now)),
                resolved: RwLock::new(None),
                keys: RwLock::new(None),
                fetch: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// Builds a verifier from `GROW_AUTH_ISSUER` (required), `GROW_AUTH_AUDIENCE` (default
    /// `GROW_AUTH_CLIENT_ID`), `GROW_AUTH_JWKS_URL`, `GROW_AUTH_ROLES_CLAIM` (default `roles`) and
    /// `GROW_AUTH_CLOCK_SKEW` (duration, default `60s`).
    pub fn from_env() -> Result<Self> {
        Self::from_env_map(&std::env::vars().collect())
    }

    /// [`Verifier::from_env`] with an explicit environment map (tests).
    pub fn from_env_map(env: &HashMap<String, String>) -> Result<Self> {
        let get = |name: &str| non_empty(env.get(name));
        let issuer = get("GROW_AUTH_ISSUER")
            .ok_or_else(|| Error::config("oidc: GROW_AUTH_ISSUER is required"))?;
        let audience = get("GROW_AUTH_AUDIENCE")
            .or_else(|| get("GROW_AUTH_CLIENT_ID"))
            .ok_or_else(|| {
                Error::config("oidc: GROW_AUTH_AUDIENCE (or GROW_AUTH_CLIENT_ID) is required")
            })?;
        let mut options = VerifierOptions {
            issuer,
            audience,
            jwks_url: get("GROW_AUTH_JWKS_URL"),
            roles_claim: get("GROW_AUTH_ROLES_CLAIM"),
            ..VerifierOptions::default()
        };
        if let Some(skew) = get("GROW_AUTH_CLOCK_SKEW") {
            options.clock_skew = crate::core::parse_duration(&skew)
                .ok_or_else(|| Error::config("oidc: GROW_AUTH_CLOCK_SKEW is not a duration"))?;
        }
        Self::new(options)
    }

    /// The expected issuer.
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    /// The expected audience.
    pub fn audience(&self) -> &str {
        &self.inner.audience
    }

    /// The roles claim path.
    pub fn roles_claim(&self) -> &str {
        &self.inner.roles_claim
    }

    /// The `exp`/`nbf` tolerance.
    pub fn clock_skew(&self) -> Duration {
        self.inner.skew
    }

    /// Drops the cached JWKS so the next verification refetches it.
    pub fn clear_cache(&self) {
        *self.inner.keys.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Verifies a raw JWT access token and returns its user.
    pub async fn verify(&self, token: &str) -> Result<AuthUser> {
        let parts: Vec<&str> = token.split('.').collect();
        let [head, payload, sig] = parts.as_slice() else {
            return Err(auth("malformed token"));
        };
        let header: Map<String, Value> = b64(head)
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .ok_or_else(|| auth("malformed token header"))?;
        let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
        if !self.inner.algorithms.iter().any(|a| a == alg) {
            let shown: String = if alg.is_empty() {
                "(none)".into()
            } else {
                alg.chars().take(16).collect()
            };
            return Err(auth(format_args!("algorithm {shown} is not allowed")));
        }
        let kid = header.get("kid").and_then(Value::as_str);
        let claims: Map<String, Value> = b64(payload)
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .ok_or_else(|| auth("malformed token payload"))?;
        let sig = b64(sig).ok_or_else(|| auth("malformed token signature"))?;

        let mut set = self.key_set(false).await?;
        let elapsed = (self.inner.now)()
            .duration_since(set.fetched_at)
            .unwrap_or_default();
        if matching(&set, alg, kid).is_empty() && kid.is_some() && elapsed >= self.inner.cooldown {
            set = self.key_set(true).await?;
        }
        let candidates = matching(&set, alg, kid);
        if candidates.is_empty() {
            return Err(auth(format_args!(
                "no key matches kid {}",
                kid.unwrap_or("(none)")
            )));
        }
        let signed = format!("{head}.{payload}");
        if !candidates
            .iter()
            .any(|k| k.verify(alg, signed.as_bytes(), &sig))
        {
            return Err(auth("signature is invalid"));
        }
        self.check_claims(&claims)?;
        Ok(self.to_user(claims))
    }

    fn check_claims(&self, claims: &Map<String, Value>) -> Result<()> {
        let i = &self.inner;
        if claims.get("iss").and_then(Value::as_str) != Some(i.issuer.as_str()) {
            return Err(auth("claim iss is invalid (unexpected value)"));
        }
        let aud_ok = match claims.get("aud") {
            Some(Value::String(a)) => *a == i.audience,
            Some(Value::Array(list)) => {
                list.iter().any(|a| a.as_str() == Some(i.audience.as_str()))
            }
            _ => false,
        };
        if !aud_ok {
            return Err(auth("claim aud is invalid (unexpected value)"));
        }
        let now = (i.now)()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let skew = i.skew.as_secs_f64();
        let number = |name: &str| -> Result<Option<f64>> {
            match claims.get(name) {
                None => Ok(None),
                Some(v) => v
                    .as_f64()
                    .map(Some)
                    .ok_or_else(|| auth(format_args!("claim {name} is invalid (not a number)"))),
            }
        };
        let exp = number("exp")?.ok_or_else(|| auth("claim exp is invalid (missing)"))?;
        if now > exp + skew {
            return Err(auth("token expired"));
        }
        if number("nbf")?.is_some_and(|nbf| now + skew < nbf) {
            return Err(auth("claim nbf is invalid (not yet valid)"));
        }
        if claims
            .get("sub")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(auth("claim sub is invalid (missing)"));
        }
        Ok(())
    }

    fn to_user(&self, claims: Map<String, Value>) -> AuthUser {
        let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
        AuthUser {
            sub: text("sub").unwrap_or_default(),
            email: text("email"),
            name: text("name").or_else(|| text("preferred_username")),
            roles: extract_roles(&claims, &self.inner.roles_claim),
            claims,
        }
    }

    async fn key_set(&self, force: bool) -> Result<Arc<KeySet>> {
        let i = &self.inner;
        let cached = i.keys.read().unwrap_or_else(|e| e.into_inner()).clone();
        let fresh =
            |set: &KeySet| (i.now)().duration_since(set.fetched_at).unwrap_or_default() < i.ttl;
        if let Some(set) = &cached {
            if !force && fresh(set) {
                return Ok(set.clone());
            }
        }
        let _guard = i.fetch.lock().await;
        let current = i.keys.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(set) = current {
            let replaced = cached.as_ref().is_none_or(|c| !Arc::ptr_eq(c, &set));
            if replaced {
                return Ok(set); // fetched by another task meanwhile
            }
        }
        let url = match i
            .jwks_url
            .clone()
            .or_else(|| i.resolved.read().unwrap_or_else(|e| e.into_inner()).clone())
        {
            Some(url) => url,
            None => {
                let discovery = format!(
                    "{}/.well-known/openid-configuration",
                    i.issuer.trim_end_matches('/')
                );
                let doc = self.get_json("discovery", &discovery).await?;
                let uri = doc
                    .get("jwks_uri")
                    .and_then(Value::as_str)
                    .filter(|u| !u.is_empty())
                    .ok_or_else(|| Error::unavailable("discovery: document has no jwks_uri"))?
                    .to_owned();
                *i.resolved.write().unwrap_or_else(|e| e.into_inner()) = Some(uri.clone());
                uri
            }
        };
        let body = self.get_json("jwks", &url).await?;
        let keys = body
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::unavailable("jwks: response has no keys array"))?
            .iter()
            .filter_map(parse_key)
            .collect();
        let set = Arc::new(KeySet {
            keys,
            fetched_at: (i.now)(),
        });
        *i.keys.write().unwrap_or_else(|e| e.into_inner()) = Some(set.clone());
        Ok(set)
    }

    async fn get_json(&self, operation: &str, url: &str) -> Result<Value> {
        let res = self
            .inner
            .http
            .get(url)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                Error::unavailable(format!("{operation}: request failed")).with_source(e)
            })?;
        let status = res.status().as_u16();
        if !res.status().is_success() {
            return Err(Error::unavailable(format!(
                "{operation}: unexpected response (HTTP {status})"
            ))
            .with_status(status));
        }
        let bytes = res.bytes().await.map_err(|e| {
            Error::unavailable(format!("{operation}: request failed")).with_source(e)
        })?;
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v @ Value::Object(_)) => Ok(v),
            _ => Err(Error::unavailable(format!(
                "{operation}: response is not JSON"
            ))),
        }
    }
}

fn matching<'a>(set: &'a KeySet, alg: &str, kid: Option<&str>) -> Vec<&'a Key> {
    set.keys
        .iter()
        .filter(|k| kid.is_none_or(|kid| k.kid.as_deref() == Some(kid)) && k.compatible(alg))
        .collect()
}

/// Returns the bearer token of an `Authorization` header value (scheme case-insensitive).
pub fn bearer_token(authorization: &str) -> Option<&str> {
    let mut parts = authorization.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(scheme), Some(token), None) if scheme.eq_ignore_ascii_case("bearer") => Some(token),
        _ => None,
    }
}

/// Value at a claim name (`roles`) or dotted path (`realm_access.roles`); an exact top-level
/// match wins.
pub fn claim_at<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(v) = claims.get(path) {
        return Some(v);
    }
    let mut parts = path.split('.');
    let mut current = claims.get(parts.next()?)?;
    for part in parts {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

fn role_name(entry: &Value) -> Option<String> {
    let name = match entry {
        Value::String(s) => s.as_str(),
        Value::Object(obj) => ["name", "code", "role", "value"].iter().find_map(|k| {
            obj.get(*k)
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
        })?,
        _ => return None,
    };
    Some(name.trim().to_owned()).filter(|n| !n.is_empty())
}

/// Role names of the claim at `roles_claim`: a string is split on commas and whitespace; an array
/// yields each string, or each object's `name` (Casdoor), `code`, `role` or `value`. Duplicates
/// are removed, order is kept.
pub fn extract_roles(claims: &Map<String, Value>, roles_claim: &str) -> Vec<String> {
    let path = if roles_claim.trim().is_empty() {
        "roles"
    } else {
        roles_claim
    };
    let names: Vec<String> = match claim_at(claims, path) {
        Some(Value::String(s)) => s
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(list)) => list.iter().filter_map(role_name).collect(),
        _ => Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for name in names {
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// True when `have` contains at least one of `required` (case-insensitive); an empty `required`
/// means any authenticated user.
pub fn has_any_role<S: AsRef<str>>(have: &[S], required: &[&str]) -> bool {
    required.is_empty()
        || required
            .iter()
            .any(|r| have.iter().any(|h| h.as_ref().eq_ignore_ascii_case(r)))
}
