//! Verifies a real Casdoor access token (minted by docker/bootstrap) through discovery + JWKS.

use grow_oidc::{ErrorCode, Verifier};
use grow_oidc_integration::load_bootstrap_env;

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set by docker/bootstrap"))
}

#[tokio::test]
async fn verifier_from_env_verifies_a_real_token() {
    load_bootstrap_env();
    let token = var("GROW_OIDC_TOKEN");
    let verifier = Verifier::from_env().expect("verifier from env");
    let user = verifier.verify(&token).await.expect("real token verifies");
    assert_eq!(user.sub, var("GROW_OIDC_IT_SUB"));
    assert_eq!(
        user.email.as_deref(),
        Some(var("GROW_OIDC_IT_EMAIL").as_str())
    );
    assert!(
        user.has_role(&[var("GROW_OIDC_IT_ROLE").as_str()]),
        "{:?}",
        user.roles
    );
    assert_eq!(user.claims["iss"], var("GROW_AUTH_ISSUER"));

    let (signed, sig) = token.rsplit_once('.').unwrap();
    let flipped = if sig.starts_with('A') { "B" } else { "A" };
    let tampered = format!("{signed}.{flipped}{}", &sig[1..]);
    assert_eq!(
        verifier.verify(&tampered).await.unwrap_err().code(),
        ErrorCode::Authentication
    );
}
