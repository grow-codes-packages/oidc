"""Verifies a real Casdoor access token (minted by docker/bootstrap) through discovery + JWKS."""

from __future__ import annotations

import asyncio

import pytest

import grow_oidc as sdk


@pytest.fixture(scope="module")
def token(env: dict[str, str]) -> str:
    for name in ("GROW_AUTH_ISSUER", "GROW_AUTH_AUDIENCE", "GROW_OIDC_TOKEN"):
        if not env.get(name):
            pytest.fail(f"{name} must be set by docker/bootstrap")
    return env["GROW_OIDC_TOKEN"]


def test_verifier_from_env(env: dict[str, str], token: str) -> None:
    user = sdk.Verifier.from_env(env).verify(token)
    assert user.sub == env["GROW_OIDC_IT_SUB"]
    assert user.email == env["GROW_OIDC_IT_EMAIL"]
    assert env["GROW_OIDC_IT_ROLE"] in user.roles
    assert user.claims["iss"] == env["GROW_AUTH_ISSUER"]


def test_async_verify_and_rejections(env: dict[str, str], token: str) -> None:
    verifier = sdk.Verifier.from_env(env)
    assert asyncio.run(verifier.averify(token)).sub == env["GROW_OIDC_IT_SUB"]
    head, payload, sig = token.split(".")
    tampered = f"{head}.{payload}.{'B' if sig.startswith('A') else 'A'}{sig[1:]}"
    with pytest.raises(sdk.AuthenticationError):
        verifier.verify(tampered)
    with pytest.raises(sdk.AuthenticationError, match="aud"):
        sdk.Verifier.from_env(env, audience="someone-else").verify(token)


def test_fastapi_dependency(env: dict[str, str], token: str) -> None:
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    verifier = sdk.Verifier.from_env(env)
    app = FastAPI()
    role = env["GROW_OIDC_IT_ROLE"]
    dep = Depends(sdk.require_user([role], verifier=verifier))

    @app.get("/me")
    async def me(user: sdk.AuthUser = dep) -> dict[str, str]:
        return {"sub": user.sub}

    client = TestClient(app)
    assert client.get("/me").status_code == 401
    ok = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert ok.json() == {"sub": env["GROW_OIDC_IT_SUB"]}
