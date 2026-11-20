"""Conformance cases OIDC-01…OIDC-17 (docs/oidc-conformance.md) against the local fake IdP."""

from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import jwt
import pytest

from grow_oidc import (
    AuthenticationError,
    ConfigError,
    UnavailableError,
    Verifier,
    bearer_token,
    claim_at,
    extract_roles,
    has_any_role,
)
from grow_oidc.oidctest import FakeIdP


@pytest.fixture
def idp() -> Iterator[FakeIdP]:
    with FakeIdP(audience="app-client") as fake:
        yield fake


def make(idp: FakeIdP, **kwargs: Any) -> Verifier:
    return Verifier(idp.issuer, "app-client", **kwargs)


def test_oidc_01_rs256_via_discovery(idp: FakeIdP) -> None:
    token = idp.mint(
        {
            "email": "a@b.test",
            "name": "Ann",
            "roles": [{"name": "admin", "owner": "o"}, {"name": "user"}],
        }
    )
    user = make(idp).verify(token)
    assert (user.sub, user.email, user.name, user.roles) == (
        "user-1",
        "a@b.test",
        "Ann",
        ["admin", "user"],
    )
    assert user.has_role("ADMIN") and not user.has_role("x")
    assert user.claims["iss"] == idp.issuer
    assert idp.hits["/.well-known/openid-configuration"] == 1


@pytest.mark.parametrize("alg", ["ES256", "EdDSA"])
def test_oidc_02_03_other_algorithms(idp: FakeIdP, alg: str) -> None:
    idp.rotate(alg)
    user = make(idp).verify(idp.mint({"preferred_username": "bob"}))
    assert user.name == "bob"
    assert user.email is None


def test_oidc_04_to_08_claims(idp: FakeIdP) -> None:
    v = make(idp)
    now = int(time.time())
    cases = [
        ({"iss": "http://evil.test"}, "iss"),
        ({"aud": "other"}, "aud"),
        ({"exp": now - 120}, "expired"),
        ({"nbf": now + 120}, "nbf"),
        ({"exp": None}, "exp"),
        ({"exp": "soon"}, "exp"),
        ({"nbf": "soon"}, "nbf"),
        ({"sub": None}, "sub"),
    ]
    for claims, word in cases:
        with pytest.raises(AuthenticationError, match=word):
            v.verify(idp.mint(claims))
    assert v.verify(idp.mint({"aud": ["other", "app-client"]})).sub == "user-1"
    assert v.verify(idp.mint({"exp": now - 30})).sub == "user-1"
    assert v.verify(idp.mint({"nbf": now + 30})).sub == "user-1"
    with pytest.raises(AuthenticationError, match="expired"):
        make(idp, clock_skew_s=0).verify(idp.mint({"exp": now - 30}))


def test_oidc_09_algorithms(idp: FakeIdP) -> None:
    v = make(idp)

    def enc(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    with pytest.raises(AuthenticationError, match="none is not allowed"):
        v.verify(f"{enc({'alg': 'none'})}.{enc({'sub': 'x'})}.")
    hs = jwt.encode({"sub": "x"}, "0123456789abcdef0123456789abcdef", algorithm="HS256")
    with pytest.raises(AuthenticationError, match="HS256 is not allowed"):
        v.verify(hs)
    with pytest.raises(AuthenticationError, match=r"\(none\) is not allowed"):
        v.verify(f"{enc({})}.e30.c2ln")
    idp.rotate("ES256")
    with pytest.raises(AuthenticationError, match="not allowed"):
        make(idp, algorithms=["RS256"]).verify(idp.mint())
    with pytest.raises(AuthenticationError, match="malformed token"):
        v.verify("nope")
    with pytest.raises(AuthenticationError, match="malformed token header"):
        v.verify("!!.e30.c2ln")


def test_oidc_10_bad_signature(idp: FakeIdP) -> None:
    with FakeIdP(audience="app-client") as other:
        forged = other.mint({"iss": idp.issuer})
    head, payload, _ = idp.mint().split(".")
    with pytest.raises(AuthenticationError, match="signature"):
        make(idp).verify(f"{head}.{payload}.{forged.split('.')[2]}")
    with pytest.raises(AuthenticationError, match="malformed"):
        make(idp).verify(f"{head}.!!.{forged.split('.')[2]}")
    key = idp.keys[0]
    not_object = jwt.api_jws.encode(
        b"[1]", key.private_key, algorithm="RS256", headers={"kid": key.kid}
    )
    with pytest.raises(AuthenticationError, match="token is invalid"):
        make(idp).verify(not_object)


def test_oidc_11_12_rotation(idp: FakeIdP) -> None:
    now = [time.time()]
    v = make(idp, now=lambda: now[0])
    v.verify(idp.mint())
    idp.rotate("EdDSA")
    with pytest.raises(AuthenticationError, match="no key matches kid key-2"):
        v.verify(idp.mint())
    assert idp.hits["/jwks"] == 1
    now[0] += 31
    assert v.verify(idp.mint()).sub == "user-1"
    assert idp.hits["/jwks"] == 2


def test_oidc_13_cache_ttl_and_no_kid(idp: FakeIdP) -> None:
    now = [time.time()]
    v = make(idp, now=lambda: now[0])
    token = idp.mint(ttl_s=3600)
    threads = [threading.Thread(target=v.verify, args=(token,)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert idp.hits["/jwks"] == 1
    now[0] += 601
    v.verify(token)
    v.clear_cache()
    v.verify(token)
    assert idp.hits["/jwks"] == 3
    assert v.verify(idp.mint(header={"kid": None}, ttl_s=3600)).sub == "user-1"


def test_oidc_14_jwks_url_skips_discovery(idp: FakeIdP) -> None:
    make(idp, jwks_url=f"{idp.issuer}/jwks").verify(idp.mint())
    assert "/.well-known/openid-configuration" not in idp.hits


def test_oidc_15_unavailable(idp: FakeIdP) -> None:
    token = idp.mint()
    idp.fail_status = 500
    with pytest.raises(UnavailableError, match="HTTP 500"):
        make(idp).verify(token)

    def client(body: str) -> httpx.Client:
        return httpx.Client(
            transport=httpx.MockTransport(lambda _r: httpx.Response(200, text=body))
        )

    for body, msg in [
        ("nope", "not JSON"),
        ('{"issuer":"x"}', "no jwks_uri"),
        ("{}", "no jwks_uri"),
    ]:
        with pytest.raises(UnavailableError, match=msg):
            make(idp, http_client=client(body)).verify(token)
    with pytest.raises(UnavailableError, match="no keys array"):
        make(idp, jwks_url="http://x/jwks", http_client=client("{}")).verify(token)
    with pytest.raises(UnavailableError, match="request failed"):
        make(idp, jwks_url="http://127.0.0.1:1/jwks").verify(token)


def test_oidc_16_roles_claim(idp: FakeIdP) -> None:
    token = idp.mint({"realm_access": {"roles": ["editor"]}, "scope": "a b"})
    assert make(idp, roles_claim="realm_access.roles").verify(token).roles == ["editor"]
    assert make(idp, roles_claim="scope").verify(token).roles == ["a", "b"]
    assert make(idp).verify(token).roles == []
    claims = {"roles": [{"code": "b"}, {"role": "c"}, {"value": "d"}, {"x": 1}, 3, " ", "b"]}
    assert extract_roles(claims) == ["b", "c", "d"]
    assert extract_roles({"https://x/roles": ["r"]}, "https://x/roles") == ["r"]
    assert extract_roles({"roles": 5}) == []
    assert claim_at({"a": [1]}, "a.b") is None
    assert claim_at({"a": {}}, "a.b") is None
    assert has_any_role([], []) and not has_any_role(["x"], ["y"])


def test_oidc_17_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    env = {
        "GROW_AUTH_ISSUER": "http://idp:8000",
        "GROW_AUTH_CLIENT_ID": "app",
        "GROW_AUTH_ROLES_CLAIM": "groups",
    }
    v = Verifier.from_env(env)
    assert (v.audience, v.roles_claim, v.clock_skew_s) == ("app", "groups", 60.0)
    env |= {
        "GROW_AUTH_AUDIENCE": "api",
        "GROW_AUTH_JWKS_URL": "http://idp:8000/jwks",
        "GROW_AUTH_CLOCK_SKEW": "5s",
    }
    v = Verifier.from_env(env)
    assert (v.audience, v.clock_skew_s) == ("api", 5.0)
    assert Verifier.from_env(env, audience="override").audience == "override"
    with pytest.raises(ConfigError, match="CLOCK_SKEW"):
        Verifier.from_env({**env, "GROW_AUTH_CLOCK_SKEW": "soon"})
    with pytest.raises(ConfigError, match="GROW_AUTH_ISSUER"):
        Verifier.from_env({})
    with pytest.raises(ConfigError, match="GROW_AUTH_AUDIENCE"):
        Verifier.from_env({"GROW_AUTH_ISSUER": "http://x"})
    monkeypatch.setenv("GROW_AUTH_ISSUER", "http://idp")
    monkeypatch.setenv("GROW_AUTH_AUDIENCE", "x")
    assert Verifier.from_env().issuer == "http://idp"
    bad: list[dict[str, Any]] = [
        {"issuer": "", "audience": "a"},
        {"issuer": "http://x", "audience": " "},
        {"issuer": "nope", "audience": "a"},
        {"issuer": "http://x", "audience": "a", "jwks_url": "ftp://x"},
        {"issuer": "http://x", "audience": "a", "algorithms": []},
        {"issuer": "http://x", "audience": "a", "algorithms": ["HS256"]},
        {"issuer": "http://x", "audience": "a", "clock_skew_s": -1},
    ]
    for kwargs in bad:
        with pytest.raises(ConfigError):
            Verifier(**kwargs)


def test_jwks_ignores_unusable_keys(idp: FakeIdP) -> None:
    good = idp.keys[0].public_jwk
    junk = [
        "x",
        {"kty": "RSA", "n": "AQAB"},
        {"kty": "oct", "k": "AA"},
        {**good, "use": "enc"},
        {**good, "alg": "ES256"},
        {**good, "kid": "other"},
    ]
    http = httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"keys": junk}))
    )
    v = make(idp, jwks_url="http://x/jwks", http_client=http)
    with pytest.raises(AuthenticationError, match="no key matches kid key-1"):
        v.verify(idp.mint())
    ec = idp.rotate("ES256")
    junk.append({**ec.public_jwk, "kid": "key-1"})
    v.clear_cache()
    with pytest.raises(AuthenticationError, match="no key matches"):
        v.verify(idp.mint(kid="key-1"))


def test_bearer_token_shapes(idp: FakeIdP) -> None:
    class Req:
        headers = {"Authorization": "bearer  xyz "}

    assert bearer_token("Bearer abc") == "abc"
    assert bearer_token(Req()) == "xyz"
    assert bearer_token({"authorization": "Basic abc"}) is None
    assert bearer_token(None) is None
    assert bearer_token(42) is None
    with pytest.raises(AuthenticationError, match="missing bearer"):
        make(idp).verify_request({})
    assert make(idp).verify_request({"authorization": f"Bearer {idp.mint()}"}).sub == "user-1"


async def test_async_verify(idp: FakeIdP) -> None:
    now = [time.time()]
    v = make(idp, now=lambda: now[0])
    assert (await v.averify(idp.mint())).sub == "user-1"
    idp.rotate("ES256")
    now[0] += 31
    assert (await v.averify(idp.mint())).sub == "user-1"
    assert idp.hits["/jwks"] == 2
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _r: httpx.Response(503))
    ) as client:
        with pytest.raises(UnavailableError, match="HTTP 503"):
            await make(idp, async_http_client=client).averify(idp.mint())
    with pytest.raises(UnavailableError, match="request failed"):
        await make(idp, jwks_url="http://127.0.0.1:1/jwks").averify(idp.mint())
