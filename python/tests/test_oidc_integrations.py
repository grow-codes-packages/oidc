"""Conformance case OIDC-18 (middleware) for FastAPI, ASGI and Django."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from grow_oidc import (
    AuthUser,
    DjangoOidcMiddleware,
    OidcMiddleware,
    Verifier,
    default_verifier,
    django_require_roles,
    require_user,
    set_default_verifier,
)
from grow_oidc.oidctest import FakeIdP

# ruff: noqa: B008


@pytest.fixture(scope="module")
def idp() -> Iterator[FakeIdP]:
    with FakeIdP(audience="api") as fake:
        yield fake


@pytest.fixture(scope="module")
def verifier(idp: FakeIdP) -> Verifier:
    return Verifier(idp.issuer, "api")


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_fastapi_dependency(idp: FakeIdP, verifier: Verifier) -> None:
    app = FastAPI()

    @app.get("/me")
    async def me(user: AuthUser = Depends(require_user(verifier=verifier))) -> dict[str, Any]:
        return {"sub": user.sub, "roles": user.roles}

    @app.get("/admin")
    async def admin(
        user: AuthUser = Depends(require_user(["admin"], verifier=verifier)),
    ) -> dict[str, str]:
        return {"sub": user.sub}

    @app.get("/maybe")
    async def maybe(
        user: AuthUser | None = Depends(require_user(verifier=verifier, optional=True)),
    ) -> dict[str, Any]:
        return {"sub": user.sub if user else None}

    client = TestClient(app)
    none = client.get("/me")
    assert none.status_code == 401
    assert none.headers["www-authenticate"] == "Bearer"
    assert client.get("/me", headers=auth("x.y.z")).status_code == 401
    ok = client.get("/me", headers=auth(idp.mint({"roles": ["user"]})))
    assert ok.json() == {"sub": "user-1", "roles": ["user"]}
    assert client.get("/admin", headers=auth(idp.mint({"roles": ["user"]}))).status_code == 403
    assert (
        client.get("/admin", headers=auth(idp.mint({"roles": [{"name": "Admin"}]}))).status_code
        == 200
    )
    assert client.get("/maybe").json() == {"sub": None}
    down = Verifier(idp.issuer, "api", jwks_url="http://127.0.0.1:1/jwks")
    app.get("/down")(lambda user=Depends(require_user(verifier=down)): {"ok": True})
    assert client.get("/down", headers=auth(idp.mint())).status_code == 503


def test_asgi_middleware(idp: FakeIdP, verifier: Verifier) -> None:
    async def inner(scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        user = scope.get("user")
        body = (user.sub if user else "anon").encode()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    client = TestClient(OidcMiddleware(inner, verifier))
    assert client.get("/health").text == "anon"
    assert client.get("/health/check", headers=auth("x.y.z")).text == "anon"
    assert client.get("/data").status_code == 401
    assert client.get("/data", headers=auth("x.y.z")).status_code == 401
    assert client.get("/data", headers=auth(idp.mint())).text == "user-1"
    assert TestClient(OidcMiddleware(inner, verifier, optional=True)).get("/data").text == "anon"
    down = Verifier(idp.issuer, "api", jwks_url="http://127.0.0.1:1/jwks")
    assert (
        TestClient(OidcMiddleware(inner, down)).get("/x", headers=auth(idp.mint())).status_code
        == 503
    )
    seen: list[str] = []

    async def other(scope: Any, receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    asyncio.run(OidcMiddleware(other, verifier)({"type": "websocket"}, None, None))  # type: ignore[arg-type]
    assert seen == ["websocket"]


def test_default_verifier(monkeypatch: pytest.MonkeyPatch, idp: FakeIdP) -> None:
    set_default_verifier(None)
    monkeypatch.setenv("GROW_AUTH_ISSUER", idp.issuer)
    monkeypatch.setenv("GROW_AUTH_AUDIENCE", "api")
    first = default_verifier()
    assert default_verifier() is first
    app = FastAPI()
    app.get("/me")(lambda user=Depends(require_user()): {"sub": user.sub})
    assert TestClient(app).get("/me", headers=auth(idp.mint())).json() == {"sub": "user-1"}
    set_default_verifier(None)


def test_django_middleware(idp: FakeIdP, verifier: Verifier) -> None:
    from django.conf import settings

    if not settings.configured:
        settings.configure(DEFAULT_CHARSET="utf-8")

    class Request:
        def __init__(self, headers: dict[str, str]) -> None:
            self.headers = headers

    @django_require_roles("admin")
    def view(request: Any) -> str:
        """Admin view."""
        return "ok"

    mw = DjangoOidcMiddleware(view, verifier)
    assert mw(Request({})).status_code == 401
    assert mw(Request(auth("x.y.z")))["WWW-Authenticate"].startswith("Bearer")
    assert mw(Request(auth(idp.mint({"roles": ["user"]})))).status_code == 403
    assert mw(Request(auth(idp.mint({"roles": ["admin"]})))) == "ok"
    assert view.__doc__ == "Admin view."
    down = DjangoOidcMiddleware(view, Verifier(idp.issuer, "api", jwks_url="http://127.0.0.1:1/j"))
    assert down(Request(auth(idp.mint()))).status_code == 503
