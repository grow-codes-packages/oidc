"""Framework adapters: FastAPI dependency, ASGI middleware, Django middleware (service-owned).

FastAPI and Django are optional (``pip install "grow-oidc[fastapi]"`` / ``[django]``); they are
imported only when their adapter is used. Responses never say why a token was rejected.
"""

from __future__ import annotations

import inspect
import json
import threading
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any

from ._core.errors import OidcError, UnavailableError
from .roles import has_any_role
from .verifier import AuthUser, Verifier, bearer_token

__all__ = [
    "OidcMiddleware",
    "DjangoOidcMiddleware",
    "default_verifier",
    "django_require_roles",
    "require_user",
    "set_default_verifier",
]

_default: Verifier | None = None
_default_lock = threading.Lock()


def default_verifier() -> Verifier:
    """The process-wide verifier (``Verifier.from_env()`` on first use)."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Verifier.from_env()
        return _default


def set_default_verifier(verifier: Verifier | None) -> None:
    """Replaces the process-wide verifier (``None`` = rebuild from the environment)."""
    global _default
    with _default_lock:
        _default = verifier


def _status_for(err: OidcError) -> int:
    return 503 if isinstance(err, UnavailableError) else 401


# --------------------------------------------------------------------------- FastAPI


def require_user(
    roles: Iterable[str] | None = None,
    *,
    verifier: Verifier | None = None,
    optional: bool = False,
) -> Callable[..., Awaitable[AuthUser | None]]:
    """FastAPI dependency returning the :class:`AuthUser` of the request's bearer token.

    ``Depends(require_user())`` → 401 without/with an invalid token, 503 when the IdP is
    unreachable; ``require_user(roles=["admin"])`` → 403 unless the user has one of the roles;
    ``optional=True`` returns ``None`` when there is no token. ``verifier`` defaults to
    :func:`default_verifier`.
    """
    from fastapi import HTTPException, Request  # noqa: PLC0415 - optional dependency

    required = list(roles or [])

    async def dependency(request: Request) -> AuthUser | None:
        token = bearer_token(request)
        if token is None:
            if optional:
                return None
            raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})
        try:
            user = await (verifier or default_verifier()).averify(token)
        except OidcError as exc:
            status = _status_for(exc)
            headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
            raise HTTPException(
                status, "Unauthorized" if status == 401 else "Unavailable", headers=headers
            ) from None
        if not has_any_role(user.roles, required):
            raise HTTPException(403, "Forbidden")
        request.state.user = user
        return user

    # FastAPI reads the signature; the postponed annotations of this module would hide Request.
    dependency.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        [inspect.Parameter("request", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Request)]
    )
    return dependency


# --------------------------------------------------------------------------- ASGI

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


async def _send_json(send: Send, status: int, error: str) -> None:
    headers = [(b"content-type", b"application/json")]
    if status == 401:
        headers.append((b"www-authenticate", b'Bearer error="invalid_token"'))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": json.dumps({"error": error}).encode()})


class OidcMiddleware:
    """Pure ASGI middleware (Starlette, FastAPI, any ASGI app).

    Verifies the bearer token of every HTTP request and stores the user in ``scope["user"]`` and
    ``scope["state"]["user"]`` (``request.user`` / ``request.state.user`` in Starlette).
    ``public_paths`` (exact paths or prefixes ending in ``*``) and ``optional=True`` let requests
    without a token through. Missing/invalid token → 401, IdP unreachable → 503.
    """

    def __init__(
        self,
        app: ASGIApp,
        verifier: Verifier | None = None,
        *,
        optional: bool = False,
        public_paths: Iterable[str] = ("/health", "/health/*", "/docs", "/openapi.json"),
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.optional = optional
        self.public_paths = tuple(public_paths)

    def _is_public(self, path: str) -> bool:
        for pattern in self.public_paths:
            if pattern.endswith("*"):
                if path.startswith(pattern[:-1]):
                    return True
            elif path == pattern:
                return True
        return False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        token = bearer_token(headers)
        public = self._is_public(str(scope.get("path", "")))
        if token is None:
            if self.optional or public:
                await self.app(scope, receive, send)
            else:
                await _send_json(send, 401, "unauthorized")
            return
        try:
            user = await (self.verifier or default_verifier()).averify(token)
        except OidcError as exc:
            if public:
                await self.app(scope, receive, send)
                return
            status = _status_for(exc)
            await _send_json(send, status, "unauthorized" if status == 401 else "auth_unavailable")
            return
        scope["user"] = user
        scope.setdefault("state", {})["user"] = user
        await self.app(scope, receive, send)


# --------------------------------------------------------------------------- Django


def _django_json(status: int, error: str) -> Any:
    from django.http import JsonResponse  # noqa: PLC0415 - optional dependency

    response = JsonResponse({"error": error}, status=status)
    if status == 401:
        response["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    return response


class DjangoOidcMiddleware:
    """Django middleware: sets ``request.auth_user`` (``AuthUser`` or ``None``).

    A request without a token passes with ``auth_user = None`` (protect views with
    :func:`django_require_roles`); an invalid token → 401, IdP unreachable → 503. Add
    ``"grow_oidc.integrations.DjangoOidcMiddleware"`` to ``MIDDLEWARE``.
    """

    def __init__(
        self, get_response: Callable[[Any], Any], verifier: Verifier | None = None
    ) -> None:
        self.get_response = get_response
        self.verifier = verifier

    def __call__(self, request: Any) -> Any:
        request.auth_user = None
        token = bearer_token(request)
        if token is not None:
            try:
                request.auth_user = (self.verifier or default_verifier()).verify(token)
            except OidcError as exc:
                status = _status_for(exc)
                return _django_json(status, "unauthorized" if status == 401 else "auth_unavailable")
        return self.get_response(request)


def django_require_roles(*roles: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Django view decorator: 401 without ``request.auth_user``, 403 unless one of ``roles``."""

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        def wrapped(request: Any, *args: Any, **kwargs: Any) -> Any:
            user: AuthUser | None = getattr(request, "auth_user", None)
            if user is None:
                return _django_json(401, "unauthorized")
            if not has_any_role(user.roles, roles):
                return _django_json(403, "forbidden")
            return view(request, *args, **kwargs)

        wrapped.__name__ = getattr(view, "__name__", "view")
        wrapped.__doc__ = view.__doc__
        return wrapped

    return decorator
