"""OIDC clients (sync and async).

This file is owned by the service package (generated once by sdk-kit). The client talks to the
OpenID provider itself: ``health`` reads the discovery document, ``ping`` calls the provider's
``userinfo_endpoint`` with the configured access token; OpenID Connect has no version endpoint.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from types import TracebackType
from typing import Any

import httpx

from ._core import (
    AsyncHttpTransport,
    CancelledError,
    CancelToken,
    ConfigError,
    HealthStatus,
    HttpTransport,
    Request,
    ResourceRegistry,
    Response,
    ServiceError,
    TimeoutError,
    UnavailableError,
    UnsupportedError,
    ValidationError,
)
from .config import OidcConfig

__all__ = ["DISCOVERY_PATH", "AsyncOidcClient", "OidcClient", "relative_endpoint"]

#: Discovery document path, relative to the provider URL (realm prefixes such as Keycloak's kept).
DISCOVERY_PATH = ".well-known/openid-configuration"
_HEALTH = Request("GET", DISCOVERY_PATH, operation="health", raise_for_status=False, max_retries=0)
_DISCOVERY = Request("GET", DISCOVERY_PATH, operation="ping")
_NO_VERSION = "server_version: OpenID Connect providers expose no version"


def relative_endpoint(base: str, endpoint: str) -> str:
    """Path of ``endpoint`` relative to the provider URL ``base``.

    The part after ``base`` when the endpoint starts with it (keeps realm prefixes out), else the
    endpoint's own path and query.
    """
    root = base.rstrip("/")
    if endpoint.startswith(root + "/"):
        return endpoint[len(root) :]
    parsed = httpx.URL(endpoint)
    path = parsed.path or endpoint
    query = parsed.query.decode()
    return f"{path}?{query}" if query else path


def _userinfo(resp: Response, config: OidcConfig) -> Request:
    body: Any = resp.json()
    endpoint = body.get("userinfo_endpoint") if isinstance(body, Mapping) else None
    if not isinstance(endpoint, str) or not endpoint:
        raise UnsupportedError("ping: the provider has no userinfo endpoint")
    return Request(
        "GET",
        relative_endpoint(config.url, endpoint),
        operation="ping",
        headers=_auth_headers(config),
    )


def _auth_headers(config: OidcConfig) -> dict[str, str]:
    if config.token is None:
        return {}
    return {"Authorization": f"Bearer {config.token.reveal()}"}


def _health_from_response(resp: Response) -> HealthStatus:
    status = "ok" if resp.ok else "unhealthy"
    details: dict[str, str] = {}
    try:
        body: Any = resp.json()
    except ValidationError:
        body = None
    if isinstance(body, Mapping) and isinstance(body.get("issuer"), str):
        details["issuer"] = body["issuer"]
    if not resp.ok:
        details.setdefault("httpStatus", str(resp.status))
    return HealthStatus(healthy=resp.ok, status=status, details=details)


def _health_from_error(err: ServiceError) -> HealthStatus:
    if isinstance(err, (CancelledError, ConfigError)):
        raise err
    word = "unreachable" if isinstance(err, (UnavailableError, TimeoutError)) else "unhealthy"
    return HealthStatus(healthy=False, status=word, details={"error": err.message})


class OidcClient:
    """Synchronous OIDC client. Thread-safe; use as a context manager or call
    :meth:`close`.

    Every I/O method accepts ``cancel=`` (a :class:`CancelToken`) to abort from another thread.
    """

    def __init__(
        self,
        config: OidcConfig | None = None,
        *,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        if config is None:
            config = OidcConfig.from_env()
        self.config = config.validate()
        self._resources = ResourceRegistry()
        self._transport = HttpTransport(
            self.config, known_secrets=self.config.known_secrets, http_transport=http_transport
        )

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        **overrides: Any,
    ) -> OidcClient:
        """Build a client from the ``GROW_<KEY>_*`` and vendor environment variables."""
        return cls(OidcConfig.from_env(env, **overrides))

    @property
    def resources(self) -> ResourceRegistry:
        """Background resources (watchers, renewers) stopped by :meth:`close`."""
        return self._resources

    def request(self, req: Request, *, cancel: CancelToken | None = None) -> Response:
        """Send a raw request through the client's transport (retries, hooks, redaction)."""
        return self._transport.request(req, cancel=cancel)

    def health(self, *, cancel: CancelToken | None = None) -> HealthStatus:
        """Unauthenticated health check; never raises for an unhealthy/unreachable service."""
        try:
            resp = self._transport.request(_HEALTH, cancel=cancel)
        except ServiceError as err:
            return _health_from_error(err)
        return _health_from_response(resp)

    def ping(self, *, cancel: CancelToken | None = None) -> float:
        """Authenticated round trip (userinfo with the configured token); latency in ms.

        :class:`AuthenticationError` for a rejected token, :class:`UnsupportedError` when the
        provider has no userinfo endpoint.
        """
        started = time.monotonic()
        discovery = self._transport.request(_DISCOVERY, cancel=cancel)
        self._transport.request(_userinfo(discovery, self.config), cancel=cancel)
        return (time.monotonic() - started) * 1000.0

    def server_version(self, *, cancel: CancelToken | None = None) -> str:
        """Always :class:`UnsupportedError` (``CancelledError`` once closed)."""
        if self._transport.closed:
            raise CancelledError("server_version: client is closed")
        raise UnsupportedError(_NO_VERSION)

    def close(self) -> None:
        """Stop watchers/renewers and close connections (idempotent)."""
        self._resources.stop_all()
        self._transport.close()

    def __enter__(self) -> OidcClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"OidcClient(config={self.config!r})"


class AsyncOidcClient:
    """Asynchronous OIDC client; use ``async with`` or call :meth:`aclose`.

    Cancel a call by cancelling its task: the SDK raises :class:`CancelledError`, which is also
    an :class:`asyncio.CancelledError`.
    """

    def __init__(
        self,
        config: OidcConfig | None = None,
        *,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if config is None:
            config = OidcConfig.from_env()
        self.config = config.validate()
        self._resources = ResourceRegistry()
        self._transport = AsyncHttpTransport(
            self.config, known_secrets=self.config.known_secrets, http_transport=http_transport
        )

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        **overrides: Any,
    ) -> AsyncOidcClient:
        return cls(OidcConfig.from_env(env, **overrides))

    @property
    def resources(self) -> ResourceRegistry:
        return self._resources

    async def request(self, req: Request) -> Response:
        return await self._transport.request(req)

    async def health(self) -> HealthStatus:
        try:
            resp = await self._transport.request(_HEALTH)
        except ServiceError as err:
            return _health_from_error(err)
        return _health_from_response(resp)

    async def ping(self) -> float:
        started = time.monotonic()
        discovery = await self._transport.request(_DISCOVERY)
        await self._transport.request(_userinfo(discovery, self.config))
        return (time.monotonic() - started) * 1000.0

    async def server_version(self) -> str:
        if self._transport.closed:
            raise CancelledError("server_version: client is closed")
        raise UnsupportedError(_NO_VERSION)

    async def aclose(self) -> None:
        """Stop watchers/renewers and close connections (idempotent)."""
        self._resources.stop_all()
        await self._transport.aclose()

    close = aclose

    async def __aenter__(self) -> AsyncOidcClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"AsyncOidcClient(config={self.config!r})"
