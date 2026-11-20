"""Provider-neutral OIDC access-token verification (service-owned).

JWKS discovery, caching and rotation; RS256/ES256/EdDSA; ``iss``/``aud``/``exp``/``nbf`` checks
with a clock skew (default 60 s); roles from a configurable claim.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
import jwt

from ._core.env import parse_duration
from ._core.errors import AuthenticationError, ConfigError, UnavailableError
from .roles import extract_roles, has_any_role

__all__ = [
    "DEFAULT_ALGORITHMS",
    "DEFAULT_CLOCK_SKEW_S",
    "DEFAULT_HTTP_TIMEOUT_S",
    "DEFAULT_JWKS_CACHE_TTL_S",
    "DEFAULT_JWKS_REFRESH_COOLDOWN_S",
    "AuthUser",
    "Verifier",
    "bearer_token",
]

#: Accepted algorithms (asymmetric only; ``none`` and HMAC are never accepted).
DEFAULT_ALGORITHMS: tuple[str, ...] = ("RS256", "ES256", "EdDSA")
#: Tolerance applied to ``exp`` and ``nbf``.
DEFAULT_CLOCK_SKEW_S = 60.0
#: JWKS cache lifetime.
DEFAULT_JWKS_CACHE_TTL_S = 600.0
#: Minimum interval between two refetches caused by an unknown ``kid``.
DEFAULT_JWKS_REFRESH_COOLDOWN_S = 30.0
#: Timeout of discovery and JWKS requests.
DEFAULT_HTTP_TIMEOUT_S = 10.0

_KTY_FOR_ALG = {"RS256": "RSA", "ES256": "EC", "EdDSA": "OKP"}
_BEARER_RE = re.compile(r"^\s*bearer\s+(\S+)\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class AuthUser:
    """The authenticated user of a verified access token."""

    sub: str
    roles: list[str]
    claims: dict[str, Any] = field(repr=False)
    email: str | None = None
    name: str | None = None

    def has_role(self, *roles: str) -> bool:
        """True when the user has at least one of ``roles`` (case-insensitive)."""
        return has_any_role(self.roles, roles)


def bearer_token(source: Any) -> str | None:
    """Bearer token of an ``Authorization`` header, or ``None``.

    ``source`` is a header value string, a headers mapping (case-insensitive lookup), or an
    object with ``.headers`` (Starlette/FastAPI/Django/httpx requests).
    """
    value: Any = source
    if source is not None and not isinstance(source, str):
        headers = getattr(source, "headers", source)
        value = None
        if isinstance(headers, Mapping) or hasattr(headers, "get"):
            value = headers.get("authorization") or headers.get("Authorization")
    if not isinstance(value, str):
        return None
    match = _BEARER_RE.match(value)
    return match.group(1) if match else None


def _check_url(name: str, value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ConfigError(f"oidc: {name} must be an http or https URL")


@dataclass
class _KeySet:
    keys: list[tuple[str | None, str | None, str | None, jwt.PyJWK]]
    fetched_at: float


class Verifier:
    """Verifies OIDC access tokens (JWT) against the issuer's JWKS. Thread-safe.

    Raises :class:`AuthenticationError` for every invalid token (the message names the failed check,
    never the token), :class:`UnavailableError` when discovery or the JWKS cannot be fetched and
    :class:`ConfigError` for invalid options. ``verify`` is synchronous; ``averify`` is the
    ``async`` variant with the same behaviour.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        *,
        jwks_url: str | None = None,
        roles_claim: str = "roles",
        algorithms: Sequence[str] = DEFAULT_ALGORITHMS,
        clock_skew_s: float = DEFAULT_CLOCK_SKEW_S,
        jwks_cache_ttl_s: float = DEFAULT_JWKS_CACHE_TTL_S,
        jwks_refresh_cooldown_s: float = DEFAULT_JWKS_REFRESH_COOLDOWN_S,
        http_timeout_s: float = DEFAULT_HTTP_TIMEOUT_S,
        http_client: httpx.Client | None = None,
        async_http_client: httpx.AsyncClient | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        if not issuer or not issuer.strip():
            raise ConfigError("oidc: issuer is required")
        if not audience or not audience.strip():
            raise ConfigError("oidc: audience is required")
        self.issuer = issuer.strip()
        self.audience = audience.strip()
        _check_url("issuer", self.issuer)
        self._jwks_url = jwks_url.strip() if jwks_url and jwks_url.strip() else None
        if self._jwks_url is not None:
            _check_url("jwks_url", self._jwks_url)
        self.roles_claim = (roles_claim or "roles").strip() or "roles"
        algs = tuple(algorithms)
        if not algs or any(alg not in DEFAULT_ALGORITHMS for alg in algs):
            raise ConfigError("oidc: algorithms must be a non-empty subset of RS256, ES256, EdDSA")
        self.algorithms = algs
        for name, value in (
            ("clock_skew_s", clock_skew_s),
            ("jwks_cache_ttl_s", jwks_cache_ttl_s),
            ("jwks_refresh_cooldown_s", jwks_refresh_cooldown_s),
            ("http_timeout_s", http_timeout_s),
        ):
            if value < 0:
                raise ConfigError(f"oidc: {name} must not be negative")
        self.clock_skew_s = float(clock_skew_s)
        self._ttl = float(jwks_cache_ttl_s)
        self._cooldown = float(jwks_refresh_cooldown_s)
        self._timeout = float(http_timeout_s)
        self._http = http_client
        self._ahttp = async_http_client
        self._now = now
        self._lock = threading.Lock()
        self._fetch_lock = threading.Lock()
        self._resolved: str | None = None
        self._keys: _KeySet | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> Verifier:
        """Builds a verifier from ``GROW_AUTH_*`` variables; keyword ``overrides`` win.

        ``GROW_AUTH_ISSUER`` (required), ``GROW_AUTH_AUDIENCE`` (default ``GROW_AUTH_CLIENT_ID``),
        ``GROW_AUTH_JWKS_URL``, ``GROW_AUTH_ROLES_CLAIM`` (default ``roles``) and
        ``GROW_AUTH_CLOCK_SKEW`` (duration, default ``60s``).
        """
        source = os.environ if env is None else env

        def read(name: str) -> str | None:
            value = source.get(name, "").strip()
            return value or None

        issuer = overrides.pop("issuer", None) or read("GROW_AUTH_ISSUER")
        if issuer is None:
            raise ConfigError("oidc: GROW_AUTH_ISSUER is required")
        audience = (
            overrides.pop("audience", None)
            or read("GROW_AUTH_AUDIENCE")
            or read("GROW_AUTH_CLIENT_ID")
        )
        if audience is None:
            raise ConfigError("oidc: GROW_AUTH_AUDIENCE (or GROW_AUTH_CLIENT_ID) is required")
        kwargs: dict[str, Any] = {}
        if (jwks_url := read("GROW_AUTH_JWKS_URL")) is not None:
            kwargs["jwks_url"] = jwks_url
        if (roles_claim := read("GROW_AUTH_ROLES_CLAIM")) is not None:
            kwargs["roles_claim"] = roles_claim
        if (skew := read("GROW_AUTH_CLOCK_SKEW")) is not None:
            try:
                kwargs["clock_skew_s"] = parse_duration(skew)
            except (ValueError, TypeError) as exc:
                raise ConfigError("oidc: GROW_AUTH_CLOCK_SKEW is not a duration") from exc
        kwargs.update(overrides)
        return cls(issuer, audience, **kwargs)

    def clear_cache(self) -> None:
        """Drops the cached JWKS so the next verification refetches it."""
        with self._lock:
            self._keys = None

    # ------------------------------------------------------------------ verification

    def _parse(self, token: str) -> tuple[str, str | None]:
        if not isinstance(token, str) or token.count(".") != 2:
            raise AuthenticationError("verify: malformed token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthenticationError("verify: malformed token header") from exc
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self.algorithms:
            shown = alg[:16] if isinstance(alg, str) and alg else "(none)"
            raise AuthenticationError(f"verify: algorithm {shown} is not allowed")
        kid = header.get("kid")
        return alg, kid if isinstance(kid, str) else None

    @staticmethod
    def _candidates(keys: _KeySet, alg: str, kid: str | None) -> list[jwt.PyJWK]:
        out = []
        for key_kid, key_alg, use, key in keys.keys:
            if kid is not None and key_kid != kid:
                continue
            if use == "enc" or (key_alg is not None and key_alg != alg):
                continue
            if key.key_type != _KTY_FOR_ALG[alg]:
                continue
            out.append(key)
        return out

    def _finish(self, token: str, alg: str, kid: str | None, keys: list[jwt.PyJWK]) -> AuthUser:
        if not keys:
            raise AuthenticationError(f"verify: no key matches kid {kid or '(none)'}")
        claims: dict[str, Any] | None = None
        for key in keys:
            try:
                claims = jwt.decode(
                    token,
                    key=key.key,
                    algorithms=[alg],
                    options={
                        "verify_signature": True,
                        "verify_exp": False,
                        "verify_nbf": False,
                        "verify_iat": False,
                        "verify_aud": False,
                        "verify_iss": False,
                        "verify_sub": False,
                        "verify_jti": False,
                    },
                )
                break
            except jwt.InvalidSignatureError:
                continue
            except jwt.PyJWTError as exc:
                raise AuthenticationError("verify: token is invalid") from exc
        if claims is None:
            raise AuthenticationError("verify: signature is invalid")
        self._check_claims(claims)
        return self._to_user(claims)

    def _check_claims(self, claims: Mapping[str, Any]) -> None:
        if claims.get("iss") != self.issuer:
            raise AuthenticationError("verify: claim iss is invalid (unexpected value)")
        aud = claims.get("aud")
        if not (aud == self.audience or (isinstance(aud, list) and self.audience in aud)):
            raise AuthenticationError("verify: claim aud is invalid (unexpected value)")
        now = self._now()
        exp = claims.get("exp")
        if exp is None:
            raise AuthenticationError("verify: claim exp is invalid (missing)")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise AuthenticationError("verify: claim exp is invalid (not a number)")
        if now > exp + self.clock_skew_s:
            raise AuthenticationError("verify: token expired")
        nbf = claims.get("nbf")
        if nbf is not None:
            if isinstance(nbf, bool) or not isinstance(nbf, (int, float)):
                raise AuthenticationError("verify: claim nbf is invalid (not a number)")
            if now + self.clock_skew_s < nbf:
                raise AuthenticationError("verify: claim nbf is invalid (not yet valid)")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise AuthenticationError("verify: claim sub is invalid (missing)")

    def _to_user(self, claims: dict[str, Any]) -> AuthUser:
        email = claims.get("email")
        name = claims.get("name")
        if not isinstance(name, str):
            name = claims.get("preferred_username")
        return AuthUser(
            sub=str(claims["sub"]),
            roles=extract_roles(claims, self.roles_claim),
            claims=claims,
            email=email if isinstance(email, str) else None,
            name=name if isinstance(name, str) else None,
        )

    def _cached(self, force: bool) -> _KeySet | None:
        with self._lock:
            keys = self._keys
        if not force and keys is not None and self._now() - keys.fetched_at < self._ttl:
            return keys
        return None

    def _may_refresh(self, keys: _KeySet, kid: str | None) -> bool:
        return kid is not None and self._now() - keys.fetched_at >= self._cooldown

    def verify(self, token: str) -> AuthUser:
        """Verifies a raw JWT access token and returns its user."""
        alg, kid = self._parse(token)
        keys = self._key_set(force=False)
        candidates = self._candidates(keys, alg, kid)
        if not candidates and self._may_refresh(keys, kid):
            candidates = self._candidates(self._key_set(force=True), alg, kid)
        return self._finish(token, alg, kid, candidates)

    async def averify(self, token: str) -> AuthUser:
        """``async`` variant of :meth:`verify`."""
        alg, kid = self._parse(token)
        keys = await self._akey_set(force=False)
        candidates = self._candidates(keys, alg, kid)
        if not candidates and self._may_refresh(keys, kid):
            candidates = self._candidates(await self._akey_set(force=True), alg, kid)
        return self._finish(token, alg, kid, candidates)

    def verify_request(self, request: Any) -> AuthUser:
        """Verifies the bearer token of a request (``AuthenticationError`` when missing)."""
        token = bearer_token(request)
        if token is None:
            raise AuthenticationError("verify: missing bearer token")
        return self.verify(token)

    # ------------------------------------------------------------------ JWKS

    def _store(self, body: Any) -> _KeySet:
        if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
            raise UnavailableError("jwks: response has no keys array")
        parsed = []
        for raw in body["keys"]:
            if not isinstance(raw, dict):
                continue
            try:
                key = jwt.PyJWK(raw)
            except (jwt.PyJWTError, ValueError, TypeError, KeyError):
                continue
            parsed.append((raw.get("kid"), raw.get("alg"), raw.get("use"), key))
        keys = _KeySet(parsed, self._now())
        with self._lock:
            self._keys = keys
        return keys

    @staticmethod
    def _decode(operation: str, res: httpx.Response) -> Any:
        if not res.is_success:
            raise UnavailableError(
                f"{operation}: unexpected response (HTTP {res.status_code})",
                http_status=res.status_code,
            )
        try:
            return res.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise UnavailableError(f"{operation}: response is not JSON", cause=exc) from exc

    def _discovery_url(self) -> str:
        return self.issuer.rstrip("/") + "/.well-known/openid-configuration"

    def _resolve(self, doc: Any) -> str:
        uri = doc.get("jwks_uri") if isinstance(doc, dict) else None
        if not isinstance(uri, str) or not uri:
            raise UnavailableError("discovery: document has no jwks_uri")
        self._resolved = uri
        return uri

    def _get(self, operation: str, url: str) -> Any:
        try:
            if self._http is not None:
                res = self._http.get(url, headers={"accept": "application/json"})
            else:
                with httpx.Client(timeout=self._timeout, trust_env=False) as client:
                    res = client.get(url, headers={"accept": "application/json"})
        except httpx.HTTPError as exc:
            raise UnavailableError(f"{operation}: request failed", cause=exc) from exc
        return self._decode(operation, res)

    async def _aget(self, operation: str, url: str) -> Any:
        try:
            if self._ahttp is not None:
                res = await self._ahttp.get(url, headers={"accept": "application/json"})
            else:
                async with httpx.AsyncClient(timeout=self._timeout, trust_env=False) as client:
                    res = await client.get(url, headers={"accept": "application/json"})
        except httpx.HTTPError as exc:
            raise UnavailableError(f"{operation}: request failed", cause=exc) from exc
        return self._decode(operation, res)

    def _key_set(self, force: bool) -> _KeySet:
        cached = self._cached(force)
        if cached is not None:
            return cached
        with self._fetch_lock:
            with self._lock:
                current = self._keys
            if current is not None and not force and self._now() - current.fetched_at < self._ttl:
                return current
            url = self._jwks_url or self._resolved
            if url is None:
                url = self._resolve(self._get("discovery", self._discovery_url()))
            return self._store(self._get("jwks", url))

    async def _akey_set(self, force: bool) -> _KeySet:
        cached = self._cached(force)
        if cached is not None:
            return cached
        url = self._jwks_url or self._resolved
        if url is None:
            url = self._resolve(await self._aget("discovery", self._discovery_url()))
        return self._store(await self._aget("jwks", url))
