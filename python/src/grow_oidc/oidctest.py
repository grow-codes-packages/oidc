"""A local fake OpenID provider for tests (service-owned). Never use it outside tests.

Serves ``/.well-known/openid-configuration`` and ``/jwks`` on 127.0.0.1, mints signed tokens
(RS256/ES256/EdDSA) and rotates keys::

    with FakeIdP(audience="api") as idp:
        token = idp.mint({"roles": ["admin"]})
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

__all__ = ["FakeIdP", "FakeKey"]


@dataclass
class FakeKey:
    """One signing key of the fake IdP."""

    kid: str
    alg: str
    private_key: Any
    public_jwk: dict[str, Any]


def _public_jwk(alg: str, private_key: Any) -> dict[str, Any]:
    public = private_key.public_key()
    if alg == "RS256":
        return dict(jwt.algorithms.RSAAlgorithm.to_jwk(public, as_dict=True))
    if alg == "ES256":
        return dict(jwt.algorithms.ECAlgorithm.to_jwk(public, as_dict=True))
    return dict(jwt.algorithms.OKPAlgorithm.to_jwk(public, as_dict=True))


class FakeIdP:
    """Fake OpenID provider; use as a context manager or call :meth:`start` / :meth:`stop`."""

    def __init__(self, audience: str = "test-client", alg: str = "RS256") -> None:
        self.audience = audience
        self.issuer = ""
        self.keys: list[FakeKey] = []
        self.hits: dict[str, int] = {}
        self.fail_status: int | None = None
        self._alg = alg
        self._current = ""
        self._counter = 0
        self._server: ThreadingHTTPServer | None = None
        self._lock = threading.Lock()

    def __enter__(self) -> FakeIdP:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def start(self) -> FakeIdP:
        """Starts the HTTP server and creates the first key."""
        idp = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:
                path = self.path.split("?")[0]
                with idp._lock:
                    idp.hits[path] = idp.hits.get(path, 0) + 1
                    keys = [key.public_jwk for key in idp.keys]
                if idp.fail_status is not None:
                    self.send_response(idp.fail_status)
                    self.end_headers()
                    return
                if path == "/.well-known/openid-configuration":
                    body: Any = {"issuer": idp.issuer, "jwks_uri": f"{idp.issuer}/jwks"}
                elif path == "/jwks":
                    body = {"keys": keys}
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.issuer = f"http://127.0.0.1:{self._server.server_address[1]}"
        self.rotate(self._alg)
        return self

    def stop(self) -> None:
        """Stops the HTTP server."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def rotate(self, alg: str = "RS256") -> FakeKey:
        """Adds a new current key; older keys stay published until :meth:`remove_key`."""
        self._counter += 1
        kid = f"key-{self._counter}"
        private_key: Any
        if alg == "ES256":
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif alg == "EdDSA":
            private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            alg = "RS256"
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = {**_public_jwk(alg, private_key), "kid": kid, "alg": alg, "use": "sig"}
        key = FakeKey(kid, alg, private_key, jwk)
        with self._lock:
            self.keys.append(key)
        self._current = kid
        return key

    def remove_key(self, kid: str) -> None:
        """Stops publishing ``kid``."""
        with self._lock:
            self.keys = [key for key in self.keys if key.kid != kid]

    def mint(
        self,
        claims: dict[str, Any] | None = None,
        *,
        kid: str | None = None,
        header: dict[str, Any] | None = None,
        ttl_s: int = 300,
    ) -> str:
        """Signs ``claims`` over ``iss``/``aud``/``sub``/``iat``/``exp``; ``None`` removes a claim.

        ``header={"kid": None}`` omits the kid header.
        """
        use = kid or self._current
        key = next((k for k in self.keys if k.kid == use), None)
        if key is None:
            raise KeyError(f"fake idp: unknown kid {use}")
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "user-1",
            "iat": now,
            "exp": now + ttl_s,
        }
        payload.update(claims or {})
        payload = {k: v for k, v in payload.items() if v is not None}
        headers: dict[str, Any] = {"kid": key.kid, **(header or {})}
        headers = {k: v for k, v in headers.items() if v is not None}
        return jwt.encode(payload, key.private_key, algorithm=key.alg, headers=headers)
