"""Grow Codes SDK for OIDC: provider-neutral access-token verification.

>>> from grow_oidc import Verifier
>>> verifier = Verifier.from_env()  # doctest: +SKIP
>>> user = verifier.verify(token)  # doctest: +SKIP
"""

from . import _core
from ._core import *  # noqa: F403
from ._version import __version__
from .client import DISCOVERY_PATH, AsyncOidcClient, OidcClient, relative_endpoint
from .config import DEFAULT_URL, OidcConfig
from .integrations import (
    DjangoOidcMiddleware,
    OidcMiddleware,
    default_verifier,
    django_require_roles,
    require_user,
    set_default_verifier,
)
from .roles import claim_at, extract_roles, has_any_role
from .verifier import (
    DEFAULT_ALGORITHMS,
    DEFAULT_CLOCK_SKEW_S,
    DEFAULT_HTTP_TIMEOUT_S,
    DEFAULT_JWKS_CACHE_TTL_S,
    DEFAULT_JWKS_REFRESH_COOLDOWN_S,
    AuthUser,
    Verifier,
    bearer_token,
)

__all__ = [
    "__version__",
    "OidcClient",
    "AsyncOidcClient",
    "OidcConfig",
    "DEFAULT_URL",
    "DISCOVERY_PATH",
    "relative_endpoint",
    "Verifier",
    "AuthUser",
    "bearer_token",
    "extract_roles",
    "has_any_role",
    "claim_at",
    "require_user",
    "OidcMiddleware",
    "DjangoOidcMiddleware",
    "django_require_roles",
    "default_verifier",
    "set_default_verifier",
    "DEFAULT_ALGORITHMS",
    "DEFAULT_CLOCK_SKEW_S",
    "DEFAULT_HTTP_TIMEOUT_S",
    "DEFAULT_JWKS_CACHE_TTL_S",
    "DEFAULT_JWKS_REFRESH_COOLDOWN_S",
]
__all__ += _core.__all__
