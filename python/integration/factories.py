"""Factories the integration suite and the conformance runner use (owned by this repository).

sdk-kit generates this file once. Replace the bodies when the service needs more setup (extra
credentials from /bootstrap/env, namespaces, a provider built on the client …) and keep the
capability sets honest: every capability left out skips scenarios, and each skip must be
explained in docs/compatibility.md.
"""

from __future__ import annotations

from collections.abc import Mapping

import grow_oidc as sdk

URL_VAR = "GROW_OIDC_URL"

#: Capabilities of the deployment under test for the core scenarios ("version" = serverVersion,
#: "auth" = the deployment rejects a wrong token; drop it for services without authentication).
CORE_CAPABILITIES: set[str] = {"version", "auth"}


def core_client(env: Mapping[str, str]) -> sdk.OidcClient:
    """A client configured from the test environment (URL, token, … from /bootstrap/env)."""
    return sdk.OidcClient.from_env(env)


def async_core_client(env: Mapping[str, str]) -> sdk.AsyncOidcClient:
    return sdk.AsyncOidcClient.from_env(env)
