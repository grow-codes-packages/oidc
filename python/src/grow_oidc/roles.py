"""Roles extraction shared by the verifier and the framework adapters (service-owned)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

__all__ = ["claim_at", "extract_roles", "has_any_role"]

_ROLE_OBJECT_KEYS = ("name", "code", "role", "value")
_MISSING = object()


def claim_at(claims: Mapping[str, Any], path: str) -> Any:
    """Value at a claim name (``roles``) or dotted path (``realm_access.roles``), else ``None``.

    An exact top-level match wins, so claim names containing dots keep working.
    """
    if path in claims:
        return claims[path]
    current: Any = claims
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part, _MISSING)
        if current is _MISSING:
            return None
    return current


def _role_name(entry: Any) -> str:
    if isinstance(entry, str):
        return entry.strip()
    if isinstance(entry, Mapping):
        for key in _ROLE_OBJECT_KEYS:
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def extract_roles(claims: Mapping[str, Any], roles_claim: str = "roles") -> list[str]:
    """Role names of the claim at ``roles_claim``.

    A string is split on commas and whitespace; a list yields each string, or each object's
    ``name`` (Casdoor), ``code``, ``role`` or ``value``; anything else yields ``[]``.
    Duplicates are removed, order is kept.
    """
    raw = claim_at(claims, roles_claim or "roles")
    names: Iterable[str] = ()
    if isinstance(raw, str):
        names = re.split(r"[\s,]+", raw)
    elif isinstance(raw, list):
        names = [_role_name(entry) for entry in raw]
    out: list[str] = []
    for name in names:
        if name and name not in out:
            out.append(name)
    return out


def has_any_role(user_roles: Iterable[str], required: Iterable[str]) -> bool:
    """True when ``user_roles`` has at least one of ``required`` (case-insensitive).

    An empty ``required`` means any authenticated user.
    """
    wanted = [role.lower() for role in required]
    if not wanted:
        return True
    have = {role.lower() for role in user_roles}
    return any(role in have for role in wanted)
