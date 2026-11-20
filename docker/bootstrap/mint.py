"""Prepare Casdoor for the oidc integration suites and mint a real access token.

Run by bootstrap.sh inside the `bootstrap` container (python:3.13-alpine, standard library only).
Creates organization `oidc-it`, application `oidc-it-app` (JWT access tokens, password grant),
role `oidc-it-admin` and user `oidc-it-user`, then signs the user in with the password grant.
Writes KEY=VALUE lines to the file given as argv[1]; never prints a value.
Every Casdoor call answers HTTP 200 with {"status": "error"} on failure, so each status is checked.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ["SERVICE_URL"].rstrip("/")
ADMIN_PASSWORD = os.environ["CASDOOR_ADMIN_PASSWORD"]
ORG, APP, ROLE, USER = "oidc-it", "oidc-it-app", "oidc-it-admin", "oidc-it-user"
EMAIL = "oidc-it-user@example.test"
USER_PASSWORD = "Oidc-it-test-only-12345"  # throwaway test container, never a real secret

opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def call(path: str, body: object | None = None, form: dict[str, str] | None = None) -> object:
    """POST JSON/form (or GET) and return the decoded JSON; exits on HTTP errors."""
    data, headers = None, {"Accept": "application/json"}
    if body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(BASE + path, data=data, headers=headers)
    try:
        with opener.open(req, timeout=30) as res:
            return json.loads(res.read() or b"null")
    except urllib.error.HTTPError as exc:
        sys.exit(f"mint: {path.split('?')[0]} failed (HTTP {exc.code})")


def ok(path: str, body: object) -> object:
    """A Casdoor API call that must answer status ok."""
    res = call(path, body)
    if not isinstance(res, dict) or res.get("status") != "ok":
        msg = res.get("msg", "") if isinstance(res, dict) else ""
        sys.exit(f"mint: {path} refused: {str(msg)[:200]}")
    return res.get("data")


def claims(token: str) -> dict[str, object]:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def main(out: str) -> None:
    ok("/api/login", {"application": "app-built-in", "organization": "built-in", "username": "admin",
                      "password": ADMIN_PASSWORD, "type": "login"})
    ok("/api/add-organization", {"owner": "admin", "name": ORG, "displayName": "OIDC IT", "passwordType": "plain",
                                 "passwordOptions": ["AtLeast6"], "countryCodes": ["US"], "defaultApplication": APP,
                                 "accountItems": []})
    ok("/api/add-application", {"owner": "admin", "name": APP, "displayName": "OIDC IT", "organization": ORG,
                                "tokenFormat": "JWT", "grantTypes": ["password", "authorization_code"],
                                "redirectUris": ["http://localhost/callback"], "enablePassword": True,
                                "expireInHours": 24,
                                "signinMethods": [{"name": "Password", "displayName": "Password", "rule": "All"}]})
    app = call(f"/api/get-application?id=admin/{APP}")
    data = app.get("data") if isinstance(app, dict) else None
    if not isinstance(data, dict) or not data.get("clientId") or not data.get("clientSecret"):
        sys.exit("mint: application has no client credentials")
    client_id, client_secret = data["clientId"], data["clientSecret"]
    ok("/api/add-user", {"owner": ORG, "name": USER, "displayName": "OIDC IT", "email": EMAIL,
                         "password": USER_PASSWORD, "passwordType": "plain", "type": "normal-user",
                         "signupApplication": APP})
    ok("/api/add-role", {"owner": ORG, "name": ROLE, "displayName": "OIDC IT admin",
                         "users": [f"{ORG}/{USER}"], "isEnabled": True})
    tokens = call("/api/login/oauth/access_token", form={
        "grant_type": "password", "client_id": client_id, "client_secret": client_secret,
        "username": USER, "password": USER_PASSWORD, "scope": "openid profile email"})
    token = tokens.get("access_token") if isinstance(tokens, dict) else None
    if not isinstance(token, str) or token.count(".") != 2:
        sys.exit("mint: no JWT access token")
    c = claims(token)
    values = {
        "GROW_OIDC_TOKEN": token,
        "GROW_AUTH_ISSUER": str(c["iss"]),
        "GROW_AUTH_AUDIENCE": client_id,
        "GROW_AUTH_CLIENT_ID": client_id,
        "GROW_OIDC_IT_SUB": str(c["sub"]),
        "GROW_OIDC_IT_EMAIL": EMAIL,
        "GROW_OIDC_IT_ROLE": ROLE,
    }
    with open(out, "w", encoding="utf-8") as fh:
        for key, value in values.items():
            fh.write(f"{key}={value}\n")


if __name__ == "__main__":
    main(sys.argv[1])
