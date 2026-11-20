// Verifies a real Casdoor access token (minted by docker/bootstrap) through discovery + JWKS.

import assert from "node:assert/strict";
import { before, test } from "node:test";
import { AuthenticationError, Verifier, expressAuth, requireRoles } from "@grow-codes/oidc";
import { loadBootstrapEnv } from "./env.ts";

let token = "";

before(() => {
  loadBootstrapEnv();
  for (const name of ["GROW_AUTH_ISSUER", "GROW_AUTH_AUDIENCE", "GROW_OIDC_TOKEN"]) {
    assert.ok(process.env[name], `${name} must be set`);
  }
  token = process.env.GROW_OIDC_TOKEN ?? "";
});

test("Verifier.fromEnv verifies a real token (discovery + JWKS)", async () => {
  const user = await Verifier.fromEnv().verify(token);
  assert.equal(user.sub, process.env.GROW_OIDC_IT_SUB);
  assert.equal(user.email, process.env.GROW_OIDC_IT_EMAIL);
  assert.ok(user.roles.includes(process.env.GROW_OIDC_IT_ROLE ?? ""), JSON.stringify(user.roles));
  assert.equal(user.claims.iss, process.env.GROW_AUTH_ISSUER);
});

test("a tampered token and a wrong audience are rejected", async () => {
  const [h, p, s] = token.split(".");
  const tampered = `${h}.${p}.${(s ?? "").startsWith("A") ? "B" : "A"}${(s ?? "").slice(1)}`;
  await assert.rejects(Verifier.fromEnv().verify(tampered), AuthenticationError);
  await assert.rejects(Verifier.fromEnv({ audience: "someone-else" }).verify(token), /aud/);
});

test("expressAuth + requireRoles accept the real token", async () => {
  const verifier = Verifier.fromEnv();
  const req: { headers: Record<string, string>; user?: unknown } = {
    headers: { authorization: `Bearer ${token}` },
  };
  const res = { status: () => res, setHeader: () => res, json: () => res };
  let passed = 0;
  await expressAuth(verifier)(req, res, () => (passed += 1));
  await requireRoles(process.env.GROW_OIDC_IT_ROLE ?? "")(req as never, res, () => (passed += 1));
  assert.equal(passed, 2);
});
