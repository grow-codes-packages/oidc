// Integration tests for the skeleton client against the real service (docker/compose.yml).
// Service packages extend this file with one round-trip test per public function.

import assert from "node:assert/strict";
import { before, test } from "node:test";
import { OidcClient, OidcError } from "@grow-codes/oidc";
import { loadBootstrapEnv } from "./env.ts";

before(() => {
  loadBootstrapEnv();
  const urlVar = "GROW_OIDC_URL";
  assert.ok(process.env[urlVar], `${urlVar} must be set`);
});

test("health reports a healthy service", async () => {
  const client = OidcClient.fromEnv();
  try {
    const health = await client.health();
    assert.equal(health.healthy, true, JSON.stringify(health));
  } finally {
    await client.close();
  }
});

test("ping succeeds with the bootstrap credentials", async () => {
  const client = OidcClient.fromEnv();
  try {
    const latency = await client.ping();
    assert.equal(typeof latency, "number");
    assert.ok(latency >= 0);
  } finally {
    await client.close();
  }
});

test("ping with a wrong token raises AUTHENTICATION and never leaks it", async () => {
  const wrong = "wrong-token-for-integration";
  const client = OidcClient.fromEnv({ token: wrong });
  try {
    await assert.rejects(client.ping(), (err: unknown) => {
      assert.ok(err instanceof OidcError);
      assert.equal(err.code, "AUTHENTICATION");
      assert.ok(!err.message.includes(wrong));
      return true;
    });
  } finally {
    await client.close();
  }
});

test("serverVersion is UNSUPPORTED (OIDC has no version endpoint)", async () => {
  const client = OidcClient.fromEnv();
  try {
    await assert.rejects(client.serverVersion(), (err: unknown) => {
      assert.ok(err instanceof OidcError);
      assert.equal(err.code, "UNSUPPORTED");
      return true;
    });
  } finally {
    await client.close();
    await client.close();
  }
});
