// Conformance cases OIDC-01…OIDC-17 (docs/oidc-conformance.md) against a local fake IdP.
import { SignJWT, generateKeyPair } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  AuthenticationError,
  ConfigError,
  ErrorCode,
  UnavailableError,
  Verifier,
  bearerToken,
} from "../../src/index.js";
import { FakeIdp } from "../../src/testing-entry.js";

let idp: FakeIdp;

beforeEach(async () => {
  idp = await new FakeIdp("app-client").start();
});
afterEach(async () => {
  await idp.stop();
});

function verifier(extra: Partial<ConstructorParameters<typeof Verifier>[0]> = {}): Verifier {
  return new Verifier({ issuer: idp.issuer, audience: "app-client", ...extra });
}

async function expectAuthError(promise: Promise<unknown>, pattern?: RegExp): Promise<void> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AuthenticationError);
  expect((err as AuthenticationError).code).toBe(ErrorCode.Authentication);
  if (pattern !== undefined) expect((err as Error).message).toMatch(pattern);
}

describe("Verifier conformance", () => {
  it("OIDC-01 verifies an RS256 token found through discovery", async () => {
    const token = await idp.mint({
      claims: {
        email: "a@b.test",
        name: "Ann",
        roles: [{ name: "admin", owner: "org" }, { name: "user" }],
      },
    });
    const user = await verifier().verify(token);
    expect(user).toMatchObject({
      sub: "user-1",
      email: "a@b.test",
      name: "Ann",
      roles: ["admin", "user"],
    });
    expect(user.claims.iss).toBe(idp.issuer);
    expect(idp.hits["/.well-known/openid-configuration"]).toBe(1);
  });

  it.each(["ES256", "EdDSA"] as const)("OIDC-02/03 verifies %s tokens", async (alg) => {
    await idp.rotate(alg);
    const user = await verifier().verify(await idp.mint({ claims: { preferred_username: "bob" } }));
    expect(user.name).toBe("bob");
    expect(user.email).toBeUndefined();
  });

  it("OIDC-04 rejects a wrong issuer", async () => {
    await expectAuthError(
      verifier().verify(await idp.mint({ claims: { iss: "http://evil.test" } })),
      /iss/,
    );
  });

  it("OIDC-05 checks the audience (string or array)", async () => {
    await expectAuthError(verifier().verify(await idp.mint({ claims: { aud: "other" } })), /aud/);
    const user = await verifier().verify(
      await idp.mint({ claims: { aud: ["other", "app-client"] } }),
    );
    expect(user.sub).toBe("user-1");
  });

  it("OIDC-06 rejects expired tokens beyond the 60 s skew only", async () => {
    const now = Math.floor(Date.now() / 1000);
    await expectAuthError(
      verifier().verify(await idp.mint({ claims: { exp: now - 120 } })),
      /expired/,
    );
    await expect(
      verifier().verify(await idp.mint({ claims: { exp: now - 30 } })),
    ).resolves.toBeTruthy();
    await expectAuthError(
      verifier({ clockSkewMs: 0 }).verify(await idp.mint({ claims: { exp: now - 30 } })),
    );
  });

  it("OIDC-07 rejects nbf in the future beyond the skew", async () => {
    const now = Math.floor(Date.now() / 1000);
    await expectAuthError(verifier().verify(await idp.mint({ claims: { nbf: now + 120 } })), /nbf/);
    await expect(
      verifier().verify(await idp.mint({ claims: { nbf: now + 30 } })),
    ).resolves.toBeTruthy();
  });

  it("OIDC-08 requires exp and sub", async () => {
    await expectAuthError(verifier().verify(await idp.mint({ claims: { exp: undefined } })), /exp/);
    await expectAuthError(verifier().verify(await idp.mint({ claims: { sub: undefined } })), /sub/);
  });

  it("OIDC-09 rejects alg none, HMAC and algorithms outside the allow-list", async () => {
    const enc = (o: object): string => Buffer.from(JSON.stringify(o)).toString("base64url");
    const none = `${enc({ alg: "none" })}.${enc({ sub: "x", iss: idp.issuer, aud: "app-client" })}.`;
    await expectAuthError(verifier().verify(none), /not allowed/);
    const hs = await new SignJWT({ sub: "x" })
      .setProtectedHeader({ alg: "HS256" })
      .sign(new TextEncoder().encode("0123456789abcdef0123456789abcdef"));
    await expectAuthError(verifier().verify(hs), /not allowed/);
    await idp.rotate("ES256");
    await expectAuthError(
      verifier({ algorithms: ["RS256"] }).verify(await idp.mint()),
      /not allowed/,
    );
    await expectAuthError(verifier().verify("not-a-jwt"), /malformed/);
    await expectAuthError(verifier().verify("a.b.c"), /malformed token header/);
  });

  it("OIDC-10 rejects a bad signature", async () => {
    const token = await idp.mint();
    const [h, p] = token.split(".");
    const other = await generateKeyPair("RS256");
    const forged = await new SignJWT(
      JSON.parse(Buffer.from(p!, "base64url").toString()) as Record<string, unknown>,
    )
      .setProtectedHeader(JSON.parse(Buffer.from(h!, "base64url").toString()) as { alg: string })
      .sign(other.privateKey);
    await expectAuthError(verifier().verify(forged), /signature/);
  });

  it("OIDC-11 refetches the JWKS once when a new kid appears (rotation)", async () => {
    let now = Date.now();
    const v = verifier({ now: () => now });
    await v.verify(await idp.mint());
    await idp.rotate();
    now += 31_000;
    await v.verify(await idp.mint());
    expect(idp.hits["/jwks"]).toBe(2);
  });

  it("OIDC-12 does not refetch for an unknown kid within the cooldown", async () => {
    const v = verifier();
    await v.verify(await idp.mint());
    await idp.rotate();
    await expectAuthError(v.verify(await idp.mint()), /no key matches kid key-2/);
    expect(idp.hits["/jwks"]).toBe(1);
    const v0 = verifier({ jwksRefreshCooldownMs: 0 });
    await expect(v0.verify(await idp.mint())).resolves.toBeTruthy();
  });

  it("OIDC-13 caches the JWKS and refreshes after the TTL", async () => {
    let now = Date.now();
    const v = verifier({ now: () => now });
    const token = await idp.mint({ ttlSeconds: 3600 });
    await Promise.all([v.verify(token), v.verify(token)]);
    await v.verify(token);
    expect(idp.hits["/jwks"]).toBe(1);
    now += 600_001;
    await v.verify(token);
    expect(idp.hits["/jwks"]).toBe(2);
    v.clearCache();
    await v.verify(token);
    expect(idp.hits["/jwks"]).toBe(3);
  });

  it("OIDC-13b verifies tokens without kid against every matching key", async () => {
    await expect(
      verifier().verify(await idp.mint({ header: { kid: undefined } })),
    ).resolves.toBeTruthy();
  });

  it("OIDC-14 uses jwksUrl without discovery", async () => {
    await verifier({ jwksUrl: `${idp.issuer}/jwks` }).verify(await idp.mint());
    expect(idp.hits["/.well-known/openid-configuration"]).toBeUndefined();
  });

  it("OIDC-15 reports an unreachable IdP as UNAVAILABLE", async () => {
    const token = await idp.mint();
    idp.failStatus = 500;
    await expect(verifier().verify(token)).rejects.toBeInstanceOf(UnavailableError);
    await expect(verifier({ jwksUrl: `${idp.issuer}/jwks` }).verify(token)).rejects.toThrow(
      /HTTP 500/,
    );
    const failing = verifier({ fetch: () => Promise.reject(new Error("refused")) });
    await expect(failing.verify(token)).rejects.toThrow(/discovery: request failed/);
    const badJson = verifier({
      fetch: () => Promise.resolve(new Response("nope", { status: 200 })),
    });
    await expect(badJson.verify(token)).rejects.toThrow(/not JSON/);
    const noJwks = verifier({ fetch: () => Promise.resolve(Response.json({ issuer: "x" })) });
    await expect(noJwks.verify(token)).rejects.toThrow(/no jwks_uri/);
    const noKeys = verifier({
      jwksUrl: "http://127.0.0.1:1/jwks",
      fetch: () => Promise.resolve(Response.json({})),
    });
    await expect(noKeys.verify(token)).rejects.toThrow(/no keys array/);
  });

  it("OIDC-16 reads roles from a configurable claim", async () => {
    const token = await idp.mint({ claims: { realm_access: { roles: ["editor"] }, scope: "a b" } });
    expect((await verifier({ rolesClaim: "realm_access.roles" }).verify(token)).roles).toEqual([
      "editor",
    ]);
    expect((await verifier({ rolesClaim: "scope" }).verify(token)).roles).toEqual(["a", "b"]);
    expect((await verifier().verify(token)).roles).toEqual([]);
  });

  it("OIDC-17 builds from GROW_AUTH_* variables", async () => {
    const env = {
      GROW_AUTH_ISSUER: idp.issuer,
      GROW_AUTH_CLIENT_ID: "app-client",
      GROW_AUTH_ROLES_CLAIM: "groups",
    };
    const v = Verifier.fromEnv({}, env);
    expect(v.audience).toBe("app-client");
    expect(v.rolesClaim).toBe("groups");
    expect(v.clockSkewMs).toBe(60_000);
    const w = Verifier.fromEnv(
      {},
      {
        ...env,
        GROW_AUTH_AUDIENCE: "api",
        GROW_AUTH_JWKS_URL: `${idp.issuer}/jwks`,
        GROW_AUTH_CLOCK_SKEW: "5s",
      },
    );
    expect([w.audience, w.clockSkewMs]).toEqual(["api", 5000]);
    expect(() => Verifier.fromEnv({}, {})).toThrow(ConfigError);
    expect(() => Verifier.fromEnv({}, { GROW_AUTH_ISSUER: idp.issuer })).toThrow(
      /GROW_AUTH_AUDIENCE/,
    );
    expect(() => Verifier.fromEnv({}, { ...env, GROW_AUTH_CLOCK_SKEW: "soon" })).toThrow(
      /CLOCK_SKEW/,
    );
    const saved = process.env.GROW_AUTH_ISSUER;
    process.env.GROW_AUTH_ISSUER = idp.issuer;
    expect(Verifier.fromEnv({ audience: "x" }).issuer).toBe(idp.issuer);
    if (saved === undefined) delete process.env.GROW_AUTH_ISSUER;
    else process.env.GROW_AUTH_ISSUER = saved;
  });

  it("validates options", () => {
    expect(() => new Verifier({ issuer: "", audience: "a" })).toThrow(/issuer is required/);
    expect(() => new Verifier({ issuer: "http://x", audience: " " })).toThrow(
      /audience is required/,
    );
    expect(() => new Verifier({ issuer: "nope", audience: "a" })).toThrow(/not a URL/);
    expect(() => new Verifier({ issuer: "ftp://x", audience: "a" })).toThrow(/http or https/);
    expect(() => new Verifier({ issuer: "http://x", audience: "a", jwksUrl: "bad" })).toThrow(
      /jwksUrl/,
    );
    expect(() => new Verifier({ issuer: "http://x", audience: "a", algorithms: [] })).toThrow(
      /algorithms/,
    );
    expect(() => new Verifier({ issuer: "http://x", audience: "a", clockSkewMs: -1 })).toThrow(
      /clockSkewMs/,
    );
  });
});

describe("bearerToken", () => {
  it("reads Node, Fetch and Headers shapes", async () => {
    expect(bearerToken({ headers: { authorization: "Bearer abc" } })).toBe("abc");
    expect(bearerToken({ headers: { Authorization: "bearer  xyz " } })).toBe("xyz");
    expect(bearerToken({ headers: { authorization: ["Bearer one", "Bearer two"] } })).toBe("one");
    expect(bearerToken(new Request("http://x", { headers: { authorization: "BEARER t" } }))).toBe(
      "t",
    );
    expect(bearerToken(new Headers({ authorization: "Basic abc" }))).toBeNull();
    expect(bearerToken({ headers: {} })).toBeNull();
    expect(bearerToken(undefined)).toBeNull();
    expect(bearerToken(null)).toBeNull();
    const v = verifier();
    await expectAuthError(v.verifyRequest({ headers: {} }), /missing bearer/);
    const token = await idp.mint();
    await expect(
      v.verifyRequest(new Headers({ authorization: `Bearer ${token}` })),
    ).resolves.toBeTruthy();
  });
});
