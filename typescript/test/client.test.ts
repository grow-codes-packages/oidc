import { inspect } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  ConfigError,
  PACKAGE_KEY,
  REDACTED,
  RetryPolicy,
  Secret,
  VENDOR_ENV,
  OidcClient,
  OidcConfig,
  OidcError,
  relativeEndpoint,
} from "../src/index.js";
import { type MockServer, closedPort, startServer } from "./helpers/server.js";

const servers: MockServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function demoServer(token = "t0ken-value"): Promise<MockServer> {
  const s = await startServer((req) => {
    if (req.url === "/.well-known/openid-configuration") {
      return {
        status: 200,
        body: { issuer: "http://idp.test", userinfo_endpoint: "http://idp.test/api/userinfo" },
      };
    }
    if (req.url === "/api/userinfo") {
      return req.headers.authorization === `Bearer ${token}`
        ? { status: 200, body: { pong: true } }
        : { status: 401, body: { message: "bad token" } };
    }
    return { status: 404 };
  });
  servers.push(s);
  return s;
}

const fast = { retry: { maxRetries: 1, initialBackoffMs: 1 } };

describe("OidcConfig", () => {
  it("uses defaults and freezes", () => {
    const c = new OidcConfig();
    expect(c.url).toBe(OidcConfig.DEFAULT_URL);
    expect(c.requestTimeoutMs).toBe(30_000);
    expect(c.retry).toBeInstanceOf(RetryPolicy);
    expect(c.token).toBeUndefined();
    expect(Object.isFrozen(c)).toBe(true);
    expect(OidcConfig.from(c)).toBe(c);
    expect(OidcConfig.from().url).toBe(c.url);
    const prefix = `GROW_${PACKAGE_KEY.toUpperCase().replaceAll("-", "_")}_`;
    expect(OidcConfig.ENV_PREFIX).toBe(prefix);
  });

  it("keeps optional settings", () => {
    const hooks = {};
    const logger = { debug() {}, info() {}, warn() {}, error() {} };
    const c = new OidcConfig({
      proxy: "http://p:1",
      userAgentSuffix: "s",
      hooks,
      logger,
      token: new Secret("abcd"),
    });
    expect(c.proxy).toBe("http://p:1");
    expect(c.userAgentSuffix).toBe("s");
    expect(c.hooks).toBe(hooks);
    expect(c.logger).toBe(logger);
    expect(c.knownSecrets()).toEqual(["abcd"]);
  });

  it("validate() raises ConfigError", () => {
    expect(() => new OidcConfig({ url: "ftp://x" })).toThrow(ConfigError);
    expect(() => new OidcConfig({ token: "   " })).toThrow(ConfigError);
  });

  it("core.redaction.config: toString/JSON/inspect hide credentials", () => {
    const c = new OidcConfig({
      token: "super-secret-tok",
      headers: { "x-api-key": "hdr-secret" },
    });
    for (const form of [String(c), JSON.stringify(c), inspect(c), `${c.token}`]) {
      expect(form).not.toContain("super-secret-tok");
      expect(form).not.toContain("hdr-secret");
    }
    expect(String(c)).toContain(REDACTED);
    expect(String(c)).toMatch(/Config\(/);
    expect(new OidcConfig().toJSON().token).toBeNull();
  });

  it("core.config.env-precedence: explicit > GROW_* > vendor > default", () => {
    const prefix = OidcConfig.ENV_PREFIX;
    const vendor = VENDOR_ENV as { url: string[]; token: string[] };
    const saved = { url: vendor.url, token: vendor.token };
    vendor.url = ["VENDOR_ADDR"];
    vendor.token = ["VENDOR_TOKEN"];
    try {
      const env = {
        [`${prefix}URL`]: "http://grow:1",
        VENDOR_ADDR: "http://vendor:2",
        VENDOR_TOKEN: "vendor-token",
        [`${prefix}REQUEST_TIMEOUT`]: "5s",
        [`${prefix}MAX_RETRIES`]: "7",
      };
      const fromEnv = OidcConfig.fromEnv({}, env);
      expect(fromEnv.url).toBe("http://grow:1");
      expect(fromEnv.token?.reveal()).toBe("vendor-token");
      expect(fromEnv.requestTimeoutMs).toBe(5000);
      expect(fromEnv.retry.maxRetries).toBe(7);
      expect(fromEnv.connectTimeoutMs).toBe(10_000);

      const vendorOnly = OidcConfig.fromEnv({}, { VENDOR_ADDR: "http://vendor:2" });
      expect(vendorOnly.url).toBe("http://vendor:2");

      const explicit = OidcConfig.fromEnv(
        { url: "http://explicit:3", token: "explicit-token", retry: { initialBackoffMs: 1 } },
        env,
      );
      expect(explicit.url).toBe("http://explicit:3");
      expect(explicit.token?.reveal()).toBe("explicit-token");
      expect(explicit.retry.maxRetries).toBe(7);
      expect(explicit.retry.initialBackoffMs).toBe(1);

      expect(OidcConfig.fromEnv({}, {}).url).toBe(OidcConfig.DEFAULT_URL);
      expect(OidcConfig.fromEnv().url).toBeTypeOf("string");

      let err: unknown;
      try {
        OidcConfig.fromEnv({}, { [`${prefix}TOTAL_TIMEOUT`]: "forever-and-secret" });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as Error).message).toContain(`${prefix}TOTAL_TIMEOUT`);
      expect((err as Error).message).not.toContain("forever-and-secret");
    } finally {
      vendor.url = saved.url;
      vendor.token = saved.token;
    }
  });
});

describe("OidcClient", () => {
  it("health, ping and serverVersion against a provider", async () => {
    const s = await demoServer();
    const client = new OidcClient({ url: s.url, token: "t0ken-value", ...fast });
    expect(await client.health()).toEqual({
      healthy: true,
      status: "ok",
      details: { issuer: "http://idp.test" },
    });
    expect(await client.ping()).toBeGreaterThanOrEqual(0);
    await expect(client.serverVersion()).rejects.toMatchObject({ code: "UNSUPPORTED" });
    expect(client.transport.userAgent).toContain(`grow-codes-${PACKAGE_KEY}/`);
    await client.close();
  });

  it("ping with a bad token raises AuthenticationError without leaking it", async () => {
    const s = await demoServer();
    const client = new OidcClient(
      new OidcConfig({ url: s.url, token: "wrong-token-xyz", ...fast }),
    );
    const err = await client.ping().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OidcError);
    expect((err as OidcError).code).toBe("AUTHENTICATION");
    expect((err as Error).message).not.toContain("wrong-token-xyz");
    await client.close();
  });

  it("ping raises UnsupportedError without a userinfo endpoint", async () => {
    const s = await startServer([{ status: 200, body: { issuer: "x" } }]);
    servers.push(s);
    const client = new OidcClient({ url: s.url, ...fast });
    await expect(client.ping()).rejects.toMatchObject({ code: "UNSUPPORTED" });
    await client.close();
    await expect(client.serverVersion()).rejects.toMatchObject({ code: "CANCELLED" });
  });

  it("health reports unhealthy statuses", async () => {
    const empty = await startServer([{ status: 200 }]);
    servers.push(empty);
    const ok = new OidcClient({ url: empty.url, ...fast });
    expect(await ok.health()).toMatchObject({ healthy: true, status: "ok", details: {} });
    await ok.close();
    const down = await startServer([{ status: 500 }]);
    servers.push(down);
    const sick = new OidcClient({ url: down.url, ...fast });
    expect(await sick.health()).toMatchObject({ healthy: false, status: "unhealthy" });
    await sick.close();
  });

  it("relativeEndpoint keeps realm prefixes out", () => {
    expect(relativeEndpoint("http://kc/realms/x/", "http://kc/realms/x/protocol/userinfo")).toBe(
      "/protocol/userinfo",
    );
    expect(relativeEndpoint("http://a", "http://b/api/userinfo?x=1")).toBe("/api/userinfo?x=1");
    expect(relativeEndpoint("http://a", "/userinfo")).toBe("/userinfo");
  });

  it("core.health.unreachable: closed port -> healthy=false, status=unreachable", async () => {
    const port = await closedPort();
    const client = new OidcClient({ url: `http://127.0.0.1:${port}`, ...fast });
    expect(await client.health()).toEqual({
      healthy: false,
      status: "unreachable",
      details: { error: "UNAVAILABLE" },
    });
    await client.close();
  });

  it("health rethrows cancellation", async () => {
    const s = await demoServer();
    const client = new OidcClient({ url: s.url });
    await expect(client.health({ signal: AbortSignal.abort() })).rejects.toMatchObject({
      code: "CANCELLED",
    });
    await client.close();
  });

  it("core.close.idempotent: close twice is safe", async () => {
    const s = await demoServer();
    const client = new OidcClient({ url: s.url });
    await client.health();
    await client.close();
    await client.close();
    await expect(client.ping()).rejects.toMatchObject({
      code: "CANCELLED",
      message: "ping: client is closed",
    });
  });

  it("fromEnv builds from GROW_* variables", async () => {
    const s = await demoServer();
    const key = `${OidcConfig.ENV_PREFIX}URL`;
    process.env[key] = s.url;
    try {
      const client = OidcClient.fromEnv({ token: "t0ken-value" });
      expect(client.config.url).toBe(s.url);
      expect(await client.ping()).toBeGreaterThanOrEqual(0);
      await client.close();
    } finally {
      delete process.env[key];
    }
  });
});
