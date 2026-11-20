/* eslint-disable @typescript-eslint/unbound-method, @typescript-eslint/no-extraneous-class */
// Conformance case OIDC-18 (middleware) for Express and NestJS-style guards, plus role helpers.
import type { AddressInfo } from "node:net";

import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  HttpStatusError,
  NestAuthGuard,
  Public,
  Roles,
  RolesGuard,
  Verifier,
  claimAt,
  expressAuth,
  extractRoles,
  hasAnyRole,
  requireRoles,
  resetNestExceptionsForTests,
  type AuthUser,
  type ExecutionContextLike,
} from "../../src/index.js";
import { FakeIdp } from "../../src/testing-entry.js";

let idp: FakeIdp;
let verifier: Verifier;
let base: string;
let close: () => Promise<void>;

beforeAll(async () => {
  idp = await new FakeIdp("api").start();
  verifier = new Verifier({ issuer: idp.issuer, audience: "api" });
  const app = express();
  app.get("/health", (_req, res) => res.json({ ok: true }));
  app.get("/me", expressAuth(verifier), (req, res) =>
    res.json((req as unknown as { user: AuthUser }).user),
  );
  app.get("/admin", expressAuth(verifier), requireRoles("admin"), (_req, res) =>
    res.json({ ok: true }),
  );
  app.get("/maybe", expressAuth(verifier, { optional: true }), (req, res) =>
    res.json({ sub: (req as unknown as { user?: AuthUser }).user?.sub ?? null }),
  );
  app.get("/any", requireRoles(), (_req, res) => res.json({ ok: true }));
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  close = () => new Promise((resolve) => server.close(() => resolve()));
});
afterAll(async () => {
  await close();
  await idp.stop();
});

const get = (path: string, token?: string): Promise<Response> =>
  fetch(base + path, { headers: token === undefined ? {} : { authorization: `Bearer ${token}` } });

describe("OIDC-18 Express middleware", () => {
  it("returns 401 without or with an invalid token, 200 with a valid one", async () => {
    expect((await get("/health")).status).toBe(200);
    const none = await get("/me");
    expect(none.status).toBe(401);
    expect(none.headers.get("www-authenticate")).toMatch(/^Bearer/);
    expect((await get("/me", "x.y.z")).status).toBe(401);
    const ok = await get("/me", await idp.mint({ claims: { roles: ["user"] } }));
    expect(ok.status).toBe(200);
    expect(await ok.json()).toMatchObject({ sub: "user-1", roles: ["user"] });
  });

  it("enforces roles with 403", async () => {
    expect((await get("/admin", await idp.mint({ claims: { roles: ["user"] } }))).status).toBe(403);
    expect(
      (await get("/admin", await idp.mint({ claims: { roles: [{ name: "Admin" }] } }))).status,
    ).toBe(200);
    expect((await get("/any")).status).toBe(401);
  });

  it("supports optional authentication", async () => {
    expect(await (await get("/maybe")).json()).toEqual({ sub: null });
    expect(await (await get("/maybe", await idp.mint())).json()).toEqual({ sub: "user-1" });
    expect((await get("/maybe", "x.y.z")).status).toBe(401);
  });

  it("answers 503 when the IdP is down and passes unknown errors on", async () => {
    const down = new Verifier({
      issuer: idp.issuer,
      audience: "api",
      jwksUrl: "http://127.0.0.1:1/jwks",
    });
    const res = {
      code: 0,
      body: undefined as unknown,
      status(c: number) {
        this.code = c;
        return this;
      },
      setHeader() {},
      json(b: unknown) {
        this.body = b;
      },
    };
    await expressAuth(down)(
      { headers: { authorization: `Bearer ${await idp.mint()}` } },
      res,
      () => {},
    );
    expect(res.code).toBe(503);
    const boom = { verify: () => Promise.reject(new Error("boom")) } as unknown as Verifier;
    let passed: unknown;
    await expressAuth(boom)(
      { headers: { authorization: "Bearer a.b.c" } },
      res,
      (err) => (passed = err),
    );
    expect((passed as Error).message).toBe("boom");
  });
});

function ctx(
  req: Record<string, unknown>,
  handler: object = () => {},
  cls: object = class {},
): ExecutionContextLike {
  return {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => handler,
    getClass: () => cls,
  };
}

describe("OIDC-18 NestJS guards", () => {
  class Controller {
    open(): void {}
    admin(): void {}
    plain(): void {}
  }
  Public()(
    Controller.prototype,
    "open",
    Object.getOwnPropertyDescriptor(Controller.prototype, "open"),
  );
  Roles("admin")(
    Controller.prototype,
    "admin",
    Object.getOwnPropertyDescriptor(Controller.prototype, "admin"),
  );
  class StaffController {}
  Roles("staff")(StaffController);
  class OpenController {}
  Public()(OpenController);

  it("verifies tokens and honours @Public()", async () => {
    resetNestExceptionsForTests({});
    const guard = new NestAuthGuard(verifier);
    const req: Record<string, unknown> = {
      headers: { authorization: `Bearer ${await idp.mint()}` },
    };
    await expect(guard.canActivate(ctx(req))).resolves.toBe(true);
    expect((req.user as AuthUser).sub).toBe("user-1");
    const err = await guard.canActivate(ctx({ headers: {} })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(HttpStatusError);
    expect((err as HttpStatusError).getStatus()).toBe(401);
    await expect(guard.canActivate(ctx({ headers: {} }, Controller.prototype.open))).resolves.toBe(
      true,
    );
    await expect(guard.canActivate(ctx({ headers: {} }, () => {}, OpenController))).resolves.toBe(
      true,
    );
    await expect(
      guard.canActivate(
        ctx({ headers: { authorization: "Bearer x.y.z" } }, Controller.prototype.open),
      ),
    ).resolves.toBe(true);
    await expect(
      guard.canActivate(ctx({ headers: { authorization: "Bearer x.y.z" } })),
    ).rejects.toMatchObject({ statusCode: 401 });
    await expect(
      new NestAuthGuard(verifier, { optional: true }).canActivate(ctx({ headers: {} })),
    ).resolves.toBe(true);
    const down = new NestAuthGuard(
      new Verifier({ issuer: idp.issuer, audience: "api", jwksUrl: "http://127.0.0.1:1/j" }),
    );
    await expect(
      down.canActivate(ctx({ headers: { authorization: `Bearer ${await idp.mint()}` } })),
    ).rejects.toMatchObject({ statusCode: 503 });
    const boom = new NestAuthGuard({
      verify: () => Promise.reject(new Error("boom")),
    } as unknown as Verifier);
    await expect(
      boom.canActivate(ctx({ headers: { authorization: "Bearer a.b.c" } })),
    ).rejects.toThrow("boom");
  });

  it("checks roles from @Roles(), the constructor or not at all", () => {
    resetNestExceptionsForTests({});
    const user = (roles: string[]): Record<string, unknown> => ({
      user: { sub: "u", roles, claims: {} },
    });
    const guard = new RolesGuard();
    expect(guard.canActivate(ctx(user(["admin"]), Controller.prototype.admin))).toBe(true);
    expect(() => guard.canActivate(ctx(user(["user"]), Controller.prototype.admin))).toThrow(
      /Forbidden/,
    );
    expect(
      guard.canActivate(ctx(user(["staff"]), Controller.prototype.plain, StaffController)),
    ).toBe(true);
    expect(guard.canActivate(ctx(user([]), Controller.prototype.plain))).toBe(true);
    expect(guard.canActivate(ctx({}, Controller.prototype.plain))).toBe(true);
    expect(() => guard.canActivate(ctx({}, Controller.prototype.admin))).toThrow(/Unauthorized/);
    expect(new RolesGuard(["admin"]).canActivate(ctx({}, Controller.prototype.open))).toBe(true);
    expect(() => new RolesGuard(["admin"]).canActivate(ctx(user(["x"])))).toThrow(/Forbidden/);
  });

  it("throws Nest's own exceptions when @nestjs/common is available", () => {
    class Unauthorized extends Error {}
    class Forbidden extends Error {}
    resetNestExceptionsForTests({ unauthorized: Unauthorized, forbidden: Forbidden });
    expect(() => new RolesGuard(["a"]).canActivate(ctx({}))).toThrow(Unauthorized);
    expect(() => new RolesGuard(["a"]).canActivate(ctx({ user: { roles: [] } }))).toThrow(
      Forbidden,
    );
    resetNestExceptionsForTests(undefined);
    expect(() => new RolesGuard(["a"]).canActivate(ctx({}))).toThrow(/Unauthorized/);
  });
});

describe("roles helpers", () => {
  it("extracts and matches roles", () => {
    expect(
      extractRoles({
        roles: [{ name: "a" }, { code: "b" }, { role: "c" }, { value: "d" }, { x: 1 }, 3, " ", "a"],
      }),
    ).toEqual(["a", "b", "c", "d"]);
    expect(extractRoles({ roles: "x, y z" })).toEqual(["x", "y", "z"]);
    expect(extractRoles({ roles: 5 })).toEqual([]);
    expect(extractRoles({ "https://x/roles": ["r"] }, "https://x/roles")).toEqual(["r"]);
    expect(claimAt({ a: { b: [1] } }, "a.b")).toEqual([1]);
    expect(claimAt({ a: [1] }, "a.b")).toBeUndefined();
    expect(claimAt({ a: {} }, "a.b")).toBeUndefined();
    expect(hasAnyRole(["Admin"], ["admin"])).toBe(true);
    expect(hasAnyRole([], [])).toBe(true);
    expect(hasAnyRole(["x"], ["y"])).toBe(false);
  });
});
