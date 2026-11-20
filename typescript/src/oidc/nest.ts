// Service-owned: NestJS guards and decorators. No compile-time dependency on @nestjs/*: the guards
// are structural `CanActivate` implementations and throw Nest's own HTTP exceptions when the app
// has @nestjs/common installed (resolved from the app's working directory).

import { createRequire } from "node:module";
import { join } from "node:path";

import { OidcError, UnavailableError } from "../core/index.js";
import { hasAnyRole } from "./roles.js";
import { type AuthUser, type Verifier, bearerToken } from "./verifier.js";

/** Metadata key of {@link Roles}. */
export const ROLES_KEY = "grow:oidc:roles";
/** Metadata key of {@link Public}. */
export const PUBLIC_KEY = "grow:oidc:public";

/** The parts of Nest's `ExecutionContext` the guards use. */
export interface ExecutionContextLike {
  switchToHttp(): { getRequest(): unknown };
  getHandler(): unknown;
  getClass(): unknown;
}

/** Options of {@link NestAuthGuard}. */
export interface NestAuthGuardOptions {
  /** Let requests without a token through anonymously (an invalid token is still 401). */
  optional?: boolean;
}

interface ReflectMetadata {
  defineMetadata?: (key: string, value: unknown, target: object) => void;
  getMetadata?: (key: string, target: object) => unknown;
}

const reflect = Reflect as unknown as ReflectMetadata;
const store = new WeakMap<object, Map<string, unknown>>();

/** Stores metadata with `reflect-metadata` when loaded (Nest's `Reflector` sees it) and locally. */
function setMeta(target: object, key: string, value: unknown): void {
  let entry = store.get(target);
  if (entry === undefined) {
    entry = new Map();
    store.set(target, entry);
  }
  entry.set(key, value);
  reflect.defineMetadata?.(key, value, target);
}

function getMeta(target: unknown, key: string): unknown {
  if (target === null || (typeof target !== "object" && typeof target !== "function"))
    return undefined;
  const local = store.get(target)?.get(key);
  return local !== undefined ? local : reflect.getMetadata?.(key, target);
}

/** A decorator usable on classes and methods (legacy `experimentalDecorators`, as Nest uses). */
export type ClassOrMethodDecorator = (
  target: object,
  key?: string | symbol,
  descriptor?: PropertyDescriptor,
) => void;

function metaDecorator(key: string, value: unknown): ClassOrMethodDecorator {
  return (target, _key, descriptor) => {
    const holder: unknown = descriptor?.value ?? target;
    setMeta(holder as object, key, value);
  };
}

/** Requires at least one of `roles` on a controller or route (checked by {@link RolesGuard}). */
export function Roles(...roles: string[]): ClassOrMethodDecorator {
  return metaDecorator(ROLES_KEY, roles);
}

/** Marks a controller or route as public: {@link NestAuthGuard} lets it through without a token. */
export function Public(): ClassOrMethodDecorator {
  return metaDecorator(PUBLIC_KEY, true);
}

type HttpExceptionCtor = new (message?: string) => Error;
let nestExceptions:
  | {
      unauthorized?: HttpExceptionCtor;
      forbidden?: HttpExceptionCtor;
      unavailable?: HttpExceptionCtor;
    }
  | undefined;

/** Loads Nest's exception classes from the application (cached); `{}` when Nest is not installed. */
function loadNestExceptions(): NonNullable<typeof nestExceptions> {
  if (nestExceptions !== undefined) return nestExceptions;
  try {
    const appRequire = createRequire(join(process.cwd(), "package.json"));
    const common = appRequire("@nestjs/common") as Record<string, HttpExceptionCtor | undefined>;
    nestExceptions = {
      unauthorized: common.UnauthorizedException,
      forbidden: common.ForbiddenException,
      unavailable: common.ServiceUnavailableException,
    };
  } catch {
    nestExceptions = {};
  }
  return nestExceptions;
}

/** Resets the cached Nest exception classes (tests). @internal */
export function resetNestExceptionsForTests(value?: typeof nestExceptions): void {
  nestExceptions = value;
}

/** An error Nest's exception filter turns into the given status (fallback without @nestjs/common). */
export class HttpStatusError extends Error {
  readonly statusCode: number;
  constructor(statusCode: number, message: string) {
    super(message);
    this.name = "HttpStatusError";
    this.statusCode = statusCode;
  }
  /** Nest `HttpException`-compatible accessor. */
  getStatus(): number {
    return this.statusCode;
  }
}

function httpError(status: 401 | 403 | 503): Error {
  const ex = loadNestExceptions();
  const ctor = status === 401 ? ex.unauthorized : status === 403 ? ex.forbidden : ex.unavailable;
  const message =
    status === 401 ? "Unauthorized" : status === 403 ? "Forbidden" : "Service Unavailable";
  return ctor !== undefined ? new ctor(message) : new HttpStatusError(status, message);
}

function isPublic(ctx: ExecutionContextLike): boolean {
  return (
    getMeta(ctx.getHandler(), PUBLIC_KEY) === true || getMeta(ctx.getClass(), PUBLIC_KEY) === true
  );
}

/**
 * Nest guard: verifies the bearer token and sets `request.user`. Routes marked {@link Public} pass
 * without a token. Register it globally (`app.useGlobalGuards(new NestAuthGuard(verifier))` or an
 * `APP_GUARD` provider with `useFactory`). 401 for a missing/invalid token, 503 when the JWKS is
 * unreachable.
 */
export class NestAuthGuard {
  readonly #verifier: Verifier;
  readonly #optional: boolean;

  constructor(verifier: Verifier, options: NestAuthGuardOptions = {}) {
    this.#verifier = verifier;
    this.#optional = options.optional === true;
  }

  /** Nest `CanActivate`. */
  async canActivate(ctx: ExecutionContextLike): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest() as {
      headers: Record<string, string | undefined>;
      user?: AuthUser;
    };
    const token = bearerToken(req);
    if (token === null) {
      if (this.#optional || isPublic(ctx)) return true;
      throw httpError(401);
    }
    try {
      req.user = await this.#verifier.verify(token);
      return true;
    } catch (err) {
      if (isPublic(ctx)) return true;
      if (err instanceof UnavailableError) throw httpError(503);
      if (err instanceof OidcError) throw httpError(401);
      throw err;
    }
  }
}

/**
 * Nest guard: 403 unless `request.user` has at least one required role. The roles come from the
 * constructor (`new RolesGuard(["admin"])`) or else from {@link Roles} on the route/controller;
 * without either, any authenticated user passes. Runs after {@link NestAuthGuard}.
 */
export class RolesGuard {
  readonly #roles: readonly string[] | undefined;

  constructor(roles?: readonly string[]) {
    this.#roles = roles;
  }

  /** Nest `CanActivate`. */
  canActivate(ctx: ExecutionContextLike): boolean {
    const required =
      this.#roles ??
      (getMeta(ctx.getHandler(), ROLES_KEY) as string[] | undefined) ??
      (getMeta(ctx.getClass(), ROLES_KEY) as string[] | undefined);
    const user = (ctx.switchToHttp().getRequest() as { user?: AuthUser }).user;
    if (user === undefined) {
      if (required === undefined || isPublic(ctx)) return true;
      throw httpError(401);
    }
    if (required === undefined || hasAnyRole(user.roles, required)) return true;
    throw httpError(403);
  }
}
