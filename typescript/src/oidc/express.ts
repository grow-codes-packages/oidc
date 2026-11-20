// Service-owned: Express (and Express-compatible) middleware. No runtime dependency on express.

import { OidcError, UnavailableError } from "../core/index.js";
import { hasAnyRole } from "./roles.js";
import { type AuthUser, type RequestLike, type Verifier, bearerToken } from "./verifier.js";

/** The request shape the middleware needs; `user` is set after a successful verification. */
export type AuthRequest = Exclude<RequestLike, Headers | null | undefined> & { user?: AuthUser };

/** The response shape the middleware needs (Express `res`). */
export interface AuthResponse {
  status(code: number): AuthResponse;
  setHeader(name: string, value: string): unknown;
  json(body: unknown): unknown;
}

/** Express `next`. */
export type NextFunction = (err?: unknown) => void;

/** An Express-style middleware. */
export type AuthMiddleware = (
  req: AuthRequest,
  res: AuthResponse,
  next: NextFunction,
) => Promise<void>;

/** Options of {@link expressAuth}. */
export interface ExpressAuthOptions {
  /** Let requests without a token through anonymously (an invalid token is still 401). */
  optional?: boolean;
}

/** Sends a JSON error body; 401 responses carry `WWW-Authenticate: Bearer`. */
function deny(res: AuthResponse, status: number, error: string): void {
  if (status === 401) res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
  res.status(status).json({ error });
}

/**
 * Express middleware: verifies the bearer token and sets `req.user` ({@link AuthUser}).
 * Missing token → 401 (or anonymous with `optional`), invalid token → 401, JWKS/discovery
 * unreachable → 503. The response never says why a token was rejected.
 */
export function expressAuth(verifier: Verifier, options: ExpressAuthOptions = {}): AuthMiddleware {
  return async (req, res, next) => {
    const token = bearerToken(req);
    if (token === null) {
      if (options.optional === true) {
        next();
        return;
      }
      deny(res, 401, "unauthorized");
      return;
    }
    try {
      req.user = await verifier.verify(token);
    } catch (err) {
      if (err instanceof UnavailableError) {
        deny(res, 503, "auth_unavailable");
        return;
      }
      if (err instanceof OidcError) {
        deny(res, 401, "unauthorized");
        return;
      }
      next(err);
      return;
    }
    next();
  };
}

/**
 * Express middleware placed after {@link expressAuth}: 401 without `req.user`, 403 unless the user
 * has at least one of `roles` (case-insensitive). No roles = any authenticated user.
 */
export function requireRoles(...roles: string[]): AuthMiddleware {
  return (req, res, next) => {
    const user = req.user;
    if (user === undefined) deny(res, 401, "unauthorized");
    else if (!hasAnyRole(user.roles, roles)) deny(res, 403, "forbidden");
    else next();
    return Promise.resolve();
  };
}
