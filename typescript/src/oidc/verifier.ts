// Service-owned: provider-neutral OIDC access-token verification (JWKS discovery, caching, rotation).

import {
  type JSONWebKeySet,
  type JWTPayload,
  type JWTVerifyGetKey,
  createLocalJWKSet,
  decodeProtectedHeader,
  errors as joseErrors,
  jwtVerify,
} from "jose";

import {
  AuthenticationError,
  ConfigError,
  type EnvMap,
  OidcError,
  UnavailableError,
  parseDuration,
} from "../core/index.js";
import { extractRoles } from "./roles.js";

/** Signing algorithms accepted by default (asymmetric only; `none` and HMAC are never accepted). */
export const DEFAULT_ALGORITHMS: readonly SigningAlgorithm[] = ["RS256", "ES256", "EdDSA"];

/** Supported JWS algorithms. */
export type SigningAlgorithm = "RS256" | "ES256" | "EdDSA";

/** Default clock skew tolerated for `exp` / `nbf` / `iat`: 60 s. */
export const DEFAULT_CLOCK_SKEW_MS = 60_000;
/** Default JWKS cache lifetime: 10 minutes. */
export const DEFAULT_JWKS_CACHE_TTL_MS = 600_000;
/** Default minimum interval between two JWKS refetches triggered by an unknown `kid`: 30 s. */
export const DEFAULT_JWKS_REFRESH_COOLDOWN_MS = 30_000;
/** Default HTTP timeout of discovery and JWKS requests: 10 s. */
export const DEFAULT_HTTP_TIMEOUT_MS = 10_000;

/** The authenticated user of a verified access token. */
export interface AuthUser {
  /** `sub` claim. */
  sub: string;
  /** `email` claim when present. */
  email?: string;
  /** `name` claim, else `preferred_username`, when present. */
  name?: string;
  /** Role names from the roles claim (strings, or Casdoor-style `{name}` objects). */
  roles: string[];
  /** Every claim of the token. */
  claims: Record<string, unknown>;
}

/** Options of a {@link Verifier}. */
export interface VerifierOptions {
  /** Expected `iss` (exact match). Discovery uses `<issuer>/.well-known/openid-configuration`. */
  issuer: string;
  /** Expected `aud` (the token's `aud` must contain it). */
  audience: string;
  /** JWKS URL; skips discovery when set. */
  jwksUrl?: string;
  /** Claim (or dotted path such as `realm_access.roles`) holding the roles. Default `roles`. */
  rolesClaim?: string;
  /** Accepted algorithms. Default RS256, ES256, EdDSA. */
  algorithms?: readonly SigningAlgorithm[];
  /** Clock skew tolerance in milliseconds. Default 60 000. */
  clockSkewMs?: number;
  /** JWKS cache lifetime in milliseconds. Default 600 000. */
  jwksCacheTtlMs?: number;
  /** Minimum interval between unknown-`kid` refetches in milliseconds. Default 30 000. */
  jwksRefreshCooldownMs?: number;
  /** Timeout of discovery/JWKS requests in milliseconds. Default 10 000. */
  httpTimeoutMs?: number;
  /** `fetch` implementation (tests, proxies). Default `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Clock in epoch milliseconds (tests). Default `Date.now`. */
  now?: () => number;
}

/** Anything a bearer token can be read from: Node/Express requests, Fetch `Request`s, `Headers`. */
export type RequestLike =
  | { headers: Headers }
  | { headers: Readonly<Record<string, string | readonly string[] | undefined>> }
  | Headers
  | null
  | undefined;

/**
 * Returns the bearer token of a request's `Authorization` header (scheme case-insensitive), or
 * `null` when there is none.
 */
export function bearerToken(req: RequestLike): string | null {
  if (req === null || req === undefined) return null;
  let value: string | null | undefined;
  if (req instanceof Headers) {
    value = req.get("authorization");
  } else if (req.headers instanceof Headers) {
    value = req.headers.get("authorization");
  } else {
    const headers = req.headers;
    const raw = headers.authorization ?? headers.Authorization;
    value = Array.isArray(raw) ? (raw[0] as string | undefined) : (raw as string | undefined);
  }
  if (typeof value !== "string") return null;
  const match = /^\s*bearer\s+(\S+)\s*$/iu.exec(value);
  return match?.[1] ?? null;
}

interface KeySetEntry {
  getKey: JWTVerifyGetKey;
  fetchedAt: number;
}

/**
 * Verifies OIDC access tokens (JWT) against the issuer's JWKS.
 *
 * Checks the signature (RS256/ES256/EdDSA allow-list), `iss` (exact), `aud` (contains),
 * `exp` (required) and `nbf` with a clock skew (default 60 s). Keys come from
 * `jwksUrl` or OIDC discovery, are cached (default 10 min) and refetched when a token names an
 * unknown `kid` (key rotation, at most once per cooldown).
 *
 * Errors: `AuthenticationError` for every invalid token (the message names the failed check, never
 * the token), `UnavailableError` when discovery/JWKS cannot be fetched, `ConfigError` for bad options.
 */
export class Verifier {
  readonly issuer: string;
  readonly audience: string;
  readonly rolesClaim: string;
  readonly algorithms: readonly SigningAlgorithm[];
  readonly clockSkewMs: number;
  readonly #jwksUrl: string | undefined;
  readonly #ttlMs: number;
  readonly #cooldownMs: number;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  #resolvedJwksUrl: string | undefined;
  #keys: KeySetEntry | undefined;
  #inflight: Promise<KeySetEntry> | undefined;

  constructor(options: VerifierOptions) {
    if (typeof options.issuer !== "string" || options.issuer.trim() === "") {
      throw new ConfigError("oidc: issuer is required");
    }
    if (typeof options.audience !== "string" || options.audience.trim() === "") {
      throw new ConfigError("oidc: audience is required");
    }
    const algorithms = options.algorithms ?? DEFAULT_ALGORITHMS;
    if (algorithms.length === 0 || algorithms.some((alg) => !DEFAULT_ALGORITHMS.includes(alg))) {
      throw new ConfigError("oidc: algorithms must be a non-empty subset of RS256, ES256, EdDSA");
    }
    for (const [name, value] of [
      ["clockSkewMs", options.clockSkewMs],
      ["jwksCacheTtlMs", options.jwksCacheTtlMs],
      ["jwksRefreshCooldownMs", options.jwksRefreshCooldownMs],
      ["httpTimeoutMs", options.httpTimeoutMs],
    ] as const) {
      if (value !== undefined && (!Number.isFinite(value) || value < 0)) {
        throw new ConfigError(`oidc: ${name} must be a non-negative number`);
      }
    }
    this.issuer = options.issuer.trim();
    this.audience = options.audience.trim();
    this.rolesClaim = options.rolesClaim?.trim() || "roles";
    this.algorithms = [...algorithms];
    this.clockSkewMs = options.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
    this.#jwksUrl = options.jwksUrl?.trim() || undefined;
    if (this.#jwksUrl !== undefined) checkUrl("jwksUrl", this.#jwksUrl);
    checkUrl("issuer", this.issuer);
    this.#ttlMs = options.jwksCacheTtlMs ?? DEFAULT_JWKS_CACHE_TTL_MS;
    this.#cooldownMs = options.jwksRefreshCooldownMs ?? DEFAULT_JWKS_REFRESH_COOLDOWN_MS;
    this.#timeoutMs = options.httpTimeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#now = options.now ?? Date.now;
  }

  /**
   * Builds a verifier from `GROW_AUTH_ISSUER` (required), `GROW_AUTH_AUDIENCE` (default
   * `GROW_AUTH_CLIENT_ID`), `GROW_AUTH_JWKS_URL`, `GROW_AUTH_ROLES_CLAIM` (default `roles`) and
   * `GROW_AUTH_CLOCK_SKEW` (duration, default 60s). Explicit `overrides` win.
   */
  static fromEnv(overrides: Partial<VerifierOptions> = {}, env: EnvMap = process.env): Verifier {
    const read = (name: string): string | undefined => {
      const value = env[name]?.trim();
      return value === undefined || value === "" ? undefined : value;
    };
    const issuer = overrides.issuer ?? read("GROW_AUTH_ISSUER");
    if (issuer === undefined) throw new ConfigError("oidc: GROW_AUTH_ISSUER is required");
    const audience =
      overrides.audience ?? read("GROW_AUTH_AUDIENCE") ?? read("GROW_AUTH_CLIENT_ID");
    if (audience === undefined) {
      throw new ConfigError("oidc: GROW_AUTH_AUDIENCE (or GROW_AUTH_CLIENT_ID) is required");
    }
    let clockSkewMs = overrides.clockSkewMs;
    const skew = read("GROW_AUTH_CLOCK_SKEW");
    if (clockSkewMs === undefined && skew !== undefined) {
      clockSkewMs = parseDuration(skew);
      if (clockSkewMs === undefined)
        throw new ConfigError("oidc: GROW_AUTH_CLOCK_SKEW is not a duration");
    }
    const options: VerifierOptions = { ...overrides, issuer, audience };
    const jwksUrl = overrides.jwksUrl ?? read("GROW_AUTH_JWKS_URL");
    if (jwksUrl !== undefined) options.jwksUrl = jwksUrl;
    const rolesClaim = overrides.rolesClaim ?? read("GROW_AUTH_ROLES_CLAIM");
    if (rolesClaim !== undefined) options.rolesClaim = rolesClaim;
    if (clockSkewMs !== undefined) options.clockSkewMs = clockSkewMs;
    return new Verifier(options);
  }

  /** Verifies a raw JWT access token and returns its user. */
  async verify(token: string): Promise<AuthUser> {
    if (typeof token !== "string" || token.split(".").length !== 3) {
      throw new AuthenticationError("verify: malformed token");
    }
    let alg: string | undefined;
    let kid: string | undefined;
    try {
      ({ alg, kid } = decodeProtectedHeader(token));
    } catch {
      throw new AuthenticationError("verify: malformed token header");
    }
    if (alg === undefined || !(this.algorithms as readonly string[]).includes(alg)) {
      throw new AuthenticationError(`verify: algorithm ${String(alg)} is not allowed`);
    }
    let entry = await this.#keySet(false);
    try {
      return await this.#verifyWith(token, entry);
    } catch (err) {
      if (!(err instanceof joseErrors.JWKSNoMatchingKey) || !this.#mayRefresh(entry)) {
        throw mapJoseError(err, kid);
      }
    }
    entry = await this.#keySet(true);
    try {
      return await this.#verifyWith(token, entry);
    } catch (err) {
      throw mapJoseError(err, kid);
    }
  }

  /** Verifies the bearer token of a request (`AuthenticationError` when there is none). */
  async verifyRequest(req: RequestLike): Promise<AuthUser> {
    const token = bearerToken(req);
    if (token === null) throw new AuthenticationError("verify: missing bearer token");
    return this.verify(token);
  }

  /** Drops the cached JWKS so the next verification refetches it. */
  clearCache(): void {
    this.#keys = undefined;
  }

  async #verifyWith(token: string, entry: KeySetEntry): Promise<AuthUser> {
    const { payload } = await jwtVerify(token, entry.getKey, {
      issuer: this.issuer,
      audience: this.audience,
      algorithms: [...this.algorithms],
      clockTolerance: Math.floor(this.clockSkewMs / 1000),
      requiredClaims: ["exp", "sub"],
      currentDate: new Date(this.#now()),
    });
    return this.#toUser(payload);
  }

  #toUser(payload: JWTPayload): AuthUser {
    const claims = { ...payload } as Record<string, unknown>;
    const user: AuthUser = {
      sub: String(payload.sub),
      roles: extractRoles(claims, this.rolesClaim),
      claims,
    };
    if (typeof claims.email === "string") user.email = claims.email;
    const name = typeof claims.name === "string" ? claims.name : claims.preferred_username;
    if (typeof name === "string") user.name = name;
    return user;
  }

  #mayRefresh(entry: KeySetEntry): boolean {
    return this.#now() - entry.fetchedAt >= this.#cooldownMs;
  }

  async #keySet(force: boolean): Promise<KeySetEntry> {
    const cached = this.#keys;
    if (!force && cached !== undefined && this.#now() - cached.fetchedAt < this.#ttlMs)
      return cached;
    if (this.#inflight !== undefined) return this.#inflight;
    const pending = this.#loadKeySet().finally(() => {
      this.#inflight = undefined;
    });
    this.#inflight = pending;
    return pending;
  }

  async #loadKeySet(): Promise<KeySetEntry> {
    const url = await this.#jwksUri();
    const body = await this.#getJson(url, "jwks");
    if (
      body === null ||
      typeof body !== "object" ||
      !Array.isArray((body as { keys?: unknown }).keys)
    ) {
      throw new UnavailableError("jwks: response has no keys array");
    }
    const entry: KeySetEntry = {
      getKey: createLocalJWKSet(body as JSONWebKeySet),
      fetchedAt: this.#now(),
    };
    this.#keys = entry;
    return entry;
  }

  async #jwksUri(): Promise<string> {
    if (this.#jwksUrl !== undefined) return this.#jwksUrl;
    if (this.#resolvedJwksUrl !== undefined) return this.#resolvedJwksUrl;
    const url = `${trimTrailingSlashes(this.issuer)}/.well-known/openid-configuration`;
    const doc = await this.#getJson(url, "discovery");
    const jwksUri = (doc as { jwks_uri?: unknown } | null)?.jwks_uri;
    if (typeof jwksUri !== "string" || jwksUri === "") {
      throw new UnavailableError("discovery: document has no jwks_uri");
    }
    this.#resolvedJwksUrl = jwksUri;
    return jwksUri;
  }

  async #getJson(url: string, operation: string): Promise<unknown> {
    let res: Response;
    try {
      res = await this.#fetch(url, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (err) {
      throw new UnavailableError(`${operation}: request failed`, { cause: err });
    }
    if (!res.ok) {
      throw new UnavailableError(`${operation}: unexpected response (HTTP ${res.status})`, {
        httpStatus: res.status,
      });
    }
    try {
      return await res.json();
    } catch (err) {
      throw new UnavailableError(`${operation}: response is not JSON`, { cause: err });
    }
  }
}

/** `value` without trailing slashes (a loop, not a regex: no backtracking on long inputs). */
function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) end -= 1;
  return value.slice(0, end);
}

function checkUrl(name: string, value: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ConfigError(`oidc: ${name} is not a URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ConfigError(`oidc: ${name} must use http or https`);
  }
}

/** Maps a jose verification error to an `AuthenticationError` that never contains the token. */
function mapJoseError(err: unknown, kid: string | undefined): OidcError {
  if (err instanceof OidcError) return err;
  if (err instanceof joseErrors.JWTExpired) return new AuthenticationError("verify: token expired");
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    return new AuthenticationError(`verify: claim ${err.claim} is invalid (${err.reason})`);
  }
  if (err instanceof joseErrors.JWKSNoMatchingKey) {
    return new AuthenticationError(`verify: no key matches kid ${kid ?? "(none)"}`);
  }
  if (err instanceof joseErrors.JWKSMultipleMatchingKeys) {
    return new AuthenticationError("verify: several keys match and none verified the signature");
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
    return new AuthenticationError("verify: signature is invalid");
  }
  return new AuthenticationError("verify: token is invalid", { cause: err });
}
