// Service-owned: generated once by sdk-kit, then maintained in this repository.
// The client talks to the OpenID provider itself: discovery for health, userinfo for ping.

import {
  type HealthStatus,
  HttpTransport,
  type TransportOptions,
  UnsupportedError,
  healthStatus,
  probeHealth,
} from "./core/index.js";
import { OidcConfig, type OidcConfigOptions } from "./config.js";

/** Discovery document path, relative to the provider URL (keeps realm prefixes such as Keycloak's). */
export const DISCOVERY_PATH = ".well-known/openid-configuration";

/** `value` without trailing slashes (a loop, not a regex: no backtracking on long inputs). */
function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) end -= 1;
  return value.slice(0, end);
}

/**
 * Path of an endpoint relative to the provider URL: the part after the provider URL when the
 * endpoint starts with it (keeps realm prefixes out), else the endpoint's own path and query.
 */
export function relativeEndpoint(base: string, endpoint: string): string {
  const root = trimTrailingSlashes(base);
  if (endpoint.startsWith(root + "/")) return endpoint.slice(root.length);
  try {
    const url = new URL(endpoint);
    return url.pathname + url.search;
  } catch {
    return endpoint;
  }
}

/** Per-call options. */
export interface CallOptions {
  /** Cancels the call (`CancelledError`). */
  signal?: AbortSignal;
}

/** Test seams (undici `MockAgent`, fake sleep). Not part of the stable API. */
export type ClientInternals = Pick<TransportOptions, "dispatcher" | "sleep" | "now">;

/** Client for OIDC. */
export class OidcClient {
  /** The immutable configuration. */
  readonly config: OidcConfig;
  readonly #transport: HttpTransport;
  #closed = false;

  /** Accepts a {@link OidcConfig} or plain options. */
  constructor(config: OidcConfigOptions = {}, internals: ClientInternals = {}) {
    const cfg = OidcConfig.from(config);
    this.config = cfg;
    this.#transport = new HttpTransport({
      ...internals,
      config: cfg,
      knownSecrets: () => cfg.knownSecrets(),
    });
  }

  /** Builds a client from `GROW_OIDC_*` (and vendor) environment variables. */
  static fromEnv(overrides: OidcConfigOptions = {}): OidcClient {
    return new OidcClient(OidcConfig.fromEnv(overrides));
  }

  /** The shared HTTP transport (for service modules). @internal */
  get transport(): HttpTransport {
    return this.#transport;
  }

  /**
   * Unauthenticated liveness: `GET <url>/.well-known/openid-configuration` (healthy when the
   * discovery document answers 2xx). Never throws for an unhealthy or unreachable provider (only
   * `CANCELLED` and `CONFIG`).
   */
  health(options: CallOptions = {}): Promise<HealthStatus> {
    return probeHealth(async () => {
      const doc = await this.#discovery("health", options);
      const details: Record<string, unknown> = {};
      if (typeof doc.issuer === "string") details.issuer = doc.issuer;
      return healthStatus("ok", details);
    });
  }

  /**
   * Authenticated round trip with the configured access token (`token`): `GET` the provider's
   * `userinfo_endpoint` from discovery. Returns the latency in milliseconds; a rejected token
   * raises `AuthenticationError`, a provider without userinfo `UnsupportedError`.
   */
  async ping(options: CallOptions = {}): Promise<number> {
    const start = performance.now();
    const doc = await this.#discovery("ping", options);
    if (typeof doc.userinfo_endpoint !== "string" || doc.userinfo_endpoint === "") {
      throw new UnsupportedError("ping: the provider has no userinfo endpoint");
    }
    // Only the userinfo call carries the token (some providers reject discovery with a bad one).
    const token = this.config.token;
    await this.#transport.get(relativeEndpoint(this.config.url, doc.userinfo_endpoint), {
      operation: "ping",
      responseType: "none",
      headers: token === undefined ? {} : { authorization: `Bearer ${token.reveal()}` },
      ...options,
    });
    return performance.now() - start;
  }

  /** OpenID Connect has no version endpoint: always `UnsupportedError` (`CANCELLED` once closed). */
  serverVersion(_options: CallOptions = {}): Promise<string> {
    return new Promise((_resolve, reject) => {
      this.#transport.ensureOpen("serverVersion");
      reject(new UnsupportedError("serverVersion: OpenID Connect providers expose no version"));
    });
  }

  async #discovery(operation: string, options: CallOptions): Promise<Record<string, unknown>> {
    const res = await this.#transport.get(DISCOVERY_PATH, { operation, ...options });
    const data = res.data;
    return data !== null && typeof data === "object" && !Array.isArray(data)
      ? (data as Record<string, unknown>)
      : {};
  }

  /** Releases connections. Idempotent. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#transport.close();
  }
}
