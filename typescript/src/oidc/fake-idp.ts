// Service-owned: a local fake OpenID provider for tests (discovery + JWKS over HTTP, token minting).

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { type CryptoKey, type JWK, SignJWT, exportJWK, generateKeyPair } from "jose";

import { DEFAULT_ALGORITHMS, type SigningAlgorithm } from "./verifier.js";

/** One signing key of the fake IdP. */
export interface FakeIdpKey {
  kid: string;
  alg: SigningAlgorithm;
  privateKey: CryptoKey;
  publicJwk: JWK;
}

/** Options of {@link FakeIdp.prototype.mint}. */
export interface MintOptions {
  /** Claims merged over the defaults (`iss`, `aud`, `sub`, `iat`, `exp`). `undefined` removes one. */
  claims?: Record<string, unknown>;
  /** Signing key id (default: the current key). */
  kid?: string;
  /** Header overrides (e.g. `{ kid: undefined }`). */
  header?: Record<string, unknown>;
  /** Lifetime in seconds (default 300). */
  ttlSeconds?: number;
}

/**
 * A local OpenID provider for unit and conformance tests: serves
 * `/.well-known/openid-configuration` and `/jwks` on 127.0.0.1, mints signed tokens and rotates
 * keys. Never use it outside tests.
 */
export class FakeIdp {
  /** Issuer URL (`http://127.0.0.1:<port>`), set by {@link start}. */
  issuer = "";
  /** Audience put into minted tokens. */
  readonly audience: string;
  /** Keys published in the JWKS. */
  readonly keys: FakeIdpKey[] = [];
  /** Request counters per path. */
  readonly hits: Record<string, number> = {};
  /** When set, the server answers every request with this status. */
  failStatus: number | undefined;
  #server: Server | undefined;
  #current = "";
  #counter = 0;

  constructor(audience = "test-client") {
    this.audience = audience;
  }

  /** Starts the server and creates the first key (`alg`, default RS256). */
  async start(alg: SigningAlgorithm = "RS256"): Promise<this> {
    const server = createServer((req, res) => {
      const path = (req.url ?? "/").split("?")[0] ?? "/";
      this.hits[path] = (this.hits[path] ?? 0) + 1;
      if (this.failStatus !== undefined) {
        res.writeHead(this.failStatus).end();
        return;
      }
      let body: unknown;
      if (path === "/.well-known/openid-configuration") {
        body = {
          issuer: this.issuer,
          jwks_uri: `${this.issuer}/jwks`,
          id_token_signing_alg_values_supported: [...DEFAULT_ALGORITHMS],
        };
      } else if (path === "/jwks") {
        body = { keys: this.keys.map((key) => key.publicJwk) };
      } else {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(body));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    this.#server = server;
    this.issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    await this.rotate(alg);
    return this;
  }

  /**
   * Adds a new key of `alg` (any supported algorithm; EC curves follow the algorithm, RSA keys are
   * 2048-bit) and makes it current (the old keys stay published until removed).
   */
  async rotate(alg: SigningAlgorithm = "RS256"): Promise<FakeIdpKey> {
    this.#counter += 1;
    const kid = `key-${this.#counter}`;
    const { privateKey, publicKey } = await generateKeyPair(
      alg,
      alg === "EdDSA" ? { crv: "Ed25519" } : {},
    );
    const publicJwk = { ...(await exportJWK(publicKey)), kid, alg, use: "sig" };
    const key: FakeIdpKey = { kid, alg, privateKey, publicJwk };
    this.keys.push(key);
    this.#current = kid;
    return key;
  }

  /** Removes a key from the JWKS. */
  removeKey(kid: string): void {
    const index = this.keys.findIndex((key) => key.kid === kid);
    if (index >= 0) this.keys.splice(index, 1);
  }

  /** Signs a token with the current (or the given) key. */
  async mint(options: MintOptions = {}): Promise<string> {
    const kid = options.kid ?? this.#current;
    const key = this.keys.find((candidate) => candidate.kid === kid);
    if (key === undefined) throw new Error(`fake idp: unknown kid ${kid}`);
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      iss: this.issuer,
      aud: this.audience,
      sub: "user-1",
      iat: now,
      exp: now + (options.ttlSeconds ?? 300),
      ...options.claims,
    };
    for (const [name, value] of Object.entries(claims))
      if (value === undefined) Reflect.deleteProperty(claims, name);
    const header: Record<string, unknown> = {
      alg: key.alg,
      kid: key.kid,
      typ: "JWT",
      ...options.header,
    };
    for (const [name, value] of Object.entries(header))
      if (value === undefined) Reflect.deleteProperty(header, name);
    return new SignJWT(claims).setProtectedHeader(header as { alg: string }).sign(key.privateKey);
  }

  /** Stops the server. */
  async stop(): Promise<void> {
    const server = this.#server;
    this.#server = undefined;
    if (server !== undefined) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
    }
  }
}
