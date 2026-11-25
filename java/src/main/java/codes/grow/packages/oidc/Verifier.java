package codes.grow.packages.oidc;

import codes.grow.packages.oidc.core.AuthenticationException;
import codes.grow.packages.oidc.core.CancelledException;
import codes.grow.packages.oidc.core.ConfigException;
import codes.grow.packages.oidc.core.EnvReader;
import codes.grow.packages.oidc.core.Json;
import codes.grow.packages.oidc.core.UnavailableException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Verifies OIDC access tokens (JWT) against the issuer's JWKS. Thread-safe.
 *
 * <p>Checks the signature (RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA allow-list; the
 * key type and curve must match the algorithm), {@code iss} (exact, trailing slashes ignored),
 * {@code aud} (contains), {@code exp} (required), {@code nbf} and {@code sub} with a clock skew
 * (default 60 s). Keys come from the JWKS URL or OIDC discovery, are cached (default 10 min) and
 * refetched when a token names an unknown {@code kid} (key rotation, at most once per cooldown).
 *
 * <p>Throws {@link AuthenticationException} for every invalid token (the message names the failed
 * check, never the token), {@link UnavailableException} when discovery or the JWKS cannot be
 * fetched and {@link ConfigException} for invalid options.
 */
public final class Verifier {
  /**
   * Accepted algorithms by default: every supported asymmetric algorithm ({@code none} and HMAC are
   * never accepted).
   */
  public static final List<String> DEFAULT_ALGORITHMS =
      List.of(
          "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA");

  /** Default tolerance applied to {@code exp} and {@code nbf}. */
  public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);

  /** Default JWKS cache lifetime. */
  public static final Duration DEFAULT_JWKS_CACHE_TTL = Duration.ofMinutes(10);

  /** Default minimum interval between two unknown-kid refetches. */
  public static final Duration DEFAULT_JWKS_REFRESH_COOLDOWN = Duration.ofSeconds(30);

  /** Default timeout of discovery and JWKS requests. */
  public static final Duration DEFAULT_HTTP_TIMEOUT = Duration.ofSeconds(10);

  private final String issuer;
  private final String audience;
  private final String rolesClaim;
  private final String jwksUrl;
  private final List<String> algorithms;
  private final Duration clockSkew;
  private final Duration ttl;
  private final Duration cooldown;
  private final Duration httpTimeout;
  private final HttpClient http;
  private final Clock clock;
  private final ReentrantLock fetchLock = new ReentrantLock();
  private volatile String resolvedJwksUrl;
  private volatile KeySet keys;

  private record KeySet(List<Jwks.Key> keys, Instant fetchedAt) {}

  private Verifier(Builder b) {
    this.issuer = trim(b.issuer);
    this.audience = trim(b.audience);
    if (issuer.isEmpty()) {
      throw new ConfigException("oidc: issuer is required");
    }
    if (audience.isEmpty()) {
      throw new ConfigException("oidc: audience is required");
    }
    checkUrl("issuer", issuer);
    String jwks = trim(b.jwksUrl);
    this.jwksUrl = jwks.isEmpty() ? null : jwks;
    if (jwksUrl != null) {
      checkUrl("jwksUrl", jwksUrl);
    }
    String claim = trim(b.rolesClaim);
    this.rolesClaim = claim.isEmpty() ? "roles" : claim;
    if (b.algorithms.isEmpty() || !DEFAULT_ALGORITHMS.containsAll(b.algorithms)) {
      throw new ConfigException(
          "oidc: algorithms must be a non-empty subset of RS256, RS384, RS512, PS256, PS384, PS512,"
              + " ES256, ES384, ES512, EdDSA");
    }
    this.algorithms = List.copyOf(b.algorithms);
    this.clockSkew = nonNegative("clockSkew", b.clockSkew);
    this.ttl = nonNegative("jwksCacheTtl", b.jwksCacheTtl);
    this.cooldown = nonNegative("jwksRefreshCooldown", b.jwksRefreshCooldown);
    this.httpTimeout = nonNegative("httpTimeout", b.httpTimeout);
    this.http =
        b.httpClient != null
            ? b.httpClient
            : HttpClient.newBuilder()
                .connectTimeout(httpTimeout)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    this.clock = b.clock;
  }

  private static String trim(String value) {
    return value == null ? "" : value.trim();
  }

  private static Duration nonNegative(String name, Duration value) {
    if (value == null || value.isNegative()) {
      throw new ConfigException("oidc: " + name + " must not be negative");
    }
    return value;
  }

  private static void checkUrl(String name, String value) {
    try {
      URI uri = new URI(value);
      if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))
          || uri.getHost() == null) {
        throw new ConfigException("oidc: " + name + " must be an http or https URL");
      }
    } catch (URISyntaxException e) {
      throw new ConfigException("oidc: " + name + " is not a URL");
    }
  }

  /**
   * Starts a builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builds a verifier from {@code GROW_AUTH_ISSUER} (required), {@code GROW_AUTH_AUDIENCE} (default
   * {@code GROW_AUTH_CLIENT_ID}), {@code GROW_AUTH_JWKS_URL}, {@code GROW_AUTH_ROLES_CLAIM}
   * (default {@code roles}) and {@code GROW_AUTH_CLOCK_SKEW} (duration, default 60s).
   *
   * @return the verifier
   */
  public static Verifier fromEnv() {
    return fromEnv(System.getenv());
  }

  /**
   * {@link #fromEnv()} with an explicit environment map (tests).
   *
   * @param env the environment
   * @return the verifier
   */
  public static Verifier fromEnv(Map<String, String> env) {
    EnvReader reader = new EnvReader("GROW_AUTH_", env);
    String issuer =
        reader
            .string("ISSUER")
            .orElseThrow(() -> new ConfigException("oidc: GROW_AUTH_ISSUER is required"));
    String audience =
        reader
            .string("AUDIENCE", "GROW_AUTH_CLIENT_ID")
            .orElseThrow(
                () ->
                    new ConfigException(
                        "oidc: GROW_AUTH_AUDIENCE (or GROW_AUTH_CLIENT_ID) is required"));
    Builder b = builder().issuer(issuer).audience(audience);
    reader.string("JWKS_URL").ifPresent(b::jwksUrl);
    reader.string("ROLES_CLAIM").ifPresent(b::rolesClaim);
    reader.duration("CLOCK_SKEW").ifPresent(b::clockSkew);
    return b.build();
  }

  /**
   * The expected issuer.
   *
   * @return the issuer
   */
  public String issuer() {
    return issuer;
  }

  /**
   * The expected audience.
   *
   * @return the audience
   */
  public String audience() {
    return audience;
  }

  /**
   * The roles claim path.
   *
   * @return the claim
   */
  public String rolesClaim() {
    return rolesClaim;
  }

  /**
   * The exp/nbf tolerance.
   *
   * @return the clock skew
   */
  public Duration clockSkew() {
    return clockSkew;
  }

  /** Drops the cached JWKS so the next verification refetches it. */
  public void clearCache() {
    keys = null;
  }

  private static AuthenticationException auth(String reason) {
    return new AuthenticationException("verify: " + reason);
  }

  /**
   * Verifies a raw JWT access token.
   *
   * @param token the token
   * @return the user
   * @throws AuthenticationException when the token is invalid
   * @throws UnavailableException when discovery or the JWKS cannot be fetched
   */
  public AuthUser verify(String token) {
    String[] parts = token == null ? new String[0] : token.split("\\.", -1);
    if (parts.length != 3) {
      throw auth("malformed token");
    }
    JsonNode header;
    try {
      header = Json.mapper().readTree(Jwks.decode(parts[0]));
    } catch (IOException | IllegalArgumentException e) {
      throw auth("malformed token header");
    }
    String alg = header != null && header.path("alg").isTextual() ? header.get("alg").asText() : "";
    if (!algorithms.contains(alg)) {
      String shown = alg.isEmpty() ? "(none)" : alg.substring(0, Math.min(16, alg.length()));
      throw auth("algorithm " + shown + " is not allowed");
    }
    String kid = header.path("kid").isTextual() ? header.get("kid").asText() : null;
    Map<String, Object> claims;
    byte[] signature;
    try {
      claims =
          Json.mapper()
              .readValue(Jwks.decode(parts[1]), new TypeReference<Map<String, Object>>() {});
      signature = Jwks.decode(parts[2]);
    } catch (IOException | IllegalArgumentException e) {
      throw auth("malformed token payload");
    }
    if (claims == null) {
      throw auth("malformed token payload");
    }
    KeySet set = keySet(false);
    List<Jwks.Key> candidates = candidates(set, alg, kid);
    if (candidates.isEmpty()
        && kid != null
        && !clock.instant().isBefore(set.fetchedAt().plus(cooldown))) {
      candidates = candidates(keySet(true), alg, kid);
    }
    if (candidates.isEmpty()) {
      throw auth("no key matches kid " + (kid == null ? "(none)" : kid));
    }
    byte[] signed = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
    if (candidates.stream().noneMatch(k -> k.verify(alg, signed, signature))) {
      throw auth("signature is invalid");
    }
    checkClaims(claims);
    return toUser(claims);
  }

  /**
   * Asynchronous {@link #verify(String)}.
   *
   * @param token the token
   * @return the user, or a future failed with the same exceptions
   */
  public CompletableFuture<AuthUser> verifyAsync(String token) {
    return CompletableFuture.supplyAsync(() -> verify(token));
  }

  /**
   * Returns the bearer token of an {@code Authorization} header value.
   *
   * @param authorization the header value, may be null
   * @return the token, or empty
   */
  public static Optional<String> bearerToken(String authorization) {
    if (authorization == null) {
      return Optional.empty();
    }
    String[] parts = authorization.trim().split("\\s+");
    if (parts.length != 2 || !parts[0].equalsIgnoreCase("bearer")) {
      return Optional.empty();
    }
    return Optional.of(parts[1]);
  }

  private static List<Jwks.Key> candidates(KeySet set, String alg, String kid) {
    List<Jwks.Key> out = new ArrayList<>();
    for (Jwks.Key key : set.keys()) {
      if ((kid == null || kid.equals(key.kid())) && key.compatible(alg)) {
        out.add(key);
      }
    }
    return out;
  }

  private static double number(Map<String, Object> claims, String name) {
    Object value = claims.get(name);
    if (!(value instanceof Number n)) {
      throw auth("claim " + name + " is invalid (not a number)");
    }
    return n.doubleValue();
  }

  /** {@code value} without trailing slashes (a loop, no regex backtracking). */
  static String stripTrailingSlashes(String value) {
    int end = value.length();
    while (end > 0 && value.charAt(end - 1) == '/') {
      end--;
    }
    return value.substring(0, end);
  }

  private void checkClaims(Map<String, Object> claims) {
    // Exact match except trailing slashes (Authentik's iss always ends with "/").
    if (!(claims.get("iss") instanceof String iss)
        || !stripTrailingSlashes(iss).equals(stripTrailingSlashes(issuer))) {
      throw auth("claim iss is invalid (unexpected value)");
    }
    Object aud = claims.get("aud");
    boolean audOk =
        audience.equals(aud) || (aud instanceof List<?> list && list.contains(audience));
    if (!audOk) {
      throw auth("claim aud is invalid (unexpected value)");
    }
    double now = clock.millis() / 1000.0;
    double skew = clockSkew.toMillis() / 1000.0;
    if (!claims.containsKey("exp")) {
      throw auth("claim exp is invalid (missing)");
    }
    if (now > number(claims, "exp") + skew) {
      throw auth("token expired");
    }
    if (claims.containsKey("nbf") && now + skew < number(claims, "nbf")) {
      throw auth("claim nbf is invalid (not yet valid)");
    }
    if (!(claims.get("sub") instanceof String sub) || sub.isEmpty()) {
      throw auth("claim sub is invalid (missing)");
    }
  }

  private AuthUser toUser(Map<String, Object> claims) {
    Object name = claims.get("name");
    if (!(name instanceof String)) {
      name = claims.get("preferred_username");
    }
    return new AuthUser(
        (String) claims.get("sub"),
        claims.get("email") instanceof String email ? Optional.of(email) : Optional.empty(),
        name instanceof String n ? Optional.of(n) : Optional.empty(),
        Roles.extract(claims, rolesClaim),
        withoutNulls(claims));
  }

  private static Map<String, Object> withoutNulls(Map<String, Object> claims) {
    Map<String, Object> copy = new java.util.LinkedHashMap<>();
    claims.forEach(
        (k, v) -> {
          if (v != null) {
            copy.put(k, v);
          }
        });
    return copy;
  }

  private KeySet keySet(boolean force) {
    KeySet cached = keys;
    Instant now = clock.instant();
    if (!force && cached != null && now.isBefore(cached.fetchedAt().plus(ttl))) {
      return cached;
    }
    fetchLock.lock();
    try {
      KeySet current = keys;
      if (current != null && current != cached) {
        return current; // fetched by another thread meanwhile
      }
      String url = jwksUrl != null ? jwksUrl : resolvedJwksUrl;
      if (url == null) {
        JsonNode doc =
            getJson(
                "discovery", stripTrailingSlashes(issuer) + "/.well-known/openid-configuration");
        JsonNode uri = doc.path("jwks_uri");
        if (!uri.isTextual() || uri.asText().isEmpty()) {
          throw new UnavailableException("discovery: document has no jwks_uri");
        }
        url = uri.asText();
        resolvedJwksUrl = url;
      }
      JsonNode body = getJson("jwks", url);
      if (!body.path("keys").isArray()) {
        throw new UnavailableException("jwks: response has no keys array");
      }
      KeySet fresh = new KeySet(Jwks.parse(body.get("keys")), clock.instant());
      keys = fresh;
      return fresh;
    } finally {
      fetchLock.unlock();
    }
  }

  private JsonNode getJson(String operation, String url) {
    HttpResponse<byte[]> res;
    try {
      HttpRequest req =
          HttpRequest.newBuilder(URI.create(url))
              .timeout(httpTimeout)
              .header("Accept", "application/json")
              .GET()
              .build();
      res = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new CancelledException(operation + ": interrupted", e);
    } catch (IOException | IllegalArgumentException e) {
      throw new UnavailableException(operation + ": request failed", e);
    }
    if (res.statusCode() < 200 || res.statusCode() > 299) {
      throw new UnavailableException(
          operation + ": unexpected response (HTTP " + res.statusCode() + ")",
          res.statusCode(),
          null,
          null,
          null);
    }
    try {
      JsonNode node = Json.mapper().readTree(res.body());
      if (node == null || !node.isObject()) {
        throw new IOException("not an object");
      }
      return node;
    } catch (IOException e) {
      throw new UnavailableException(operation + ": response is not JSON", e);
    }
  }

  /** Builder of a {@link Verifier}. */
  public static final class Builder {
    private String issuer;
    private String audience;
    private String jwksUrl;
    private String rolesClaim = "roles";
    private List<String> algorithms = DEFAULT_ALGORITHMS;
    private Duration clockSkew = DEFAULT_CLOCK_SKEW;
    private Duration jwksCacheTtl = DEFAULT_JWKS_CACHE_TTL;
    private Duration jwksRefreshCooldown = DEFAULT_JWKS_REFRESH_COOLDOWN;
    private Duration httpTimeout = DEFAULT_HTTP_TIMEOUT;
    private HttpClient httpClient;
    private Clock clock = Clock.systemUTC();

    private Builder() {}

    /**
     * Expected {@code iss} (exact, except that trailing slashes on either side are ignored);
     * discovery uses {@code <issuer without trailing slashes>/.well-known/openid-configuration}.
     *
     * @param value the issuer URL
     * @return this builder
     */
    public Builder issuer(String value) {
      this.issuer = value;
      return this;
    }

    /**
     * Expected {@code aud}.
     *
     * @param value the audience
     * @return this builder
     */
    public Builder audience(String value) {
      this.audience = value;
      return this;
    }

    /**
     * JWKS URL; skips discovery when set.
     *
     * @param value the URL
     * @return this builder
     */
    public Builder jwksUrl(String value) {
      this.jwksUrl = value;
      return this;
    }

    /**
     * Claim (or dotted path) holding the roles; default {@code roles}.
     *
     * @param value the claim
     * @return this builder
     */
    public Builder rolesClaim(String value) {
      this.rolesClaim = value;
      return this;
    }

    /**
     * Accepted algorithms, a subset of RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384,
     * ES512, EdDSA (default all).
     *
     * @param value the algorithms
     * @return this builder
     */
    public Builder algorithms(List<String> value) {
      this.algorithms = List.copyOf(value);
      return this;
    }

    /**
     * Tolerance applied to {@code exp}/{@code nbf}; default 60 s.
     *
     * @param value the skew
     * @return this builder
     */
    public Builder clockSkew(Duration value) {
      this.clockSkew = value;
      return this;
    }

    /**
     * JWKS cache lifetime; default 10 min.
     *
     * @param value the TTL
     * @return this builder
     */
    public Builder jwksCacheTtl(Duration value) {
      this.jwksCacheTtl = value;
      return this;
    }

    /**
     * Minimum interval between unknown-kid refetches; default 30 s.
     *
     * @param value the cooldown
     * @return this builder
     */
    public Builder jwksRefreshCooldown(Duration value) {
      this.jwksRefreshCooldown = value;
      return this;
    }

    /**
     * Timeout of discovery/JWKS requests; default 10 s.
     *
     * @param value the timeout
     * @return this builder
     */
    public Builder httpTimeout(Duration value) {
      this.httpTimeout = value;
      return this;
    }

    /**
     * HTTP client for discovery/JWKS (proxies, TLS); default a new JDK client.
     *
     * @param value the client
     * @return this builder
     */
    public Builder httpClient(HttpClient value) {
      this.httpClient = value;
      return this;
    }

    /**
     * Clock (tests).
     *
     * @param value the clock
     * @return this builder
     */
    public Builder clock(Clock value) {
      this.clock = value;
      return this;
    }

    /**
     * Validates the options and builds the verifier (no network call).
     *
     * @return the verifier
     * @throws ConfigException for invalid options
     */
    public Verifier build() {
      return new Verifier(this);
    }
  }
}
