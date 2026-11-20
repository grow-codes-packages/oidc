package codes.grow.packages.oidc;

import codes.grow.packages.oidc.core.AuthenticationException;
import codes.grow.packages.oidc.core.CancelledException;
import codes.grow.packages.oidc.core.ConfigException;
import codes.grow.packages.oidc.core.EnvReader;
import codes.grow.packages.oidc.core.HealthCheck;
import codes.grow.packages.oidc.core.HealthStatus;
import codes.grow.packages.oidc.core.Hooks;
import codes.grow.packages.oidc.core.HttpTransport;
import codes.grow.packages.oidc.core.Logger;
import codes.grow.packages.oidc.core.RetryPolicy;
import codes.grow.packages.oidc.core.Secret;
import codes.grow.packages.oidc.core.TlsOptions;
import codes.grow.packages.oidc.core.TransportRequest;
import codes.grow.packages.oidc.core.UnsupportedException;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Client for OIDC.
 *
 * <p>Implements SPEC section 2.4. Thread-safe; create one per endpoint and close it when done.
 *
 * <pre>{@code
 * try (OidcClient client = OidcClient.fromEnv()) {
 *   HealthStatus health = client.health();
 * }
 * }</pre>
 *
 * <p>Every I/O method has a blocking form and an {@code …Async} form returning {@link
 * CompletableFuture}. This file is owned by the service package (generated once by sdk-kit); add
 * service modules here.
 */
public final class OidcClient implements AutoCloseable {
  private final OidcConfig config;
  private final HttpTransport transport;
  private final AtomicBoolean closed = new AtomicBoolean();
  private final List<AutoCloseable> resources = new ArrayList<>();

  private OidcClient(OidcConfig config) {
    this.config = config;
    this.transport = new HttpTransport(config.toTransportConfig());
  }

  /**
   * Creates a client.
   *
   * @param config validated configuration
   * @return a new client
   * @throws ConfigException when TLS or proxy settings are invalid
   */
  public static OidcClient create(OidcConfig config) {
    config.validate();
    return new OidcClient(config);
  }

  /**
   * Creates a client from the SDK and vendor environment variables.
   *
   * @return a new client
   */
  public static OidcClient fromEnv() {
    return create(OidcConfig.fromEnv());
  }

  /**
   * Starts a client builder.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns the configuration.
   *
   * @return the configuration
   */
  public OidcConfig config() {
    return config;
  }

  /**
   * Returns the HTTP transport, for service modules built on this client.
   *
   * @return the transport
   */
  public HttpTransport transport() {
    return transport;
  }

  /**
   * Registers a resource (watcher, renewer, batch processor) closed with the client.
   *
   * @param resource the resource
   */
  public void register(AutoCloseable resource) {
    synchronized (resources) {
      resources.add(resource);
    }
  }

  /** Discovery document path, relative to the provider URL. */
  public static final String DISCOVERY_PATH = ".well-known/openid-configuration";

  /**
   * Checks liveness ({@code GET <url>/.well-known/openid-configuration}). Never throws for an
   * unhealthy or unreachable provider.
   *
   * @return the health status
   * @throws CancelledException when interrupted or closed
   */
  public HealthStatus health() {
    return trim(HealthCheck.check(transport, DISCOVERY_PATH));
  }

  /**
   * Asynchronous {@link #health()}.
   *
   * @return a future with the health status
   */
  public CompletableFuture<HealthStatus> healthAsync() {
    return HealthCheck.checkAsync(transport, DISCOVERY_PATH).thenApply(OidcClient::trim);
  }

  /** Keeps only the issuer of a healthy discovery document (not every endpoint). */
  private static HealthStatus trim(HealthStatus h) {
    if (!h.healthy()) {
      return h;
    }
    Map<String, String> details = new LinkedHashMap<>();
    if (h.details().containsKey("issuer")) {
      details.put("issuer", h.details().get("issuer"));
    }
    return new HealthStatus(true, h.status(), details);
  }

  /**
   * Performs an authenticated round trip with the configured access token: {@code GET} the
   * provider's {@code userinfo_endpoint} from discovery.
   *
   * @return the latency
   * @throws AuthenticationException for a rejected token
   * @throws UnsupportedException when the provider has no userinfo endpoint
   */
  public Duration ping() {
    return HttpTransport.await(pingAsync(), "ping");
  }

  /**
   * Asynchronous {@link #ping()}.
   *
   * @return a future with the latency
   */
  public CompletableFuture<Duration> pingAsync() {
    long start = System.nanoTime();
    return transport
        .sendAsync(TransportRequest.get(DISCOVERY_PATH).operation("ping").build())
        .thenCompose(
            doc -> {
              JsonNode endpoint = doc.jsonNode().get("userinfo_endpoint");
              if (endpoint == null || !endpoint.isTextual() || endpoint.asText().isEmpty()) {
                throw new UnsupportedException("ping: the provider has no userinfo endpoint");
              }
              String path = relativeEndpoint(config.url(), endpoint.asText());
              return transport.sendAsync(authorized(TransportRequest.get(path).operation("ping")));
            })
        .thenApply(r -> Duration.ofNanos(System.nanoTime() - start));
  }

  /**
   * Path of an endpoint relative to the provider URL: the part after the provider URL when the
   * endpoint starts with it (keeps realm prefixes out), else the endpoint's own path and query.
   *
   * @param base the provider URL
   * @param endpoint the endpoint URL from discovery
   * @return the relative path
   */
  public static String relativeEndpoint(String base, String endpoint) {
    String root = base.replaceAll("/+$", "");
    if (endpoint.startsWith(root + "/")) {
      return endpoint.substring(root.length());
    }
    try {
      URI uri = new URI(endpoint);
      if (uri.getRawPath() == null || uri.getRawPath().isEmpty()) {
        return endpoint;
      }
      return uri.getRawQuery() == null
          ? uri.getRawPath()
          : uri.getRawPath() + "?" + uri.getRawQuery();
    } catch (URISyntaxException e) {
      return endpoint;
    }
  }

  /**
   * OpenID Connect providers expose no version: always {@link UnsupportedException}.
   *
   * @return never returns normally
   * @throws UnsupportedException always while open
   * @throws CancelledException once closed
   */
  public String serverVersion() {
    return HttpTransport.await(serverVersionAsync(), "serverVersion");
  }

  /**
   * Asynchronous {@link #serverVersion()}.
   *
   * @return a future failed with {@link UnsupportedException} ({@link CancelledException} once
   *     closed)
   */
  public CompletableFuture<String> serverVersionAsync() {
    return CompletableFuture.failedFuture(
        closed.get()
            ? new CancelledException("serverVersion: client is closed")
            : new UnsupportedException(
                "serverVersion: OpenID Connect providers expose no version"));
  }

  private TransportRequest authorized(TransportRequest.Builder b) {
    config.token().ifPresent(t -> b.header("Authorization", "Bearer " + t.reveal()));
    return b.build();
  }

  /**
   * Returns whether {@link #close()} was called.
   *
   * @return true once closed
   */
  public boolean isClosed() {
    return closed.get();
  }

  /** Stops registered resources and the transport. Idempotent. */
  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    List<AutoCloseable> copy;
    synchronized (resources) {
      copy = new ArrayList<>(resources);
      resources.clear();
    }
    for (AutoCloseable r : copy) {
      try {
        r.close();
      } catch (Exception ignored) {
        // best effort: close must not throw
      }
    }
    transport.close();
  }

  @Override
  public String toString() {
    return "OidcClient{" + config + "}";
  }

  /** Builder that configures and creates a client in one chain. */
  public static final class Builder {
    private final OidcConfig.Builder config = OidcConfig.builder();

    private Builder() {}

    /**
     * Fills unset fields from an environment reader.
     *
     * @param env reader, e.g. {@link EnvReader#system()}
     * @return this builder
     */
    public Builder fromEnv(EnvReader env) {
      config.fromEnv(env);
      return this;
    }

    /**
     * Sets the endpoint base URL.
     *
     * @param url URL
     * @return this builder
     */
    public Builder url(String url) {
      config.url(url);
      return this;
    }

    /**
     * Sets the API token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(String token) {
      config.token(token);
      return this;
    }

    /**
     * Sets the API token.
     *
     * @param token token
     * @return this builder
     */
    public Builder token(Secret token) {
      config.token(token);
      return this;
    }

    /**
     * Sets the connect timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      config.connectTimeout(d);
      return this;
    }

    /**
     * Sets the per-attempt timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder requestTimeout(Duration d) {
      config.requestTimeout(d);
      return this;
    }

    /**
     * Sets the total timeout.
     *
     * @param d duration
     * @return this builder
     */
    public Builder totalTimeout(Duration d) {
      config.totalTimeout(d);
      return this;
    }

    /**
     * Sets the retry policy.
     *
     * @param retry policy
     * @return this builder
     */
    public Builder retry(RetryPolicy retry) {
      config.retry(retry);
      return this;
    }

    /**
     * Sets the TLS options.
     *
     * @param tls options
     * @return this builder
     */
    public Builder tls(TlsOptions tls) {
      config.tls(tls);
      return this;
    }

    /**
     * Sets the proxy URL.
     *
     * @param proxy URL
     * @return this builder
     */
    public Builder proxy(String proxy) {
      config.proxy(proxy);
      return this;
    }

    /**
     * Adds a header.
     *
     * @param name name
     * @param value value
     * @return this builder
     */
    public Builder header(String name, String value) {
      config.header(name, value);
      return this;
    }

    /**
     * Sets the user agent suffix.
     *
     * @param suffix suffix
     * @return this builder
     */
    public Builder userAgentSuffix(String suffix) {
      config.userAgentSuffix(suffix);
      return this;
    }

    /**
     * Sets hooks.
     *
     * @param hooks hooks
     * @return this builder
     */
    public Builder hooks(Hooks hooks) {
      config.hooks(hooks);
      return this;
    }

    /**
     * Sets the logger.
     *
     * @param logger logger
     * @return this builder
     */
    public Builder logger(Logger logger) {
      config.logger(logger);
      return this;
    }

    /**
     * Builds the configuration and the client.
     *
     * @return a new client
     * @throws ConfigException when the configuration is invalid
     */
    public OidcClient build() {
      return create(config.build());
    }
  }
}
