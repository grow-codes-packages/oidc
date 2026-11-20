package codes.grow.packages.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import codes.grow.packages.oidc.core.AuthenticationException;
import codes.grow.packages.oidc.core.ConfigException;
import codes.grow.packages.oidc.core.UnavailableException;
import codes.grow.packages.oidc.oidctest.FakeIdp;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Conformance cases OIDC-01…OIDC-17 (docs/oidc-conformance.md) against the local fake IdP. */
class VerifierTest {
  private FakeIdp idp;

  @BeforeEach
  void start() throws IOException {
    idp = FakeIdp.start("app-client", "RS256");
  }

  @AfterEach
  void stop() {
    idp.close();
  }

  private Verifier.Builder builder() {
    return Verifier.builder().issuer(idp.issuer()).audience("app-client");
  }

  private Verifier verifier() {
    return builder().build();
  }

  private static Map<String, Object> claims(Object... kv) {
    Map<String, Object> out = new HashMap<>();
    for (int i = 0; i < kv.length; i += 2) {
      out.put((String) kv[i], kv[i + 1]);
    }
    return out;
  }

  private static void assertAuth(Runnable r, String contains) {
    assertThatThrownBy(r::run)
        .isInstanceOf(AuthenticationException.class)
        .hasMessageContaining(contains);
  }

  /** A mutable clock. */
  private static final class MutableClock extends Clock {
    private Instant now = Instant.now();

    void advance(Duration d) {
      now = now.plus(d);
    }

    @Override
    public java.time.ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  @Test
  void oidc01VerifiesRs256ViaDiscovery() {
    String token =
        idp.mint(
            claims(
                "email",
                "a@b.test",
                "name",
                "Ann",
                "roles",
                List.of(Map.of("name", "admin", "owner", "o"), Map.of("name", "user")),
                "nothing",
                null));
    AuthUser user = verifier().verify(token);
    assertThat(user.sub()).isEqualTo("user-1");
    assertThat(user.getName()).isEqualTo("user-1");
    assertThat(user.email()).contains("a@b.test");
    assertThat(user.name()).contains("Ann");
    assertThat(user.roles()).containsExactly("admin", "user");
    assertThat(user.hasRole("ADMIN")).isTrue();
    assertThat(user.hasRole("x")).isFalse();
    assertThat(user.claims()).containsEntry("iss", idp.issuer());
    assertThat(idp.hits("/.well-known/openid-configuration")).isEqualTo(1);
  }

  @ParameterizedTest
  @ValueSource(strings = {"ES256", "EdDSA"})
  void oidc02And03OtherAlgorithms(String alg) {
    idp.rotate(alg);
    AuthUser user = verifier().verify(idp.mint(claims("preferred_username", "bob")));
    assertThat(user.name()).contains("bob");
    assertThat(user.email()).isEmpty();
  }

  @Test
  void oidc04To08Claims() {
    Verifier v = verifier();
    long now = System.currentTimeMillis() / 1000;
    assertAuth(() -> v.verify(idp.mint(claims("iss", "http://evil.test"))), "iss");
    assertAuth(() -> v.verify(idp.mint(claims("aud", "other"))), "aud");
    assertThat(v.verify(idp.mint(claims("aud", List.of("other", "app-client")))).sub())
        .isEqualTo("user-1");
    assertAuth(() -> v.verify(idp.mint(claims("exp", now - 120))), "expired");
    assertThat(v.verify(idp.mint(claims("exp", now - 30)))).isNotNull();
    Verifier strict = builder().clockSkew(Duration.ZERO).build();
    assertAuth(() -> strict.verify(idp.mint(claims("exp", now - 30))), "expired");
    assertAuth(() -> v.verify(idp.mint(claims("nbf", now + 120))), "nbf");
    assertThat(v.verify(idp.mint(claims("nbf", now + 30)))).isNotNull();
    assertAuth(() -> v.verify(idp.mint(claims("exp", null))), "exp");
    assertAuth(() -> v.verify(idp.mint(claims("exp", "soon"))), "exp");
    assertAuth(() -> v.verify(idp.mint(claims("sub", null))), "sub");
    assertAuth(() -> v.verify(idp.mint(claims("sub", ""))), "sub");
  }

  private static String enc(String json) {
    return Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(json.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void oidc09Algorithms() {
    Verifier v = verifier();
    assertAuth(() -> v.verify(enc("{\"alg\":\"none\"}") + "." + enc("{}") + "."), "not allowed");
    assertAuth(() -> v.verify(enc("{\"alg\":\"HS256\"}") + ".e30.c2ln"), "HS256 is not allowed");
    assertAuth(() -> v.verify(enc("{}") + ".e30.c2ln"), "(none) is not allowed");
    assertAuth(
        () -> v.verify(enc("{\"alg\":\"" + "A".repeat(40) + "\"}") + ".e30.c2ln"), "not allowed");
    idp.rotate("ES256");
    Verifier rsOnly = builder().algorithms(List.of("RS256")).build();
    assertAuth(() -> rsOnly.verify(idp.mint(Map.of())), "not allowed");
    assertAuth(() -> v.verify("nope"), "malformed token");
    assertAuth(() -> v.verify(null), "malformed token");
    assertAuth(() -> v.verify("!!.e30.c2ln"), "malformed token header");
    assertAuth(() -> v.verify(enc("{\"alg\":\"RS256\"}") + ".!!.c2ln"), "malformed token payload");
    assertAuth(() -> v.verify(enc("{\"alg\":\"RS256\"}") + "." + enc("null") + ".c2ln"), "payload");
  }

  @Test
  void oidc10BadSignature() throws IOException {
    String token = idp.mint(Map.of());
    try (FakeIdp other = FakeIdp.start("app-client", "RS256")) {
      String forged = other.mint(claims("iss", idp.issuer()));
      String[] p = token.split("\\.");
      assertAuth(
          () -> verifier().verify(p[0] + "." + p[1] + "." + forged.split("\\.")[2]), "signature");
    }
  }

  @Test
  void oidc11And12Rotation() {
    MutableClock clock = new MutableClock();
    Verifier v = builder().clock(clock).build();
    v.verify(idp.mint(Map.of()));
    idp.rotate("EdDSA");
    assertAuth(() -> v.verify(idp.mint(Map.of())), "no key matches kid key-2");
    assertThat(idp.hits("/jwks")).isEqualTo(1);
    clock.advance(Duration.ofSeconds(31));
    assertThat(v.verify(idp.mint(Map.of())).sub()).isEqualTo("user-1");
    assertThat(idp.hits("/jwks")).isEqualTo(2);
  }

  @Test
  void oidc13CachingAndNoKid() throws Exception {
    MutableClock clock = new MutableClock();
    Verifier v = builder().clock(clock).build();
    String token = idp.mint(Map.of(), null, Map.of(), 3600);
    List<Thread> threads = new ArrayList<>();
    for (int i = 0; i < 4; i++) {
      Thread t = new Thread(() -> v.verify(token));
      t.start();
      threads.add(t);
    }
    for (Thread t : threads) {
      t.join();
    }
    assertThat(idp.hits("/jwks")).isEqualTo(1);
    clock.advance(Duration.ofMinutes(11));
    v.verify(token);
    v.clearCache();
    v.verify(token);
    assertThat(idp.hits("/jwks")).isEqualTo(3);
    Map<String, Object> noKid = new HashMap<>();
    noKid.put("kid", null);
    assertThat(v.verify(idp.mint(Map.of(), null, noKid, 3600)).sub()).isEqualTo("user-1");
    assertThat(v.verifyAsync(token).get().sub()).isEqualTo("user-1");
    assertThatThrownBy(() -> v.verifyAsync("x").join())
        .isInstanceOf(CompletionException.class)
        .hasCauseInstanceOf(AuthenticationException.class);
  }

  @Test
  void oidc14JwksUrlSkipsDiscovery() {
    builder().jwksUrl(idp.issuer() + "/jwks").build().verify(idp.mint(Map.of()));
    assertThat(idp.hits("/.well-known/openid-configuration")).isZero();
  }

  private static HttpServer serve(String body) throws IOException {
    HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(
        "/",
        ex -> {
          byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
          ex.sendResponseHeaders(200, bytes.length);
          ex.getResponseBody().write(bytes);
          ex.close();
        });
    server.start();
    return server;
  }

  @Test
  void oidc15Unavailable() throws IOException {
    String token = idp.mint(Map.of());
    idp.fail(500);
    assertThatThrownBy(() -> verifier().verify(token))
        .isInstanceOf(UnavailableException.class)
        .hasMessageContaining("HTTP 500");
    Map<String, String> cases =
        Map.of(
            "nope", "not JSON",
            "[1]", "not JSON",
            "{\"issuer\":\"x\"}", "no jwks_uri",
            "{\"jwks_uri\":\"http://127.0.0.1:1/j\"}", "request failed");
    for (Map.Entry<String, String> c : cases.entrySet()) {
      HttpServer s = serve(c.getKey());
      try {
        String url = "http://127.0.0.1:" + s.getAddress().getPort();
        Verifier v = Verifier.builder().issuer(url).audience("a").build();
        assertThatThrownBy(() -> v.verify(token))
            .isInstanceOf(UnavailableException.class)
            .hasMessageContaining(c.getValue());
      } finally {
        s.stop(0);
      }
    }
    HttpServer s = serve("{}");
    try {
      Verifier v =
          builder().jwksUrl("http://127.0.0.1:" + s.getAddress().getPort() + "/jwks").build();
      assertThatThrownBy(() -> v.verify(token)).hasMessageContaining("no keys array");
    } finally {
      s.stop(0);
    }
  }

  @Test
  void oidc15Interrupted() {
    String token = idp.mint(Map.of());
    Thread.currentThread().interrupt();
    assertThatThrownBy(() -> verifier().verify(token))
        .isInstanceOf(codes.grow.packages.oidc.core.CancelledException.class);
    assertThat(Thread.interrupted()).isTrue();
  }

  @Test
  void oidc16RolesClaim() {
    String token =
        idp.mint(claims("realm_access", Map.of("roles", List.of("editor")), "scope", "a b"));
    assertThat(builder().rolesClaim("realm_access.roles").build().verify(token).roles())
        .containsExactly("editor");
    assertThat(builder().rolesClaim("scope").build().verify(token).roles())
        .containsExactly("a", "b");
    assertThat(verifier().verify(token).roles()).isEmpty();
    List<Object> mixed = new ArrayList<>();
    mixed.add(Map.of("code", "b"));
    mixed.add(Map.of("role", "c"));
    mixed.add(Map.of("value", "d"));
    mixed.add(Map.of("x", 1));
    mixed.add(Map.of("name", " "));
    mixed.add(3);
    mixed.add(" ");
    mixed.add("b");
    assertThat(Roles.extract(Map.of("roles", mixed), null)).containsExactly("b", "c", "d");
    assertThat(Roles.extract(Map.of("https://x/roles", List.of("r")), "https://x/roles"))
        .containsExactly("r");
    assertThat(Roles.extract(Map.of("roles", 5), " ")).isEmpty();
    assertThat(Roles.claimAt(Map.of("a", List.of()), "a.b")).isNull();
    assertThat(Roles.claimAt(Map.of("a", Map.of()), "a.b")).isNull();
    assertThat(Roles.hasAny(List.of(), List.of())).isTrue();
    assertThat(Roles.hasAny(List.of("x"), List.of("y"))).isFalse();
  }

  @Test
  void oidc17FromEnv() {
    Map<String, String> env = new HashMap<>();
    env.put("GROW_AUTH_ISSUER", "http://idp:8000");
    env.put("GROW_AUTH_CLIENT_ID", "app");
    env.put("GROW_AUTH_ROLES_CLAIM", "groups");
    Verifier v = Verifier.fromEnv(env);
    assertThat(v.issuer()).isEqualTo("http://idp:8000");
    assertThat(v.audience()).isEqualTo("app");
    assertThat(v.rolesClaim()).isEqualTo("groups");
    assertThat(v.clockSkew()).isEqualTo(Duration.ofSeconds(60));
    env.put("GROW_AUTH_AUDIENCE", "api");
    env.put("GROW_AUTH_JWKS_URL", "http://idp:8000/jwks");
    env.put("GROW_AUTH_CLOCK_SKEW", "5s");
    v = Verifier.fromEnv(env);
    assertThat(v.audience()).isEqualTo("api");
    assertThat(v.clockSkew()).isEqualTo(Duration.ofSeconds(5));
    env.put("GROW_AUTH_CLOCK_SKEW", "soon");
    assertThatThrownBy(() -> Verifier.fromEnv(env)).isInstanceOf(ConfigException.class);
    assertThatThrownBy(() -> Verifier.fromEnv(Map.of()))
        .isInstanceOf(ConfigException.class)
        .hasMessageContaining("GROW_AUTH_ISSUER");
    assertThatThrownBy(() -> Verifier.fromEnv(Map.of("GROW_AUTH_ISSUER", "http://x")))
        .hasMessageContaining("GROW_AUTH_AUDIENCE");
    AtomicReference<Verifier> sys = new AtomicReference<>();
    assertThatThrownBy(() -> sys.set(Verifier.fromEnv())).isInstanceOfAny(ConfigException.class);
    List<Runnable> bad =
        List.of(
            () -> Verifier.builder().audience("a").build(),
            () -> Verifier.builder().issuer("http://x").build(),
            () -> Verifier.builder().issuer("nope").audience("a").build(),
            () -> Verifier.builder().issuer("http://x y").audience("a").build(),
            () -> Verifier.builder().issuer("http://x").audience("a").jwksUrl("ftp://x").build(),
            () -> Verifier.builder().issuer("http://x").audience("a").algorithms(List.of()).build(),
            () ->
                Verifier.builder()
                    .issuer("http://x")
                    .audience("a")
                    .algorithms(List.of("HS256"))
                    .build(),
            () ->
                Verifier.builder()
                    .issuer("http://x")
                    .audience("a")
                    .clockSkew(Duration.ofSeconds(-1))
                    .build());
    for (Runnable r : bad) {
      assertThatThrownBy(r::run).isInstanceOf(ConfigException.class);
    }
    assertThat(
            Verifier.builder()
                .issuer("http://x")
                .audience("a")
                .jwksCacheTtl(Duration.ofMinutes(1))
                .jwksRefreshCooldown(Duration.ZERO)
                .httpTimeout(Duration.ofSeconds(1))
                .httpClient(java.net.http.HttpClient.newHttpClient())
                .build()
                .issuer())
        .isEqualTo("http://x");
  }

  @Test
  void bearerTokens() {
    assertThat(Verifier.bearerToken("Bearer abc")).contains("abc");
    assertThat(Verifier.bearerToken(" bearer  xyz ")).contains("xyz");
    assertThat(Verifier.bearerToken("Basic abc")).isEmpty();
    assertThat(Verifier.bearerToken("Bearer a b")).isEmpty();
    assertThat(Verifier.bearerToken(null)).isEmpty();
  }

  @Test
  void jwksIgnoresUnusableKeys() throws IOException {
    FakeIdp.Key ec = idp.rotate("ES256");
    idp.removeKey(ec.kid());
    Map<String, Object> good = idp.keys().get(0).publicJwk();
    Map<String, Object> enc = new HashMap<>(good);
    enc.put("use", "enc");
    Map<String, Object> wrongAlg = new HashMap<>(good);
    wrongAlg.put("alg", "ES256");
    List<Object> junk =
        List.of(
            "x",
            Map.of("kty", "RSA", "n", "AQAB", "e", "AQAB"),
            Map.of("kty", "RSA"),
            Map.of("kty", "EC", "crv", "P-384", "x", "AA", "y", "AA"),
            Map.of("kty", "EC", "crv", "P-256", "x", "AA", "y", "AA"),
            Map.of("kty", "EC", "crv", "P-256", "x", "A".repeat(43), "y", "A".repeat(43)),
            Map.of("kty", "OKP", "crv", "X25519", "x", "AA"),
            Map.of("kty", "OKP", "crv", "Ed25519", "x", "AA"),
            Map.of("kty", "oct", "k", "AA"),
            enc,
            wrongAlg);
    HttpServer s =
        serve(
            new String(
                codes.grow.packages.oidc.core.Json.encode(Map.of("keys", junk)),
                StandardCharsets.UTF_8));
    try {
      Verifier v = builder().jwksUrl("http://127.0.0.1:" + s.getAddress().getPort()).build();
      assertAuth(
          () -> v.verify(idp.mint(Map.of(), "key-1", Map.of(), 300)), "no key matches kid key-1");
    } finally {
      s.stop(0);
    }
  }
}
