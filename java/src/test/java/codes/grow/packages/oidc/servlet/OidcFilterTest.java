package codes.grow.packages.oidc.servlet;

import static org.assertj.core.api.Assertions.assertThat;

import codes.grow.packages.oidc.AuthUser;
import codes.grow.packages.oidc.Verifier;
import codes.grow.packages.oidc.oidctest.FakeIdp;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Conformance case OIDC-18 (middleware) for the servlet filters. */
class OidcFilterTest {
  private static FakeIdp idp;
  private static Verifier verifier;

  @BeforeAll
  static void start() throws IOException {
    idp = FakeIdp.start("api", "RS256");
    verifier = Verifier.builder().issuer(idp.issuer()).audience("api").build();
  }

  @AfterAll
  static void stop() {
    idp.close();
  }

  /** Captured response state. */
  static final class Res {
    int status = 200;
    final Map<String, String> headers = new HashMap<>();
    final StringWriter body = new StringWriter();
  }

  static HttpServletRequest request(String path, String authorization) {
    Map<String, Object> attrs = new HashMap<>();
    return (HttpServletRequest)
        Proxy.newProxyInstance(
            OidcFilterTest.class.getClassLoader(),
            new Class<?>[] {HttpServletRequest.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getRequestURI" -> path;
                  case "getContextPath" -> path == null ? null : "";
                  case "getHeader" -> "Authorization".equals(args[0]) ? authorization : null;
                  case "getAttribute" -> attrs.get((String) args[0]);
                  case "setAttribute" -> attrs.put((String) args[0], args[1]);
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                });
  }

  static HttpServletResponse response(Res res) {
    return (HttpServletResponse)
        Proxy.newProxyInstance(
            OidcFilterTest.class.getClassLoader(),
            new Class<?>[] {HttpServletResponse.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "setStatus" -> {
                    res.status = (Integer) args[0];
                    yield null;
                  }
                  case "setHeader" -> res.headers.put((String) args[0], (String) args[1]);
                  case "getWriter" -> new PrintWriter(res.body, true);
                  default -> null;
                });
  }

  /** Runs filters then a terminal handler that records the request it saw. */
  static Res run(
      List<Filter> filters, String path, String auth, AtomicReference<ServletRequest> seen)
      throws Exception {
    Res res = new Res();
    HttpServletResponse response = response(res);
    FilterChain[] chain = new FilterChain[1];
    int[] index = {0};
    chain[0] =
        (req, resp) -> {
          if (index[0] < filters.size()) {
            filters.get(index[0]++).doFilter(req, resp, chain[0]);
          } else {
            seen.set(req);
          }
        };
    chain[0].doFilter(request(path, auth), response);
    return res;
  }

  private static String bearer(String token) {
    return "Bearer " + token;
  }

  @Test
  void requiresAValidToken() throws Exception {
    AtomicReference<ServletRequest> seen = new AtomicReference<>();
    List<Filter> filters = List.of(new OidcFilter(verifier));
    Res none = run(filters, "/data", null, seen);
    assertThat(none.status).isEqualTo(401);
    assertThat(none.headers.get("WWW-Authenticate")).startsWith("Bearer");
    assertThat(none.body.toString()).contains("unauthorized");
    assertThat(run(filters, "/data", "Bearer x.y.z", seen).status).isEqualTo(401);
    assertThat(seen.get()).isNull();
    assertThat(run(filters, "/health", null, seen).status).isEqualTo(200);
    assertThat(run(filters, "/health/check", "Bearer x.y.z", seen).status).isEqualTo(200);
    seen.set(null);
    Res ok = run(filters, "/data", bearer(idp.mint(Map.of("roles", List.of("user")))), seen);
    assertThat(ok.status).isEqualTo(200);
    HttpServletRequest req = (HttpServletRequest) seen.get();
    AuthUser user = OidcFilter.user(req).orElseThrow();
    assertThat(user.sub()).isEqualTo("user-1");
    assertThat(req.getUserPrincipal()).isEqualTo(user);
    assertThat(req.getRemoteUser()).isEqualTo("user-1");
    assertThat(req.isUserInRole("USER")).isTrue();
    assertThat(req.getAuthType()).isEqualTo("Bearer");
    assertThat(OidcFilter.user(request("/", null))).isEmpty();
    assertThat(run(filters, null, null, seen).status).isEqualTo(401);
  }

  @Test
  void optionalAndUnavailable() throws Exception {
    AtomicReference<ServletRequest> seen = new AtomicReference<>();
    Filter optional = new OidcFilter(verifier, true, List.of());
    assertThat(run(List.of(optional), "/data", null, seen).status).isEqualTo(200);
    Verifier down =
        Verifier.builder()
            .issuer(idp.issuer())
            .audience("api")
            .jwksUrl("http://127.0.0.1:1/jwks")
            .build();
    Res res = run(List.of(new OidcFilter(down)), "/data", bearer(idp.mint(Map.of())), seen);
    assertThat(res.status).isEqualTo(503);
    assertThat(res.body.toString()).contains("auth_unavailable");
  }

  @Test
  void requireRoles() throws Exception {
    AtomicReference<ServletRequest> seen = new AtomicReference<>();
    List<Filter> admin = List.of(new OidcFilter(verifier), new RequireRolesFilter("admin"));
    assertThat(run(admin, "/a", bearer(idp.mint(Map.of("roles", List.of("user")))), seen).status)
        .isEqualTo(403);
    assertThat(
            run(
                    admin,
                    "/a",
                    bearer(idp.mint(Map.of("roles", List.of(Map.of("name", "Admin"))))),
                    seen)
                .status)
        .isEqualTo(200);
    assertThat(run(List.of(new RequireRolesFilter()), "/a", null, seen).status).isEqualTo(401);
  }

  @Test
  void passesNonHttpRequests() throws Exception {
    ServletRequest plain =
        (ServletRequest)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {ServletRequest.class},
                (p, m, a) -> null);
    ServletResponse plainRes =
        (ServletResponse)
            Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[] {ServletResponse.class},
                (p, m, a) -> null);
    AtomicReference<Boolean> called = new AtomicReference<>(false);
    new OidcFilter(verifier).doFilter(plain, plainRes, (q, r) -> called.set(true));
    assertThat(called.get()).isTrue();
    called.set(false);
    new RequireRolesFilter("x").doFilter(plain, plainRes, (q, r) -> called.set(true));
    assertThat(called.get()).isTrue();
    called.set(false);
    new OidcFilter(verifier).doFilter(request("/x", null), plainRes, (q, r) -> called.set(true));
    assertThat(called.get()).isTrue();
  }
}
