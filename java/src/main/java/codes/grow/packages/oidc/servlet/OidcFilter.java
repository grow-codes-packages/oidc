package codes.grow.packages.oidc.servlet;

import codes.grow.packages.oidc.AuthUser;
import codes.grow.packages.oidc.Verifier;
import codes.grow.packages.oidc.core.OidcException;
import codes.grow.packages.oidc.core.UnavailableException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Optional;

/**
 * Jakarta Servlet filter: verifies the bearer token and exposes the user as the request attribute
 * {@link #USER_ATTRIBUTE}, {@code getUserPrincipal()} and {@code isUserInRole()}.
 *
 * <p>Missing or invalid token → 401, IdP unreachable → 503. {@code publicPaths} (exact paths, or
 * prefixes ending in {@code *}) and {@code optional} let requests without a token through. The
 * response never says why a token was rejected. Requires {@code jakarta.servlet-api} 5+ on the
 * classpath (provided by the container).
 */
public final class OidcFilter implements Filter {
  /** Request attribute holding the {@link AuthUser}. */
  public static final String USER_ATTRIBUTE = "codes.grow.packages.oidc.user";

  /** Default public paths: health checks and API docs. */
  public static final List<String> DEFAULT_PUBLIC_PATHS =
      List.of("/health", "/health/*", "/docs", "/docs/*", "/openapi.json");

  private final Verifier verifier;
  private final boolean optional;
  private final List<String> publicPaths;

  /**
   * Filter that requires a valid token except on {@link #DEFAULT_PUBLIC_PATHS}.
   *
   * @param verifier the verifier
   */
  public OidcFilter(Verifier verifier) {
    this(verifier, false, DEFAULT_PUBLIC_PATHS);
  }

  /**
   * Filter with explicit options.
   *
   * @param verifier the verifier
   * @param optional let requests without a token through anonymously
   * @param publicPaths paths that never require a token
   */
  public OidcFilter(Verifier verifier, boolean optional, List<String> publicPaths) {
    this.verifier = verifier;
    this.optional = optional;
    this.publicPaths = List.copyOf(publicPaths);
  }

  /**
   * Returns the user stored by this filter.
   *
   * @param request the request
   * @return the user, or empty
   */
  public static Optional<AuthUser> user(ServletRequest request) {
    return request.getAttribute(USER_ATTRIBUTE) instanceof AuthUser user
        ? Optional.of(user)
        : Optional.empty();
  }

  static void deny(HttpServletResponse res, int status, String error) throws IOException {
    if (status == 401) {
      res.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
    }
    res.setStatus(status);
    res.setContentType("application/json");
    res.getWriter().write("{\"error\":\"" + error + "\"}");
  }

  private boolean isPublic(String path) {
    for (String pattern : publicPaths) {
      if (pattern.endsWith("*")
          ? path.startsWith(pattern.substring(0, pattern.length() - 1))
          : path.equals(pattern)) {
        return true;
      }
    }
    return false;
  }

  private static String path(HttpServletRequest req) {
    String uri = req.getRequestURI() == null ? "" : req.getRequestURI();
    String context = req.getContextPath() == null ? "" : req.getContextPath();
    return uri.startsWith(context) ? uri.substring(context.length()) : uri;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(request instanceof HttpServletRequest req)
        || !(response instanceof HttpServletResponse res)) {
      chain.doFilter(request, response);
      return;
    }
    boolean pub = isPublic(path(req));
    Optional<String> token = Verifier.bearerToken(req.getHeader("Authorization"));
    if (token.isEmpty()) {
      if (optional || pub) {
        chain.doFilter(request, response);
      } else {
        deny(res, 401, "unauthorized");
      }
      return;
    }
    AuthUser user;
    try {
      user = verifier.verify(token.get());
    } catch (OidcException e) {
      if (pub) {
        chain.doFilter(request, response);
      } else if (e instanceof UnavailableException) {
        deny(res, 503, "auth_unavailable");
      } else {
        deny(res, 401, "unauthorized");
      }
      return;
    }
    req.setAttribute(USER_ATTRIBUTE, user);
    chain.doFilter(new UserRequest(req, user), response);
  }

  /** Exposes the user through the standard servlet security methods. */
  private static final class UserRequest extends HttpServletRequestWrapper {
    private final AuthUser user;

    UserRequest(HttpServletRequest request, AuthUser user) {
      super(request);
      this.user = user;
    }

    @Override
    public Principal getUserPrincipal() {
      return user;
    }

    @Override
    public String getRemoteUser() {
      return user.sub();
    }

    @Override
    public boolean isUserInRole(String role) {
      return user.hasRole(role);
    }

    @Override
    public String getAuthType() {
      return "Bearer";
    }
  }
}
