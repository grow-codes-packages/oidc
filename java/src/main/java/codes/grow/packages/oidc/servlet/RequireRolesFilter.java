package codes.grow.packages.oidc.servlet;

import codes.grow.packages.oidc.AuthUser;
import codes.grow.packages.oidc.Roles;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Servlet filter placed after {@link OidcFilter}: 401 without a user, 403 unless the user has at
 * least one of the roles (case-insensitive). No roles = any authenticated user.
 */
public final class RequireRolesFilter implements Filter {
  private final List<String> roles;

  /**
   * Creates the filter.
   *
   * @param roles accepted roles
   */
  public RequireRolesFilter(String... roles) {
    this.roles = List.of(roles);
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (!(response instanceof HttpServletResponse res)) {
      chain.doFilter(request, response);
      return;
    }
    Optional<AuthUser> user = OidcFilter.user(request);
    if (user.isEmpty()) {
      OidcFilter.deny(res, 401, "unauthorized");
    } else if (!Roles.hasAny(user.get().roles(), roles)) {
      OidcFilter.deny(res, 403, "forbidden");
    } else {
      chain.doFilter(request, response);
    }
  }
}
