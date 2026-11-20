package codes.grow.packages.oidc;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The authenticated user of a verified access token.
 *
 * @param sub the {@code sub} claim
 * @param email the {@code email} claim when present
 * @param name the {@code name} claim, else {@code preferred_username}, when present
 * @param roles role names from the roles claim (strings, or Casdoor-style {@code {name}} objects)
 * @param claims every claim of the token (immutable)
 */
public record AuthUser(
    String sub,
    Optional<String> email,
    Optional<String> name,
    List<String> roles,
    Map<String, Object> claims)
    implements java.security.Principal {

  /**
   * Validates and copies the components.
   *
   * @param sub the subject
   * @param email the e-mail
   * @param name the display name
   * @param roles the role names
   * @param claims every claim
   */
  public AuthUser {
    Objects.requireNonNull(sub, "sub");
    email = email == null ? Optional.empty() : email;
    name = name == null ? Optional.empty() : name;
    roles = List.copyOf(roles);
    claims = Map.copyOf(claims);
  }

  /**
   * Returns whether the user has at least one of {@code required} (case-insensitive).
   *
   * @param required role names; none means any authenticated user
   * @return true when a role matches
   */
  public boolean hasRole(String... required) {
    return Roles.hasAny(roles, List.of(required));
  }

  /**
   * The principal name: the subject.
   *
   * @return {@link #sub()}
   */
  @Override
  public String getName() {
    return sub;
  }
}
