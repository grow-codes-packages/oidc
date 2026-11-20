package codes.grow.packages.oidc;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Roles extraction shared by the verifier and the servlet filters. */
public final class Roles {
  private static final List<String> OBJECT_KEYS = List.of("name", "code", "role", "value");

  private Roles() {}

  /**
   * Returns the value at a claim name ({@code roles}) or dotted path ({@code realm_access.roles});
   * an exact top-level match wins.
   *
   * @param claims the claims
   * @param path claim name or dotted path
   * @return the value, or null
   */
  public static Object claimAt(Map<String, ?> claims, String path) {
    if (claims.containsKey(path)) {
      return claims.get(path);
    }
    Object current = claims;
    for (String part : path.split("\\.", -1)) {
      if (!(current instanceof Map<?, ?> map) || !map.containsKey(part)) {
        return null;
      }
      current = map.get(part);
    }
    return current;
  }

  private static String roleName(Object entry) {
    if (entry instanceof String s) {
      return s.trim();
    }
    if (entry instanceof Map<?, ?> map) {
      for (String key : OBJECT_KEYS) {
        if (map.get(key) instanceof String s && !s.isBlank()) {
          return s.trim();
        }
      }
    }
    return "";
  }

  /**
   * Extracts role names: a string is split on commas and whitespace; a list yields each string, or
   * each object's {@code name} (Casdoor), {@code code}, {@code role} or {@code value}. Duplicates
   * are removed, order is kept.
   *
   * @param claims the claims
   * @param rolesClaim claim name or dotted path (null or blank = {@code roles})
   * @return the role names (never null)
   */
  public static List<String> extract(Map<String, ?> claims, String rolesClaim) {
    String path = rolesClaim == null || rolesClaim.isBlank() ? "roles" : rolesClaim;
    Object raw = claimAt(claims, path);
    List<String> names = new ArrayList<>();
    if (raw instanceof String s) {
      names.addAll(List.of(s.split("[\\s,]+")));
    } else if (raw instanceof Collection<?> list) {
      for (Object entry : list) {
        names.add(roleName(entry));
      }
    }
    List<String> out = new ArrayList<>();
    for (String name : names) {
      if (!name.isEmpty() && !out.contains(name)) {
        out.add(name);
      }
    }
    return List.copyOf(out);
  }

  /**
   * Returns whether {@code have} contains at least one of {@code required} (case-insensitive).
   *
   * @param have the user's roles
   * @param required wanted roles; empty means any authenticated user
   * @return true on a match
   */
  public static boolean hasAny(Collection<String> have, Collection<String> required) {
    if (required.isEmpty()) {
      return true;
    }
    Set<String> lower =
        have.stream().map(r -> r.toLowerCase(Locale.ROOT)).collect(Collectors.toSet());
    return required.stream().anyMatch(r -> lower.contains(r.toLowerCase(Locale.ROOT)));
  }
}
