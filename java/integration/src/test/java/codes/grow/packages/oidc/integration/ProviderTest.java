package codes.grow.packages.oidc.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import codes.grow.packages.oidc.AuthUser;
import codes.grow.packages.oidc.OidcClient;
import codes.grow.packages.oidc.Verifier;
import codes.grow.packages.oidc.core.AuthenticationException;
import codes.grow.packages.oidc.core.EnvReader;
import codes.grow.packages.oidc.core.UnsupportedException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Verifies a real Casdoor access token (minted by docker/bootstrap) through discovery + JWKS and
 * checks the client against the provider.
 */
class ProviderTest {
  private static Map<String, String> env;

  @BeforeAll
  static void load() throws IOException {
    env = ConformanceTest.environment();
    assumeTrue(env.containsKey("GROW_OIDC_TOKEN"), "GROW_OIDC_TOKEN is not set; use docker");
  }

  @Test
  void verifierFromEnvVerifiesARealToken() {
    String token = env.get("GROW_OIDC_TOKEN");
    Verifier verifier = Verifier.fromEnv(env);
    AuthUser user = verifier.verify(token);
    assertEquals(env.get("GROW_OIDC_IT_SUB"), user.sub());
    assertEquals(env.get("GROW_OIDC_IT_EMAIL"), user.email().orElse(""));
    assertTrue(user.hasRole(env.get("GROW_OIDC_IT_ROLE")), user.roles().toString());
    assertEquals(env.get("GROW_AUTH_ISSUER"), user.claims().get("iss"));
    int dot = token.lastIndexOf('.');
    String sig = token.substring(dot + 1);
    String tampered = token.substring(0, dot + 1) + (sig.startsWith("A") ? "B" : "A") + sig.substring(1);
    assertThrows(AuthenticationException.class, () -> verifier.verify(tampered));
    Map<String, String> other = new HashMap<>(env);
    other.put("GROW_AUTH_AUDIENCE", "someone-else");
    assertThrows(AuthenticationException.class, () -> Verifier.fromEnv(other).verify(token));
  }

  @Test
  void clientAgainstTheProvider() {
    try (OidcClient c = OidcClient.builder().fromEnv(EnvReader.of(env)).build()) {
      assertTrue(c.health().healthy());
      assertFalse(c.ping().isNegative());
      assertThrows(UnsupportedException.class, c::serverVersion);
    }
    Map<String, String> wrong = new HashMap<>(env);
    wrong.put("GROW_OIDC_TOKEN", "wrong-token-for-integration");
    try (OidcClient c = OidcClient.builder().fromEnv(EnvReader.of(wrong)).build()) {
      AuthenticationException e = assertThrows(AuthenticationException.class, c::ping);
      assertFalse(e.getMessage().contains("wrong-token"));
    }
  }
}
