// Created by sdk-kit 0.3.0; owned by this repository.
package codes.grow.packages.oidc.examples;

import codes.grow.packages.oidc.OidcClient;
import codes.grow.packages.oidc.core.AuthenticationException;
import codes.grow.packages.oidc.core.HealthStatus;
import codes.grow.packages.oidc.core.UnsupportedException;

/** Basics: configuration from the environment, health, ping, server version and errors. */
public final class BasicExample {
  private BasicExample() {}

  /**
   * Runs the example.
   *
   * @param args unused
   */
  public static void main(String[] args) {
    // Reads GROW_OIDC_URL, GROW_OIDC_TOKEN, timeouts, TLS and proxy settings.
    try (var client = OidcClient.fromEnv()) {
      HealthStatus health = client.health(); // never throws for an unreachable service
      System.out.println("health: " + health);
      if (!health.healthy()) {
        return;
      }
      try {
        System.out.println("ping: " + client.ping().toMillis() + " ms");
      } catch (AuthenticationException e) {
        // messages never contain the token
        System.out.println("bad credentials: " + e.getMessage());
      }
      try {
        System.out.println("server version: " + client.serverVersion());
      } catch (UnsupportedException e) {
        System.out.println("the server exposes no version");
      }
    }
  }
}
