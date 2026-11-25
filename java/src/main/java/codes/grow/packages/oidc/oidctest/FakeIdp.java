package codes.grow.packages.oidc.oidctest;

import codes.grow.packages.oidc.core.Json;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A local fake OpenID provider for tests: serves {@code /.well-known/openid-configuration} and
 * {@code /jwks} on 127.0.0.1, mints signed tokens (RS256/384/512, PS256/384/512, ES256/384/512,
 * EdDSA) and rotates keys. Never use it outside tests.
 */
public final class FakeIdp implements AutoCloseable {
  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  private static final List<String> ALGORITHMS =
      List.of(
          "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA");

  /**
   * One signing key.
   *
   * @param kid key id
   * @param alg algorithm
   * @param privateKey the private key
   * @param publicJwk the published JWK
   */
  public record Key(String kid, String alg, PrivateKey privateKey, Map<String, Object> publicJwk) {}

  private final HttpServer server;
  private final String issuer;
  private final String audience;
  private final List<Key> keys = new ArrayList<>();
  private final Map<String, Integer> hits = new ConcurrentHashMap<>();
  private volatile int failStatus;
  private String current;
  private int counter;

  private FakeIdp(String audience) throws IOException {
    this.audience = audience;
    this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    this.issuer = "http://127.0.0.1:" + server.getAddress().getPort();
    server.createContext(
        "/",
        exchange -> {
          String path = exchange.getRequestURI().getPath();
          hits.merge(path, 1, Integer::sum);
          byte[] body = null;
          int status = failStatus;
          if (status == 0) {
            if (path.equals("/.well-known/openid-configuration")) {
              body =
                  Json.encode(
                      Map.of(
                          "issuer",
                          issuer,
                          "jwks_uri",
                          issuer + "/jwks",
                          "id_token_signing_alg_values_supported",
                          ALGORITHMS));
            } else if (path.equals("/jwks")) {
              body = Json.encode(Map.of("keys", publicKeys()));
            }
            status = body == null ? 404 : 200;
          }
          exchange.getResponseHeaders().set("Content-Type", "application/json");
          exchange.sendResponseHeaders(status, body == null ? -1 : body.length);
          if (body != null) {
            try (OutputStream out = exchange.getResponseBody()) {
              out.write(body);
            }
          }
          exchange.close();
        });
    server.start();
  }

  /**
   * Starts a fake IdP with one key.
   *
   * @param audience the {@code aud} of minted tokens
   * @param alg RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512 or EdDSA (anything
   *     else: RS256)
   * @return the started IdP
   * @throws IOException when the server cannot bind
   */
  public static FakeIdp start(String audience, String alg) throws IOException {
    FakeIdp idp = new FakeIdp(audience);
    idp.rotate(alg);
    return idp;
  }

  private synchronized List<Map<String, Object>> publicKeys() {
    return keys.stream().map(Key::publicJwk).toList();
  }

  /**
   * The issuer URL.
   *
   * @return the issuer
   */
  public String issuer() {
    return issuer;
  }

  /**
   * How often a path was requested.
   *
   * @param path the path
   * @return the count
   */
  public int hits(String path) {
    return hits.getOrDefault(path, 0);
  }

  /**
   * Makes every response use {@code status} (0 = normal).
   *
   * @param status the status
   */
  public void fail(int status) {
    this.failStatus = status;
  }

  /**
   * The published keys.
   *
   * @return a copy of the keys
   */
  public synchronized List<Key> keys() {
    return List.copyOf(keys);
  }

  private static String unsigned(BigInteger value) {
    byte[] bytes = value.toByteArray();
    if (bytes.length > 1 && bytes[0] == 0) {
      bytes = java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
    }
    return B64.encodeToString(bytes);
  }

  private static byte[] fixed(BigInteger value, int size) {
    byte[] raw = value.toByteArray();
    byte[] out = new byte[size];
    int n = Math.min(raw.length, size);
    System.arraycopy(raw, raw.length - n, out, size - n, n);
    return out;
  }

  /**
   * Adds a new current key; older keys stay published until {@link #removeKey}.
   *
   * @param alg RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512 or EdDSA (anything
   *     else: RS256)
   * @return the key
   */
  public synchronized Key rotate(String alg) {
    counter++;
    String kid = "key-" + counter;
    Map<String, Object> jwk = new LinkedHashMap<>();
    KeyPair pair;
    try {
      switch (alg) {
        case "ES256", "ES384", "ES512" -> {
          int bits = Integer.parseInt(alg.substring(2));
          int size = bits == 512 ? 66 : bits / 8;
          String crv = bits == 512 ? "P-521" : "P-" + bits;
          KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
          gen.initialize(new ECGenParameterSpec(bits == 512 ? "secp521r1" : "secp" + bits + "r1"));
          pair = gen.generateKeyPair();
          ECPublicKey pub = (ECPublicKey) pair.getPublic();
          jwk.put("kty", "EC");
          jwk.put("crv", crv);
          jwk.put("x", B64.encodeToString(fixed(pub.getW().getAffineX(), size)));
          jwk.put("y", B64.encodeToString(fixed(pub.getW().getAffineY(), size)));
        }
        case "EdDSA" -> {
          pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
          EdECPublicKey pub = (EdECPublicKey) pair.getPublic();
          byte[] le = new byte[32];
          byte[] be = fixed(pub.getPoint().getY(), 32);
          for (int i = 0; i < 32; i++) {
            le[i] = be[31 - i];
          }
          if (pub.getPoint().isXOdd()) {
            le[31] |= (byte) 0x80;
          }
          jwk.put("kty", "OKP");
          jwk.put("crv", "Ed25519");
          jwk.put("x", B64.encodeToString(le));
        }
        default -> {
          if (!ALGORITHMS.subList(0, 6).contains(alg)) { // RS256 … PS512
            alg = "RS256";
          }
          KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
          gen.initialize(2048);
          pair = gen.generateKeyPair();
          RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
          jwk.put("kty", "RSA");
          jwk.put("n", unsigned(pub.getModulus()));
          jwk.put("e", unsigned(pub.getPublicExponent()));
        }
      }
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
    jwk.put("kid", kid);
    jwk.put("alg", alg);
    jwk.put("use", "sig");
    Key key = new Key(kid, alg, pair.getPrivate(), Map.copyOf(jwk));
    keys.add(key);
    current = kid;
    return key;
  }

  /**
   * Stops publishing a key.
   *
   * @param kid the key id
   */
  public synchronized void removeKey(String kid) {
    keys.removeIf(k -> k.kid().equals(kid));
  }

  /**
   * Mints a token with the current key and a 5 minute lifetime.
   *
   * @param claims claims merged over iss/aud/sub/iat/exp; a null value removes a claim
   * @return the token
   */
  public String mint(Map<String, Object> claims) {
    return mint(claims, null, Map.of(), 300);
  }

  /**
   * Mints a token.
   *
   * @param claims claims merged over iss/aud/sub/iat/exp; a null value removes a claim
   * @param kid signing key id (null = current)
   * @param header header overrides; a null value removes a field (e.g. kid)
   * @param ttlSeconds lifetime
   * @return the token
   */
  public synchronized String mint(
      Map<String, Object> claims, String kid, Map<String, Object> header, long ttlSeconds) {
    String use = kid == null ? current : kid;
    Key key =
        keys.stream()
            .filter(k -> k.kid().equals(use))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("fake idp: unknown kid " + use));
    long now = System.currentTimeMillis() / 1000;
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("iss", issuer);
    payload.put("aud", audience);
    payload.put("sub", "user-1");
    payload.put("iat", now);
    payload.put("exp", now + ttlSeconds);
    payload.putAll(claims);
    payload.values().removeIf(java.util.Objects::isNull);
    Map<String, Object> head = new LinkedHashMap<>();
    head.put("alg", key.alg());
    head.put("typ", "JWT");
    head.put("kid", key.kid());
    head.putAll(header);
    head.values().removeIf(java.util.Objects::isNull);
    String signed =
        B64.encodeToString(Json.encode(head)) + "." + B64.encodeToString(Json.encode(payload));
    return signed + "." + B64.encodeToString(sign(key, signed.getBytes(StandardCharsets.US_ASCII)));
  }

  /**
   * Signs data in JWS form with a key.
   *
   * @param key the key
   * @param data the signing input
   * @return the signature
   */
  public static byte[] sign(Key key, byte[] data) {
    try {
      Signature signer = signature(key.alg());
      signer.initSign(key.privateKey());
      signer.update(data);
      return signer.sign();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static Signature signature(String alg) throws GeneralSecurityException {
    return switch (alg) {
      case "ES256", "ES384", "ES512" ->
          Signature.getInstance("SHA" + alg.substring(2) + "withECDSAinP1363Format");
      case "EdDSA" -> Signature.getInstance("Ed25519");
      case "PS256", "PS384", "PS512" -> {
        String hash = "SHA-" + alg.substring(2);
        Signature pss = Signature.getInstance("RSASSA-PSS");
        pss.setParameter(
            new PSSParameterSpec(
                hash,
                "MGF1",
                new MGF1ParameterSpec(hash),
                Integer.parseInt(alg.substring(2)) / 8,
                1));
        yield pss;
      }
      default -> Signature.getInstance("SHA" + alg.substring(2) + "withRSA");
    };
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
