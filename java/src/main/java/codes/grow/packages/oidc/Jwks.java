package codes.grow.packages.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/** JWK parsing and JWS signature checks with the JDK only (RS256, ES256, EdDSA). */
final class Jwks {
  private static final Base64.Decoder B64 = Base64.getUrlDecoder();

  private Jwks() {}

  /**
   * One parsed public key.
   *
   * @param kid key id, may be null
   * @param alg declared algorithm, may be null
   * @param use declared use, may be null
   * @param key the public key
   */
  record Key(String kid, String alg, String use, PublicKey key) {
    boolean compatible(String wanted) {
      if ("enc".equals(use) || (alg != null && !alg.equals(wanted))) {
        return false;
      }
      return switch (wanted) {
        case "RS256" -> key instanceof RSAPublicKey;
        case "ES256" -> key instanceof ECPublicKey;
        default -> key instanceof EdECPublicKey;
      };
    }

    boolean verify(String wanted, byte[] signed, byte[] signature) {
      String jca =
          switch (wanted) {
            case "RS256" -> "SHA256withRSA";
            case "ES256" -> "SHA256withECDSAinP1363Format";
            default -> "Ed25519";
          };
      try {
        Signature verifier = Signature.getInstance(jca);
        verifier.initVerify(key);
        verifier.update(signed);
        return verifier.verify(signature);
      } catch (GeneralSecurityException | IllegalArgumentException e) {
        return false;
      }
    }
  }

  static byte[] decode(String text) {
    return B64.decode(text.replace("=", ""));
  }

  private static String text(JsonNode node, String field) {
    JsonNode value = node.get(field);
    return value != null && value.isTextual() ? value.asText() : null;
  }

  /**
   * Parses every usable key of a JWKS {@code keys} array; unusable keys are skipped.
   *
   * @param keys the array
   * @return the keys
   */
  static List<Key> parse(JsonNode keys) {
    List<Key> out = new ArrayList<>();
    for (JsonNode node : keys) {
      parseKey(node).ifPresent(out::add);
    }
    return out;
  }

  static Optional<Key> parseKey(JsonNode node) {
    if (!node.isObject()) {
      return Optional.empty();
    }
    try {
      PublicKey key = publicKey(node);
      return key == null
          ? Optional.empty()
          : Optional.of(new Key(text(node, "kid"), text(node, "alg"), text(node, "use"), key));
    } catch (GeneralSecurityException | IllegalArgumentException | NullPointerException e) {
      return Optional.empty();
    }
  }

  private static PublicKey publicKey(JsonNode node) throws GeneralSecurityException {
    String kty = String.valueOf(text(node, "kty"));
    String crv = text(node, "crv");
    switch (kty) {
      case "RSA" -> {
        byte[] n = decode(text(node, "n"));
        if (n.length < 256) {
          return null; // at least 2048-bit keys
        }
        BigInteger e = new BigInteger(1, decode(text(node, "e")));
        return KeyFactory.getInstance("RSA")
            .generatePublic(new RSAPublicKeySpec(new BigInteger(1, n), e));
      }
      case "EC" -> {
        if (!"P-256".equals(crv)) {
          return null;
        }
        byte[] x = decode(text(node, "x"));
        byte[] y = decode(text(node, "y"));
        if (x.length != 32 || y.length != 32) {
          return null;
        }
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
      }
      case "OKP" -> {
        if (!"Ed25519".equals(crv)) {
          return null;
        }
        byte[] x = decode(text(node, "x"));
        if (x.length != 32) {
          return null;
        }
        boolean xOdd = (x[31] & 0x80) != 0;
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) {
          be[i] = x[31 - i];
        }
        be[0] &= 0x7f;
        EdECPoint point = new EdECPoint(xOdd, new BigInteger(1, be));
        return KeyFactory.getInstance("Ed25519")
            .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
      }
      default -> {
        return null;
      }
    }
  }
}
