package codes.grow.packages.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
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
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * JWK parsing and JWS signature checks with the JDK only (RS256/384/512, PS256/384/512,
 * ES256/384/512, EdDSA).
 */
final class Jwks {
  private static final Base64.Decoder B64 = Base64.getUrlDecoder();

  private Jwks() {}

  /**
   * One parsed public key.
   *
   * @param kid key id, may be null
   * @param alg declared algorithm, may be null
   * @param use declared use, may be null
   * @param crv curve of an EC or OKP key ({@code P-256}, {@code P-384}, {@code P-521}, {@code
   *     Ed25519}), null for RSA
   * @param key the public key
   */
  record Key(String kid, String alg, String use, String crv, PublicKey key) {
    boolean compatible(String wanted) {
      if ("enc".equals(use) || (alg != null && !alg.equals(wanted))) {
        return false;
      }
      return switch (wanted) {
        case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" -> key instanceof RSAPublicKey;
        case "ES256" -> key instanceof ECPublicKey && "P-256".equals(crv);
        case "ES384" -> key instanceof ECPublicKey && "P-384".equals(crv);
        case "ES512" -> key instanceof ECPublicKey && "P-521".equals(crv);
        case "EdDSA" -> key instanceof EdECPublicKey && "Ed25519".equals(crv);
        default -> false;
      };
    }

    boolean verify(String wanted, byte[] signed, byte[] signature) {
      try {
        Signature verifier = signature(wanted);
        verifier.initVerify(key);
        verifier.update(signed);
        return verifier.verify(signature);
      } catch (GeneralSecurityException | IllegalArgumentException e) {
        return false;
      }
    }
  }

  /**
   * A JCA {@link Signature} for a JWS algorithm.
   *
   * @param alg the JWS algorithm
   * @return the uninitialised signature
   * @throws GeneralSecurityException when the algorithm is unknown or unavailable
   */
  static Signature signature(String alg) throws GeneralSecurityException {
    return switch (alg) {
      case "RS256" -> Signature.getInstance("SHA256withRSA");
      case "RS384" -> Signature.getInstance("SHA384withRSA");
      case "RS512" -> Signature.getInstance("SHA512withRSA");
      case "PS256" -> pss("SHA-256", MGF1ParameterSpec.SHA256, 32);
      case "PS384" -> pss("SHA-384", MGF1ParameterSpec.SHA384, 48);
      case "PS512" -> pss("SHA-512", MGF1ParameterSpec.SHA512, 64);
      case "ES256" -> Signature.getInstance("SHA256withECDSAinP1363Format");
      case "ES384" -> Signature.getInstance("SHA384withECDSAinP1363Format");
      case "ES512" -> Signature.getInstance("SHA512withECDSAinP1363Format");
      case "EdDSA" -> Signature.getInstance("Ed25519");
      default -> throw new NoSuchAlgorithmException("unsupported JWS algorithm");
    };
  }

  private static Signature pss(String hash, MGF1ParameterSpec mgf, int saltLength)
      throws GeneralSecurityException {
    Signature signature = Signature.getInstance("RSASSA-PSS");
    signature.setParameter(new PSSParameterSpec(hash, "MGF1", mgf, saltLength, 1));
    return signature;
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
          : Optional.of(
              new Key(
                  text(node, "kid"),
                  text(node, "alg"),
                  text(node, "use"),
                  "RSA".equals(text(node, "kty")) ? null : text(node, "crv"),
                  key));
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
        String curve;
        int size;
        if ("P-256".equals(crv)) {
          curve = "secp256r1";
          size = 32;
        } else if ("P-384".equals(crv)) {
          curve = "secp384r1";
          size = 48;
        } else if ("P-521".equals(crv)) {
          curve = "secp521r1";
          size = 66;
        } else {
          return null;
        }
        byte[] x = decode(text(node, "x"));
        byte[] y = decode(text(node, "y"));
        if (x.length != size || y.length != size) {
          return null;
        }
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curve));
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
