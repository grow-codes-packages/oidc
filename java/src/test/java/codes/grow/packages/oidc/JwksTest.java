package codes.grow.packages.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Key/algorithm binding of {@link Jwks.Key} (OIDC-19). */
class JwksTest {
  private static PublicKey ec(String curve) throws GeneralSecurityException {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec(curve));
    return gen.generateKeyPair().getPublic();
  }

  @Test
  void oidc19KeyTypeAndCurveBindTheAlgorithm() throws GeneralSecurityException {
    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
    rsaGen.initialize(2048);
    Jwks.Key rsa = new Jwks.Key("r", null, null, null, rsaGen.generateKeyPair().getPublic());
    Jwks.Key p256 = new Jwks.Key("a", null, null, "P-256", ec("secp256r1"));
    Jwks.Key p384 = new Jwks.Key("b", null, null, "P-384", ec("secp384r1"));
    Jwks.Key p521 = new Jwks.Key("c", null, null, "P-521", ec("secp521r1"));
    Jwks.Key ed =
        new Jwks.Key(
            "d",
            null,
            null,
            "Ed25519",
            KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic());
    Jwks.Key edWrongCrv = new Jwks.Key("e", null, null, "Ed448", ed.key());
    List<String> all = Verifier.DEFAULT_ALGORITHMS;
    for (String alg : all) {
      boolean rsaAlg = alg.startsWith("RS") || alg.startsWith("PS");
      assertThat(rsa.compatible(alg)).as("RSA %s", alg).isEqualTo(rsaAlg);
      assertThat(p256.compatible(alg)).as("P-256 %s", alg).isEqualTo(alg.equals("ES256"));
      assertThat(p384.compatible(alg)).as("P-384 %s", alg).isEqualTo(alg.equals("ES384"));
      assertThat(p521.compatible(alg)).as("P-521 %s", alg).isEqualTo(alg.equals("ES512"));
      assertThat(ed.compatible(alg)).as("Ed25519 %s", alg).isEqualTo(alg.equals("EdDSA"));
      assertThat(edWrongCrv.compatible(alg)).isFalse();
    }
    for (String alg : List.of("none", "HS256", "HS384", "HS512", "ES256K", "")) {
      assertThat(rsa.compatible(alg)).isFalse();
      assertThat(p256.compatible(alg)).isFalse();
      assertThat(ed.compatible(alg)).isFalse();
    }
    Jwks.Key declared = new Jwks.Key("f", "RS256", "sig", null, rsa.key());
    assertThat(declared.compatible("RS256")).isTrue();
    assertThat(declared.compatible("PS256")).isFalse();
    assertThat(new Jwks.Key("g", null, "enc", null, rsa.key()).compatible("RS256")).isFalse();
    // A P-256 key wrongly labelled P-384 never verifies an ES384 signature.
    Jwks.Key lying = new Jwks.Key("h", null, null, "P-384", p256.key());
    byte[] data = "x".getBytes(StandardCharsets.US_ASCII);
    assertThat(lying.verify("ES384", data, new byte[96])).isFalse();
    assertThat(rsa.verify("HS256", data, new byte[256])).isFalse();
  }

  @Test
  void signatureRejectsUnknownAlgorithms() throws GeneralSecurityException {
    for (String alg : Verifier.DEFAULT_ALGORITHMS) {
      assertThat(Jwks.signature(alg)).isNotNull();
    }
    for (String alg : List.of("none", "HS256", "RSA-OAEP")) {
      assertThatThrownBy(() -> Jwks.signature(alg)).isInstanceOf(NoSuchAlgorithmException.class);
    }
  }
}
