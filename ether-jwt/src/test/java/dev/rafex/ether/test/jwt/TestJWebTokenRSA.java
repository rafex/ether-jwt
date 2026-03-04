package dev.rafex.ether.test.jwt;

import dev.rafex.ether.jwt.JWebToken;
import dev.rafex.ether.jwt.impl.JWebTokenImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
public class TestJWebTokenRSA {

    @BeforeAll
    static void beforeAll() {
        System.setProperty("jwt.secret", "test-suite-secret");
    }

    @Test
    void legacyTokenHasJwtHeader() {
        final JWebToken token = new JWebTokenImpl.Builder()
                .subject("legacy-rsa-name-test")
                .audience("legacy-api")
                .expirationPlusMinutes(5)
                .build();

        final JWebToken parsed = new JWebTokenImpl(token.toString());
        final String header = new String(java.util.Base64.getUrlDecoder().decode(parsed.getEncodedHeader()), java.nio.charset.StandardCharsets.UTF_8);

        Assertions.assertTrue(parsed.isValid());
        Assertions.assertTrue(header.contains("\"typ\":\"JWT\""));
    }

    @Test
    void legacyInvalidFormatThrows() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new JWebTokenImpl("broken-token"));
    }
}
