package dev.rafex.ether.test.jwt;

import dev.rafex.ether.jwt.JWebToken;
import dev.rafex.ether.jwt.impl.JWebTokenImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
public class TestJWebTokenHMAC {

    @BeforeAll
    static void beforeAll() {
        System.setProperty("jwt.secret", "test-suite-secret");
    }

    @Test
    void legacyBuilderCreatesValidToken() {
        final JWebToken token = new JWebTokenImpl.Builder()
                .issuer("issuer-legacy")
                .subject("user-123")
                .audience("legacy-api")
                .expirationPlusMinutes(10)
                .build();

        final JWebToken parsed = new JWebTokenImpl(token.toString());
        Assertions.assertTrue(parsed.isValid());
        Assertions.assertEquals("user-123", parsed.getSubject());
        Assertions.assertEquals("issuer-legacy", parsed.getIssuer());
    }

    @Test
    void legacyClaimBridgeWorks() {
        final JWebToken token = new JWebTokenImpl.Builder()
                .subject("user-123")
                .audience("legacy-api")
                .expirationPlusMinutes(10)
                .claim("tenant_id", "tenant-a")
                .build();

        final JWebToken parsed = new JWebTokenImpl(token.toString());
        Assertions.assertTrue(parsed.isValid());
        Assertions.assertEquals("tenant-a", parsed.get("tenant_id"));
    }
}
