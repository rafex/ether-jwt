package dev.rafex.ether.test.jwt;

import dev.rafex.ether.jwt.DefaultTokenIssuer;
import dev.rafex.ether.jwt.DefaultTokenVerifier;
import dev.rafex.ether.jwt.JwtAlgorithm;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;

public class TestJwtConfigAndFailFast {

    @Test
    void tokenSpecRequiresSubjectAndExpiry() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> TokenSpec.builder()
                .issuer("iss")
                .ttl(Duration.ofMinutes(5))
                .build());

        Assertions.assertThrows(IllegalArgumentException.class, () -> TokenSpec.builder()
                .subject("sub")
                .issuer("iss")
                .build());

        Assertions.assertThrows(IllegalArgumentException.class, () -> TokenSpec.builder()
                .subject("sub")
                .issuer("iss")
                .ttl(Duration.ZERO)
                .build());
    }

    @Test
    void jwtConfigRejectsNegativeClockSkew() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> JwtConfig.builder(KeyProvider.hmac("secret"))
                .clockSkew(Duration.ofSeconds(-1))
                .build());
    }

    @Test
    void issuerAndVerifierFailFastWithInvalidKeyProvider() {
        final KeyProvider badHsProvider = new KeyProvider() {
            @Override
            public JwtAlgorithm algorithm() {
                return JwtAlgorithm.HS256;
            }

            @Override
            public byte[] hmacSecret() {
                return null;
            }

            @Override
            public PrivateKey privateKey() {
                return null;
            }

            @Override
            public PublicKey publicKey() {
                return null;
            }
        };

        final JwtConfig hsConfig = JwtConfig.builder(badHsProvider).build();
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DefaultTokenIssuer(hsConfig));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DefaultTokenVerifier(hsConfig));

        final KeyProvider badRsProvider = new KeyProvider() {
            @Override
            public JwtAlgorithm algorithm() {
                return JwtAlgorithm.RS256;
            }

            @Override
            public byte[] hmacSecret() {
                return null;
            }

            @Override
            public PrivateKey privateKey() {
                return null;
            }

            @Override
            public PublicKey publicKey() {
                return null;
            }
        };

        final JwtConfig rsConfig = JwtConfig.builder(badRsProvider).build();
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DefaultTokenIssuer(rsConfig));
        Assertions.assertThrows(IllegalArgumentException.class, () -> new DefaultTokenVerifier(rsConfig));
    }
}
