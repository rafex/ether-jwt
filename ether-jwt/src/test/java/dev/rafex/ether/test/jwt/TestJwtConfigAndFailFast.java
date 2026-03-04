package dev.rafex.ether.test.jwt;

/*-
 * #%L
 * ether-jwt
 * %%
 * Copyright (C) 2025 - 2026 Raúl Eduardo González Argote
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

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
