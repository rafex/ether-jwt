package dev.rafex.ether.test.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenSpec;
import dev.rafex.ether.jwt.VerificationCode;

public class TestTokenIssuerVerifierRsa {

    @Test
    void issueAndVerifyRsaToken() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final KeyPair keyPair = generator.generateKeyPair();

        final JwtConfig issuerConfig = JwtConfig.builder(KeyProvider.rsa(keyPair.getPrivate(), keyPair.getPublic()))
                .expectedIssuer("issuer-rsa").expectedAudience("service-rsa").build();

        final JwtConfig verifierConfig = JwtConfig.builder(KeyProvider.rsaVerifier(keyPair.getPublic()))
                .expectedIssuer("issuer-rsa").expectedAudience("service-rsa").build();

        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(issuerConfig);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(verifierConfig);

        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final String token = issuer.issue(TokenSpec.builder().subject("rsa-user").issuer("issuer-rsa")
                .audience("service-rsa").issuedAt(now).ttl(Duration.ofMinutes(5)).build());

        Assertions.assertTrue(verifier.verify(token, now.plusSeconds(30)).ok());
    }

    @Test
    void rejectsUnsupportedAlgorithm() throws Exception {
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");

        final DefaultTokenIssuer hmacIssuer = new DefaultTokenIssuer(
                JwtConfig.builder(KeyProvider.hmac("hmac-secret")).build());

        final String hmacToken = hmacIssuer.issue(
                TokenSpec.builder().subject("user").issuer("iss").issuedAt(now).ttl(Duration.ofMinutes(5)).build());

        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final KeyPair keyPair = generator.generateKeyPair();

        final DefaultTokenVerifier rsaVerifier = new DefaultTokenVerifier(
                JwtConfig.builder(KeyProvider.rsaVerifier(keyPair.getPublic())).build());

        Assertions.assertEquals(VerificationCode.UNSUPPORTED_ALG,
                rsaVerifier.verify(hmacToken, now).verificationCode());
    }
}
