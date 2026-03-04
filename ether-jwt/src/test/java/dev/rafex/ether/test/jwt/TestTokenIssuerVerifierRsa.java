package dev.rafex.ether.test.jwt;

import dev.rafex.ether.jwt.DefaultTokenIssuer;
import dev.rafex.ether.jwt.DefaultTokenVerifier;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.VerificationCode;
import dev.rafex.ether.jwt.TokenSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;

public class TestTokenIssuerVerifierRsa {

    @Test
    void issueAndVerifyRsaToken() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final KeyPair keyPair = generator.generateKeyPair();

        final JwtConfig issuerConfig = JwtConfig.builder(KeyProvider.rsa(keyPair.getPrivate(), keyPair.getPublic()))
                .expectedIssuer("issuer-rsa")
                .expectedAudience("service-rsa")
                .build();

        final JwtConfig verifierConfig = JwtConfig.builder(KeyProvider.rsaVerifier(keyPair.getPublic()))
                .expectedIssuer("issuer-rsa")
                .expectedAudience("service-rsa")
                .build();

        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(issuerConfig);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(verifierConfig);

        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final String token = issuer.issue(TokenSpec.builder()
                .subject("rsa-user")
                .issuer("issuer-rsa")
                .audience("service-rsa")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .build());

        Assertions.assertTrue(verifier.verify(token, now.plusSeconds(30)).ok());
    }

    @Test
    void rejectsUnsupportedAlgorithm() throws Exception {
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");

        final DefaultTokenIssuer hmacIssuer = new DefaultTokenIssuer(
                JwtConfig.builder(KeyProvider.hmac("hmac-secret")).build());

        final String hmacToken = hmacIssuer.issue(TokenSpec.builder()
                .subject("user")
                .issuer("iss")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .build());

        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        final KeyPair keyPair = generator.generateKeyPair();

        final DefaultTokenVerifier rsaVerifier = new DefaultTokenVerifier(
                JwtConfig.builder(KeyProvider.rsaVerifier(keyPair.getPublic())).build());

        Assertions.assertEquals(VerificationCode.UNSUPPORTED_ALG, rsaVerifier.verify(hmacToken, now).verificationCode());
    }
}
