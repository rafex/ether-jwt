package dev.rafex.ether.test.jwt;

import dev.rafex.ether.jwt.DefaultTokenIssuer;
import dev.rafex.ether.jwt.DefaultTokenVerifier;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenSpec;
import dev.rafex.ether.jwt.TokenType;
import dev.rafex.ether.jwt.VerificationCode;
import dev.rafex.ether.jwt.VerificationResult;
import dev.rafex.ether.jwt.internal.JwtCodec;
import dev.rafex.ether.jwt.internal.JwtSigner;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

public class TestJwtValidationScenarios {

    @Test
    void missingSubjectCanBeRequiredOrOptional() {
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final JwtConfig signingConfig = JwtConfig.builder(KeyProvider.hmac("secret")).build();
        final String encodedHeader = JwtCodec.encodeHeader("HS256");
        final String encodedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("{\"iss\":\"iss\",\"iat\":" + now.getEpochSecond() + ",\"exp\":" + now.plusSeconds(300).getEpochSecond() + "}")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        final String signingInput = encodedHeader + "." + encodedPayload;
        final String signature = JwtSigner.sign(signingInput, signingConfig);
        final String missingSubToken = signingInput + "." + signature;

        final DefaultTokenVerifier requiredSubVerifier = new DefaultTokenVerifier(JwtConfig.builder(KeyProvider.hmac("secret")).requireSubject(true).build());
        Assertions.assertEquals(VerificationCode.MISSING_SUB, requiredSubVerifier.verify(missingSubToken, now).verificationCode());

        final DefaultTokenVerifier optionalSubVerifier = new DefaultTokenVerifier(JwtConfig.builder(KeyProvider.hmac("secret")).requireSubject(false).build());
        Assertions.assertTrue(optionalSubVerifier.verify(missingSubToken, now).ok());
    }

    @Test
    void tokenTypeValidationAndClientIdRules() {
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final JwtConfig config = JwtConfig.builder(KeyProvider.hmac("secret")).build();
        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(config);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);

        final String badTokenType = issuer.issue(TokenSpec.builder()
                .subject("u1")
                .issuer("iss")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .claim("token_type", "robot")
                .build());
        Assertions.assertEquals(VerificationCode.BAD_TOKEN_TYPE, verifier.verify(badTokenType, now).verificationCode());

        final String appWithoutClient = issuer.issue(TokenSpec.builder()
                .subject("service-a")
                .issuer("iss")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .tokenType(TokenType.APP)
                .build());
        Assertions.assertEquals(VerificationCode.MISSING_CLIENT_ID, verifier.verify(appWithoutClient, now).verificationCode());

        final DefaultTokenVerifier relaxedVerifier = new DefaultTokenVerifier(
                JwtConfig.builder(KeyProvider.hmac("secret"))
                        .requireClientIdForAppTokens(false)
                        .build());
        Assertions.assertTrue(relaxedVerifier.verify(appWithoutClient, now).ok());
    }

    @Test
    void clockSkewWorksForExpAndNbfBoundaries() {
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final JwtConfig config = JwtConfig.builder(KeyProvider.hmac("secret"))
                .clockSkew(Duration.ofSeconds(10))
                .build();

        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(config);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);

        final String nearExpired = issuer.issue(TokenSpec.builder()
                .subject("u1")
                .issuer("iss")
                .issuedAt(now.minusSeconds(60))
                .expiresAt(now.minusSeconds(5))
                .build());
        Assertions.assertTrue(verifier.verify(nearExpired, now).ok());

        final String notBeforeSoon = issuer.issue(TokenSpec.builder()
                .subject("u2")
                .issuer("iss")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .notBefore(now.plusSeconds(8))
                .build());
        Assertions.assertTrue(verifier.verify(notBeforeSoon, now).ok());

        final String notBeforeFar = issuer.issue(TokenSpec.builder()
                .subject("u3")
                .issuer("iss")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .notBefore(now.plusSeconds(20))
                .build());
        Assertions.assertEquals(VerificationCode.TOKEN_NOT_BEFORE, verifier.verify(notBeforeFar, now).verificationCode());
    }

    @Test
    void verifierReturnsBadFormatForMalformedTokens() {
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(JwtConfig.builder(KeyProvider.hmac("secret")).build());
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");

        Assertions.assertEquals(VerificationCode.BAD_FORMAT, verifier.verify("", now).verificationCode());
        Assertions.assertEquals(VerificationCode.BAD_FORMAT, verifier.verify("abc.def", now).verificationCode());
        Assertions.assertEquals(VerificationCode.BAD_FORMAT, verifier.verify("abc.def.ghi", now).verificationCode());
    }

    @Test
    void verificationResultProvidesNormalizedClaimsWhenOk() {
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(JwtConfig.builder(KeyProvider.hmac("secret")).build());
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(JwtConfig.builder(KeyProvider.hmac("secret")).build());

        final String token = issuer.issue(TokenSpec.builder()
                .subject("user-7")
                .issuer("issuer-7")
                .audience("a", "b")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(15))
                .tokenType(TokenType.USER)
                .roles("admin", "report")
                .claim("active", true)
                .build());

        final VerificationResult result = verifier.verify(token, now.plusSeconds(1));
        Assertions.assertTrue(result.ok());
        Assertions.assertEquals(VerificationCode.OK, result.verificationCode());
        Assertions.assertTrue(result.claims().isPresent());
        Assertions.assertEquals("user-7", result.claims().orElseThrow().subject());
        Assertions.assertEquals(java.util.List.of("admin", "report"), result.claims().orElseThrow().roles());
        Assertions.assertEquals(Boolean.TRUE, result.claims().orElseThrow().extras().get("active"));
    }
}
