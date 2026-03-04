package dev.rafex.ether.test.jwt;

import dev.rafex.ether.jwt.DefaultTokenIssuer;
import dev.rafex.ether.jwt.DefaultTokenVerifier;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenClaims;
import dev.rafex.ether.jwt.TokenSpec;
import dev.rafex.ether.jwt.TokenType;
import dev.rafex.ether.jwt.VerificationCode;
import dev.rafex.ether.jwt.VerificationResult;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

public class TestTokenIssuerVerifierHmac {

    @Test
    void issueAndVerifyUserToken() {
        final JwtConfig config = JwtConfig.builder(KeyProvider.hmac("my-hmac-secret"))
                .expectedIssuer("auth.rafex.dev")
                .expectedAudience("kiwi-api")
                .build();

        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(config);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);

        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final String token = issuer.issue(TokenSpec.builder()
                .subject("user-123")
                .issuer("auth.rafex.dev")
                .audience("kiwi-api", "admin")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(15))
                .tokenType(TokenType.USER)
                .roles("admin", "viewer")
                .claim("feature_flags", List.of("payments", "reports"))
                .build());

        final VerificationResult result = verifier.verify(token, now.plusSeconds(60));
        Assertions.assertTrue(result.ok());
        Assertions.assertEquals("ok", result.code());

        final TokenClaims claims = result.claims().orElseThrow();
        Assertions.assertEquals("user-123", claims.subject());
        Assertions.assertEquals(List.of("admin", "viewer"), claims.roles());
        Assertions.assertEquals(TokenType.USER, claims.tokenType());
        Assertions.assertEquals(List.of("payments", "reports"), claims.extras().get("feature_flags"));
    }

    @Test
    void tokenTypeAppRequiresClientId() {
        final JwtConfig config = JwtConfig.builder(KeyProvider.hmac("my-hmac-secret"))
                .expectedIssuer("auth.rafex.dev")
                .build();

        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(config);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");

        final String token = issuer.issue(TokenSpec.builder()
                .subject("svc-gateway")
                .issuer("auth.rafex.dev")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(10))
                .tokenType(TokenType.APP)
                .roles("svc")
                .build());

        final VerificationResult result = verifier.verify(token, now.plusSeconds(1));
        Assertions.assertFalse(result.ok());
        Assertions.assertEquals(VerificationCode.MISSING_CLIENT_ID, result.verificationCode());
    }

    @Test
    void tokenExpiredAndNbfAndIssuerAudienceCodes() {
        final JwtConfig config = JwtConfig.builder(KeyProvider.hmac("my-hmac-secret"))
                .expectedIssuer("issuer-a")
                .expectedAudience("aud-a")
                .clockSkew(Duration.ofSeconds(5))
                .build();

        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(config);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");

        final String expiredToken = issuer.issue(TokenSpec.builder()
                .subject("u1")
                .issuer("issuer-a")
                .audience("aud-a")
                .issuedAt(now.minusSeconds(120))
                .expiresAt(now.minusSeconds(6))
                .build());
        Assertions.assertEquals(VerificationCode.TOKEN_EXPIRED, verifier.verify(expiredToken, now).verificationCode());

        final String nbfToken = issuer.issue(TokenSpec.builder()
                .subject("u2")
                .issuer("issuer-a")
                .audience("aud-a")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .notBefore(now.plusSeconds(20))
                .build());
        Assertions.assertEquals(VerificationCode.TOKEN_NOT_BEFORE, verifier.verify(nbfToken, now).verificationCode());

        final String badIssuerToken = issuer.issue(TokenSpec.builder()
                .subject("u3")
                .issuer("issuer-b")
                .audience("aud-a")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .build());
        Assertions.assertEquals(VerificationCode.BAD_ISS, verifier.verify(badIssuerToken, now).verificationCode());

        final String badAudienceToken = issuer.issue(TokenSpec.builder()
                .subject("u4")
                .issuer("issuer-a")
                .audience("aud-b")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .build());
        Assertions.assertEquals(VerificationCode.BAD_AUD, verifier.verify(badAudienceToken, now).verificationCode());
    }

    @Test
    void badSignatureAndBadFormat() {
        final JwtConfig config = JwtConfig.builder(KeyProvider.hmac("my-hmac-secret"))
                .build();

        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(config);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");

        final String token = issuer.issue(TokenSpec.builder()
                .subject("u1")
                .issuer("issuer")
                .issuedAt(now)
                .ttl(Duration.ofMinutes(5))
                .build());

        final String tampered = token.substring(0, token.length() - 2) + "aa";
        Assertions.assertEquals(VerificationCode.BAD_SIGNATURE, verifier.verify(tampered, now).verificationCode());
        Assertions.assertEquals(VerificationCode.BAD_FORMAT, verifier.verify("broken", now).verificationCode());
    }
}
