package dev.rafex.ether.test.jwt;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import dev.rafex.ether.jwt.DefaultTokenIssuer;
import dev.rafex.ether.jwt.DefaultTokenVerifier;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenClaims;
import dev.rafex.ether.jwt.TokenSpec;
import dev.rafex.ether.jwt.VerificationResult;

public class TestJwtStandardClaimsSerialization {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void standardJwtShapeAndHeaderAreCorrect() throws Exception {
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final String token = new DefaultTokenIssuer(JwtConfig.builder(KeyProvider.hmac("secret")).build())
                .issue(TokenSpec.builder().subject("user").issuer("issuer").audience("api").issuedAt(now)
                        .ttl(Duration.ofMinutes(5)).build());

        final String[] parts = token.split("\\.");
        Assertions.assertEquals(3, parts.length);
        Assertions.assertFalse(parts[0].contains("="));
        Assertions.assertFalse(parts[1].contains("="));
        Assertions.assertFalse(parts[2].contains("="));

        final JsonNode header = MAPPER
                .readTree(new String(java.util.Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
        final JsonNode payload = MAPPER
                .readTree(new String(java.util.Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));

        Assertions.assertEquals("JWT", header.get("typ").asText());
        Assertions.assertEquals("HS256", header.get("alg").asText());
        Assertions.assertTrue(payload.get("exp").isIntegralNumber());
        Assertions.assertTrue(payload.get("iat").isIntegralNumber());
    }

    @Test
    void extrasSupportPrimitiveArrayAndObjectClaims() {
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final JwtConfig config = JwtConfig.builder(KeyProvider.hmac("secret")).build();
        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(config);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);

        final String token = issuer.issue(TokenSpec.builder().subject("user").issuer("issuer").issuedAt(now)
                .ttl(Duration.ofMinutes(5)).claim("enabled", true).claim("tier", 3).claim("ratio", 1.25d)
                .claim("scopes", List.of("read", "write")).claim("profile", Map.of("region", "us", "age", 30)).build());

        final VerificationResult result = verifier.verify(token, now.plusSeconds(2));
        Assertions.assertTrue(result.ok());

        final TokenClaims claims = result.claims().orElseThrow();
        Assertions.assertEquals(Boolean.TRUE, claims.extras().get("enabled"));
        Assertions.assertEquals(3, ((Number) claims.extras().get("tier")).intValue());
        Assertions.assertEquals(1.25d, ((Number) claims.extras().get("ratio")).doubleValue());
        Assertions.assertEquals(List.of("read", "write"), claims.extras().get("scopes"));

        @SuppressWarnings("unchecked")
        final Map<String, Object> profile = (Map<String, Object>) claims.extras().get("profile");
        Assertions.assertEquals("us", profile.get("region"));
        Assertions.assertEquals(30, ((Number) profile.get("age")).intValue());
    }

    @Test
    void audienceIsNormalizedWhenProvidedAsSingleString() {
        final Instant now = Instant.parse("2026-03-04T12:00:00Z");
        final JwtConfig config = JwtConfig.builder(KeyProvider.hmac("secret")).expectedAudience("api-a").build();
        final DefaultTokenIssuer issuer = new DefaultTokenIssuer(config);
        final DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);

        final String token = issuer.issue(TokenSpec.builder().subject("u1").issuer("iss").issuedAt(now)
                .ttl(Duration.ofMinutes(5)).claim("aud", "api-a").build());

        final VerificationResult result = verifier.verify(token, now.plusSeconds(1));
        Assertions.assertTrue(result.ok());
        Assertions.assertEquals(List.of("api-a"), result.claims().orElseThrow().audience());
    }
}
