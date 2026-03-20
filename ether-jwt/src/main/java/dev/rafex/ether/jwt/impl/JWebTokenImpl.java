package dev.rafex.ether.jwt.impl;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/*-
 * #%L
 * ether-jwt
 * %%
 * Copyright (C) 2025 Raúl Eduardo González Argote
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
import dev.rafex.ether.jwt.JWebToken;
import dev.rafex.ether.jwt.JwtAlgorithm;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenSpec;
import dev.rafex.ether.jwt.VerificationResult;
import dev.rafex.ether.jwt.internal.JwtCodec;

/**
 * Legacy JWT implementation. Prefer {@link DefaultTokenIssuer} +
 * {@link DefaultTokenVerifier}.
 *
 * @deprecated Use reusable APIs in package {@code dev.rafex.ether.jwt}.
 */
@Deprecated(since = "3.1.0", forRemoval = false)
public final class JWebTokenImpl implements JWebToken {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final JsonNode payload;
    private final String signature;
    private final String encodedHeader;
    private final String token;

    private JWebTokenImpl(final String token, final JsonNode payload, final String encodedHeader,
            final String signature) {
        this.token = token;
        this.payload = payload;
        this.encodedHeader = encodedHeader;
        this.signature = signature;
    }

    /** Parse an existing JWT token string. */
    public JWebTokenImpl(final String token) {
        final JwtCodec.ParsedJwt parsed = JwtCodec.parse(token);
        this.token = token;
        this.payload = parsed.payload();
        this.encodedHeader = parsed.encodedHeader();
        this.signature = parsed.encodedSignature();
    }

    @Override
    public JsonNode getPayload() {
        return payload;
    }

    @Override
    public String getIssuer() {
        return payload.path("iss").asText("");
    }

    @Override
    public String getSubject() {
        return payload.path("sub").asText("");
    }

    @Override
    public List<String> getAudience() {
        final List<String> values = new ArrayList<>();
        final JsonNode audience = payload.get("aud");
        if (audience == null || audience.isNull()) {
            return values;
        }
        if (audience.isArray()) {
            audience.forEach(node -> values.add(node.asText()));
            return values;
        }
        values.add(audience.asText());
        return values;
    }

    @Override
    public Long getExpiration() {
        return payload.path("exp").asLong(0L);
    }

    @Override
    public Long getNotBefore() {
        return payload.path("nbf").asLong(0L);
    }

    @Override
    public Long getIssuedAt() {
        return payload.path("iat").asLong(0L);
    }

    @Override
    public String getJwtId() {
        return payload.path("jti").asText("");
    }

    @Override
    public String get(final String property) {
        return payload.path(property).asText("");
    }

    @Override
    public String getSignature() {
        return signature;
    }

    @Override
    public String getEncodedHeader() {
        return encodedHeader;
    }

    @Override
    public boolean isValid() {
        final VerificationResult result = LegacySupport.VERIFIER.verify(token, Instant.now());
        return result.ok();
    }

    @Override
    public String aJson() {
        return payload.toString();
    }

    @Override
    public String toString() {
        return token;
    }

    /**
     * Legacy builder kept for migration compatibility.
     *
     * @deprecated Use {@link TokenSpec#builder()} + {@link DefaultTokenIssuer}.
     */
    @Deprecated(since = "3.1.0", forRemoval = false)
    public static class Builder {
        private final Instant now = Instant.now();
        private String issuer = "rafex.dev";
        private String subject;
        private final List<String> audience = new ArrayList<>();
        private Instant issuedAt = now;
        private Instant expiresAt;
        private Instant notBefore;
        private String jwtId = UUID.randomUUID().toString();
        private final Map<String, Object> extraClaims = new LinkedHashMap<>();

        public Builder issuer(final String iss) {
            if (iss != null && !iss.isBlank()) {
                issuer = iss;
            }
            return this;
        }

        public Builder subject(final String sub) {
            subject = sub;
            return this;
        }

        public Builder audience(final String... aud) {
            if (aud != null) {
                for (final String value : aud) {
                    if (value != null && !value.isBlank()) {
                        audience.add(value);
                    }
                }
            }
            return this;
        }

        public Builder expiration(final long exp) {
            if (exp > 0) {
                expiresAt = Instant.ofEpochSecond(exp);
            }
            return this;
        }

        public Builder expirationPlusMinutes(final int mins) {
            if (mins > 0) {
                expiresAt = now.plusSeconds(mins * 60L);
            }
            return this;
        }

        public Builder notBeforePlusSeconds(final int secs) {
            if (secs > 0) {
                notBefore = now.plusSeconds(secs);
            }
            return this;
        }

        public Builder claim(final String key, final String val) {
            if (key != null && !key.isBlank() && val != null && !val.isBlank()) {
                extraClaims.put(key, val);
            }
            return this;
        }

        public JWebTokenImpl build() {
            final TokenSpec.Builder spec = TokenSpec.builder().issuer(issuer).subject(subject).issuedAt(issuedAt)
                    .jwtId(jwtId).audience(audience.toArray(String[]::new));

            if (expiresAt != null) {
                spec.expiresAt(expiresAt);
            }
            if (notBefore != null) {
                spec.notBefore(notBefore);
            }
            for (final Map.Entry<String, Object> entry : extraClaims.entrySet()) {
                spec.claim(entry.getKey(), entry.getValue());
            }

            final String token = LegacySupport.ISSUER.issue(spec.build());
            final JwtCodec.ParsedJwt parsed = JwtCodec.parse(token);
            return new JWebTokenImpl(token, parsed.payload(), parsed.encodedHeader(), parsed.encodedSignature());
        }
    }

    private static final class LegacySupport {
        private static final DefaultTokenIssuer ISSUER;
        private static final DefaultTokenVerifier VERIFIER;

        static {
            final JwtConfig config = loadConfig();
            ISSUER = new DefaultTokenIssuer(config);
            VERIFIER = new DefaultTokenVerifier(config);
        }

        private LegacySupport() {
        }

        private static JwtConfig loadConfig() {
            final Properties properties = new Properties();
            try (InputStream in = Thread.currentThread().getContextClassLoader()
                    .getResourceAsStream("jwt.properties")) {
                if (in != null) {
                    properties.load(in);
                }
            } catch (final Exception ignored) {
                // Legacy compatibility: ignore missing properties files.
            }

            applySystemOverride(properties, "jwt.algorithm");
            applySystemOverride(properties, "jwt.secret");
            applySystemOverride(properties, "jwt.privateKey");
            applySystemOverride(properties, "jwt.publicKey");
            applySystemOverride(properties, "jwt.privateKeyPath");
            applySystemOverride(properties, "jwt.publicKeyPath");

            final KeyProvider provider = resolveKeyProvider(properties);
            return JwtConfig.builder(provider).build();
        }

        private static void applySystemOverride(final Properties properties, final String key) {
            final String sys = System.getProperty(key);
            if (sys != null && !sys.isBlank()) {
                properties.setProperty(key, sys);
            }
        }

        private static KeyProvider resolveKeyProvider(final Properties properties) {
            final String configuredAlgorithm = firstNonBlank(properties.getProperty("jwt.algorithm"),
                    System.getenv("JWT_ALGORITHM"));

            final String secret = firstNonBlank(properties.getProperty("jwt.secret"), System.getenv("JWT_SECRET"));
            final String privateKeyText = readKeyText(properties, "jwt.privateKey", "JWT_PRIVATE_KEY",
                    "jwt.privateKeyPath", "JWT_PRIVATE_KEY_PATH");
            final String publicKeyText = readKeyText(properties, "jwt.publicKey", "JWT_PUBLIC_KEY", "jwt.publicKeyPath",
                    "JWT_PUBLIC_KEY_PATH");

            final JwtAlgorithm algorithm;
            if (configuredAlgorithm != null) {
                algorithm = JwtAlgorithm.valueOf(configuredAlgorithm.trim().toUpperCase());
            } else if (privateKeyText != null || publicKeyText != null) {
                algorithm = JwtAlgorithm.RS256;
            } else {
                algorithm = JwtAlgorithm.HS256;
            }

            if (algorithm == JwtAlgorithm.HS256) {
                if (secret == null || secret.isBlank()) {
                    throw new IllegalStateException("Missing jwt.secret/JWT_SECRET for HS256 legacy JWT config");
                }
                return KeyProvider.hmac(secret);
            }

            if (privateKeyText == null || publicKeyText == null) {
                throw new IllegalStateException("Missing RSA key material for legacy RS256 JWT config");
            }

            try {
                final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                final PrivateKey privateKey = keyFactory
                        .generatePrivate(new PKCS8EncodedKeySpec(stripPem(privateKeyText)));
                final PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(stripPem(publicKeyText)));
                return KeyProvider.rsa(privateKey, publicKey);
            } catch (final Exception e) {
                throw new IllegalStateException("Invalid RSA key material for legacy JWT config", e);
            }
        }

        private static String readKeyText(final Properties properties, final String inlineProperty,
                final String inlineEnv, final String pathProperty, final String pathEnv) {
            final String inlineValue = firstNonBlank(properties.getProperty(inlineProperty), System.getenv(inlineEnv));
            if (inlineValue != null) {
                return inlineValue;
            }
            final String pathValue = firstNonBlank(properties.getProperty(pathProperty), System.getenv(pathEnv));
            if (pathValue == null) {
                return null;
            }
            try {
                return Files.readString(Path.of(pathValue), StandardCharsets.UTF_8);
            } catch (final Exception e) {
                throw new IllegalStateException("Unable to read JWT key path: " + pathValue, e);
            }
        }

        private static String firstNonBlank(final String first, final String second) {
            if (first != null && !first.isBlank()) {
                return first;
            }
            if (second != null && !second.isBlank()) {
                return second;
            }
            return null;
        }

        private static byte[] stripPem(final String pem) {
            final String body = pem.replaceAll("-----BEGIN (.*)-----", "").replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
            return Base64.getDecoder().decode(body);
        }
    }
}
