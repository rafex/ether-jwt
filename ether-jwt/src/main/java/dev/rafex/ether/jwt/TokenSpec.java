package dev.rafex.ether.jwt;

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

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Specification used by {@link TokenIssuer} to issue JWT tokens. */
public final class TokenSpec {

    private final TokenClaims claims;

    private TokenSpec(final Builder builder) {
        final Instant issuedAt = builder.issuedAt == null ? Instant.now() : builder.issuedAt;
        final Instant expiresAt = resolveExpiresAt(issuedAt, builder.expiresAt, builder.ttl);

        if (builder.subject == null || builder.subject.isBlank()) {
            throw new IllegalArgumentException("subject is required");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt or ttl is required");
        }

        claims = TokenClaims.builder()
                .subject(builder.subject)
                .issuer(builder.issuer)
                .audience(builder.audience)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(builder.notBefore)
                .jwtId(builder.jwtId == null || builder.jwtId.isBlank() ? UUID.randomUUID().toString() : builder.jwtId)
                .roles(builder.roles)
                .tokenType(builder.tokenType)
                .clientId(builder.clientId)
                .extras(builder.customClaims)
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public TokenClaims claims() {
        return claims;
    }

    private static Instant resolveExpiresAt(final Instant issuedAt, final Instant expiresAt, final Duration ttl) {
        if (expiresAt != null) {
            return expiresAt;
        }
        if (ttl != null) {
            if (ttl.isNegative() || ttl.isZero()) {
                throw new IllegalArgumentException("ttl must be > 0");
            }
            return issuedAt.plus(ttl);
        }
        return null;
    }

    public static final class Builder {
        private String subject;
        private String issuer;
        private String[] audience;
        private Instant issuedAt;
        private Instant expiresAt;
        private Duration ttl;
        private Instant notBefore;
        private String jwtId;
        private String[] roles;
        private TokenType tokenType;
        private String clientId;
        private Map<String, Object> customClaims = new LinkedHashMap<>();

        private Builder() {
        }

        public Builder subject(final String subject) {
            this.subject = subject;
            return this;
        }

        public Builder issuer(final String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder audience(final String... audience) {
            this.audience = audience == null ? new String[0] : audience;
            return this;
        }

        public Builder issuedAt(final Instant issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public Builder expiresAt(final Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder ttl(final Duration ttl) {
            this.ttl = ttl;
            return this;
        }

        public Builder notBefore(final Instant notBefore) {
            this.notBefore = notBefore;
            return this;
        }

        public Builder jwtId(final String jwtId) {
            this.jwtId = jwtId;
            return this;
        }

        public Builder roles(final String... roles) {
            this.roles = roles == null ? new String[0] : roles;
            return this;
        }

        public Builder tokenType(final TokenType tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public Builder clientId(final String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder claim(final String key, final Object value) {
            if (key == null || key.isBlank()) {
                throw new IllegalArgumentException("claim key is required");
            }
            customClaims.put(key, value);
            return this;
        }

        public Builder claims(final Map<String, Object> claims) {
            customClaims = claims == null ? new LinkedHashMap<>() : new LinkedHashMap<>(claims);
            return this;
        }

        public TokenSpec build() {
            return new TokenSpec(this);
        }
    }
}
