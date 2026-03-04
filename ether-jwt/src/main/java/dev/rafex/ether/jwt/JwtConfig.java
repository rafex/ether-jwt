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
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Configures JWT signing and verification behavior.
 */
public final class JwtConfig {

    private final KeyProvider keyProvider;
    private final String expectedIssuer;
    private final Set<String> expectedAudience;
    private final Duration clockSkew;
    private final boolean validateExpiration;
    private final boolean validateNotBefore;
    private final boolean requireExpiration;
    private final boolean requireSubject;
    private final boolean requireClientIdForAppTokens;

    private JwtConfig(final Builder builder) {
        keyProvider = Objects.requireNonNull(builder.keyProvider, "keyProvider");
        expectedIssuer = builder.expectedIssuer;
        expectedAudience = Set.copyOf(builder.expectedAudience);
        clockSkew = builder.clockSkew;
        validateExpiration = builder.validateExpiration;
        validateNotBefore = builder.validateNotBefore;
        requireExpiration = builder.requireExpiration;
        requireSubject = builder.requireSubject;
        requireClientIdForAppTokens = builder.requireClientIdForAppTokens;
    }

    public static Builder builder(final KeyProvider keyProvider) {
        return new Builder(keyProvider);
    }

    public KeyProvider keyProvider() {
        return keyProvider;
    }

    public String expectedIssuer() {
        return expectedIssuer;
    }

    public Set<String> expectedAudience() {
        return expectedAudience;
    }

    public Duration clockSkew() {
        return clockSkew;
    }

    public boolean validateExpiration() {
        return validateExpiration;
    }

    public boolean validateNotBefore() {
        return validateNotBefore;
    }

    public boolean requireExpiration() {
        return requireExpiration;
    }

    public boolean requireSubject() {
        return requireSubject;
    }

    public boolean requireClientIdForAppTokens() {
        return requireClientIdForAppTokens;
    }

    public static final class Builder {
        private final KeyProvider keyProvider;
        private String expectedIssuer;
        private Set<String> expectedAudience = new LinkedHashSet<>();
        private Duration clockSkew = Duration.ZERO;
        private boolean validateExpiration = true;
        private boolean validateNotBefore = true;
        private boolean requireExpiration = true;
        private boolean requireSubject = true;
        private boolean requireClientIdForAppTokens = true;

        private Builder(final KeyProvider keyProvider) {
            this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider");
        }

        public Builder expectedIssuer(final String expectedIssuer) {
            this.expectedIssuer = blankToNull(expectedIssuer);
            return this;
        }

        public Builder expectedAudience(final Set<String> expectedAudience) {
            this.expectedAudience = expectedAudience == null ? new LinkedHashSet<>() : new LinkedHashSet<>(expectedAudience);
            this.expectedAudience.removeIf(value -> value == null || value.isBlank());
            return this;
        }

        public Builder expectedAudience(final String... expectedAudience) {
            final Set<String> values = new LinkedHashSet<>();
            if (expectedAudience != null) {
                for (final String aud : expectedAudience) {
                    if (aud != null && !aud.isBlank()) {
                        values.add(aud);
                    }
                }
            }
            this.expectedAudience = values;
            return this;
        }

        public Builder clockSkew(final Duration clockSkew) {
            this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
            if (clockSkew.isNegative()) {
                throw new IllegalArgumentException("clockSkew must be >= 0");
            }
            return this;
        }

        public Builder validateExpiration(final boolean validateExpiration) {
            this.validateExpiration = validateExpiration;
            return this;
        }

        public Builder validateNotBefore(final boolean validateNotBefore) {
            this.validateNotBefore = validateNotBefore;
            return this;
        }

        public Builder requireExpiration(final boolean requireExpiration) {
            this.requireExpiration = requireExpiration;
            return this;
        }

        public Builder requireSubject(final boolean requireSubject) {
            this.requireSubject = requireSubject;
            return this;
        }

        public Builder requireClientIdForAppTokens(final boolean requireClientIdForAppTokens) {
            this.requireClientIdForAppTokens = requireClientIdForAppTokens;
            return this;
        }

        public JwtConfig build() {
            return new JwtConfig(this);
        }

        private static String blankToNull(final String value) {
            return value == null || value.isBlank() ? null : value;
        }
    }
}
