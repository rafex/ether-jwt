package dev.rafex.ether.jwt;

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
