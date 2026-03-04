package dev.rafex.ether.jwt;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Normalized claims extracted from a JWT token. */
public final class TokenClaims {

    private final String subject;
    private final String issuer;
    private final List<String> audience;
    private final Instant expiresAt;
    private final Instant issuedAt;
    private final Instant notBefore;
    private final String jwtId;
    private final List<String> roles;
    private final TokenType tokenType;
    private final String clientId;
    private final Map<String, Object> extras;

    private TokenClaims(final Builder builder) {
        this.subject = builder.subject;
        this.issuer = builder.issuer;
        this.audience = immutableList(builder.audience);
        this.expiresAt = builder.expiresAt;
        this.issuedAt = builder.issuedAt;
        this.notBefore = builder.notBefore;
        this.jwtId = builder.jwtId;
        this.roles = immutableList(builder.roles);
        this.tokenType = builder.tokenType;
        this.clientId = builder.clientId;
        this.extras = Collections.unmodifiableMap(new LinkedHashMap<>(builder.extras));
    }

    public static Builder builder() {
        return new Builder();
    }

    public String subject() {
        return subject;
    }

    public String issuer() {
        return issuer;
    }

    public List<String> audience() {
        return audience;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public Instant issuedAt() {
        return issuedAt;
    }

    public Instant notBefore() {
        return notBefore;
    }

    public String jwtId() {
        return jwtId;
    }

    public List<String> roles() {
        return roles;
    }

    public TokenType tokenType() {
        return tokenType;
    }

    public String clientId() {
        return clientId;
    }

    public Map<String, Object> extras() {
        return extras;
    }

    public Builder toBuilder() {
        return builder()
                .subject(subject)
                .issuer(issuer)
                .audience(audience)
                .expiresAt(expiresAt)
                .issuedAt(issuedAt)
                .notBefore(notBefore)
                .jwtId(jwtId)
                .roles(roles)
                .tokenType(tokenType)
                .clientId(clientId)
                .extras(extras);
    }

    private static List<String> immutableList(final List<String> input) {
        if (input == null || input.isEmpty()) {
            return List.of();
        }
        final List<String> values = new ArrayList<>();
        for (final String value : input) {
            if (value != null && !value.isBlank()) {
                values.add(value);
            }
        }
        return Collections.unmodifiableList(values);
    }

    public static final class Builder {
        private String subject;
        private String issuer;
        private List<String> audience = new ArrayList<>();
        private Instant expiresAt;
        private Instant issuedAt;
        private Instant notBefore;
        private String jwtId;
        private List<String> roles = new ArrayList<>();
        private TokenType tokenType;
        private String clientId;
        private Map<String, Object> extras = new LinkedHashMap<>();

        private Builder() {
        }

        public Builder subject(final String subject) {
            this.subject = blankToNull(subject);
            return this;
        }

        public Builder issuer(final String issuer) {
            this.issuer = blankToNull(issuer);
            return this;
        }

        public Builder audience(final List<String> audience) {
            this.audience = audience == null ? new ArrayList<>() : new ArrayList<>(audience);
            return this;
        }

        public Builder audience(final String... audience) {
            final List<String> values = new ArrayList<>();
            if (audience != null) {
                Collections.addAll(values, audience);
            }
            this.audience = values;
            return this;
        }

        public Builder expiresAt(final Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder issuedAt(final Instant issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public Builder notBefore(final Instant notBefore) {
            this.notBefore = notBefore;
            return this;
        }

        public Builder jwtId(final String jwtId) {
            this.jwtId = blankToNull(jwtId);
            return this;
        }

        public Builder roles(final List<String> roles) {
            this.roles = roles == null ? new ArrayList<>() : new ArrayList<>(roles);
            return this;
        }

        public Builder roles(final String... roles) {
            final List<String> values = new ArrayList<>();
            if (roles != null) {
                Collections.addAll(values, roles);
            }
            this.roles = values;
            return this;
        }

        public Builder tokenType(final TokenType tokenType) {
            this.tokenType = tokenType;
            return this;
        }

        public Builder clientId(final String clientId) {
            this.clientId = blankToNull(clientId);
            return this;
        }

        public Builder extras(final Map<String, Object> extras) {
            this.extras = extras == null ? new LinkedHashMap<>() : new LinkedHashMap<>(extras);
            return this;
        }

        public Builder extra(final String key, final Object value) {
            if (key == null || key.isBlank()) {
                throw new IllegalArgumentException("extra claim key is required");
            }
            extras.put(key, value);
            return this;
        }

        public TokenClaims build() {
            return new TokenClaims(this);
        }

        private static String blankToNull(final String value) {
            return value == null || value.isBlank() ? null : value;
        }
    }
}
