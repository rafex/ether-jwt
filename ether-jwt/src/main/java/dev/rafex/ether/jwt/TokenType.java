package dev.rafex.ether.jwt;

/** Supported business token types. */
public enum TokenType {
    USER("user"),
    APP("app");

    private final String claimValue;

    TokenType(final String claimValue) {
        this.claimValue = claimValue;
    }

    public String claimValue() {
        return claimValue;
    }

    public static TokenType fromClaimValue(final String claimValue) {
        for (final TokenType type : values()) {
            if (type.claimValue.equals(claimValue)) {
                return type;
            }
        }
        return null;
    }
}
