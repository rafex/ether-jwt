package dev.rafex.ether.jwt;

/** Supported JWT signature algorithms. */
public enum JwtAlgorithm {
    HS256("HS256"),
    RS256("RS256");

    private final String headerValue;

    JwtAlgorithm(final String headerValue) {
        this.headerValue = headerValue;
    }

    public String headerValue() {
        return headerValue;
    }

    public static JwtAlgorithm fromHeaderValue(final String value) {
        for (final JwtAlgorithm algorithm : values()) {
            if (algorithm.headerValue.equals(value)) {
                return algorithm;
            }
        }
        return null;
    }
}
