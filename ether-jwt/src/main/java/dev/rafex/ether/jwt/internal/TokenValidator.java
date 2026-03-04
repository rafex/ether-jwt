package dev.rafex.ether.jwt.internal;

import com.fasterxml.jackson.databind.JsonNode;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.TokenClaims;
import dev.rafex.ether.jwt.TokenType;
import dev.rafex.ether.jwt.VerificationCode;

import java.time.Instant;

public final class TokenValidator {

    private TokenValidator() {
    }

    public static VerificationCode validate(
            final TokenClaims claims,
            final JsonNode payload,
            final JwtConfig config,
            final Instant now,
            final String tokenTypeRaw) {

        if (config.requireSubject() && isBlank(claims.subject())) {
            return VerificationCode.MISSING_SUB;
        }

        if (config.validateExpiration()) {
            if (claims.expiresAt() == null) {
                return VerificationCode.BAD_FORMAT;
            }
            if (now.isAfter(claims.expiresAt().plus(config.clockSkew()))) {
                return VerificationCode.TOKEN_EXPIRED;
            }
        } else if (config.requireExpiration() && claims.expiresAt() == null) {
            return VerificationCode.BAD_FORMAT;
        }

        if (config.validateNotBefore() && claims.notBefore() != null) {
            if (now.plus(config.clockSkew()).isBefore(claims.notBefore())) {
                return VerificationCode.TOKEN_NOT_BEFORE;
            }
        }

        final String expectedIssuer = config.expectedIssuer();
        if (expectedIssuer != null && !expectedIssuer.equals(claims.issuer())) {
            return VerificationCode.BAD_ISS;
        }

        if (!config.expectedAudience().isEmpty()) {
            boolean matches = false;
            for (final String value : claims.audience()) {
                if (config.expectedAudience().contains(value)) {
                    matches = true;
                    break;
                }
            }
            if (!matches) {
                return VerificationCode.BAD_AUD;
            }
        }

        if (tokenTypeRaw != null && claims.tokenType() == null) {
            return VerificationCode.BAD_TOKEN_TYPE;
        }

        if (claims.tokenType() == TokenType.APP && config.requireClientIdForAppTokens() && isBlank(claims.clientId())) {
            return VerificationCode.MISSING_CLIENT_ID;
        }

        return VerificationCode.OK;
    }

    private static boolean isBlank(final String value) {
        return value == null || value.isBlank();
    }
}
