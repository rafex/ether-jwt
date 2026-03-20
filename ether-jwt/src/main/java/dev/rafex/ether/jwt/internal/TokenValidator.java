package dev.rafex.ether.jwt.internal;

import java.time.Instant;

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

import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.TokenClaims;
import dev.rafex.ether.jwt.TokenType;
import dev.rafex.ether.jwt.VerificationCode;

public final class TokenValidator {

    private TokenValidator() {
    }

    public static VerificationCode validate(final TokenClaims claims, final JsonNode payload, final JwtConfig config,
            final Instant now, final String tokenTypeRaw) {

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
