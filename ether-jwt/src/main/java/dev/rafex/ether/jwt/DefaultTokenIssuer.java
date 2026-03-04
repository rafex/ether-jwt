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

import dev.rafex.ether.jwt.internal.ClaimsMapper;
import dev.rafex.ether.jwt.internal.JwtCodec;
import dev.rafex.ether.jwt.internal.JwtSigner;

import java.util.Objects;

/** Default implementation of {@link TokenIssuer}. */
public final class DefaultTokenIssuer implements TokenIssuer {

    private final JwtConfig config;

    public DefaultTokenIssuer(final JwtConfig config) {
        this.config = Objects.requireNonNull(config, "config");
        validateIssuerConfig(config);
    }

    @Override
    public String issue(final TokenSpec tokenSpec) {
        final TokenClaims claims = Objects.requireNonNull(tokenSpec, "tokenSpec").claims();
        final String encodedHeader = JwtCodec.encodeHeader(config.keyProvider().algorithm().headerValue());
        final String encodedPayload = JwtCodec.encodeJson(ClaimsMapper.toPayload(claims));
        final String signingInput = encodedHeader + "." + encodedPayload;
        final String signature = JwtSigner.sign(signingInput, config);
        return signingInput + "." + signature;
    }

    private static void validateIssuerConfig(final JwtConfig config) {
        if (config.keyProvider().algorithm() == JwtAlgorithm.HS256 && config.keyProvider().hmacSecret() == null) {
            throw new IllegalArgumentException("HS256 requires explicit hmac secret");
        }
        if (config.keyProvider().algorithm() == JwtAlgorithm.RS256 && config.keyProvider().privateKey() == null) {
            throw new IllegalArgumentException("RS256 requires private key for issuing");
        }
    }
}
