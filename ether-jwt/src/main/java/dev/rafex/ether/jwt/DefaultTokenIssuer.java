package dev.rafex.ether.jwt;

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
