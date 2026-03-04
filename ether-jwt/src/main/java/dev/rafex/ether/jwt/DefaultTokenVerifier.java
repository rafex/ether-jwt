package dev.rafex.ether.jwt;

import dev.rafex.ether.jwt.internal.ClaimsMapper;
import dev.rafex.ether.jwt.internal.JwtCodec;
import dev.rafex.ether.jwt.internal.JwtSigner;
import dev.rafex.ether.jwt.internal.TokenValidator;

import java.time.Instant;
import java.util.Objects;

/** Default implementation of {@link TokenVerifier}. */
public final class DefaultTokenVerifier implements TokenVerifier {

    private final JwtConfig config;

    public DefaultTokenVerifier(final JwtConfig config) {
        this.config = Objects.requireNonNull(config, "config");
        validateVerifierConfig(config);
    }

    @Override
    public VerificationResult verify(final String token, final Instant now) {
        try {
            final JwtCodec.ParsedJwt parsed = JwtCodec.parse(token);
            final JwtAlgorithm tokenAlg = JwtAlgorithm.fromHeaderValue(parsed.header().path("alg").asText(null));
            if (tokenAlg == null || tokenAlg != config.keyProvider().algorithm()) {
                return VerificationResult.fail(VerificationCode.UNSUPPORTED_ALG);
            }

            if (!JwtSigner.verify(parsed.signingInput(), parsed.encodedSignature(), config)) {
                return VerificationResult.fail(VerificationCode.BAD_SIGNATURE);
            }

            final String tokenTypeRaw = ClaimsMapper.tokenTypeRaw(parsed.payload());
            final TokenClaims claims = ClaimsMapper.fromPayload(parsed.payload());
            final VerificationCode validationResult = TokenValidator.validate(claims, parsed.payload(), config,
                    now == null ? Instant.now() : now, tokenTypeRaw);

            if (validationResult != VerificationCode.OK) {
                return VerificationResult.fail(validationResult);
            }
            return VerificationResult.ok(claims);
        } catch (final IllegalArgumentException e) {
            return VerificationResult.fail(VerificationCode.BAD_FORMAT);
        } catch (final Exception e) {
            return VerificationResult.fail(VerificationCode.VERIFY_EXCEPTION);
        }
    }

    private static void validateVerifierConfig(final JwtConfig config) {
        if (config.keyProvider().algorithm() == JwtAlgorithm.HS256 && config.keyProvider().hmacSecret() == null) {
            throw new IllegalArgumentException("HS256 requires explicit hmac secret");
        }
        if (config.keyProvider().algorithm() == JwtAlgorithm.RS256 && config.keyProvider().publicKey() == null) {
            throw new IllegalArgumentException("RS256 requires public key for verification");
        }
    }
}
