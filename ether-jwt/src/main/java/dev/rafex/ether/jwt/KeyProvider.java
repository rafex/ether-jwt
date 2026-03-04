package dev.rafex.ether.jwt;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;

/** Provides cryptographic material used to sign and verify JWT tokens. */
public interface KeyProvider {

    JwtAlgorithm algorithm();

    byte[] hmacSecret();

    PrivateKey privateKey();

    PublicKey publicKey();

    static KeyProvider hmac(final String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("secret is required for HS256");
        }
        return hmac(secret.getBytes(StandardCharsets.UTF_8));
    }

    static KeyProvider hmac(final byte[] secret) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("secret is required for HS256");
        }
        final byte[] copy = Arrays.copyOf(secret, secret.length);
        return new BasicKeyProvider(JwtAlgorithm.HS256, copy, null, null);
    }

    static KeyProvider rsa(final PrivateKey privateKey, final PublicKey publicKey) {
        if (privateKey == null || publicKey == null) {
            throw new IllegalArgumentException("privateKey and publicKey are required for RS256");
        }
        return new BasicKeyProvider(JwtAlgorithm.RS256, null, privateKey, publicKey);
    }

    static KeyProvider rsaVerifier(final PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey is required for RS256 verification");
        }
        return new BasicKeyProvider(JwtAlgorithm.RS256, null, null, publicKey);
    }

    final class BasicKeyProvider implements KeyProvider {
        private final JwtAlgorithm algorithm;
        private final byte[] hmacSecret;
        private final PrivateKey privateKey;
        private final PublicKey publicKey;

        private BasicKeyProvider(
                final JwtAlgorithm algorithm,
                final byte[] hmacSecret,
                final PrivateKey privateKey,
                final PublicKey publicKey) {
            this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
            this.hmacSecret = hmacSecret == null ? null : Arrays.copyOf(hmacSecret, hmacSecret.length);
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        @Override
        public JwtAlgorithm algorithm() {
            return algorithm;
        }

        @Override
        public byte[] hmacSecret() {
            return hmacSecret == null ? null : Arrays.copyOf(hmacSecret, hmacSecret.length);
        }

        @Override
        public PrivateKey privateKey() {
            return privateKey;
        }

        @Override
        public PublicKey publicKey() {
            return publicKey;
        }
    }
}
