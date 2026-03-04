package dev.rafex.ether.jwt.internal;

import dev.rafex.ether.jwt.JwtAlgorithm;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;

public final class JwtSigner {

    private JwtSigner() {
    }

    public static String sign(final String signingInput, final JwtConfig config) {
        try {
            final KeyProvider keyProvider = config.keyProvider();
            if (keyProvider.algorithm() == JwtAlgorithm.HS256) {
                final byte[] signature = signHmac(signingInput.getBytes(StandardCharsets.UTF_8), keyProvider.hmacSecret());
                return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            }
            final Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(keyProvider.privateKey());
            rsa.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(rsa.sign());
        } catch (final Exception e) {
            throw new IllegalStateException("error while signing token", e);
        }
    }

    public static boolean verify(final String signingInput, final String encodedSignature, final JwtConfig config) {
        try {
            final KeyProvider keyProvider = config.keyProvider();
            if (keyProvider.algorithm() == JwtAlgorithm.HS256) {
                final byte[] expected = signHmac(signingInput.getBytes(StandardCharsets.UTF_8), keyProvider.hmacSecret());
                final byte[] provided = Base64.getUrlDecoder().decode(encodedSignature);
                return MessageDigest.isEqual(expected, provided);
            }
            final Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initVerify(keyProvider.publicKey());
            rsa.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return rsa.verify(Base64.getUrlDecoder().decode(encodedSignature));
        } catch (final Exception e) {
            return false;
        }
    }

    private static byte[] signHmac(final byte[] data, final byte[] secret) throws Exception {
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        return mac.doFinal(data);
    }
}
