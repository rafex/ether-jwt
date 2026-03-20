package dev.rafex.ether.jwt.internal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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

import dev.rafex.ether.jwt.JwtAlgorithm;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;

public final class JwtSigner {

    private JwtSigner() {
    }

    public static String sign(final String signingInput, final JwtConfig config) {
        try {
            final KeyProvider keyProvider = config.keyProvider();
            if (keyProvider.algorithm() == JwtAlgorithm.HS256) {
                final byte[] signature = signHmac(signingInput.getBytes(StandardCharsets.UTF_8),
                        keyProvider.hmacSecret());
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
                final byte[] expected = signHmac(signingInput.getBytes(StandardCharsets.UTF_8),
                        keyProvider.hmacSecret());
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
