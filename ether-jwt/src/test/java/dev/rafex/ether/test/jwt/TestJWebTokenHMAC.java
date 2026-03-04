package dev.rafex.ether.test.jwt;

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

import dev.rafex.ether.jwt.JWebToken;
import dev.rafex.ether.jwt.impl.JWebTokenImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
public class TestJWebTokenHMAC {

    @BeforeAll
    static void beforeAll() {
        System.setProperty("jwt.secret", "test-suite-secret");
    }

    @Test
    void legacyBuilderCreatesValidToken() {
        final JWebToken token = new JWebTokenImpl.Builder()
                .issuer("issuer-legacy")
                .subject("user-123")
                .audience("legacy-api")
                .expirationPlusMinutes(10)
                .build();

        final JWebToken parsed = new JWebTokenImpl(token.toString());
        Assertions.assertTrue(parsed.isValid());
        Assertions.assertEquals("user-123", parsed.getSubject());
        Assertions.assertEquals("issuer-legacy", parsed.getIssuer());
    }

    @Test
    void legacyClaimBridgeWorks() {
        final JWebToken token = new JWebTokenImpl.Builder()
                .subject("user-123")
                .audience("legacy-api")
                .expirationPlusMinutes(10)
                .claim("tenant_id", "tenant-a")
                .build();

        final JWebToken parsed = new JWebTokenImpl(token.toString());
        Assertions.assertTrue(parsed.isValid());
        Assertions.assertEquals("tenant-a", parsed.get("tenant_id"));
    }
}
