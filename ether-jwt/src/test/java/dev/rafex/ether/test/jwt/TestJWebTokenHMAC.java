package dev.rafex.ether.test.jwt;

/*-
 * #%L
 * ether-jwt
 * %%
 * Copyright (C) 2025 Raúl Eduardo González Argote
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

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import dev.rafex.ether.jwt.JWebToken;
import dev.rafex.ether.jwt.impl.JWebTokenImpl;

public class TestJWebTokenHMAC {

    private LocalDateTime ldt;
    private ObjectMapper objectMapper;
    private JsonNode payload;

    @BeforeAll
    static void beforeAll() {
        // This method can be used for any setup that needs to run once before all tests
        System.out.println("Starting JWebToken tests...");
        System.setProperty("jwt.secret", "my-secret");
        System.setProperty("jwt.privateKeyPath", "algo.pem");
        System.setProperty("jwt.publicKeyPath", "otro.pem");

    }

    @BeforeEach
    void setUp() throws Exception {

        ldt = LocalDateTime.now().plusDays(90);
        objectMapper = new ObjectMapper();
        final var json = "{\"sub\":\"1234\",\"aud\":[\"admin\"],\"exp\":" + ldt.toEpochSecond(ZoneOffset.UTC) + "}";
        payload = objectMapper.readTree(json);
    }

    @Test
    void createJson() throws Exception {
        final var jsonObject = objectMapper.createObjectNode();
        final String[] aud = { "admin", "user" };
        jsonObject.put("sub", "jajaja");
        final var audArray = objectMapper.valueToTree(aud);
        jsonObject.set("aud", audArray);

        Assertions.assertTrue(jsonObject.has("sub"));
        Assertions.assertTrue(jsonObject.has("aud"));
        Assertions.assertEquals(2, jsonObject.get("aud").size());
    }

    @Test
    void testWithData() throws Exception {
        final var exp = LocalDateTime.now().plusDays(90).toEpochSecond(ZoneOffset.UTC);
        final String[] audience = { "admin" };
        final JWebToken jWebToken = new JWebTokenImpl.Builder().subject("1234").expiration(exp).audience(audience).build();
        final var token = jWebToken.toString();

        final JWebToken incomingToken = new JWebTokenImpl(token);
        Assertions.assertTrue(incomingToken.isValid());
        Assertions.assertEquals("1234", incomingToken.getSubject());
        Assertions.assertEquals("admin", incomingToken.getAudience().get(0));
    }

    @Test
    void expire5Minutes() throws Exception {
        final String[] audience = { "admin" };
        final JWebToken jWebToken = new JWebTokenImpl.Builder().subject("1234").expirationPlusMinutes(5).audience(audience).build();
        final var token = jWebToken.toString();

        final JWebToken incomingToken = new JWebTokenImpl(token);
        Assertions.assertTrue(incomingToken.isValid());
        Assertions.assertEquals("1234", incomingToken.getSubject());
    }

    @Test
    void notBefore1Second() throws Exception {
        final String[] audience = { "admin" };
        final JWebToken jWebToken = new JWebTokenImpl.Builder().subject("1234").expirationPlusMinutes(5).notBeforePlusSeconds(1).audience(audience).build();
        final var token = jWebToken.toString();

        TimeUnit.SECONDS.sleep(2);
        final JWebToken incomingToken = new JWebTokenImpl(token);
        Assertions.assertTrue(incomingToken.isValid());
        Assertions.assertEquals("1234", incomingToken.getSubject());
    }

    @Test
    @Disabled("for demonstration purposes")
    void expire1MinuteFail() throws Exception {
        final String[] audience = { "admin" };
        final JWebToken jWebToken = new JWebTokenImpl.Builder().subject("1234").expirationPlusMinutes(1).audience(audience).build();
        final var token = jWebToken.toString();

        TimeUnit.MINUTES.sleep(2);
        final JWebToken incomingToken = new JWebTokenImpl(token);
        Assertions.assertFalse(incomingToken.isValid());
    }

    @Test
    void addClaim() throws Exception {
        final var exp = LocalDateTime.now().plusDays(90).toEpochSecond(ZoneOffset.UTC);
        final String[] audience = { "admin" };
        final JWebToken jWebToken = new JWebTokenImpl.Builder().subject("1234").claim("user", "rafex").expiration(exp).audience(audience).build();
        final var token = jWebToken.toString();

        final var incomingToken = new JWebTokenImpl(token);
        Assertions.assertTrue(incomingToken.isValid());
        Assertions.assertEquals("rafex", incomingToken.get("user"));
        Assertions.assertEquals("admin", incomingToken.getAudience().get(0));
    }

    @Test
    void custom() throws Exception {
        final JWebToken token = new JWebTokenImpl.Builder().issuer("rafex.dev").subject("user-1234").audience("app1").expirationPlusMinutes(60).notBeforePlusSeconds(0)
                // Public Claims
                .claim("email", "user@example.com").claim("role", "admin")
                // Private Claims
                .claim("userId", "42").claim("x-rafex-customData", "{\"cartId\":123,\"tier\":\"gold\"}").build();

        final var tokenString = token.toString();

        final var incomingToken = new JWebTokenImpl(tokenString);
        System.out.println("Token: " + tokenString);
        Assertions.assertTrue(incomingToken.isValid());
        Assertions.assertEquals("user-1234", incomingToken.getSubject());
    }

    @Test
    void testWithSecret() throws Exception {

        // Build a token signed with HS256
        final String[] audience = { "user" };
        final JWebToken hmacToken = new JWebTokenImpl.Builder().subject("hmac-user").audience(audience).expirationPlusMinutes(5).build();
        final var tokenString = hmacToken.toString();

        // Parse and validate
        final JWebToken parsed = new JWebTokenImpl(tokenString);
        Assertions.assertTrue(parsed.isValid(), "HMAC token should be valid");
        Assertions.assertEquals("hmac-user", parsed.getSubject());

        // Verify the header indicates HS256
        final var decodedHeader = new String(java.util.Base64.getUrlDecoder().decode(parsed.getEncodedHeader()), java.nio.charset.StandardCharsets.UTF_8);
        Assertions.assertTrue(decodedHeader.contains("\"alg\":\"HS256\""), "Header must indicate HS256 algorithm");
    }

}