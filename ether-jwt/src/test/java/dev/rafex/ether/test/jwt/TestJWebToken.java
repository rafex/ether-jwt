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

import static org.junit.jupiter.api.Assertions.fail;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import dev.rafex.ether.jwt.impl.JWebTokenImpl;

public class TestJWebToken {

    private LocalDateTime ldt;
    private ObjectMapper objectMapper;
    private JsonNode payload;

    @BeforeEach
    void setUp() throws Exception {
        ldt = LocalDateTime.now().plusDays(90);
        objectMapper = new ObjectMapper();
        String json = "{\"sub\":\"1234\",\"aud\":[\"admin\"],\"exp\":" +
                      ldt.toEpochSecond(ZoneOffset.UTC) + "}";
        payload = objectMapper.readTree(json);
    }

    @Test
    void createJson() throws Exception {
        ObjectNode jsonObject = objectMapper.createObjectNode();
        String[] aud = { "admin", "user" };
        jsonObject.put("sub", "jajaja");
        ArrayNode audArray = objectMapper.valueToTree(aud);
        jsonObject.set("aud", audArray);

        Assertions.assertTrue(jsonObject.has("sub"));
        Assertions.assertTrue(jsonObject.has("aud"));
        Assertions.assertEquals(2, jsonObject.get("aud").size());
    }

    @Test
    void testWithData() throws Exception {
        long exp = LocalDateTime.now().plusDays(90).toEpochSecond(ZoneOffset.UTC);
        String[] audience = { "admin" };
        JWebTokenImpl jWebToken = new JWebTokenImpl.Builder()
            .subject("1234")
            .expiration(exp)
            .audience(audience)
            .build();
        String token = jWebToken.toString();

        JWebTokenImpl incomingToken = new JWebTokenImpl(token);
        Assertions.assertTrue(incomingToken.isValid());
        Assertions.assertEquals("1234", incomingToken.getSubject());
        Assertions.assertEquals("admin", incomingToken.getAudience().get(0));
    }

    @Test
    void expire5Minutes() throws Exception {
        String[] audience = { "admin" };
        JWebTokenImpl jWebToken = new JWebTokenImpl.Builder()
            .subject("1234")
            .expirationPlusMinutes(5)
            .audience(audience)
            .build();
        String token = jWebToken.toString();

        JWebTokenImpl incomingToken = new JWebTokenImpl(token);
        Assertions.assertTrue(incomingToken.isValid());
        Assertions.assertEquals("1234", incomingToken.getSubject());
    }

    @Test
    void notBefore1Second() throws Exception {
        String[] audience = { "admin" };
        JWebTokenImpl jWebToken = new JWebTokenImpl.Builder()
            .subject("1234")
            .expirationPlusMinutes(5)
            .notBeforePlusSeconds(1)
            .audience(audience)
            .build();
        String token = jWebToken.toString();

        TimeUnit.SECONDS.sleep(2);
        JWebTokenImpl incomingToken = new JWebTokenImpl(token);
        Assertions.assertTrue(incomingToken.isValid());
        Assertions.assertEquals("1234", incomingToken.getSubject());
    }

    @Test
    @Disabled("for demonstration purposes")
    void expire1MinuteFail() throws Exception {
        String[] audience = { "admin" };
        JWebTokenImpl jWebToken = new JWebTokenImpl.Builder()
            .subject("1234")
            .expirationPlusMinutes(1)
            .audience(audience)
            .build();
        String token = jWebToken.toString();

        TimeUnit.MINUTES.sleep(2);
        JWebTokenImpl incomingToken = new JWebTokenImpl(token);
        Assertions.assertFalse(incomingToken.isValid());
    }

    @Test
    void addClaim() throws Exception {
        long exp = LocalDateTime.now().plusDays(90).toEpochSecond(ZoneOffset.UTC);
        String[] audience = { "admin" };
        JWebTokenImpl jWebToken = new JWebTokenImpl.Builder()
            .subject("1234")
            .claim("user", "rafex")
            .expiration(exp)
            .audience(audience)
            .build();
        String token = jWebToken.toString();

        JWebTokenImpl incomingToken = new JWebTokenImpl(token);
        Assertions.assertTrue(incomingToken.isValid());
        Assertions.assertEquals("rafex", incomingToken.get("user"));
        Assertions.assertEquals("admin", incomingToken.getAudience().get(0));
    }
}
