package dev.rafex.ether.jwt.internal;

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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class JwtCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JwtCodec() {
    }

    public static ParsedJwt parse(final String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("token is required");
        }
        final String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("invalid token format");
        }

        final JsonNode header = readJson(decode(parts[0]));
        final JsonNode payload = readJson(decode(parts[1]));
        return new ParsedJwt(parts[0], parts[1], parts[2], header, payload);
    }

    public static String encodeJson(final JsonNode node) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(node.toString().getBytes(StandardCharsets.UTF_8));
    }

    public static String encodeHeader(final String alg) {
        final ObjectNode header = MAPPER.createObjectNode();
        header.put("alg", alg);
        header.put("typ", "JWT");
        return encodeJson(header);
    }

    public static String decode(final String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    public static JsonNode readJson(final String json) {
        try {
            return MAPPER.readTree(json);
        } catch (final Exception e) {
            throw new IllegalArgumentException("invalid JSON", e);
        }
    }

    public static final class ParsedJwt {
        private final String encodedHeader;
        private final String encodedPayload;
        private final String encodedSignature;
        private final JsonNode header;
        private final JsonNode payload;

        ParsedJwt(
                final String encodedHeader,
                final String encodedPayload,
                final String encodedSignature,
                final JsonNode header,
                final JsonNode payload) {
            this.encodedHeader = encodedHeader;
            this.encodedPayload = encodedPayload;
            this.encodedSignature = encodedSignature;
            this.header = header;
            this.payload = payload;
        }

        public String encodedHeader() {
            return encodedHeader;
        }

        public String encodedPayload() {
            return encodedPayload;
        }

        public String encodedSignature() {
            return encodedSignature;
        }

        public JsonNode header() {
            return header;
        }

        public JsonNode payload() {
            return payload;
        }

        public String signingInput() {
            return encodedHeader + "." + encodedPayload;
        }
    }
}
