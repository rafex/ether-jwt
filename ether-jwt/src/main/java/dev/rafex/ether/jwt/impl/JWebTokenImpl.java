package dev.rafex.ether.jwt.impl;

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

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import dev.rafex.ether.json.JsonUtils;
import dev.rafex.ether.jwt.JWebToken;
import dev.rafex.ether.jwt.enums.AlgorithmType;
import dev.rafex.ether.jwt.enums.SignType;

/**
 * HMAC-SHA256 JSON Web Token implementation.
 */
public final class JWebTokenImpl implements JWebToken {

    private static final Logger LOGGER = Logger.getLogger(JWebTokenImpl.class.getName());
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String JWT_PROPERTIES = "jwt.properties";
    private static final String PRIVATE_KEY_PATH_PROP = "privateKeyPath";
    private static final String PUBLIC_KEY_PATH_PROP = "publicKeyPath";
    private static final String SECRET_PROP = "secret";
    private static final Properties PROPS = new Properties();
    private static final String SECRET;

    private static PrivateKey PRIVATE_KEY;
    private static PublicKey PUBLIC_KEY;

    private static boolean USE_RSA = false;

    static {
        String key = null;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        try (InputStream in = loader.getResourceAsStream(JWT_PROPERTIES)) {
            if (in != null) {
                PROPS.load(in);
                key = PROPS.getProperty(SECRET_PROP);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error loading jwt.properties", e);
        }
        if (key == null || key.isBlank()) {
            key = UUID.randomUUID().toString();
        }
        SECRET = key;
        // Try load RSA keys from classpath if configured
        String privRes = PROPS.getProperty(PRIVATE_KEY_PATH_PROP);
        String pubRes = PROPS.getProperty(PUBLIC_KEY_PATH_PROP);
        if (privRes != null && pubRes != null) {
            try (InputStream pin = loader.getResourceAsStream(privRes);
                 InputStream pub = loader.getResourceAsStream(pubRes)) {
                if (pin != null && pub != null) {
                    byte[] privBytes = stripPem(new String(pin.readAllBytes(), StandardCharsets.UTF_8));
                    byte[] pubBytes = stripPem(new String(pub.readAllBytes(), StandardCharsets.UTF_8));
                    var kf = java.security.KeyFactory.getInstance("RSA");
                    PRIVATE_KEY = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
                    PUBLIC_KEY = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
                    USE_RSA = true;
                    LOGGER.info("JWT initialized with RSA (RS256)");
                }
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Error loading RSA keys, fallback to HMAC", e);
                USE_RSA = false;
            }
        }
        if (!USE_RSA) {
            LOGGER.info("JWT using HMAC (HS256)");
        }
    }

    private final JsonNode payload;
    private final String signature;
    private final String encodedHeader;

    private JWebTokenImpl(JsonNode payload, String encodedHeader, String signature) {
        this.payload = payload;
        this.encodedHeader = encodedHeader;
        this.signature = signature;
    }

    /**
     * Parse an existing JWT token string.
     */
    public JWebTokenImpl(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format");
        }
        this.encodedHeader = parts[0];
        this.payload = JsonUtils.parseTree(decode(parts[1]));
        this.signature = parts[2];
    }

    @Override
    public JsonNode getPayload() {
        return payload;
    }

    @Override
    public String getIssuer() {
        return payload.has("iss") ? payload.get("iss").asText() : "";
    }

    @Override
    public String getSubject() {
        return payload.has("sub") ? payload.get("sub").asText() : "";
    }

    @Override
    public List<String> getAudience() {
        List<String> list = new ArrayList<>();
        if (payload.has("aud") && payload.get("aud").isArray()) {
            ArrayNode arr = (ArrayNode) payload.get("aud");
            arr.forEach(n -> list.add(n.asText()));
        }
        return list;
    }

    @Override
    public Long getExpiration() {
        return payload.has("exp") ? payload.get("exp").asLong() : 0L;
    }

    @Override
    public Long getNotBefore() {
        return payload.has("nbf") ? payload.get("nbf").asLong() : 0L;
    }

    @Override
    public Long getIssuedAt() {
        return payload.has("iat") ? payload.get("iat").asLong() : 0L;
    }

    @Override
    public String getJwtId() {
        return payload.has("jti") ? payload.get("jti").asText() : "";
    }

    @Override
    public String get(String property) {
        return payload.has(property) ? payload.get(property).asText() : "";
    }

    @Override
    public String getSignature() {
        return signature;
    }

    @Override
    public String getEncodedHeader() {
        return encodedHeader;
    }

    @Override
    public boolean isValid() {
        try {
            long now = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
            if (payload.has("nbf") && payload.get("nbf").asLong() > now) return false;
            if (!payload.has("exp") || payload.get("exp").asLong() <= now) return false;
            String body = encode(payload);
            String data = encodedHeader + "." + body;
            if (USE_RSA) {
                java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
                sig.initVerify(PUBLIC_KEY);
                sig.update(data.getBytes(StandardCharsets.UTF_8));
                return sig.verify(Base64.getUrlDecoder().decode(signature));
            } else {
                String expected = signData(data);
                return expected.equals(signature);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error validating JWT", e);
            return false;
        }
    }

    @Override
    public String aJson() {
        return JsonUtils.toJson(payload);
    }

    @Override
    public String toString() {
        return encodedHeader + "." + encode(payload) + "." + signature;
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String encode(JsonNode node) {
        return encode(node.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String s) {
        return new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8);
    }

    private static String signData(String data) throws Exception {
        if (USE_RSA) {
            java.security.Signature sig = java.security.Signature.getInstance(SignType.SHA256WITHRSA.getValue());
            sig.initSign(PRIVATE_KEY);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign());
        } else {
            Mac mac = Mac.getInstance(SignType.HMACSHA256.getValue());
            mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), SignType.HMACSHA256.getValue()));
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        }
    }

    private static String getHeaderJson() {
        return USE_RSA
            ? AlgorithmType.RS256.getHeader()
            : AlgorithmType.HS256.getHeader();
    }

    /** Builder for creating JWT tokens. */
    public static class Builder {
        private final ObjectNode payload = MAPPER.createObjectNode();
        private final LocalDateTime now = LocalDateTime.now();

        public Builder() {
            payload.put("iss", "rafex.dev");
            payload.put("jti", UUID.randomUUID().toString());
            payload.put("iat", now.toEpochSecond(ZoneOffset.UTC));
        }

        public Builder issuer(String iss) {
            if (iss != null && !iss.isBlank()) payload.put("iss", iss);
            return this;
        }

        public Builder subject(String sub) {
            if (sub != null && !sub.isBlank()) payload.put("sub", sub);
            return this;
        }

        public Builder audience(String... aud) {
            if (aud != null && aud.length > 0) {
                ArrayNode arr = MAPPER.createArrayNode();
                for (String s : aud) arr.add(s);
                payload.set("aud", arr);
            }
            return this;
        }

        public Builder expiration(long exp) {
            if (exp > 0) payload.put("exp", exp);
            return this;
        }

        public Builder expirationPlusMinutes(int mins) {
            if (mins > 0) payload.put("exp", now.plusMinutes(mins).toEpochSecond(ZoneOffset.UTC));
            return this;
        }

        public Builder notBeforePlusSeconds(int secs) {
            if (secs > 0) payload.put("nbf", now.plusSeconds(secs).toEpochSecond(ZoneOffset.UTC));
            return this;
        }

        public Builder claim(String key, String val) {
            if (key != null && !key.isBlank() && val != null && !val.isBlank()) payload.put(key, val);
            return this;
        }

        public JWebTokenImpl build() throws Exception {
            String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(getHeaderJson().getBytes(StandardCharsets.UTF_8));
            String body = encode(payload);
            String sig = signData(header + "." + body);
            JsonNode pl = payload;
            return new JWebTokenImpl(pl, header, sig);
        }
    }

    private static byte[] stripPem(String pem) {
        // remove PEM headers/footers and whitespace
        String[] lines = pem
            .replaceAll("-----BEGIN (.*)-----", "")
            .replaceAll("-----END (.*)-----", "")
            .split("\\r?\\n");
        StringBuilder sb = new StringBuilder();
        for (String line : lines) sb.append(line.trim());
        return Base64.getDecoder().decode(sb.toString());
    }
}
