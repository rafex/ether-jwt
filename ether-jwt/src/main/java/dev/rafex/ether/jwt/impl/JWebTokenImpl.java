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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
// Removed MessageDigest, NoSuchAlgorithmException, InvalidKeyException imports as unused
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import dev.rafex.ether.json.JsonUtils;
import dev.rafex.ether.jwt.JWebToken;

public final class JWebTokenImpl implements JWebToken {

    private static final Logger LOGGER = Logger.getLogger(JWebTokenImpl.class.getName());
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String JWT_HEADER_HS = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    private static final String JWT_HEADER_RS = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    public static final String JWT_PROPERTIES = "jwt.properties";
    public static final String PRIVATE_KEY_PATH_PROP = "privateKeyPath";
    public static final String PUBLIC_KEY_PATH_PROP = "publicKeyPath";
    public static Properties PROPERTIES;
    private static String SECRET_KEY;

    private static PrivateKey PRIVATE_KEY;
    private static PublicKey PUBLIC_KEY;
    private static boolean USE_RSA = false;

    private JsonNode payload;
    private String signature;
    private String encodedHeader;

    static {
        try {
            // load secret or keys
            loadProperties(JWT_PROPERTIES, PROPERTIES);
            SECRET_KEY = PROPERTIES.getProperty("secret", UUID.randomUUID().toString());
            // try load RSA keys
            String privPath = PROPERTIES.getProperty(PRIVATE_KEY_PATH_PROP);
            String pubPath = PROPERTIES.getProperty(PUBLIC_KEY_PATH_PROP);
            if (privPath != null && pubPath != null) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                byte[] privBytes = stripPem(new String(Files.readAllBytes(Paths.get(privPath)), StandardCharsets.UTF_8));
                PRIVATE_KEY = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
                byte[] pubBytes = stripPem(new String(Files.readAllBytes(Paths.get(pubPath)), StandardCharsets.UTF_8));
                PUBLIC_KEY = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
                USE_RSA = true;
                LOGGER.info("JWT using RSA (RS256) signing");
            } else {
                LOGGER.info("JWT using HMAC (HS256) signing");
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "[WARN] Error initializing JWT keys: ", e);
        }
    }

    /**
     * Encode JWT header based on configured algorithm (HS256 or RS256).
     */
    private String encodeHeader() {
        String headerJson = USE_RSA ? JWT_HEADER_RS : JWT_HEADER_HS;
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
    }

    private JWebTokenImpl() {
        this.encodedHeader = encodeHeader();
    }

    private JWebTokenImpl(final Builder builder) throws Exception {
        this();
        this.payload = builder.payload;
        String data = encodedHeader + "." + encode(payload);
        this.signature = signData(data);
    }

    public JWebTokenImpl(final String token) throws Exception {
        this();
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid Token format");
        }
        this.encodedHeader = parts[0];
        this.payload = JsonUtils.parseTree(decode(parts[1]));
        if (!payload.has("exp")) {
            throw new IllegalArgumentException("Payload missing expiration: " + payload);
        }
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
            ArrayNode aud = (ArrayNode) payload.get("aud");
            aud.forEach(node -> list.add(node.asText()));
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
            if (payload.has("nbf") && payload.get("nbf").asLong() > now) {
                return false;
            }
            if (payload.get("exp").asLong() <= now) {
                return false;
            }
            String data = encodedHeader + "." + encode(payload);
            if (USE_RSA) {
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(PUBLIC_KEY);
                sig.update(data.getBytes(StandardCharsets.UTF_8));
                return sig.verify(Base64.getUrlDecoder().decode(signature));
            } else {
                return signature.equals(hmacSha256(data, SECRET_KEY));
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "[WARN] Error validating token: ", e);
            return false;
        }
    }

    private String signData(String data) throws Exception {
        if (USE_RSA) {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(PRIVATE_KEY);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign());
        }
        return hmacSha256(data, SECRET_KEY);
    }

    private String hmacSha256(final String data, final String secret) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, ex.getMessage(), ex);
            return null;
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

    private static String encode(JsonNode node) {
        return encode(node.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String decode(final String encoded) {
        return new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
    }

    private static byte[] stripPem(String pem) {
        String base64 = pem.replaceAll("-----BEGIN [^\r\n]+-----", "")
                           .replaceAll("-----END [^\r\n]+-----", "")
                           .replaceAll("\s+", "");
        return Base64.getDecoder().decode(base64);
    }

    static boolean loadProperties(final String resourceName, final Properties props) {
        final ClassLoader loader = Thread.currentThread().getContextClassLoader();
        final URL testProps = loader.getResource(resourceName);
        if (testProps != null) {
            try (InputStream in = testProps.openStream()) {
                PROPERTIES = new Properties();
                PROPERTIES.load(in);
                return true;
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "[WARN] Error loading properties config: ", e);
            }
        }
        return false;
    }

    public static final class Builder {
        private final ObjectNode payload;
        private final LocalDateTime NOW = LocalDateTime.now();

        public Builder() {
            payload = MAPPER.createObjectNode();
            payload.put("iss", "rafex.dev");
            payload.put("jti", UUID.randomUUID().toString());
            payload.put("iat", NOW.toEpochSecond(ZoneOffset.UTC));
        }

        public Builder issuer(final String issuer) {
            if (issuer != null && !issuer.isBlank()) {
                payload.put("iss", issuer);
            }
            return this;
        }

        public Builder subject(final String subject) {
            if (subject != null && !subject.isBlank()) {
                payload.put("sub", subject);
            }
            return this;
        }

        public Builder audience(final String[] audience) {
            if (audience != null && audience.length > 0) {
                ArrayNode arr = MAPPER.createArrayNode();
                for (String s : audience) {
                    arr.add(s);
                }
                payload.set("aud", arr);
            }
            return this;
        }

        public Builder expiration(final long expiration) {
            if (expiration > 0) {
                payload.put("exp", expiration);
            }
            return this;
        }

        public Builder expirationPlusDays(final int days) {
            if (days > 0) {
                payload.put("exp", NOW.plusDays(days).toEpochSecond(ZoneOffset.UTC));
            }
            return this;
        }

        public Builder expirationPlusHours(final int hours) {
            if (hours > 0) {
                payload.put("exp", NOW.plusHours(hours).toEpochSecond(ZoneOffset.UTC));
            }
            return this;
        }

        public Builder expirationPlusMinutes(final int minutes) {
            if (minutes > 0) {
                payload.put("exp", NOW.plusMinutes(minutes).toEpochSecond(ZoneOffset.UTC));
            }
            return this;
        }

        public Builder notBefore(final long notBefore) {
            if (notBefore > 0L) {
                payload.put("nbf", notBefore);
            }
            return this;
        }

        public Builder notBeforePlusSeconds(final int seconds) {
            if (seconds > 0) {
                payload.put("nbf", NOW.plusSeconds(seconds).toEpochSecond(ZoneOffset.UTC));
            }
            return this;
        }

        public Builder claim(final String property, final String value) {
            if (property != null && !property.isBlank() && value != null && !value.isBlank()) {
                payload.put(property, value);
            }
            return this;
        }

        public JWebTokenImpl build() throws Exception {
            return new JWebTokenImpl(this);
        }
    }
}
