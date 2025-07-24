package dev.rafex.ether.jwt.impl;

import java.io.FileInputStream;

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
import java.nio.file.Files;
import java.nio.file.Paths;
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
    private static final String PRIVATE_KEY_PATH_PROP = "jwt.privateKeyPath";
    private static final String PUBLIC_KEY_PATH_PROP = "jwt.publicKeyPath";
    private static final String SECRET_PROP = "jwt.secret";
    private static final Properties PROPS = new Properties();

    static {
        // Override from system properties if present
        for (String p : new String[]{SECRET_PROP, PRIVATE_KEY_PATH_PROP, PUBLIC_KEY_PATH_PROP}) {
            String sys = System.getProperty(p);
            if (sys != null && !sys.isBlank()) {
                PROPS.setProperty(p, sys);
            }
        }
    }

    private static final String SECRET;

    private static PrivateKey PRIVATE_KEY;
    private static PublicKey PUBLIC_KEY;

    private static boolean USE_RSA = false;

    static {
        String key = null;
        final var loader = Thread.currentThread().getContextClassLoader();
        InputStream in = null;
        try {
            // First attempt to load from classpath
            in = loader.getResourceAsStream(JWT_PROPERTIES);
            if (in == null) {
                // Fallback: load from src/main/resources directory on file system
                final var propFile = Paths.get(System.getProperty("user.dir"), "src", "main", "resources", JWT_PROPERTIES);
                if (Files.exists(propFile)) {
                    in = new FileInputStream(propFile.toFile());
                }
            }
            if (in != null) {
                PROPS.load(in);
            } else {
                LOGGER.info("jwt.properties not found on classpath or file system, using default secret");
            }
        } catch (final Exception e) {
            LOGGER.log(Level.WARNING, "Error loading jwt.properties", e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (final Exception ignore) {
                }
            }
        }
        // After loading properties from file, re-apply system properties overrides
        for (String p : new String[]{SECRET_PROP, PRIVATE_KEY_PATH_PROP, PUBLIC_KEY_PATH_PROP}) {
            String sys = System.getProperty(p);
            if (sys != null && !sys.isBlank()) {
                PROPS.setProperty(p, sys);
            }
        }
        key = PROPS.getProperty(SECRET_PROP);
        if (key == null || key.isBlank()) {
            key = UUID.randomUUID().toString();
        }
        SECRET = key;
        // Try load RSA keys from filesystem if configured
        final var privRes = PROPS.getProperty(PRIVATE_KEY_PATH_PROP);
        final var pubRes = PROPS.getProperty(PUBLIC_KEY_PATH_PROP);
        if (privRes != null && pubRes != null) {
            try (InputStream pin = new FileInputStream(privRes); InputStream pub = new FileInputStream(pubRes)) {
                final var privBytes = stripPem(new String(pin.readAllBytes(), StandardCharsets.UTF_8));
                final var pubBytes = stripPem(new String(pub.readAllBytes(), StandardCharsets.UTF_8));
                final var kf = java.security.KeyFactory.getInstance("RSA");
                PRIVATE_KEY = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
                PUBLIC_KEY = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
                USE_RSA = true;
                LOGGER.info("JWT initialized with RSA (RS256)");
            } catch (final Exception e) {
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

    private JWebTokenImpl(final JsonNode payload, final String encodedHeader, final String signature) {
        this.payload = payload;
        this.encodedHeader = encodedHeader;
        this.signature = signature;
    }

    /**
     * Parse an existing JWT token string.
     */
    public JWebTokenImpl(final String token) {
        final var parts = token.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT format");
        }
        encodedHeader = parts[0];
        payload = JsonUtils.parseTree(decode(parts[1]));
        signature = parts[2];
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
        final List<String> list = new ArrayList<>();
        if (payload.has("aud") && payload.get("aud").isArray()) {
            final var arr = (ArrayNode) payload.get("aud");
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
    public String get(final String property) {
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
            final var now = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
            if ((payload.has("nbf") && payload.get("nbf").asLong() > now) || !payload.has("exp") || payload.get("exp").asLong() <= now) {
                return false;
            }
            final var body = encode(payload);
            final var data = encodedHeader + "." + body;
            if (USE_RSA) {
                final var sig = java.security.Signature.getInstance("SHA256withRSA");
                sig.initVerify(PUBLIC_KEY);
                sig.update(data.getBytes(StandardCharsets.UTF_8));
                return sig.verify(Base64.getUrlDecoder().decode(signature));
            }
            final var expected = signData(data);
            return expected.equals(signature);
        } catch (final Exception e) {
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

    private static String encode(final byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String encode(final JsonNode node) {
        return encode(node.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(final String s) {
        return new String(Base64.getUrlDecoder().decode(s), StandardCharsets.UTF_8);
    }

    private static String signData(final String data) throws Exception {
        if (USE_RSA) {
            final var sig = java.security.Signature.getInstance(SignType.SHA256WITHRSA.getValue());
            sig.initSign(PRIVATE_KEY);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign());
        }
        final var mac = Mac.getInstance(SignType.HMACSHA256.getValue());
        mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), SignType.HMACSHA256.getValue()));
        final var hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private static String getHeaderJson() {
        return USE_RSA ? AlgorithmType.RS256.getHeader() : AlgorithmType.HS256.getHeader();
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

        public Builder issuer(final String iss) {
            if (iss != null && !iss.isBlank()) {
                payload.put("iss", iss);
            }
            return this;
        }

        public Builder subject(final String sub) {
            if (sub != null && !sub.isBlank()) {
                payload.put("sub", sub);
            }
            return this;
        }

        public Builder audience(final String... aud) {
            if (aud != null && aud.length > 0) {
                final var arr = MAPPER.createArrayNode();
                for (final String s : aud) {
                    arr.add(s);
                }
                payload.set("aud", arr);
            }
            return this;
        }

        public Builder expiration(final long exp) {
            if (exp > 0) {
                payload.put("exp", exp);
            }
            return this;
        }

        public Builder expirationPlusMinutes(final int mins) {
            if (mins > 0) {
                payload.put("exp", now.plusMinutes(mins).toEpochSecond(ZoneOffset.UTC));
            }
            return this;
        }

        public Builder notBeforePlusSeconds(final int secs) {
            if (secs > 0) {
                payload.put("nbf", now.plusSeconds(secs).toEpochSecond(ZoneOffset.UTC));
            }
            return this;
        }

        public Builder claim(final String key, final String val) {
            if (key != null && !key.isBlank() && val != null && !val.isBlank()) {
                payload.put(key, val);
            }
            return this;
        }

        public JWebTokenImpl build() throws Exception {
            final var header = Base64.getUrlEncoder().withoutPadding().encodeToString(getHeaderJson().getBytes(StandardCharsets.UTF_8));
            final var body = encode(payload);
            final var sig = signData(header + "." + body);
            final JsonNode pl = payload;
            return new JWebTokenImpl(pl, header, sig);
        }
    }

    private static byte[] stripPem(final String pem) {
        // remove PEM headers/footers and whitespace
        final var lines = pem.replaceAll("-----BEGIN (.*)-----", "").replaceAll("-----END (.*)-----", "").split("\\r?\\n");
        final var sb = new StringBuilder();
        for (final String line : lines) {
            sb.append(line.trim());
        }
        return Base64.getDecoder().decode(sb.toString());
    }
}
