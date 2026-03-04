package dev.rafex.ether.jwt.internal;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.rafex.ether.jwt.TokenClaims;
import dev.rafex.ether.jwt.TokenType;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class ClaimsMapper {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ClaimsMapper() {
    }

    public static ObjectNode toPayload(final TokenClaims claims) {
        final ObjectNode node = MAPPER.createObjectNode();

        putString(node, "sub", claims.subject());
        putString(node, "iss", claims.issuer());
        putArray(node, "aud", claims.audience());
        putInstant(node, "iat", claims.issuedAt());
        putInstant(node, "exp", claims.expiresAt());
        putInstant(node, "nbf", claims.notBefore());
        putString(node, "jti", claims.jwtId());

        putArray(node, "roles", claims.roles());
        if (claims.tokenType() != null) {
            node.put("token_type", claims.tokenType().claimValue());
        }
        putString(node, "client_id", claims.clientId());

        for (final Map.Entry<String, Object> entry : claims.extras().entrySet()) {
            node.set(entry.getKey(), MAPPER.valueToTree(entry.getValue()));
        }
        return node;
    }

    public static TokenClaims fromPayload(final JsonNode payload) {
        final Map<String, Object> allClaims = MAPPER.convertValue(payload, new TypeReference<>() {
        });
        final Map<String, Object> extras = new LinkedHashMap<>(allClaims);
        extras.keySet().removeIf(ClaimsMapper::isKnownClaim);

        final String tokenTypeRaw = asText(payload.get("token_type"));
        return TokenClaims.builder()
                .subject(asText(payload.get("sub")))
                .issuer(asText(payload.get("iss")))
                .audience(readStringList(payload.get("aud")))
                .issuedAt(asInstant(payload.get("iat")))
                .expiresAt(asInstant(payload.get("exp")))
                .notBefore(asInstant(payload.get("nbf")))
                .jwtId(asText(payload.get("jti")))
                .roles(readStringList(payload.get("roles")))
                .tokenType(tokenTypeRaw == null ? null : TokenType.fromClaimValue(tokenTypeRaw))
                .clientId(asText(payload.get("client_id")))
                .extras(extras)
                .build();
    }

    public static String tokenTypeRaw(final JsonNode payload) {
        return asText(payload.get("token_type"));
    }

    private static boolean isKnownClaim(final String claim) {
        return "sub".equals(claim)
                || "iss".equals(claim)
                || "aud".equals(claim)
                || "exp".equals(claim)
                || "iat".equals(claim)
                || "nbf".equals(claim)
                || "jti".equals(claim)
                || "roles".equals(claim)
                || "token_type".equals(claim)
                || "client_id".equals(claim);
    }

    private static void putString(final ObjectNode node, final String name, final String value) {
        if (value != null && !value.isBlank()) {
            node.put(name, value);
        }
    }

    private static void putInstant(final ObjectNode node, final String name, final Instant value) {
        if (value != null) {
            node.put(name, value.getEpochSecond());
        }
    }

    private static void putArray(final ObjectNode node, final String name, final List<String> values) {
        if (values == null || values.isEmpty()) {
            return;
        }
        final ArrayNode arrayNode = node.putArray(name);
        for (final String value : values) {
            if (value != null && !value.isBlank()) {
                arrayNode.add(value);
            }
        }
    }

    private static String asText(final JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        final String text = node.asText();
        return text == null || text.isBlank() ? null : text;
    }

    private static Instant asInstant(final JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (!node.isIntegralNumber()) {
            throw new IllegalArgumentException("time claim must be epoch seconds");
        }
        return Instant.ofEpochSecond(node.asLong());
    }

    private static List<String> readStringList(final JsonNode node) {
        if (node == null || node.isNull()) {
            return List.of();
        }
        if (node.isArray()) {
            final List<String> values = new ArrayList<>();
            for (final JsonNode element : node) {
                final String text = asText(element);
                if (text != null) {
                    values.add(text);
                }
            }
            return values;
        }
        final String singleValue = asText(node);
        return singleValue == null ? List.of() : List.of(singleValue);
    }
}
