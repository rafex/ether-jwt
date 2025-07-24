package dev.rafex.ether.jwt;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;


public interface JWebToken {

    JsonNode getPayload();

    String getIssuer();

    String getSubject();

    List<String> getAudience();

    Long getExpiration();

    Long getNotBefore();

    Long getIssuedAt();

    String getJwtId();

    String get(String property);

    String getSignature();

    String getEncodedHeader();

    boolean isValid();

    String aJson();

}
