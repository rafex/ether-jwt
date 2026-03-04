package dev.rafex.ether.jwt;

/** API for issuing JWT tokens. */
public interface TokenIssuer {
    String issue(TokenSpec tokenSpec);
}
