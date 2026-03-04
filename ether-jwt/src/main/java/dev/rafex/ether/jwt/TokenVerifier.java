package dev.rafex.ether.jwt;

import java.time.Instant;

/** API for verifying JWT tokens. */
public interface TokenVerifier {
    VerificationResult verify(String token, Instant now);
}
