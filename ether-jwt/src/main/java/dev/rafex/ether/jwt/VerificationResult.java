package dev.rafex.ether.jwt;

import java.util.Objects;
import java.util.Optional;

/** Result returned by token verification. */
public final class VerificationResult {

    private final boolean ok;
    private final VerificationCode code;
    private final TokenClaims claims;

    private VerificationResult(final boolean ok, final VerificationCode code, final TokenClaims claims) {
        this.ok = ok;
        this.code = Objects.requireNonNull(code, "code");
        this.claims = claims;
    }

    public static VerificationResult ok(final TokenClaims claims) {
        return new VerificationResult(true, VerificationCode.OK, Objects.requireNonNull(claims, "claims"));
    }

    public static VerificationResult fail(final VerificationCode code) {
        return new VerificationResult(false, code, null);
    }

    public boolean ok() {
        return ok;
    }

    public VerificationCode verificationCode() {
        return code;
    }

    public String code() {
        return code.code();
    }

    public Optional<TokenClaims> claims() {
        return Optional.ofNullable(claims);
    }
}
