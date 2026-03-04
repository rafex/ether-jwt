package dev.rafex.ether.jwt;

/** Stable verification error/success codes. */
public enum VerificationCode {
    OK("ok"),
    BAD_FORMAT("bad_format"),
    BAD_SIGNATURE("bad_signature"),
    TOKEN_EXPIRED("token_expired"),
    TOKEN_NOT_BEFORE("token_not_before"),
    BAD_ISS("bad_iss"),
    BAD_AUD("bad_aud"),
    MISSING_SUB("missing_sub"),
    UNSUPPORTED_ALG("unsupported_alg"),
    BAD_TOKEN_TYPE("bad_token_type"),
    MISSING_CLIENT_ID("missing_client_id"),
    VERIFY_EXCEPTION("verify_exception");

    private final String code;

    VerificationCode(final String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }
}
