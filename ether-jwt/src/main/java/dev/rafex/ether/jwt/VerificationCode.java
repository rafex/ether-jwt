package dev.rafex.ether.jwt;

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
