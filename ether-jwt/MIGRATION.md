# ether-jwt Migration Guide (legacy -> reusable API)

## Why this change
`ether-jwt` now exposes reusable, transport-agnostic JWT APIs focused on issuance, verification, typed claims and stable verification codes.

## Old API -> New API
- `new JWebTokenImpl.Builder()...build()` -> `new DefaultTokenIssuer(jwtConfig).issue(TokenSpec.builder()...build())`
- `new JWebTokenImpl(token).isValid()` -> `new DefaultTokenVerifier(jwtConfig).verify(token, Instant.now())`
- `JWebToken#get*()` -> `VerificationResult.claims()` -> `TokenClaims`

Legacy classes remain available:
- `JWebToken`
- `JWebTokenImpl`

Both are marked `@Deprecated` and internally bridged to the new engine.

## New core types
- `JwtConfig`: validation/signature config (issuer, audience, skew, required claims).
- `KeyProvider`: explicit key source (`hmac`, `rsa`, `rsaVerifier`).
- `TokenSpec`: builder for token issuance input.
- `TokenIssuer`/`DefaultTokenIssuer`: signs tokens.
- `TokenVerifier`/`DefaultTokenVerifier`: verifies tokens.
- `VerificationResult`: rich result with `ok`, `code`, and normalized `TokenClaims`.
- `TokenClaims`: typed claims (`sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `roles`, `token_type`, `client_id`, extras).

## Verification codes
Stable codes include:
- `ok`
- `bad_format`
- `bad_signature`
- `token_expired`
- `token_not_before`
- `bad_iss`
- `bad_aud`
- `missing_sub`
- `unsupported_alg`
- `bad_token_type`
- `missing_client_id`
- `verify_exception`

## Example: user token (kiwi-compatible)
```java
JwtConfig config = JwtConfig.builder(KeyProvider.hmac(secret))
        .expectedIssuer("auth.rafex.dev")
        .expectedAudience("kiwi-api")
        .build();

TokenIssuer issuer = new DefaultTokenIssuer(config);
String token = issuer.issue(TokenSpec.builder()
        .subject("user-123")
        .issuer("auth.rafex.dev")
        .audience("kiwi-api")
        .ttl(Duration.ofMinutes(15))
        .tokenType(TokenType.USER)
        .roles("admin", "viewer")
        .build());

TokenVerifier verifier = new DefaultTokenVerifier(config);
VerificationResult result = verifier.verify(token, Instant.now());
if (result.ok()) {
    TokenClaims claims = result.claims().orElseThrow();
    // use claims in middleware
}
```

## Example: app token with `client_id`
```java
String appToken = issuer.issue(TokenSpec.builder()
        .subject("svc-gateway")
        .issuer("auth.rafex.dev")
        .audience("kiwi-api")
        .ttl(Duration.ofMinutes(10))
        .tokenType(TokenType.APP)
        .clientId("kiwi-gateway")
        .roles("svc")
        .build());
```

## Integrator notes (kiwi)
- Avoid `isValid()` and branch on `VerificationResult.code()`.
- Build a middleware context from `TokenClaims`.
- Configure secrets/keys explicitly via app config. Do not rely on implicit files.
- Keep legacy API only during migration windows.
