# ether-jwt

**Group ID:** `dev.rafex.ether.jwt`
**Artifact ID:** `ether-jwt`
**Packaging:** `jar`
**License:** MIT

`ether-jwt` is a lightweight, zero-framework JWT library for Java 21. It provides a clean interface-driven API for issuing and verifying JSON Web Tokens using HMAC-SHA256 (HS256) or RSA (RS256). There are no annotation processors, no reflection magic, and no external JWT framework dependencies beyond `ether-json`.

The library is designed for the scenario where you control both the issuing service and the verifying service (or have access to the public key in the RS256 case). It is intentionally not a full OIDC/OAuth2 library.

---

## Table of Contents

1. [Maven dependency](#maven-dependency)
2. [Architecture overview](#architecture-overview)
3. [Token lifecycle sequence](#token-lifecycle-sequence)
4. [Core types at a glance](#core-types-at-a-glance)
5. [Configure JwtConfig with HS256](#configure-jwtconfig-with-hs256)
6. [Issue a token with subject, roles, and custom claims](#issue-a-token-with-subject-roles-and-custom-claims)
7. [Verify a token and extract claims](#verify-a-token-and-extract-claims)
8. [Handle verification failures gracefully](#handle-verification-failures-gracefully)
9. [RS256 with RSA public/private keys](#rs256-with-rsa-publicprivate-keys)
10. [TokenType: USER vs APP tokens](#tokentype-user-vs-app-tokens)
11. [Clock skew tolerance](#clock-skew-tolerance)
12. [All VerificationCode values](#all-verificationcode-values)
13. [Integration example: Jetty handler middleware](#integration-example-jetty-handler-middleware)

---

## Maven dependency

```xml
<dependency>
    <groupId>dev.rafex.ether.jwt</groupId>
    <artifactId>ether-jwt</artifactId>
    <version>8.0.0-SNAPSHOT</version>
</dependency>
```

`ether-jwt` depends on `ether-json` which is pulled in transitively. If your project inherits from `ether-parent` or imports it as a BOM, omit the `<version>` tag.

---

## Architecture overview

```mermaid
classDiagram
    direction TB

    class TokenIssuer {
        <<interface>>
        +issue(TokenSpec) String
    }

    class TokenVerifier {
        <<interface>>
        +verify(String token, Instant now) VerificationResult
    }

    class DefaultTokenIssuer {
        -JwtConfig config
        +DefaultTokenIssuer(JwtConfig)
    }

    class DefaultTokenVerifier {
        -JwtConfig config
        +DefaultTokenVerifier(JwtConfig)
    }

    class JwtConfig {
        -KeyProvider keyProvider
        -String expectedIssuer
        -Set~String~ expectedAudience
        -Duration clockSkew
        -boolean validateExpiration
        -boolean requireSubject
        +static builder(KeyProvider) Builder
    }

    class KeyProvider {
        <<interface>>
        +algorithm() JwtAlgorithm
        +hmacSecret() byte[]
        +privateKey() PrivateKey
        +publicKey() PublicKey
        +static hmac(String) KeyProvider
        +static rsa(PrivateKey, PublicKey) KeyProvider
        +static rsaVerifier(PublicKey) KeyProvider
    }

    class JwtAlgorithm {
        <<enum>>
        HS256
        RS256
    }

    class TokenSpec {
        -TokenClaims claims
        +static builder() Builder
        +claims() TokenClaims
    }

    class TokenClaims {
        +subject() String
        +issuer() String
        +audience() List~String~
        +expiresAt() Instant
        +issuedAt() Instant
        +roles() List~String~
        +tokenType() TokenType
        +clientId() String
        +extras() Map~String,Object~
    }

    class VerificationResult {
        +ok() boolean
        +verificationCode() VerificationCode
        +code() String
        +claims() Optional~TokenClaims~
        +static ok(TokenClaims) VerificationResult
        +static fail(VerificationCode) VerificationResult
    }

    class VerificationCode {
        <<enum>>
        OK
        BAD_FORMAT
        BAD_SIGNATURE
        TOKEN_EXPIRED
        TOKEN_NOT_BEFORE
        BAD_ISS
        BAD_AUD
        MISSING_SUB
        UNSUPPORTED_ALG
        BAD_TOKEN_TYPE
        MISSING_CLIENT_ID
        VERIFY_EXCEPTION
    }

    TokenIssuer <|.. DefaultTokenIssuer
    TokenVerifier <|.. DefaultTokenVerifier
    DefaultTokenIssuer --> JwtConfig
    DefaultTokenVerifier --> JwtConfig
    JwtConfig --> KeyProvider
    KeyProvider --> JwtAlgorithm
    TokenIssuer ..> TokenSpec : takes
    TokenSpec --> TokenClaims
    TokenVerifier ..> VerificationResult : returns
    VerificationResult --> TokenClaims
    VerificationResult --> VerificationCode
```

---

## Token lifecycle sequence

```mermaid
sequenceDiagram
    participant Client
    participant AuthService
    participant API

    Client->>AuthService: POST /auth/login (credentials)
    AuthService->>AuthService: Validate credentials
    AuthService->>AuthService: DefaultTokenIssuer.issue(TokenSpec)
    AuthService-->>Client: { "token": "eyJ..." }

    Client->>API: GET /api/orders\nAuthorization: Bearer eyJ...
    API->>API: Extract token from header
    API->>API: DefaultTokenVerifier.verify(token, Instant.now())
    alt VerificationResult.ok() == true
        API->>API: Extract subject, roles from TokenClaims
        API-->>Client: 200 OK + response body
    else VerificationResult.ok() == false
        API-->>Client: 401 Unauthorized\n{ "code": "token_expired" }
    end
```

---

## Core types at a glance

| Type | Role |
|---|---|
| `TokenIssuer` | Interface for creating JWT tokens from a `TokenSpec` |
| `TokenVerifier` | Interface for verifying a raw JWT string and returning a `VerificationResult` |
| `DefaultTokenIssuer` | Standard implementation backed by `JwtConfig` |
| `DefaultTokenVerifier` | Standard implementation backed by `JwtConfig` |
| `JwtConfig` | Immutable configuration: keys, issuer, audience, clock skew, flags |
| `KeyProvider` | Supplies the cryptographic material (HMAC secret or RSA key pair) |
| `JwtAlgorithm` | Enum: `HS256` or `RS256` |
| `TokenSpec` | Builder that collects all claims before issuing |
| `TokenClaims` | Typed, immutable view of extracted JWT claims |
| `VerificationResult` | Outcome of a verification: `ok()` flag, `VerificationCode`, optional `TokenClaims` |
| `VerificationCode` | Stable string-code enum for all failure reasons |
| `TokenType` | Enum: `USER` or `APP` |

---

## Configure JwtConfig with HS256

`JwtConfig` is built with a fluent builder. The only required parameter is a `KeyProvider`. Everything else has safe defaults.

```java
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;

import java.time.Duration;

// Minimal HS256 config — only a secret is required
JwtConfig minimal = JwtConfig.builder(
        KeyProvider.hmac("my-secret-key-at-least-32-chars-long"))
    .build();

// Full HS256 config for a production auth service
JwtConfig config = JwtConfig.builder(
        KeyProvider.hmac("my-secret-key-at-least-32-chars-long"))
    .expectedIssuer("auth.example.com")
    .expectedAudience("api.example.com", "admin.example.com")
    .clockSkew(Duration.ofSeconds(30))   // tolerate up to 30s of clock drift
    .validateExpiration(true)            // reject expired tokens (default: true)
    .validateNotBefore(true)             // honour nbf claim (default: true)
    .requireExpiration(true)             // reject tokens with no exp claim (default: true)
    .requireSubject(true)                // reject tokens with no sub claim (default: true)
    .requireClientIdForAppTokens(true)   // enforce clientId for APP tokens (default: true)
    .build();
```

---

## Issue a token with subject, roles, and custom claims

`TokenSpec.builder()` gives you a complete DSL for building the claims payload. A `subject` and either `ttl` or `expiresAt` are required; everything else is optional.

```java
import dev.rafex.ether.jwt.DefaultTokenIssuer;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenSpec;
import dev.rafex.ether.jwt.TokenType;

import java.time.Duration;
import java.util.List;

JwtConfig config = JwtConfig.builder(
        KeyProvider.hmac("my-secret-key-at-least-32-chars-long"))
    .expectedIssuer("auth.example.com")
    .expectedAudience("api.example.com")
    .build();

var issuer = new DefaultTokenIssuer(config);

// Issue a user token valid for 15 minutes
String token = issuer.issue(
    TokenSpec.builder()
        .subject("user-42")
        .issuer("auth.example.com")
        .audience("api.example.com")
        .ttl(Duration.ofMinutes(15))
        .tokenType(TokenType.USER)
        .roles("admin", "editor")
        // Custom claims are included in the JWT payload
        .claim("tenant_id", "acme-corp")
        .claim("feature_flags", List.of("payments", "reports"))
        .claim("plan", "enterprise")
        .build()
);

System.out.println(token);
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Issue a service-to-service APP token

```java
String appToken = issuer.issue(
    TokenSpec.builder()
        .subject("svc-gateway")
        .issuer("auth.example.com")
        .audience("api.example.com")
        .ttl(Duration.ofHours(1))
        .tokenType(TokenType.APP)
        .clientId("gateway-service-id-abc123") // required for APP tokens
        .roles("svc")
        .build()
);
```

---

## Verify a token and extract claims

`DefaultTokenVerifier.verify()` takes the raw token string and the current `Instant` (allowing deterministic testing without mocking system time).

```java
import dev.rafex.ether.jwt.DefaultTokenVerifier;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenClaims;
import dev.rafex.ether.jwt.VerificationResult;

import java.time.Instant;
import java.util.List;

JwtConfig config = JwtConfig.builder(
        KeyProvider.hmac("my-secret-key-at-least-32-chars-long"))
    .expectedIssuer("auth.example.com")
    .expectedAudience("api.example.com")
    .build();

var verifier = new DefaultTokenVerifier(config);

// Verify using the current wall clock
VerificationResult result = verifier.verify(incomingToken, Instant.now());

if (result.ok()) {
    TokenClaims claims = result.claims().orElseThrow();

    String subject  = claims.subject();         // "user-42"
    List<String> roles = claims.roles();        // ["admin", "editor"]
    String tenant   = (String) claims.extras()
                          .get("tenant_id");    // "acme-corp"
    Instant expires = claims.expiresAt();

    System.out.println("Token valid for subject: " + subject);
    System.out.println("Roles: " + roles);
} else {
    System.err.println("Token rejected: " + result.code());
    // e.g. "token_expired", "bad_signature", "bad_iss"
}
```

---

## Handle verification failures gracefully

Each failure reason is a stable `VerificationCode` enum value with a corresponding string `code()`. Map the code to an appropriate HTTP status code or error response.

```java
import dev.rafex.ether.jwt.VerificationCode;
import dev.rafex.ether.jwt.VerificationResult;

import java.time.Instant;

public record AuthResult(int httpStatus, String errorCode, String errorMessage) {}

public AuthResult authenticate(String rawToken) {
    var result = verifier.verify(rawToken, Instant.now());

    if (result.ok()) {
        return null; // no error
    }

    return switch (result.verificationCode()) {
        case BAD_FORMAT      -> new AuthResult(400, result.code(), "Token is malformed");
        case BAD_SIGNATURE   -> new AuthResult(401, result.code(), "Token signature is invalid");
        case TOKEN_EXPIRED   -> new AuthResult(401, result.code(), "Token has expired");
        case TOKEN_NOT_BEFORE -> new AuthResult(401, result.code(), "Token is not yet valid");
        case BAD_ISS         -> new AuthResult(401, result.code(), "Token issuer is not trusted");
        case BAD_AUD         -> new AuthResult(401, result.code(), "Token audience does not match");
        case MISSING_SUB     -> new AuthResult(401, result.code(), "Token is missing subject claim");
        case UNSUPPORTED_ALG -> new AuthResult(401, result.code(), "Signing algorithm is not supported");
        case MISSING_CLIENT_ID -> new AuthResult(401, result.code(), "APP token missing client_id");
        case VERIFY_EXCEPTION -> new AuthResult(500, result.code(), "Internal verification error");
        default              -> new AuthResult(401, result.code(), "Token is not valid");
    };
}
```

### Test-specific time control

Because `verify()` accepts an explicit `Instant`, you can test time-sensitive scenarios without mocking static methods:

```java
import java.time.Instant;

Instant issuedAt = Instant.parse("2026-01-01T12:00:00Z");

String token = issuer.issue(
    TokenSpec.builder()
        .subject("u1")
        .issuer("auth.example.com")
        .issuedAt(issuedAt)
        .ttl(Duration.ofMinutes(5))
        .build()
);

// Verify at a point 3 minutes after issuance — should pass
Assertions.assertTrue(
    verifier.verify(token, issuedAt.plusSeconds(180)).ok()
);

// Verify 10 minutes after issuance — should be expired
Assertions.assertEquals(
    VerificationCode.TOKEN_EXPIRED,
    verifier.verify(token, issuedAt.plusSeconds(600)).verificationCode()
);
```

---

## RS256 with RSA public/private keys

RS256 is appropriate when the service that issues tokens is different from the service that verifies them. The issuer keeps the private key; verifiers only need the public key.

### Generate an RSA key pair (for testing)

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
gen.initialize(2048);
KeyPair keyPair = gen.generateKeyPair();

PrivateKey privateKey = keyPair.getPrivate();
PublicKey  publicKey  = keyPair.getPublic();
```

### Issuer configuration (holds the private key)

```java
import dev.rafex.ether.jwt.DefaultTokenIssuer;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenSpec;
import dev.rafex.ether.jwt.TokenType;

import java.time.Duration;

JwtConfig issuerConfig = JwtConfig.builder(
        KeyProvider.rsa(privateKey, publicKey))
    .expectedIssuer("auth.example.com")
    .expectedAudience("api.example.com")
    .build();

var issuer = new DefaultTokenIssuer(issuerConfig);

String token = issuer.issue(
    TokenSpec.builder()
        .subject("user-99")
        .issuer("auth.example.com")
        .audience("api.example.com")
        .ttl(Duration.ofHours(1))
        .tokenType(TokenType.USER)
        .roles("viewer")
        .build()
);
```

### Verifier configuration (holds only the public key)

```java
import dev.rafex.ether.jwt.DefaultTokenVerifier;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.VerificationResult;

import java.time.Instant;

// Only the public key is needed for verification
JwtConfig verifierConfig = JwtConfig.builder(
        KeyProvider.rsaVerifier(publicKey))
    .expectedIssuer("auth.example.com")
    .expectedAudience("api.example.com")
    .build();

var verifier = new DefaultTokenVerifier(verifierConfig);
VerificationResult result = verifier.verify(token, Instant.now());

System.out.println(result.ok()); // true
System.out.println(result.claims().orElseThrow().subject()); // "user-99"
```

### Loading keys from PEM files in production

```java
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// Load private key (PKCS8 DER or base64-encoded PEM minus headers)
private static PrivateKey loadPrivateKey(Path pemPath) throws Exception {
    var pem = Files.readString(pemPath)
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replaceAll("\\s+", "");
    var decoded = Base64.getDecoder().decode(pem);
    var spec = new PKCS8EncodedKeySpec(decoded);
    return KeyFactory.getInstance("RSA").generatePrivate(spec);
}

// Load public key (X.509 DER or base64-encoded PEM minus headers)
private static PublicKey loadPublicKey(Path pemPath) throws Exception {
    var pem = Files.readString(pemPath)
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s+", "");
    var decoded = Base64.getDecoder().decode(pem);
    var spec = new X509EncodedKeySpec(decoded);
    return KeyFactory.getInstance("RSA").generatePublic(spec);
}

// Usage
PrivateKey priv = loadPrivateKey(Path.of("/secrets/jwt-private.pem"));
PublicKey  pub  = loadPublicKey(Path.of("/secrets/jwt-public.pem"));

JwtConfig config = JwtConfig.builder(KeyProvider.rsa(priv, pub))
    .expectedIssuer("auth.example.com")
    .build();
```

---

## TokenType: USER vs APP tokens

`TokenType` distinguishes end-user tokens from service-to-service tokens.

| `TokenType` | Represents | Notes |
|---|---|---|
| `USER` | An authenticated human user | Normal tokens; no `clientId` required |
| `APP` | A machine/service client | Requires `clientId` when `requireClientIdForAppTokens = true` |

The verifier checks that APP tokens carry a non-blank `clientId` claim. If the claim is missing, `VerificationResult` returns `MISSING_CLIENT_ID`.

```java
// APP token without clientId — verification will fail
String appToken = issuer.issue(
    TokenSpec.builder()
        .subject("svc-gateway")
        .issuer("auth.example.com")
        .ttl(Duration.ofMinutes(10))
        .tokenType(TokenType.APP)
        // .clientId("...") intentionally omitted
        .build()
);

VerificationResult result = verifier.verify(appToken, Instant.now());
System.out.println(result.verificationCode()); // MISSING_CLIENT_ID
```

---

## Clock skew tolerance

In distributed systems, individual nodes may have clocks that are slightly out of sync. `clockSkew` allows you to tolerate a configurable amount of drift on both expiry and `not-before` checks.

```java
JwtConfig config = JwtConfig.builder(KeyProvider.hmac("my-secret"))
    .clockSkew(Duration.ofSeconds(30)) // accept tokens up to 30s past expiry
    .build();
```

A token that expired 20 seconds ago will still pass verification with a 30-second skew. A token that expired 60 seconds ago will fail with `TOKEN_EXPIRED`.

---

## All VerificationCode values

| Enum constant | String code | When returned |
|---|---|---|
| `OK` | `ok` | Token is valid |
| `BAD_FORMAT` | `bad_format` | Token does not have three dot-separated parts |
| `BAD_SIGNATURE` | `bad_signature` | HMAC or RSA signature does not match |
| `TOKEN_EXPIRED` | `token_expired` | `exp` claim is in the past (beyond clock skew) |
| `TOKEN_NOT_BEFORE` | `token_not_before` | `nbf` claim is in the future (beyond clock skew) |
| `BAD_ISS` | `bad_iss` | `iss` claim does not match `expectedIssuer` |
| `BAD_AUD` | `bad_aud` | `aud` claim does not include any `expectedAudience` value |
| `MISSING_SUB` | `missing_sub` | `sub` claim is absent and `requireSubject = true` |
| `UNSUPPORTED_ALG` | `unsupported_alg` | `alg` header value is not HS256 or RS256 |
| `BAD_TOKEN_TYPE` | `bad_token_type` | `token_type` claim is present but unrecognised |
| `MISSING_CLIENT_ID` | `missing_client_id` | APP token is missing `client_id` claim |
| `VERIFY_EXCEPTION` | `verify_exception` | Unexpected exception during verification |

---

## Integration example: Jetty handler middleware

This example shows how to wire `DefaultTokenVerifier` into a Jetty 12 request handler as a simple authentication filter.

```java
import dev.rafex.ether.jwt.DefaultTokenVerifier;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenClaims;
import dev.rafex.ether.jwt.VerificationResult;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.Callback;

import java.time.Instant;

public class JwtAuthHandler extends Handler.Wrapper {

    private final DefaultTokenVerifier verifier;

    public JwtAuthHandler(JwtConfig config, Handler next) {
        super(next);
        this.verifier = new DefaultTokenVerifier(config);
    }

    @Override
    public boolean handle(Request request, Response response, Callback callback)
            throws Exception {

        var authHeader = request.getHeaders().get("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(401);
            callback.succeeded();
            return true;
        }

        var token = authHeader.substring("Bearer ".length()).strip();
        var result = verifier.verify(token, Instant.now());

        if (!result.ok()) {
            response.setStatus(401);
            response.getHeaders().put("X-Auth-Error", result.code());
            callback.succeeded();
            return true;
        }

        // Attach claims to request attributes for downstream handlers
        TokenClaims claims = result.claims().orElseThrow();
        request.setAttribute("auth.subject", claims.subject());
        request.setAttribute("auth.roles",   claims.roles());

        // Delegate to the next handler
        return super.handle(request, response, callback);
    }
}

// Wire it up at startup:
JwtConfig config = JwtConfig.builder(
        KeyProvider.hmac("my-secret-key-at-least-32-chars-long"))
    .expectedIssuer("auth.example.com")
    .expectedAudience("api.example.com")
    .clockSkew(Duration.ofSeconds(15))
    .build();

var server = new org.eclipse.jetty.server.Server(8080);
server.setHandler(new JwtAuthHandler(config, yourApiHandler));
server.start();
```
