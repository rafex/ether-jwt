# ether-jwt

## Español

**ether-jwt** es una librería Java liviana para crear y verificar JSON Web Tokens (JWT) usando HMAC-SHA256.

### Características

- Generación y firma de JWT con API fluida mediante `Builder`.
- Análisis y validación de cadenas JWT.
- Soporte de claims estándar: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`.
- Añadir claims personalizados de tipo cadena.
- Codificación Base64 URL-safe sin padding.
- Verificación de firma con HMAC-SHA256.

### Uso rápido

#### Crear un JWT
```java
import dev.rafex.ether.jwt.impl.JWebTokenImpl;

String token = new JWebTokenImpl.Builder()
    .issuer("mi-servicio")          // por defecto "rafex.dev"
    .subject("usuario123")
    .audience(new String[]{"admin", "user"})
    .expirationPlusDays(7)
    .claim("rol", "admin")         // claim personalizado
    .build()
    .toString();
```

#### Analizar y validar un JWT
```java
import dev.rafex.ether.jwt.JWebToken;
import dev.rafex.ether.jwt.impl.JWebTokenImpl;

try {
    JWebTokenImpl jwt = new JWebTokenImpl(token);
    if (jwt.isValid()) {
        String subject = jwt.getSubject();
        List<String> aud = jwt.getAudience();
        String rol = jwt.get("rol");
        // usar claims...
    } else {
        // token inválido o expirado
    }
} catch (Exception e) {
    // manejar errores
}
```

### Referencia de API

#### Interfaz `JWebToken`

- `JsonObject getPayload()` – Payload JSON crudo.
- `String getIssuer()` – Claim `iss`.
- `String getSubject()` – Claim `sub`.
- `List<String> getAudience()` – Claim `aud`.
- `Long getExpiration()` – Claim `exp` (epoch segundos).
- `Long getNotBefore()` – Claim `nbf` (epoch segundos).
- `Long getIssuedAt()` – Claim `iat` (epoch segundos).
- `String getJwtId()` – Claim `jti`.
- `String get(String property)` – Claim personalizado.
- `String getSignature()` – Firma del token.
- `String getEncodedHeader()` – Header codificado Base64URL.
- `boolean isValid()` – Verifica expiración, `nbf` y firma.
- `String aJson()` – Exporta token como JSON (excluye campos sin `@Expose`).

#### Clase `JWebTokenImpl.Builder`
Fluent builder para crear JWT firmados.

- `.issuer(String issuer)`
- `.subject(String subject)`
- `.audience(String[] audience)`
- `.expiration(long epochSeconds)`
- `.expirationPlusDays(int days)`
- `.expirationPlusHours(int hours)`
- `.expirationPlusMinutes(int minutes)`
- `.notBefore(long epochSeconds)`
- `.notBeforePlusMinutes(int minutes)`
- `.notBeforePlusSeconds(int seconds)`
- `.issuedAt(long epochSeconds)`
- `.jwtId(String jti)`
- `.claim(String name, String value)`
- `.build()` – Devuelve `JWebTokenImpl`.

---
## English

**ether-jwt** is a lightweight Java library for creating and verifying JSON Web Tokens (JWT) using HMAC-SHA256.

### Features

- Create and sign JWTs with a fluent `Builder` API.
- Parse and validate JWT strings.
- Support standard claims: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`.
- Add custom string claims.
- Base64 URL-safe encoding without padding.
- Signature verification with HMAC-SHA256.

### Quick Start

#### Create a JWT
```java
import dev.rafex.ether.jwt.impl.JWebTokenImpl;

String token = new JWebTokenImpl.Builder()
    .issuer("my-service")            // default "rafex.dev"
    .subject("user123")
    .audience(new String[]{"admin", "user"})
    .expirationPlusDays(7)
    .claim("role", "admin")         // custom claim
    .build()
    .toString();
```

#### Parse and Validate a JWT
```java
import dev.rafex.ether.jwt.JWebToken;
import dev.rafex.ether.jwt.impl.JWebTokenImpl;

try {
    JWebTokenImpl jwt = new JWebTokenImpl(token);
    if (jwt.isValid()) {
        String subject = jwt.getSubject();
        List<String> aud = jwt.getAudience();
        String role = jwt.get("role");
        // use claims...
    } else {
        // token invalid or expired
    }
} catch (Exception e) {
    // handle errors
}
```

### API Reference

#### Interface `JWebToken`

- `JsonObject getPayload()` – Raw JSON payload.
- `String getIssuer()` – `iss` claim.
- `String getSubject()` – `sub` claim.
- `List<String> getAudience()` – `aud` claim.
- `Long getExpiration()` – `exp` claim (epoch seconds).
- `Long getNotBefore()` – `nbf` claim (epoch seconds).
- `Long getIssuedAt()` – `iat` claim (epoch seconds).
- `String getJwtId()` – `jti` claim.
- `String get(String property)` – Custom claim.
- `String getSignature()` – Token signature.
- `String getEncodedHeader()` – Base64URL-encoded header.
- `boolean isValid()` – Check expiry, `nbf` and signature.
- `String aJson()` – Export token as JSON (excludes non-`@Expose`).

#### Class `JWebTokenImpl.Builder`

Fluent builder for creating signed JWTs.

- `.issuer(String issuer)`
- `.subject(String subject)`
- `.audience(String[] audience)`
- `.expiration(long epochSeconds)`
- `.expirationPlusDays(int days)`
- `.expirationPlusHours(int hours)`
- `.expirationPlusMinutes(int minutes)`
- `.notBefore(long epochSeconds)`
- `.notBeforePlusMinutes(int minutes)`
- `.notBeforePlusSeconds(int seconds)`
- `.issuedAt(long epochSeconds)`
- `.jwtId(String jti)`
- `.claim(String name, String value)`
- `.build()` – Returns `JWebTokenImpl`.
