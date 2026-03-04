# Guía detallada de uso de ether-jwt

## 1. Objetivo de la librería
`ether-jwt` está diseñada como base reusable de autenticación JWT para múltiples servicios.

Principios:
- API independiente de transporte (sin Jetty/Spring).
- Configuración explícita de claves y algoritmo.
- Verificación con resultado rico (`VerificationResult`) en lugar de solo booleano.
- Claims estándar y claims de negocio tipados.
- Defaults seguros para producción.

## 2. Modelo mental
Flujo principal:
1. Configuras seguridad con `JwtConfig` + `KeyProvider`.
2. Emites tokens con `TokenIssuer` usando `TokenSpec`.
3. Verificas tokens con `TokenVerifier` y obtienes `VerificationResult`.
4. Si `ok=true`, consumes `TokenClaims` tipado en middleware/controladores.

## 3. Componentes principales
- `KeyProvider`: material criptográfico.
- `JwtConfig`: reglas de validación.
- `TokenSpec`: entrada para emisión.
- `DefaultTokenIssuer`: firma el token.
- `DefaultTokenVerifier`: valida formato, algoritmo, firma y claims.
- `VerificationResult`: resultado (`ok`, `code`, `claims`).
- `TokenClaims`: claims normalizados.

## 4. Configuración de claves y algoritmo

### 4.0 Uso de `generate-jwt-keys.sh` (RSA)
El repositorio incluye el script:
- `/Users/rafex/repository/github/rafex/ether/ether-deployment-hub/ether-jwt/generate-jwt-keys.sh`

Este script genera un par RSA en formato PEM:
- privada PKCS#8 (`*_private.pem`)
- pública X.509 (`*_public.pem`)

Ejemplo de ejecución (desde `ether-deployment-hub/ether-jwt`):
```bash
./generate-jwt-keys.sh -d ./keys -n jwt
```

Parámetros:
- `-d <directorio>`: carpeta de salida (default `.`)
- `-n <nombre_base>`: prefijo de archivos (default `jwt`)

Archivos resultantes del ejemplo:
- `./keys/jwt_private.pem`
- `./keys/jwt_public.pem`

Notas:
- Requiere `openssl` instalado en el sistema.
- El script es para RSA; no genera secretos HMAC.
- No publiques `*_private.pem` en repositorios ni logs.

### 4.1 HMAC (HS256)
```java
KeyProvider keyProvider = KeyProvider.hmac("my-long-random-secret");

JwtConfig config = JwtConfig.builder(keyProvider)
        .expectedIssuer("auth.example")
        .expectedAudience("api.example")
        .build();
```

Generar un secreto HMAC con script del repositorio:
```bash
# desde ether-deployment-hub/ether-jwt
./generate-jwt-hmac-secret.sh -d ./keys -n jwt -b 48
```

Salida generada:
- `./keys/jwt_hmac.secret` (solo el secreto)
- `./keys/jwt_hmac.properties` (`jwt.secret=...`)

Generación manual alternativa (CLI):
```bash
openssl rand -base64 48
```

Recomendación:
- Guarda el secreto en un secret manager o variable de entorno (`JWT_SECRET`).
- Rota secretos periódicamente con estrategia de despliegue controlada.
- Mantén permisos restrictivos en archivos locales (`chmod 600`).

### 4.2 RSA (RS256)
```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;

KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
KeyPair kp = kpg.generateKeyPair();

JwtConfig issuerConfig = JwtConfig.builder(KeyProvider.rsa(kp.getPrivate(), kp.getPublic()))
        .expectedIssuer("auth.example")
        .expectedAudience("api.example")
        .build();

JwtConfig verifierConfig = JwtConfig.builder(KeyProvider.rsaVerifier(kp.getPublic()))
        .expectedIssuer("auth.example")
        .expectedAudience("api.example")
        .build();
```

Notas:
- `DefaultTokenIssuer` con RS256 requiere clave privada.
- `DefaultTokenVerifier` con RS256 requiere clave pública.
- La librería falla rápido (`IllegalArgumentException`) si falta material requerido.

## 5. Emisión de tokens

### 5.1 Claims estándar
`TokenSpec` soporta:
- `subject` (`sub`) obligatorio.
- `issuer` (`iss`) opcional.
- `audience` (`aud`) opcional.
- `issuedAt` (`iat`) opcional (si no se define, usa `Instant.now()`).
- `expiresAt` (`exp`) o `ttl` obligatorio.
- `notBefore` (`nbf`) opcional.
- `jwtId` (`jti`) opcional (si no se define, genera UUID).

### 5.2 Claims de negocio
`TokenSpec` soporta:
- `roles` (lista de strings).
- `tokenType` (`TokenType.USER` o `TokenType.APP`).
- `clientId`.
- `claim(key, value)` para extras tipados.

### 5.3 Ejemplo: user token
```java
TokenSpec userSpec = TokenSpec.builder()
        .subject("user-42")
        .issuer("auth.example")
        .audience("kiwi-api")
        .ttl(Duration.ofMinutes(20))
        .tokenType(TokenType.USER)
        .roles("admin", "billing")
        .claim("region", "mx")
        .claim("feature_flags", java.util.List.of("payments", "reports"))
        .build();

String userToken = new DefaultTokenIssuer(config).issue(userSpec);
```

### 5.4 Ejemplo: app token
```java
TokenSpec appSpec = TokenSpec.builder()
        .subject("svc-gateway")
        .issuer("auth.example")
        .audience("kiwi-api")
        .ttl(Duration.ofMinutes(5))
        .tokenType(TokenType.APP)
        .clientId("gateway-01")
        .roles("svc", "internal")
        .build();

String appToken = new DefaultTokenIssuer(config).issue(appSpec);
```

## 6. Verificación de tokens
```java
DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);
VerificationResult result = verifier.verify(token, Instant.now());

if (!result.ok()) {
    String code = result.code();
    // mapear code a HTTP status / respuesta de negocio
    return;
}

TokenClaims claims = result.claims().orElseThrow();
String subject = claims.subject();
java.util.List<String> roles = claims.roles();
TokenType tokenType = claims.tokenType();
String clientId = claims.clientId();
```

## 7. Códigos de verificación (`VerificationCode`)

Códigos estables disponibles:
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

Recomendación de uso:
- No uses `isValid()` como único contrato.
- Construye tu manejo de errores/middleware sobre `result.code()`.

## 8. Claims normalizados en `TokenClaims`

Campos estándar:
- `subject`, `issuer`, `audience`, `expiresAt`, `issuedAt`, `notBefore`, `jwtId`.

Campos de negocio:
- `roles`, `tokenType`, `clientId`, `extras`.

Normalización:
- `aud` puede venir como array o string, se expone como `List<String>`.
- `extras` mantiene tipos primitivos, arrays y objetos (`Map`, `List`, `Boolean`, `Number`, etc).

## 9. Configuración de validación (`JwtConfig`)

Opciones más usadas:
- `expectedIssuer("...")`
- `expectedAudience("aud1", "aud2")`
- `clockSkew(Duration.ofSeconds(n))`
- `validateExpiration(boolean)`
- `validateNotBefore(boolean)`
- `requireExpiration(boolean)`
- `requireSubject(boolean)`
- `requireClientIdForAppTokens(boolean)`

Ejemplo estricto:
```java
JwtConfig strictConfig = JwtConfig.builder(KeyProvider.hmac(secret))
        .expectedIssuer("auth.example")
        .expectedAudience("kiwi-api")
        .clockSkew(Duration.ofSeconds(10))
        .validateExpiration(true)
        .validateNotBefore(true)
        .requireExpiration(true)
        .requireSubject(true)
        .requireClientIdForAppTokens(true)
        .build();
```

## 10. Buenas prácticas de seguridad
- Usa secretos HMAC largos y aleatorios.
- Protege llaves privadas RSA fuera del código fuente.
- Usa `generate-jwt-keys.sh` solo para entornos controlados; en producción prioriza KMS/HSM/secret manager.
- Define algoritmo esperado de forma explícita por servicio.
- Habilita validación de `iss`, `aud`, `exp`, `nbf` según tu dominio.
- Ajusta `clockSkew` solo lo necesario.
- No loguees tokens completos ni secretos.
- No aceptes claims críticos solo por presencia; valida semántica de negocio en tu capa de aplicación.

## 11. Integración sugerida en middlewares
Contrato sugerido para servicios:
1. Extraer token de `Authorization: Bearer` (capa HTTP externa a la librería).
2. Llamar `verifier.verify(token, Instant.now())`.
3. Si `!ok`, mapear `code` a error de autenticación/autorización.
4. Si `ok`, crear contexto de seguridad con `TokenClaims`.
5. Aplicar autorización por `roles`, `tokenType`, `clientId`.

## 12. Compatibilidad legacy
`JWebToken` y `JWebTokenImpl` se mantienen funcionales pero están deprecados.

Uso legacy mínimo:
```java
@SuppressWarnings("deprecation")
String token = new dev.rafex.ether.jwt.impl.JWebTokenImpl.Builder()
        .issuer("legacy-auth")
        .subject("legacy-user")
        .audience("legacy-api")
        .expirationPlusMinutes(10)
        .claim("tenant", "a")
        .build()
        .toString();
```

Para migrar, revisa [`MIGRATION.md`](../MIGRATION.md).

## 13. Pruebas y calidad
Ejecutar:
```bash
mvn test
```

La suite incluye escenarios de:
- HMAC y RSA.
- expiración, `nbf`, `iss`, `aud`.
- `token_type=app` con/sin `client_id`.
- serialización de arrays y tipos primitivos en claims.
- códigos esperados de error.
- fail-fast de configuración criptográfica.
