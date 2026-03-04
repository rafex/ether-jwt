# ether-jwt

Librería JWT reusable para Java 21 enfocada en emisión/verificación segura, claims tipados y resultados de validación ricos.

## Estado actual
- API nueva recomendada: `TokenIssuer` + `TokenVerifier`.
- API legacy compatible: `JWebToken` / `JWebTokenImpl` (marcada como `@Deprecated`).
- Sin acoplamiento a frameworks web (Jetty/Spring/etc).

## Dependencia Maven
```xml
<dependency>
  <groupId>dev.rafex.ether.jwt</groupId>
  <artifactId>ether-jwt</artifactId>
  <version>3.0.1-SNAPSHOT</version>
</dependency>
```

## Inicio rápido (API nueva)
```java
import dev.rafex.ether.jwt.DefaultTokenIssuer;
import dev.rafex.ether.jwt.DefaultTokenVerifier;
import dev.rafex.ether.jwt.JwtConfig;
import dev.rafex.ether.jwt.KeyProvider;
import dev.rafex.ether.jwt.TokenSpec;
import dev.rafex.ether.jwt.TokenType;

import java.time.Duration;
import java.time.Instant;

JwtConfig config = JwtConfig.builder(KeyProvider.hmac("super-secret"))
        .expectedIssuer("auth.example")
        .expectedAudience("my-api")
        .build();

DefaultTokenIssuer issuer = new DefaultTokenIssuer(config);
DefaultTokenVerifier verifier = new DefaultTokenVerifier(config);

String token = issuer.issue(TokenSpec.builder()
        .subject("user-123")
        .issuer("auth.example")
        .audience("my-api")
        .issuedAt(Instant.now())
        .ttl(Duration.ofMinutes(15))
        .tokenType(TokenType.USER)
        .roles("admin", "viewer")
        .build());

var result = verifier.verify(token, Instant.now());
if (result.ok()) {
    var claims = result.claims().orElseThrow();
    // usar claims tipados
}
```

## Documentación detallada
- Guía completa de uso: [`docs/USAGE_ES.md`](docs/USAGE_ES.md)
- Migración legacy -> API nueva: [`MIGRATION.md`](MIGRATION.md)
- Script de llaves RSA: `../generate-jwt-keys.sh`
- Script de secreto HMAC: `../generate-jwt-hmac-secret.sh`

## Generación de material criptográfico

### RSA (script oficial)
Desde `ether-deployment-hub/ether-jwt`:
```bash
./generate-jwt-keys.sh -d ./keys -n jwt
```

Salida esperada:
- `./keys/jwt_private.pem`
- `./keys/jwt_public.pem`

Uso en Java:
```java
KeyProvider.rsa(privateKey, publicKey);      // emitir
KeyProvider.rsaVerifier(publicKey);          // verificar
```

### HMAC (secreto compartido)
HMAC no usa certificados/pares de llaves.

Generación con script oficial (desde `ether-deployment-hub/ether-jwt`):
```bash
./generate-jwt-hmac-secret.sh -d ./keys -n jwt -b 48
```

Archivos generados:
- `./keys/jwt_hmac.secret`
- `./keys/jwt_hmac.properties`

Alternativa manual:
```bash
openssl rand -base64 48
```

Luego configúralo en tu servicio (ejemplo variable de entorno):
```bash
export JWT_SECRET='...valor_generado...'
```

## Build
```bash
mvn test
```
