<!-- README.md -->
# Servidor de Autorização OAuth2 (Auth Server)

Este projeto implementa um Authorization Server OAuth2 usando Spring Boot 3 e Spring Authorization Server.

## Funcionalidades
- Fluxos OAuth2 suportados: Authorization Code, Client Credentials e Refresh Token
- Emissão de tokens JWT (JSON Web Tokens)
- Endpoint JWKS para chaves públicas: `/oauth2/jwks`
- Banco de dados H2 em memória para registro de clients
- Console H2 acessível em `/h2-console`
- Autenticação de usuários via Active Directory (LDAP)
- Criptografia de senhas com BCrypt

## Pré-requisitos
- Java 21 ou superior
- Maven 3.8+ (embutido no wrapper `./mvnw`)
- (Opcional) Servidor de Active Directory para autenticação LDAP

## Configuração
As principais propriedades estão em `src/main/resources/application.yaml`:
```yaml
server:
  port: 9000

spring:
  datasource:
    url: jdbc:h2:mem:testdb
    username: sa
    password: sa123456
  h2:
    console:
      enabled: true
      path: /h2-console
  sql:
    init:
      mode: always
      schema-locations: classpath:org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql
```

Configuração de autenticação LDAP em `WebSecurityConfig.java`:
```java
ActiveDirectoryLdapAuthenticationProvider provider =
    new ActiveDirectoryLdapAuthenticationProvider(
        "DOMINIO.EXEMPLO.COM",    // domínio AD
        "ldap://servidor-ldap:389/"
    );
```
Altere domínio e URL conforme seu ambiente.

## Como Executar
```bash
git clone <url-do-repo>
cd auth
./mvnw spring-boot:run
```

O servidor iniciará na porta 9000.

## Acesso ao Console H2
Abra no navegador:
```
http://localhost:9000/h2-console
```
- JDBC URL: `jdbc:h2:mem:testdb`
- Usuário: `sa`
- Senha: `sa123456`

## Registro de Clients OAuth2
Você pode cadastrar clientes diretamente via console H2 executando SQL:
```sql
INSERT INTO oauth2_registered_client (
  id, client_id, client_secret, client_secret_expires_at,
  client_name, client_authentication_methods,
  authorization_grant_types, redirect_uris,
  scopes, client_settings, token_settings
) VALUES (
  '1', 'my-client', '{bcrypt}<senha-criptografada>',
  NULL, 'Meu Cliente', 'client_secret_basic',
  'authorization_code', 'http://localhost:8080/login/oauth2/code/meu-client',
  'openid', '{}', '{}'
);
```

## Endpoints Principais
- Autorização:  `/oauth2/authorize`
- Token:         `/oauth2/token`
- JWKS:          `/oauth2/jwks`
- Introspecção: `/oauth2/introspect`
- Revogação:     `/oauth2/revoke`

## Personalizações
- Para usar outro banco, ajuste o datasource em `application.yaml`.
- Para mudar regras de segurança, edite `WebSecurityConfig.java` e/ou `AuthorizationServerConfig.java`.

---
_Desenvolvido por equipe SEINF/SJRR_