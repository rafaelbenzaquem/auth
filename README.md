<!-- README.md -->
# Servidor de Autorização OAuth2 / OpenID Connect

Servidor de Autorização OAuth2 (Auth Server) e OpenID Connect (OIDC) desenvolvido com Spring Boot 3 e Spring Authorization Server para emissão de tokens JWT.

## Tecnologias
- Java 21
- Spring Boot 3
- Spring Authorization Server
- Spring Security (LDAP/Active Directory)
- Banco de dados H2 (in-memory)
- Maven (via wrapper `mvnw`)

## Funcionalidades
- OAuth2: Authorization Code, Client Credentials, Refresh Token
- OpenID Connect: UserInfo e Logout
- Tokens JWT (SELF_CONTAINED), customizados com `authorities`
- JWKS endpoint (`/oauth2/jwks`) para chaves públicas
- Introspecção de tokens (`/oauth2/introspect`)
- Revogação de tokens (`/oauth2/revoke`)
- Autenticação via Active Directory (LDAP)
- Criptografia de senhas com BCrypt
- API REST para gerenciamento de clients (`/auth/api/clientes`)
- Banco de dados H2 em memória e console H2 (`/h2-console`)

## Conteúdo
- [Pré-requisitos](#pré-requisitos)
- [Instalação e Execução](#instalação-e-execução)
- [Configuração](#configuração)
  - [Perfis de Ambiente](#perfis-de-ambiente)
  - [Variáveis de Ambiente](#variáveis-de-ambiente)
  - [Datasource e H2 Console](#datasource-e-h2-console)
  - [LDAP / Active Directory](#ldap--active-directory)
- [Endpoints](#endpoints)
- [Exemplos de Uso (curl)](#exemplos-de-uso-curl)
- [API de Gerenciamento de Clients](#api-de-gerenciamento-de-clients)
- [Contribuição](#contribuição)

## Pré-requisitos
- Java 21 ou superior
- Maven 3.8+ (incluído no wrapper `./mvnw`)

## Instalação e Execução
```bash
git clone <URL_do_repositório>
cd auth
# Profile 'dev' é o padrão
./mvnw clean spring-boot:run
``` 
O servidor iniciará em `http://localhost:9000`.

## Configuração

### Perfis de Ambiente
Define qual arquivo de configuração será carregado:
- **dev** (padrão): `application-dev.yaml`
- **prod**: `application-prod.yaml`

Altere o profile via variável de ambiente ou parâmetro do Maven:
```bash
export AUTH_PROFILE=prod
./mvnw spring-boot:run -Dspring-boot.run.profiles=prod
```

### Variáveis de Ambiente
- `AUTH_PROFILE`: profile ativo (`dev` ou `prod`)
- `DOMAIN_CONTROL_NAME`: nome do domínio AD (ex: `EXEMPLO.COM`)
- `DOMAIN_CONTROL_URL`: URL do servidor LDAP (ex: `ldap://ad.exemplo.com:389/`)

### Datasource e H2 Console
Em `application-dev.yaml`:
```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    username: sa
    password: sa123456
  h2:
    console:
      enabled: true
      path: /h2-console
```
Acesse o console em `http://localhost:9000/h2-console`:
- JDBC URL: `jdbc:h2:mem:testdb`
- Usuário: `sa`
- Senha: `sa123456`

### LDAP / Active Directory
Configuração em `application-*.yaml` ou via variáveis:
```yaml
domain:
  control:
    name: ${DOMAIN_CONTROL_NAME:EXEMPLO.COM}
    url: ${DOMAIN_CONTROL_URL:ldap://ldap.exemplo.com:389/}
```

## Endpoints
| Método | Endpoint                   | Descrição                       |
|--------|----------------------------|---------------------------------|
| GET    | `/oauth2/authorize`        | Authorization Code (Consents)   |
| POST   | `/oauth2/token`            | Emissão de tokens               |
| GET    | `/oauth2/jwks`             | Chaves públicas (JWKS)          |
| POST   | `/oauth2/introspect`       | Introspecção de token           |
| POST   | `/oauth2/revoke`           | Revogação de token              |
| GET    | `/oauth2/userinfo`         | UserInfo (OIDC)                 |
| GET    | `/oauth2/logout`           | Logout (OIDC)                   |
| GET    | `/h2-console/**`           | Console H2                      |
| POST   | `/auth/api/clientes`       | Registrar novo client (admin)   |
| GET    | `/auth/api/clientes/{id}`  | Buscar client pelo clientId     |

## Exemplos de Uso (curl)

1. **Authorization Code (Postman)**
   - Redirect URI configurada: `https://oauth.pstmn.io/v1/callback`
   - Acesse no navegador:
     ```
     http://localhost:9000/oauth2/authorize?response_type=code&client_id=postman-client&redirect_uri=https://oauth.pstmn.io/v1/callback&scope=openid
     ```
   - Trocar código por token:
     ```bash
     curl -X POST http://localhost:9000/oauth2/token \
       -u postman-client:secret \
       -d grant_type=authorization_code \
       -d code=<authorization_code> \
       -d redirect_uri=https://oauth.pstmn.io/v1/callback
     ```

2. **Client Credentials**
   ```bash
   curl -X POST http://localhost:9000/oauth2/token \
     -u my-client:secret \
     -d grant_type=client_credentials \
     -d scope=<scope>
   ```

3. **Introspecção de Token**
   ```bash
   curl -X POST http://localhost:9000/oauth2/introspect \
     -u postman-client:secret \
     -d token=<access_token>
   ```

4. **Revogação de Token**
   ```bash
   curl -X POST http://localhost:9000/oauth2/revoke \
     -u postman-client:secret \
     -d token=<access_token>
   ```

## API de Gerenciamento de Clients
Sob perfil `dev`, um client padrão `postman-client` é criado automaticamente.
Para registrar dinamicamente:
```bash
curl -X POST http://localhost:9000/auth/api/clientes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token_com_GRP_SIPE_ADMIN>" \
  -d '{
    "clientId":"novo-client",
    "clientSecret":"secret",
    "redirectUri":"http://localhost:8080/login/oauth2/code/novo-client",
    "scopes":["openid"]
  }'
```
Resposta:
```json
{
  "clientId": "novo-client",
  "clientSecret": "<secret_codificado>"
}
```

## Contribuição
Pull requests são bem-vindos! Abra issues para sugestões e melhorias.

---
_Desenvolvido pela equipe SEINF/SJRR
