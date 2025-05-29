package br.jus.trf1.sjrr.secad.nucad.seinf.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.UUID;


@Profile(value = "dev")
@Configuration
@RequiredArgsConstructor
public class ClienteConfig {

    private final TokenSettings tokenSettings;
    private final ClientSettings clientSettings;

    @Bean
    public RegisteredClientRepository registeredClientRepository(
            JdbcOperations jdbcOperations,
            TokenSettings tokenSettings,
            PasswordEncoder passwordEncoder) {

        var repository = new JdbcRegisteredClientRepository(jdbcOperations);

        // tenta carregar; se não existir, cria como cliente público PKCE-only
        RegisteredClient sipeWeb = repository.findByClientId("sipe-web");
        if (sipeWeb == null) {
            sipeWeb = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("sipe-web")
                    // sem clientSecret: public client
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    // somente Authorization Code + PKCE
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    // opcional: se quiser refresh tokens
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:4200/index")
                    // URI que o IdP poderá usar após o logout federado
                    .postLogoutRedirectUri("http://localhost:4200")
                    .scope(OidcScopes.OPENID)

                    // se usar refresh token no SPA, adicione também OidcScopes.OFFLINE_ACCESS
                    //.scope(OidcScopes.OFFLINE_ACCESS)
                    .tokenSettings(tokenSettings)
                    // força PKCE e (opcional) consent screen
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true)
                            .requireAuthorizationConsent(false)
                            .build())
                    .build();
            repository.save(sipeWeb);
        }
        return repository;
    }

}
