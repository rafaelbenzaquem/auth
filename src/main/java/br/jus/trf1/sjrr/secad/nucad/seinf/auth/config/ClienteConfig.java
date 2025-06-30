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
    public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations, PasswordEncoder passwordEncoder) {
        var repository = new JdbcRegisteredClientRepository(jdbcOperations);
        String secret = passwordEncoder.encode("secret");
        // Cria/atualiza client de teste para Authorization Code Flow (Postman/Insomnia)
        RegisteredClient postmanClient = repository.findByClientId("postman-client");
        if (postmanClient == null) {
            postmanClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("postman-client")
                    .clientSecret(secret)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://oauth.pstmn.io/v1/callback")
                    .scope(OidcScopes.OPENID)
                    .tokenSettings(tokenSettings)
                    .clientSettings(clientSettings)
                    .build();
            repository.save(postmanClient);
        }
        return repository;
    }
}
