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

import java.time.Duration;
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

        RegisteredClient registeredClient = repository.findByClientId("angular-client");

        if (registeredClient == null) {
            RegisteredClient angularClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("angular-client")
                    .clientSecret(passwordEncoder.encode("secret"))
//                    .redirectUri("http://localhost:4200/login/oauth2/code/angular-client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .tokenSettings(tokenSettings)
                    .clientSettings(clientSettings)
                    .scope(OidcScopes.OPENID)
                    .scope("read")
                    .build();
            repository.save(angularClient);
        }
        return repository;
    }
}
