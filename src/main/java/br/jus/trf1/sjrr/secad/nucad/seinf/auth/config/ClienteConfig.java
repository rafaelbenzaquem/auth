package br.jus.trf1.sjrr.secad.nucad.seinf.auth.config;

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
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;


@Profile(value = "dev")
@Configuration
public class ClienteConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations, PasswordEncoder passwordEncoder) {
        var repository = new JdbcRegisteredClientRepository(jdbcOperations);

        RegisteredClient registeredClient = repository.findByClientId("angular-client");

        if (registeredClient == null) {
            RegisteredClient angularClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("angular-client")
                    .clientSecret(passwordEncoder.encode("secret"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(1))
                            .refreshTokenTimeToLive(Duration.ofMinutes(2))
                            .build())

                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:4200/login/oauth2/code/angular-client")
                    .scope(OidcScopes.OPENID)
                    .scope("read")
                    .build();
            repository.save(angularClient);
        }
        return repository;
    }
}
