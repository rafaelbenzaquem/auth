package br.jus.trf1.sjrr.secad.nucad.seinf.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.util.UUID;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
import static org.springframework.security.oauth2.core.oidc.OidcScopes.OPENID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("angular-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(CLIENT_SECRET_BASIC)
                .authorizationGrantType(AUTHORIZATION_CODE)
                .authorizationGrantType(REFRESH_TOKEN)
                .redirectUri("http://localhost:4200/login/oauth2/code/angular-client")
                .scope(OPENID)
                .scope("read")
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build(); // default endpoints: /oauth2/token, /oauth2/authorize etc.
    }
}