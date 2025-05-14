package br.jus.trf1.sjrr.secad.nucad.seinf.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
public class AuthorizationServerConfig {

//    @Bean
//    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Configure the endpoints for the OAuth2 Authorization Server
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        var endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http
                // Apply security only to the OAuth2 authorization endpoints
                .securityMatcher(endpointsMatcher)
                // Disable CSRF protection for the OAuth2 endpoints
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                // All requests to these endpoints require an authenticated user
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // Provide a login form for end-user authentication
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                // Apply the OAuth2 Authorization Server configuration (use with() since apply() is deprecated)
                .with(authorizationServerConfigurer, Customizer.withDefaults());
        return http.build();
    }

//    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build();
    }
}
