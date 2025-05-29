package br.jus.trf1.sjrr.secad.nucad.seinf.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfig {

    @Value("${domain.control.name}")
    private String nomeDominio;

    @Value("${domain.control.url}")
    private String urlDominio;

    @Bean
    public ActiveDirectoryLdapAuthenticationProvider adAuthenticationProvider() {
        ActiveDirectoryLdapAuthenticationProvider provider =
                new ActiveDirectoryLdapAuthenticationProvider(nomeDominio, urlDominio);
        provider.setConvertSubErrorCodesToExceptions(true);
        provider.setUseAuthenticationRequestCredentials(true);
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authenticationProvider(adAuthenticationProvider())
                .authorizeHttpRequests(authz -> authz
                        .anyRequest().hasAuthority("GRP_SIPE_USERS")
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(new AntPathRequestMatcher("/auth/**"))
                )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }
}
