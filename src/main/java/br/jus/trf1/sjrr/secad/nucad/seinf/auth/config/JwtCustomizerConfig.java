package br.jus.trf1.sjrr.secad.nucad.seinf.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

@Slf4j
@Configuration
public class JwtCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                var auth = context.getPrincipal();
                List<String> authorities = auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(authority -> authority.contains("GRP_SIPE"))
                        .toList();
                context.getClaims().claim("authorities", authorities);
            }
            log.info("JwtCustomizerConfig context: {}", context);
        };
    }
}

