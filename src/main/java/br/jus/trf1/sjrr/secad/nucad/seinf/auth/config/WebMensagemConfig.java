package br.jus.trf1.sjrr.secad.nucad.seinf.auth.config;

import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;

@Configuration
public class WebMensagemConfig {

    @Bean(name = "springSecurityMessageSource")
    public MessageSource springSecurityMessageSource() {
        ReloadableResourceBundleMessageSource source = new ReloadableResourceBundleMessageSource();
        source.setBasenames(
                "classpath:messages",                                 // seu bundle
                "classpath:org/springframework/security/messages"     // fallback padrão
        );
        source.setDefaultEncoding("UTF-8");
        return source;
    }
}
