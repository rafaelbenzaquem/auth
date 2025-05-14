package br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente;

import br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente.web.dto.ClienteRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
public class ClienteService {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder encoder;

    public ClienteService(RegisteredClientRepository registeredClientRepository, PasswordEncoder encoder) {
        this.registeredClientRepository = registeredClientRepository;
        this.encoder = encoder;
    }

    public RegisteredClient registrar(ClienteRequest clienteRequest) {

        RegisteredClient cliente = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clienteRequest.clientId())
                .clientSecret(encoder.encode(clienteRequest.clientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(clienteRequest.redirectUri())
                .scopes(c -> c.addAll(clienteRequest.scopes()))
                .tokenSettings(TokenSettings.builder()

                        .accessTokenTimeToLive(Duration.ofMinutes(2))
                        .build())
                .build();
        registeredClientRepository.save(cliente);

        return cliente;
    }

    public RegisteredClient buscar(String clientId) {
        return registeredClientRepository.findByClientId(clientId);
    }

}
