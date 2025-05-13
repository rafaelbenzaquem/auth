package br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente;

import br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente.web.ClienteCredencialResponse;
import br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente.web.ClienteRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.UUID;

@RestController
@RequestMapping("/auth/api/clientes")
public class ClientRegistrationController {

    private final RegisteredClientRepository repo;
    private final PasswordEncoder encoder;

    public ClientRegistrationController(RegisteredClientRepository repo,
                                        PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @PostMapping
    public ResponseEntity<ClienteCredencialResponse> register(@RequestBody ClienteRequest dto) {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(dto.clientId())
                .clientSecret(encoder.encode(UUID.randomUUID().toString()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(dto.redirectUri())
                .scopes(c -> c.addAll(dto.scopes()))
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(1))
                        .build())
                .build();

        repo.save(client);
        return ResponseEntity.ok(
                new ClienteCredencialResponse(client.getClientId(), client.getClientSecret())
        );
    }
}
