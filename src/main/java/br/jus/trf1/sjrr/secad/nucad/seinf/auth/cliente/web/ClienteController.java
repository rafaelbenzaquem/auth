package br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente.web;

import br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente.ClienteService;
import br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente.web.dto.ClienteCredencialResponse;
import br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente.web.dto.ClienteRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/auth/api/clientes")
public class ClienteController {


    private final ClienteService clienteService;

    public ClienteController(ClienteService clienteService) {
        this.clienteService = clienteService;
    }


    @PostMapping
    @PreAuthorize("hasAuthority('GRP_SIPE_ADMIN')")
    public ResponseEntity<ClienteCredencialResponse> register(@RequestBody ClienteRequest dto) {
        var cliente = clienteService.registrar(dto);
        return ResponseEntity.ok(
                new ClienteCredencialResponse(cliente.getClientId(), cliente.getClientSecret())
        );
    }

    @GetMapping("/{clientId}")
    @PreAuthorize("hasAuthority('GRP_SIPE_ADMIN')")
    public ResponseEntity<RegisteredClient> getUsuarioList(@PathVariable String clientId, Authentication auth) {

        log.info("getUsuarioList: {}", clientId);
        if(auth instanceof UsernamePasswordAuthenticationToken) {
            log.info("Authentication: {}", auth);
        }

        return ResponseEntity.ok(clienteService.buscar(clientId));
    }
}
