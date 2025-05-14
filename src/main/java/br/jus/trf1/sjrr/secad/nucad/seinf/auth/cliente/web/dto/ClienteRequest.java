package br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente.web.dto;

import java.util.Set;

public record ClienteRequest(String clientId,
                             String clientSecret,
                             String redirectUri,
                             Set<String> scopes) {}
