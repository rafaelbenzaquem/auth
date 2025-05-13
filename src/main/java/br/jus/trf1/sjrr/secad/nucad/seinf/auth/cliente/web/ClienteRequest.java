package br.jus.trf1.sjrr.secad.nucad.seinf.auth.cliente.web;

import java.util.Set;

public record ClienteRequest(String clientId,
                             String redirectUri,
                             Set<String> scopes) {}
