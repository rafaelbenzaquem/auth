package br.jus.trf1.sjrr.secad.nucad.seinf.auth.login;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @Value("${sipe.api.url}")
    private String urlSipeApi;

    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("urlSipeApi", urlSipeApi);
        return "login";
    }

}
