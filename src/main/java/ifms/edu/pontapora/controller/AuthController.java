package ifms.edu.pontapora.controller;


import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class AuthController {

    @GetMapping("/userinfo")
    public Map<String, Object> getUserInfo(Authentication authentication) {
        if (authentication == null) {
            return Map.of("error", "Não autenticado");
        }

        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2User oauthUser = ((OAuth2AuthenticationToken) authentication).getPrincipal();
            return Map.of(
                    "authType", "GOOGLE",
                    "email", oauthUser.getAttribute("email")
            );
        } else if (authentication instanceof UsernamePasswordAuthenticationToken) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            return Map.of(
                    "authType", "LOCAL",
                    "username", userDetails.getUsername()
            );
        }

        return Map.of("error", "Tipo de autenticação desconhecido");
    }
}