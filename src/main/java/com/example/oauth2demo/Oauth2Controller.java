package com.example.oauth2demo;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:8080")
public class Oauth2Controller {

    private final GoogleOauth2Service googleOauth2Service;

    private final GithubOauth2Service githubOauth2Service;

    @GetMapping("/login/oauth2/google")
    public RedirectView loginByGoogle() {
        return new RedirectView(googleOauth2Service.createAuthorizationURL());
    }

    @GetMapping("/login/oauth2/github")
    public RedirectView loginByGithub() {
        return new RedirectView(githubOauth2Service.createAuthorizationURL());
    }

    @GetMapping("/oauth2/google/callback")
    public RedirectView loginByGoogle(@RequestParam String code, HttpServletRequest req) throws IOException {
        googleOauth2Service.exchangeCodeForToken(code, req);
        return new RedirectView("/user/info");
    }

    @GetMapping("/oauth2/github/callback")
    public RedirectView loginByGithub(@RequestParam String code, HttpServletRequest req) throws IOException {
        githubOauth2Service.exchangeCodeForToken(code, req);
        return new RedirectView("/user/info");
    }
}
