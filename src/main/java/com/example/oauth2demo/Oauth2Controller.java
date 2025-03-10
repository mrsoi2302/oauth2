package com.example.oauth2demo;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:8080")
public class Oauth2Controller {

    private final Oauth2Service oauth2Service;

    @GetMapping("/google/callback")
    public String loginByGoogle(@RequestParam String code) throws IOException {
        return oauth2Service.exchangeCodeForToken(code);
    }
}
