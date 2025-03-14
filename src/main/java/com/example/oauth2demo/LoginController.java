package com.example.oauth2demo;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login(Model model) {
        model.addAttribute("username", "admin");
        return "login";
    }

    @GetMapping("/user/info")
    public String userInfo(Model model) {
        var user = (Oauth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        model.addAttribute("username", user.getName());
        model.addAttribute("avatarUrl", user.getAvatarUrl());
        return "result";
    }
}
