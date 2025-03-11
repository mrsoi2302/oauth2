package com.example.oauth2demo;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public class Oauth2User implements OAuth2User {

    private final Map<String, Object> attributes;

    public Oauth2User(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getName() {
        return "";
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        attributes.forEach((key, value) -> sb.append(key).append("=").append(value).append(";\n"));
        return sb.toString();
    }
}
