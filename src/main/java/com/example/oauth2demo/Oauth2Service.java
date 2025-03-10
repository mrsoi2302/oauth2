package com.example.oauth2demo;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Service
public class Oauth2Service {

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String GOOGLE_CLIENT_SECRET;
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String GOOGLE_CLIENT_ID;
    @Value("${spring.security.oauth2.client.registration.google.redirect-uri}")
    private String GOOGLE_REDIRECT_URI;
    @Value("${spring.security.oauth2.client.provider.google.token-uri}")
    private String GOOGLE_TOKEN_URL;
    @Value("${spring.security.oauth2.client.provider.google.user-info-uri}")
    private String GOOGLE_INFO_URL;

    public String exchangeCodeForToken(String code) throws JsonProcessingException {
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", GOOGLE_CLIENT_ID);
        requestBody.add("client_secret", GOOGLE_CLIENT_SECRET);
        requestBody.add("code", code);
        requestBody.add("redirect_uri", GOOGLE_REDIRECT_URI);
        requestBody.add("grant_type", "authorization_code");

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBody, headers);

        var response = restTemplate.exchange(GOOGLE_TOKEN_URL, HttpMethod.POST, request, String.class);
        if (response.getStatusCode().isError()) {
            throw new IllegalArgumentException("Invalid code");
        }
        return response.getBody();
    }
}
