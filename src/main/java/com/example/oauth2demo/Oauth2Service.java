package com.example.oauth2demo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
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
    @Value("${spring.security.oauth2.client.provider.google.authorization-uri}")
    private String GOOGLE_AUTHORIZATION_URI;

    private final SecurityContextRepository securityContextRepository;

    public String createAuthorizationURL() {
        return UriComponentsBuilder
                .fromUriString(GOOGLE_AUTHORIZATION_URI)
                .queryParam("client_id", GOOGLE_CLIENT_ID)
                .queryParam("redirect_uri", GOOGLE_REDIRECT_URI)
                .queryParam("response_type", "code")
                .queryParam("scope", "email profile")
                .build()
                .toUriString();
    }

    public void exchangeCodeForToken(String code, HttpServletRequest req) throws JsonProcessingException {
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
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(response.getBody());
        String accessToken = jsonNode.get("access_token").asText();
        HttpHeaders infoHeaders = new HttpHeaders();
        infoHeaders.setBearerAuth(accessToken);
        HttpEntity<String> infoRequest = new HttpEntity<>(infoHeaders);
        var userInfoResponse = restTemplate.exchange(GOOGLE_INFO_URL, HttpMethod.GET, infoRequest, Map.class);
        var userInfo = userInfoResponse.getBody();
        var user = new Oauth2User(userInfo);
        if (userInfo == null) {
            throw new IllegalArgumentException("Invalid user info");
        }
        // Lưu vào SecurityContext (nếu cần)
        var context = SecurityContextHolder.getContext();
        context.setAuthentication(new OAuth2AuthenticationToken(user, null, "google"));
        securityContextRepository.saveContext(context, req, null);
    }
}
