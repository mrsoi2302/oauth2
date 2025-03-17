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

@Service
@RequiredArgsConstructor
public class GithubOauth2Service {

    @Value("${spring.security.oauth2.client.registration.github.client-secret}")
    private String GITHUB_CLIENT_SECRET;
    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String GITHUB_CLIENT_ID;
    @Value("${spring.security.oauth2.client.registration.github.redirect-uri}")
    private String GITHUB_REDIRECT_URI;
    @Value("${spring.security.oauth2.client.provider.github.token-uri}")
    private String GITHUB_TOKEN_URL;
    @Value("${spring.security.oauth2.client.provider.github.user-info-uri}")
    private String GITHUB_INFO_URL;
    @Value("${spring.security.oauth2.client.provider.github.authorization-uri}")
    private String GITHUB_AUTHORIZATION_URI;

    private final SecurityContextRepository securityContextRepository;

    public String createAuthorizationURL() {
        return UriComponentsBuilder
                .fromUriString(GITHUB_AUTHORIZATION_URI)
                .queryParam("client_id", GITHUB_CLIENT_ID)
                .queryParam("redirect_uri", GITHUB_REDIRECT_URI)
                .queryParam("response_type", "code")
                .queryParam("scope", "email profile")
                .build()
                .toUriString();
    }

    public void exchangeCodeForToken(String code, HttpServletRequest req) throws JsonProcessingException {
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", GITHUB_CLIENT_ID);
        requestBody.add("client_secret", GITHUB_CLIENT_SECRET);
        requestBody.add("code", code);
        requestBody.add("redirect_uri", GITHUB_REDIRECT_URI);
        requestBody.add("grant_type", "authorization_code");

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBody, headers);

        var response = restTemplate.exchange(GITHUB_TOKEN_URL, HttpMethod.POST, request, String.class);
        if (response.getStatusCode().isError()) {
            throw new IllegalArgumentException("Invalid code");
        }
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(response.getBody());
        String accessToken = jsonNode.get("access_token").asText();
        HttpHeaders infoHeaders = new HttpHeaders();
        infoHeaders.setBearerAuth(accessToken);
        HttpEntity<String> infoRequest = new HttpEntity<>(infoHeaders);
        var userInfoResponse = restTemplate.exchange(GITHUB_INFO_URL, HttpMethod.GET, infoRequest, String.class);
        var userInfo = userInfoResponse.getBody();
        jsonNode = objectMapper.readTree(userInfo);
        var username = jsonNode.get("login");
        var avatarUrl = jsonNode.get("avatar_url");
        var user = new Oauth2User(username.asText(),avatarUrl.asText());
        if (userInfo == null) {
            throw new IllegalArgumentException("Invalid user info");
        }
        // Lưu vào SecurityContext (nếu cần)
        var context = SecurityContextHolder.getContext();
        context.setAuthentication(new OAuth2AuthenticationToken(user, null, "google"));
        securityContextRepository.saveContext(context, req, null);
    }
}
