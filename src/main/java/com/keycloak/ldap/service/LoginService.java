package com.keycloak.ldap.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
public class LoginService {

    private final RestClient restClient;

    public LoginService(RestClient restClient) {
        this.restClient = restClient;
    }



}
