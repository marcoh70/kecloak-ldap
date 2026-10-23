package com.keycloak.ldap.dto;

public record UserLogin(
        String userName,
        String password
) {
}
