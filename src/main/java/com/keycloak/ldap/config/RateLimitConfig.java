package com.keycloak.ldap.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;

@Configuration
public class RateLimitConfig {

    @Bean
    KeyResolver userKeyResolver() {
        return exchange -> exchange.getPrincipal()
                .cast(JwtAuthenticationToken.class)
                .map(jwt -> jwt.getToken().getSubject());
    }
}
