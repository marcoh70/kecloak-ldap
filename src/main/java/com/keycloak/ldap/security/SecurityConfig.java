package com.keycloak.ldap.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

//@Configuration
public class SecurityConfig {

    //@Bean
    SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http) {

        return http
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(exchanges -> exchanges

                        .pathMatchers("/actuator/health")
                        .permitAll()

                        .pathMatchers("/api/entes/**")
                        .access((authentication, context) ->
                                authentication.map(auth ->
                                        new AuthorizationDecision(
                                                auth instanceof JwtAuthenticationToken jwt
                                                        && jwt.getToken()
                                                        .getAudience()
                                                        .equals(
                                                                java.util.List.of(
                                                                        "ente-service"
                                                                )
                                                        )
                                        )
                                )
                        )

                        .pathMatchers("/api/orders/**")
                        .access((authentication, context) ->
                                authentication.map(auth ->
                                        new AuthorizationDecision(
                                                auth instanceof JwtAuthenticationToken jwt
                                                        && jwt.getToken()
                                                        .getAudience()
                                                        .equals(
                                                                java.util.List.of(
                                                                        "orders-service"
                                                                )
                                                        )
                                        )
                                )
                        )

                        .anyExchange()
                        .denyAll()
                )
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(Customizer.withDefaults())
                )
                .build();
    }
}
