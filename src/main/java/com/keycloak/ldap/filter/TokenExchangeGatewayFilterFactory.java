package com.keycloak.ldap.filter;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class TokenExchangeGatewayFilterFactory
        extends AbstractGatewayFilterFactory<
        TokenExchangeGatewayFilterFactory.Config> {

    private static final String TOKEN_EXCHANGE_GRANT =
            "urn:ietf:params:oauth:grant-type:token-exchange";

    private static final String ACCESS_TOKEN_TYPE =
            "urn:ietf:params:oauth:token-type:access_token";

    private final WebClient webClient;
    private final String tokenUri;
    private final String clientId;
    private final String clientSecret;

    public TokenExchangeGatewayFilterFactory(
            WebClient.Builder webClientBuilder,
            @Value("${app.keycloak.token-uri}") String tokenUri,
            @Value("${app.keycloak.gateway-client-id}") String clientId,
            @Value("${app.keycloak.gateway-client-secret}") String clientSecret) {

        super(Config.class);
        this.webClient = webClientBuilder.build();
        this.tokenUri = tokenUri;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    @Override
    public GatewayFilter apply(Config config) {

        return (exchange, chain) ->
                ReactiveSecurityContextHolder.getContext()
                        .map(context -> context.getAuthentication())
                        .filter(auth ->
                                auth instanceof JwtAuthenticationToken)
                        .cast(JwtAuthenticationToken.class)
                        .map(auth -> auth.getToken().getTokenValue())
                        .switchIfEmpty(Mono.error(
                                new IllegalStateException(
                                        "No authenticated JWT found")))
                        .flatMap(subjectToken ->
                                exchangeToken(
                                        subjectToken,
                                        config.getTargetAudience())
                                        .flatMap(serviceToken -> {
                                            var request = exchange
                                                    .getRequest()
                                                    .mutate()
                                                    .headers(headers -> {
                                                        headers.remove(
                                                                HttpHeaders.AUTHORIZATION);
                                                        headers.setBearerAuth(
                                                                serviceToken);
                                                    })
                                                    .build();

                                            ServerWebExchange mutatedExchange =
                                                    exchange.mutate()
                                                            .request(request)
                                                            .build();

                                            return chain.filter(mutatedExchange);
                                        }))
                        .onErrorResume(error -> {
                            // No enviar la petición sin un token válido.
                            exchange.getResponse().setStatusCode(
                                    HttpStatus.BAD_GATEWAY);
                            return exchange.getResponse().setComplete();
                        });
    }

    private Mono<String> exchangeToken(
            String subjectToken,
            String targetAudience) {

        return webClient.post()
                .uri(tokenUri)
                .headers(headers ->
                        headers.setBasicAuth(clientId, clientSecret))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(BodyInserters
                        .fromFormData("grant_type", TOKEN_EXCHANGE_GRANT)
                        .with("subject_token", subjectToken)
                        .with("subject_token_type", ACCESS_TOKEN_TYPE)
                        .with("requested_token_type", ACCESS_TOKEN_TYPE)
                        .with("audience", targetAudience))
                .retrieve()
                .bodyToMono(TokenExchangeResponse.class)
                .map(response -> {
                    if (response.accessToken() == null
                            || response.accessToken().isBlank()) {
                        throw new IllegalStateException(
                                "Keycloak did not return an access token");
                    }
                    return response.accessToken();
                });
    }

    public static class Config {

        private String targetAudience;

        public String getTargetAudience() {
            return targetAudience;
        }

        public void setTargetAudience(String targetAudience) {
            this.targetAudience = targetAudience;
        }
    }

    private record TokenExchangeResponse(
            @JsonProperty("access_token") String accessToken) {
    }
}
