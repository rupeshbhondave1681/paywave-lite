package com.PayWave.api_gateway.filter;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AuthHeaderFilter implements GlobalFilter	 {

	@Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // allow open endpoints under /auth/** (login/register)
        if (path.startsWith("/auth/")) {
            return chain.filter(exchange);
        }

        // check Authorization header for other routes
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || authHeader.isEmpty()) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // optionally: minimal token format check (starts with "Bearer ")
        // full token verification should be in auth-service or an auth filter with JWT public key
        return chain.filter(exchange);
    }
}
