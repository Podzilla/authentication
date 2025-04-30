package com.podzilla.auth.security;

import com.podzilla.auth.service.CustomUserDetailsService;
import com.podzilla.auth.service.TokenService;
import io.micrometer.common.lang.NonNullApi;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@NonNullApi
@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    private final TokenService tokenService;
    private final CustomUserDetailsService customUserDetailsService;

    public JWTAuthenticationFilter(
            final TokenService tokenService,
            final CustomUserDetailsService customUserDetailsService) {
        this.tokenService = tokenService;
        this.customUserDetailsService = customUserDetailsService;
    }

    private static final Logger LOGGER =
            LoggerFactory.getLogger(JWTAuthenticationFilter.class);

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain)
            throws ServletException, IOException {

        try {
            String jwt = tokenService.getAccessTokenFromCookie(request);
            tokenService.validateAccessToken(jwt);
            String userEmail = tokenService.extractEmail();

            UserDetails userDetails =
                    customUserDetailsService.loadUserByUsername(userEmail);

            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities());
            authToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContext context =
                    SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authToken);
            SecurityContextHolder.setContext(context);

            LOGGER.info("User {} authenticated", userEmail);
        } catch (Exception e) {
            LOGGER.error("Invalid JWT token: {}", e.getMessage());
        }
        filterChain.doFilter(request, response);
    }
}
