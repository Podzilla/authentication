package com.podzilla.auth.service;

import com.podzilla.auth.model.RefreshToken;
import com.podzilla.auth.model.User;
import com.podzilla.auth.repository.RefreshTokenRepository;
import com.podzilla.auth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.persistence.EntityExistsException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ValidationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.util.WebUtils;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Date;
import java.util.UUID;

@Service
public class TokenService {

    // set in .env
    @Value("${jwt.token.secret}")
    private String secret;

    @Value("${jwt.token.expires}")
    private Long jwtExpiresMinutes;

    private Claims claims;

    private static final Integer ACCESS_TOKEN_EXPIRATION_TIME = 60 * 1000;
    private static final Integer ACCESS_TOKEN_COOKIE_EXPIRATION_TIME = 60 * 30;
    private static final TemporalAmount REFRESH_TOKEN_EXPIRATION_TIME =
            java.time.Duration.ofDays(10);
    private static final Integer REFRESH_TOKEN_COOKIE_EXPIRATION_TIME =
            60 * 60 * 24 * 10;
    private static final String REFRESH_TOKEN_COOKIE_PATH =
            "/api/auth/refresh-token";
    private static final String ACCESS_TOKEN_COOKIE_PATH = "/";

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    public TokenService(final UserRepository userRepository,
                        final RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public void generateAccessToken(final String email,
                                    final HttpServletResponse response) {
        String jwt = Jwts.builder()
                .subject(email)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()
                        + jwtExpiresMinutes * ACCESS_TOKEN_EXPIRATION_TIME))
                .signWith(getSignInKey())
                .compact();

        Cookie cookie = new Cookie("accessToken", jwt);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(ACCESS_TOKEN_COOKIE_PATH);
        cookie.setMaxAge(ACCESS_TOKEN_COOKIE_EXPIRATION_TIME);
        response.addCookie(cookie);
    }

    public void generateRefreshToken(final String email,
                                     final HttpServletResponse response) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityExistsException("User not found"));
        RefreshToken userRefreshToken =
                refreshTokenRepository.findByUserIdAndExpiresAtAfter(
                        user.getId(), Instant.now()).orElse(null);

        if (userRefreshToken == null) {
            userRefreshToken = new RefreshToken();
            userRefreshToken.setUser(user);
            userRefreshToken.setCreatedAt(Instant.now());
            userRefreshToken.setExpiresAt(Instant.now().plus(
                    REFRESH_TOKEN_EXPIRATION_TIME));
            refreshTokenRepository.save(userRefreshToken);
        }

        String refreshTokenString = userRefreshToken.getId().toString();
        addRefreshTokenToCookie(refreshTokenString, response);
    }

    public String renewRefreshToken(final String refreshToken,
                                    final HttpServletResponse response) {
        RefreshToken token =
                refreshTokenRepository
                        .findByIdAndExpiresAtAfter(
                                UUID.fromString(refreshToken), Instant.now())
                        .orElseThrow(() ->
                                new ValidationException(
                                        "Invalid refresh token"));

        token.setExpiresAt(Instant.now());
        refreshTokenRepository.save(token);

        RefreshToken newRefreshToken = new RefreshToken();
        newRefreshToken.setUser(token.getUser());
        newRefreshToken.setCreatedAt(Instant.now());
        newRefreshToken.setExpiresAt(Instant.now().plus(
                REFRESH_TOKEN_EXPIRATION_TIME));
        refreshTokenRepository.save(newRefreshToken);

        String newRefreshTokenString = newRefreshToken.getId().toString();
        addRefreshTokenToCookie(newRefreshTokenString, response);

        return token.getUser().getEmail();
    }

    private void addRefreshTokenToCookie(final String refreshToken,
                                         final HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath(REFRESH_TOKEN_COOKIE_PATH);
        cookie.setMaxAge(REFRESH_TOKEN_COOKIE_EXPIRATION_TIME);
        response.addCookie(cookie);
    }

    public String getAccessTokenFromCookie(final HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, "accessToken");
        if (cookie != null) {
            return cookie.getValue();
        }
        return null;

    }

    public String getRefreshTokenFromCookie(final HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, "refreshToken");
        if (cookie != null) {
            return cookie.getValue();
        }
        return null;
    }

    public void validateAccessToken(final String token) throws JwtException {
        try {
            claims = Jwts.parser()
                    .verifyWith(getSignInKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();


        } catch (JwtException e) {
            throw new JwtException(e.getMessage());
        }
    }

    public void removeAccessTokenFromCookie(
            final HttpServletResponse response) {
        Cookie cookie = new Cookie("accessToken", null);
        cookie.setPath(ACCESS_TOKEN_COOKIE_PATH);

        response.addCookie(cookie);
    }

    public void removeRefreshTokenFromCookie(
            final HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setPath(REFRESH_TOKEN_COOKIE_PATH);

        response.addCookie(cookie);
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(this.secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractEmail() {
        return claims.getSubject();
    }

}
