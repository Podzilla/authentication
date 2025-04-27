package com.podzilla.auth.controller;

import com.podzilla.auth.dto.AuthenticationResponse;
import com.podzilla.auth.dto.LoginRequest;
import com.podzilla.auth.dto.SignupRequest;
import com.podzilla.auth.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    private final SecurityContextLogoutHandler logoutHandler =
            new SecurityContextLogoutHandler();

    private static final Logger LOGGER =
            LoggerFactory.getLogger(AuthenticationController.class);

    @Autowired
    public AuthenticationController(
            final AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody final LoginRequest loginRequest,
            final HttpServletResponse response) {
        try {
            AuthenticationResponse authResponse =
                    authenticationService.login(loginRequest, response);
            LOGGER.info("User {} logged in", authResponse.email());
            return new ResponseEntity<>(authResponse, HttpStatus.OK);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(
            @RequestBody final SignupRequest signupRequest,
            final HttpServletRequest request) {
        try {
            authenticationService.registerAccount(signupRequest);
            LOGGER.info("User {} registered", signupRequest.getEmail());
            return new ResponseEntity<>("Account registered.",
                    HttpStatus.CREATED);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(
            @RequestParam final UUID refreshToken,
            final HttpServletResponse response) {
        authenticationService.logoutUser(refreshToken, response);
        return new ResponseEntity<>("You've been signed out!", HttpStatus.OK);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(
            @RequestParam final UUID refreshToken,
            final HttpServletResponse response) {
        try {
            AuthenticationResponse authResponse =
                    authenticationService.refreshToken(refreshToken, response);
            LOGGER.info("User {} refreshed token", authResponse.email());
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return new ResponseEntity<>(e.getMessage(),
                    HttpStatus.UNAUTHORIZED);
        }
    }
}
